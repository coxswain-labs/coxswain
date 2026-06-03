use crate::shared::Shared;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;

/// Raw PEM bytes for a single TLS cert/key pair sourced from a `kubernetes.io/tls` Secret.
///
/// Validation happens once in the controller before insertion; the proxy re-parses
/// on each SNI handshake (cheap relative to the handshake itself).
#[derive(Debug)]
pub struct TlsCert {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    /// `"namespace/secret-name"` — for log messages only.
    pub source: String,
}

impl TlsCert {
    pub fn new(cert_pem: Vec<u8>, key_pem: Vec<u8>, source: String) -> Self {
        Self {
            cert_pem,
            key_pem,
            source,
        }
    }
}

/// PEM bytes only; `source` is diagnostic and excluded so a cert moving between owners
/// does not trigger an unnecessary `ArcSwap` store.
impl PartialEq for TlsCert {
    fn eq(&self, other: &Self) -> bool {
        self.cert_pem == other.cert_pem && self.key_pem == other.key_pem
    }
}

/// Immutable snapshot of all TLS certs indexed by host pattern.
#[derive(Debug, Default, PartialEq)]
pub struct TlsStore {
    exact: HashMap<String, Arc<TlsCert>>,
    /// Sorted most-specific (longest suffix) first.
    wildcard: Vec<(String, Arc<TlsCert>)>,
    /// Fallback cert for listeners with no hostname restriction (Gateway API allows
    /// HTTPS listeners without a `hostname` — they match any SNI).
    default: Option<Arc<TlsCert>>,
}

impl TlsStore {
    /// SNI cert lookup: exact host wins over wildcard, wildcard over default.
    /// Returns `None` when no cert matches — the caller should fail the handshake.
    pub fn find_cert(&self, sni: &str) -> Option<Arc<TlsCert>> {
        if let Some(cert) = self.exact.get(sni) {
            return Some(Arc::clone(cert));
        }
        if let Some((_, cert)) = self
            .wildcard
            .iter()
            .find(|(suffix, _)| wildcard_matches(sni, suffix))
        {
            return Some(Arc::clone(cert));
        }
        self.default.as_ref().map(Arc::clone)
    }

    pub fn cert_count(&self) -> usize {
        self.exact.len() + self.wildcard.len() + self.default.is_some() as usize
    }
}

/// Returns true when `sni` matches the wildcard pattern `*.{suffix}`.
/// Requires exactly one label before the suffix: `foo.example.com` matches
/// suffix `example.com`, but `example.com` and `a.b.example.com` do not.
fn wildcard_matches(sni: &str, suffix: &str) -> bool {
    if let Some(rest) = sni.strip_suffix(suffix)
        && let Some(label) = rest.strip_suffix('.')
    {
        return !label.is_empty() && !label.contains('.');
    }
    false
}

/// Builder for [`TlsStore`]. Not thread-safe; used only inside the debounced rebuild.
#[derive(Default)]
pub struct TlsStoreBuilder {
    exact: HashMap<String, Arc<TlsCert>>,
    /// Keyed by suffix (e.g. `"example.com"` for the pattern `"*.example.com"`).
    wildcard: HashMap<String, Arc<TlsCert>>,
    default: Option<Arc<TlsCert>>,
}

impl TlsStoreBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a cert for `host_pattern`.
    ///
    /// - `*.suffix` → wildcard bucket (suffix stored without `*.` prefix).
    /// - Exact hostname → exact bucket.
    /// - `""` or `"*"` → default fallback (served when no exact/wildcard matches the SNI).
    /// - Duplicate host → last-writer-wins with a warning.
    pub fn add_cert(&mut self, host_pattern: &str, cert: Arc<TlsCert>) {
        if host_pattern.is_empty() || host_pattern == "*" {
            self.default = Some(cert);
            return;
        }
        if let Some(suffix) = host_pattern.strip_prefix("*.") {
            if let Some(prev) = self.wildcard.insert(suffix.to_string(), cert) {
                tracing::warn!(
                    host = %host_pattern,
                    previous_source = %prev.source,
                    "TLS cert overwritten by a later Ingress"
                );
            }
        } else if let Some(prev) = self.exact.insert(host_pattern.to_string(), cert) {
            tracing::warn!(
                host = %host_pattern,
                previous_source = %prev.source,
                "TLS cert overwritten by a later Ingress"
            );
        }
    }

    pub fn build(self) -> TlsStore {
        let mut wildcard: Vec<(String, Arc<TlsCert>)> = self.wildcard.into_iter().collect();
        wildcard.sort_by_key(|(suffix, _)| Reverse(suffix.len()));
        TlsStore {
            exact: self.exact,
            wildcard,
            default: self.default,
        }
    }
}

/// A cheaply-cloneable handle to the active TLS cert store.
///
/// Certs and routes have separate lifecycles (cert-manager rotates certs
/// independently of route edits) and are swapped independently.
pub type SharedTlsStore = Shared<TlsStore>;

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(source: &str) -> Arc<TlsCert> {
        Arc::new(TlsCert::new(
            b"cert".to_vec(),
            b"key".to_vec(),
            source.to_string(),
        ))
    }

    #[test]
    fn exact_host_lookup() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("example.com", cert("ns/s1"));
        let store = b.build();
        assert!(store.find_cert("example.com").is_some());
        assert!(store.find_cert("other.com").is_none());
    }

    #[test]
    fn wildcard_host_lookup() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("*.example.com", cert("ns/s1"));
        let store = b.build();
        assert!(store.find_cert("api.example.com").is_some());
        assert!(store.find_cert("example.com").is_none());
        assert!(store.find_cert("a.b.example.com").is_none());
    }

    #[test]
    fn exact_beats_wildcard_on_sni() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("api.example.com", cert("exact"));
        b.add_cert("*.example.com", cert("wildcard"));
        let store = b.build();
        let found = store.find_cert("api.example.com").unwrap();
        assert_eq!(found.source, "exact");
    }

    #[test]
    fn no_match_returns_none() {
        let store = TlsStoreBuilder::new().build();
        assert!(store.find_cert("example.com").is_none());
    }

    #[test]
    fn catchall_host_becomes_default() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("", cert("ns/s1"));
        b.add_cert("*", cert("ns/s2")); // last writer wins
        let store = b.build();
        assert_eq!(store.cert_count(), 1);
        // Default is served for any SNI that has no exact/wildcard match.
        assert_eq!(
            store.find_cert("anything.example.com").unwrap().source,
            "ns/s2"
        );
    }

    #[test]
    fn default_cert_is_fallback_only() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("example.com", cert("exact"));
        b.add_cert("", cert("default"));
        let store = b.build();
        assert_eq!(store.find_cert("example.com").unwrap().source, "exact");
        assert_eq!(store.find_cert("other.com").unwrap().source, "default");
    }

    #[test]
    fn last_writer_wins_on_duplicate_exact_host() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("example.com", cert("first"));
        b.add_cert("example.com", cert("second"));
        let store = b.build();
        assert_eq!(store.find_cert("example.com").unwrap().source, "second");
    }

    #[test]
    fn last_writer_wins_on_duplicate_wildcard() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("*.example.com", cert("first"));
        b.add_cert("*.example.com", cert("second"));
        let store = b.build();
        assert_eq!(store.find_cert("api.example.com").unwrap().source, "second");
    }

    #[test]
    fn equal_stores_same_pem_different_source() {
        let mut b1 = TlsStoreBuilder::new();
        b1.add_cert("example.com", cert("ns/s1"));
        b1.add_cert("*.api.example.com", cert("ns/s2"));

        // Source strings differ — should still be equal because PEM bytes match.
        let mut b2 = TlsStoreBuilder::new();
        b2.add_cert("example.com", cert("ns/different-source"));
        b2.add_cert("*.api.example.com", cert("ns/s2"));

        assert_eq!(b1.build(), b2.build());
    }

    #[test]
    fn different_cert_bytes_not_equal() {
        let cert_a = Arc::new(TlsCert::new(
            b"cert-a".to_vec(),
            b"key".to_vec(),
            "ns/s1".to_string(),
        ));
        let cert_b = Arc::new(TlsCert::new(
            b"cert-b".to_vec(),
            b"key".to_vec(),
            "ns/s1".to_string(),
        ));

        let mut b1 = TlsStoreBuilder::new();
        b1.add_cert("example.com", cert_a);

        let mut b2 = TlsStoreBuilder::new();
        b2.add_cert("example.com", cert_b);

        assert_ne!(b1.build(), b2.build());
    }

    #[test]
    fn wildcard_sorted_longest_suffix_first() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("*.example.com", cert("short"));
        b.add_cert("*.api.example.com", cert("long"));
        let store = b.build();
        assert_eq!(
            store.find_cert("v1.api.example.com").unwrap().source,
            "long"
        );
        assert_eq!(store.find_cert("web.example.com").unwrap().source, "short");
    }
}
