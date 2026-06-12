//! TLS certificate store and builder — maps SNI host patterns to PEM cert/key pairs.

use crate::shared::Shared;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

/// Raw PEM bytes for a single TLS cert/key pair sourced from a `kubernetes.io/tls` Secret.
///
/// Validation happens once in the controller before insertion; the proxy re-parses
/// on each SNI handshake (cheap relative to the handshake itself).
#[non_exhaustive]
#[derive(Debug)]
pub struct TlsCert {
    /// Raw PEM-encoded certificate chain.
    pub cert_pem: Vec<u8>,
    /// Raw PEM-encoded private key.
    pub key_pem: Vec<u8>,
    /// `"namespace/secret-name"` — for log messages only.
    pub source: String,
    /// Leaf certificate `notAfter`, parsed once at load time.
    ///
    /// `None` when the PEM couldn't be parsed (logged as a warn at load
    /// time — never fatal because a metrics gap must not break route
    /// serving). Consumed by `coxswain_proxy_tls_cert_expiry_seconds`.
    pub not_after: Option<SystemTime>,
}

impl TlsCert {
    /// Construct a [`TlsCert`] from raw PEM bytes and a diagnostic source label.
    ///
    /// Use [`TlsCert::with_not_after`] to record a parsed expiry on the
    /// returned cert.
    pub fn new(cert_pem: Vec<u8>, key_pem: Vec<u8>, source: String) -> Self {
        Self {
            cert_pem,
            key_pem,
            source,
            not_after: None,
        }
    }

    /// Builder-style setter for the leaf certificate's `notAfter` expiry.
    #[must_use]
    pub fn with_not_after(mut self, not_after: Option<SystemTime>) -> Self {
        self.not_after = not_after;
        self
    }
}

/// PEM bytes only; `source` and `not_after` are diagnostic and excluded so a
/// cert moving between owners does not trigger an unnecessary `ArcSwap` store.
impl PartialEq for TlsCert {
    fn eq(&self, other: &Self) -> bool {
        self.cert_pem == other.cert_pem && self.key_pem == other.key_pem
    }
}

/// Immutable snapshot of all TLS certs indexed by host pattern.
#[non_exhaustive]
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

    /// Total number of certificates across all buckets (exact + wildcard + default).
    pub fn cert_count(&self) -> usize {
        self.exact.len() + self.wildcard.len() + self.default.is_some() as usize
    }

    /// `(exact, wildcard, default)` cert counts — feeds the
    /// `*_tls_certs_loaded{bucket}` gauge.
    pub fn cert_counts(&self) -> (usize, usize, usize) {
        (
            self.exact.len(),
            self.wildcard.len(),
            usize::from(self.default.is_some()),
        )
    }

    /// `(sni, not_after)` pairs for every cert with a parsed expiry. Used by
    /// the proxy-pod `*_tls_cert_expiry_seconds{sni}` gauge. Certs whose
    /// `not_after` is `None` (PEM parse failure) are omitted.
    ///
    /// SNI labels: exact patterns are themselves; wildcard patterns are
    /// emitted as `"*.suffix"`; the default cert is labelled `"*"`.
    pub fn expiries(&self) -> Vec<(String, SystemTime)> {
        let mut out = Vec::with_capacity(self.cert_count());
        for (sni, cert) in &self.exact {
            if let Some(t) = cert.not_after {
                out.push((sni.clone(), t));
            }
        }
        for (suffix, cert) in &self.wildcard {
            if let Some(t) = cert.not_after {
                out.push((format!("*.{suffix}"), t));
            }
        }
        if let Some(cert) = &self.default
            && let Some(t) = cert.not_after
        {
            out.push(("*".to_string(), t));
        }
        out
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
#[non_exhaustive]
#[derive(Default)]
pub struct TlsStoreBuilder {
    exact: HashMap<String, Arc<TlsCert>>,
    /// Keyed by suffix (e.g. `"example.com"` for the pattern `"*.example.com"`).
    wildcard: HashMap<String, Arc<TlsCert>>,
    default: Option<Arc<TlsCert>>,
}

impl TlsStoreBuilder {
    /// Construct an empty builder.
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

    /// Compile accumulated certs into an immutable [`TlsStore`].
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
