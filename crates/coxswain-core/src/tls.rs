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

    /// Iterate over all exact-hostname → cert mappings, in unspecified order.
    ///
    /// Used by the discovery wire layer to serialise the TLS store.
    pub fn iter_exact(&self) -> impl Iterator<Item = (&str, &Arc<TlsCert>)> {
        self.exact.iter().map(|(h, c)| (h.as_str(), c))
    }

    /// Iterate over all wildcard-suffix → cert mappings (suffix without the `*.` prefix),
    /// in longest-suffix-first order (the same precedence order as [`Self::find_cert`]).
    ///
    /// Used by the discovery wire layer to serialise the TLS store.
    pub fn iter_wildcard(&self) -> impl Iterator<Item = (&str, &Arc<TlsCert>)> {
        self.wildcard.iter().map(|(s, c)| (s.as_str(), c))
    }

    /// The default (catch-all) certificate, if one is configured.
    ///
    /// Used by the discovery wire layer to serialise the TLS store.
    pub fn default_cert(&self) -> Option<&Arc<TlsCert>> {
        self.default.as_ref()
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

// ---------------------------------------------------------------------------
// Client-certificate mTLS store (#267)
// ---------------------------------------------------------------------------

/// Per-host client-certificate mTLS state resolved from an [`Ingress`] annotation.
///
/// Keyed by SNI host pattern in [`ClientCertStore`] and read by the proxy during
/// every TLS handshake. The enum is crypto-free; PEM parsing happens at reconcile
/// time (reflector) and at handshake time (proxy).
///
/// [`Ingress`]: k8s_openapi::api::networking::v1::Ingress
#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum ClientCertConfigState {
    /// mTLS configured and the CA Secret was resolved successfully.
    Config(ClientCertConfig),
    /// The annotation is present but the CA Secret was missing, unlabeled,
    /// lacked a `ca.crt` key, or held unparseable PEM. Fail-closed: the proxy
    /// aborts every TLS handshake to this host until the Secret is corrected.
    Unavailable,
}

/// Resolved client-certificate mTLS configuration for a single Ingress host.
#[non_exhaustive]
#[derive(Debug)]
pub struct ClientCertConfig {
    /// PEM-encoded CA certificate bundle sourced from `Secret.data["ca.crt"]`.
    pub ca_pem: Vec<u8>,
    /// Maximum client-certificate chain verification depth. Default is `1`
    /// (leaf certificate only, matching Istio's default for `tls.mode: MUTUAL`).
    pub verify_depth: u32,
    /// When `true` the verified client certificate is forwarded to the upstream
    /// as `X-SSL-Client-Cert` (URL-encoded PEM).
    pub pass_to_upstream: bool,
}

impl ClientCertConfig {
    /// Construct a new [`ClientCertConfig`].
    pub fn new(ca_pem: Vec<u8>, verify_depth: u32, pass_to_upstream: bool) -> Self {
        Self {
            ca_pem,
            verify_depth,
            pass_to_upstream,
        }
    }
}

/// Equality compares PEM bytes, depth, and pass flag only. The diagnostic `source`
/// label (if any) is excluded so a CA moving between Secrets does not churn the
/// [`ArcSwap`] — same pattern as [`TlsCert`].
///
/// [`ArcSwap`]: arc_swap::ArcSwap
impl PartialEq for ClientCertConfig {
    fn eq(&self, other: &Self) -> bool {
        self.ca_pem == other.ca_pem
            && self.verify_depth == other.verify_depth
            && self.pass_to_upstream == other.pass_to_upstream
    }
}

/// Immutable snapshot of per-host mTLS configuration, keyed by SNI pattern.
///
/// Built once per reconcile cycle and shared read-only with the proxy via
/// [`SharedClientCertStore`]. Swapped independently of [`SharedTlsStore`] so
/// CA rotation does not churn the server-cert snapshot.
#[non_exhaustive]
#[derive(Debug, Default, PartialEq)]
pub struct ClientCertStore {
    exact: HashMap<String, Arc<ClientCertConfigState>>,
    /// Sorted most-specific (longest suffix) first.
    wildcard: Vec<(String, Arc<ClientCertConfigState>)>,
    /// Fallback config when no exact/wildcard pattern matches the SNI.
    default: Option<Arc<ClientCertConfigState>>,
}

impl ClientCertStore {
    /// Look up the client-cert config for `sni`.
    ///
    /// Returns `None` when no pattern matches — mTLS is not required for this
    /// SNI. Exact match wins over wildcard, wildcard over default, matching the
    /// precedence of [`TlsStore::find_cert`].
    pub fn find_config(&self, sni: &str) -> Option<Arc<ClientCertConfigState>> {
        if let Some(cfg) = self.exact.get(sni) {
            return Some(Arc::clone(cfg));
        }
        if let Some((_, cfg)) = self
            .wildcard
            .iter()
            .find(|(suffix, _)| wildcard_matches(sni, suffix))
        {
            return Some(Arc::clone(cfg));
        }
        self.default.as_ref().map(Arc::clone)
    }

    /// Total number of configured host patterns (exact + wildcard + default).
    pub fn host_count(&self) -> usize {
        self.exact.len() + self.wildcard.len() + self.default.is_some() as usize
    }

    /// Iterate over all exact-hostname → config mappings, in unspecified order.
    ///
    /// Used by the discovery wire layer to serialise the client-cert store.
    pub fn iter_exact(&self) -> impl Iterator<Item = (&str, &Arc<ClientCertConfigState>)> {
        self.exact.iter().map(|(h, s)| (h.as_str(), s))
    }

    /// Iterate over all wildcard-suffix → config mappings (suffix without the `*.` prefix),
    /// in longest-suffix-first order.
    ///
    /// Used by the discovery wire layer to serialise the client-cert store.
    pub fn iter_wildcard(&self) -> impl Iterator<Item = (&str, &Arc<ClientCertConfigState>)> {
        self.wildcard.iter().map(|(s, cfg)| (s.as_str(), cfg))
    }

    /// The default (catch-all) client-cert config, if one is configured.
    ///
    /// Used by the discovery wire layer to serialise the client-cert store.
    pub fn default_state(&self) -> Option<&Arc<ClientCertConfigState>> {
        self.default.as_ref()
    }
}

/// Builder for [`ClientCertStore`]. Not thread-safe; used only inside the
/// debounced rebuild, mirroring [`TlsStoreBuilder`].
#[non_exhaustive]
#[derive(Default)]
pub struct ClientCertStoreBuilder {
    exact: HashMap<String, Arc<ClientCertConfigState>>,
    /// Keyed by suffix (e.g. `"example.com"` for the pattern `"*.example.com"`).
    wildcard: HashMap<String, Arc<ClientCertConfigState>>,
    default: Option<Arc<ClientCertConfigState>>,
}

impl ClientCertStoreBuilder {
    /// Construct an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register client-cert config for `host_pattern`.
    ///
    /// - `*.suffix` → wildcard bucket (suffix stored without the `*.` prefix).
    /// - Exact hostname → exact bucket.
    /// - `""` or `"*"` → default fallback.
    /// - Duplicate host → last-writer-wins with a `WARN` log.
    ///
    /// Alias of [`Self::add_client_cert`] for use in generic wire-codec callers.
    pub fn add_config(&mut self, host_pattern: &str, cfg: Arc<ClientCertConfigState>) {
        self.add_client_cert(host_pattern, cfg);
    }

    /// Register client-cert config for `host_pattern`.
    ///
    /// - `*.suffix` → wildcard bucket (suffix stored without the `*.` prefix).
    /// - Exact hostname → exact bucket.
    /// - `""` or `"*"` → default fallback.
    /// - Duplicate host → last-writer-wins with a `WARN` log.
    pub fn add_client_cert(&mut self, host_pattern: &str, cfg: Arc<ClientCertConfigState>) {
        if host_pattern.is_empty() || host_pattern == "*" {
            self.default = Some(cfg);
            return;
        }
        if let Some(suffix) = host_pattern.strip_prefix("*.") {
            if self.wildcard.insert(suffix.to_string(), cfg).is_some() {
                tracing::warn!(
                    host = %host_pattern,
                    "mTLS client-cert config overwritten by a later Ingress"
                );
            }
        } else if self.exact.insert(host_pattern.to_string(), cfg).is_some() {
            tracing::warn!(
                host = %host_pattern,
                "mTLS client-cert config overwritten by a later Ingress"
            );
        }
    }

    /// Compile accumulated configs into an immutable [`ClientCertStore`].
    pub fn build(self) -> ClientCertStore {
        let mut wildcard: Vec<(String, Arc<ClientCertConfigState>)> =
            self.wildcard.into_iter().collect();
        wildcard.sort_by_key(|(suffix, _)| Reverse(suffix.len()));
        ClientCertStore {
            exact: self.exact,
            wildcard,
            default: self.default,
        }
    }
}

/// A cheaply-cloneable handle to the active client-cert mTLS configuration store.
///
/// Swapped independently of [`SharedTlsStore`] so CA rotation does not churn
/// the server-cert snapshot.
pub type SharedClientCertStore = Shared<ClientCertStore>;

#[cfg(test)]
mod tests {
    use crate::tls::*;
    use std::sync::Arc;

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

    // --- ClientCertStore tests ---

    fn cfg(ca: &[u8]) -> Arc<ClientCertConfigState> {
        Arc::new(ClientCertConfigState::Config(ClientCertConfig::new(
            ca.to_vec(),
            1,
            false,
        )))
    }

    fn unavailable() -> Arc<ClientCertConfigState> {
        Arc::new(ClientCertConfigState::Unavailable)
    }

    #[test]
    fn client_cert_exact_lookup() {
        let mut b = ClientCertStoreBuilder::new();
        b.add_client_cert("example.com", cfg(b"ca"));
        let store = b.build();
        assert!(store.find_config("example.com").is_some());
        assert!(store.find_config("other.com").is_none());
    }

    #[test]
    fn client_cert_wildcard_lookup() {
        let mut b = ClientCertStoreBuilder::new();
        b.add_client_cert("*.example.com", cfg(b"ca"));
        let store = b.build();
        assert!(store.find_config("api.example.com").is_some());
        assert!(store.find_config("example.com").is_none());
        assert!(store.find_config("a.b.example.com").is_none());
    }

    #[test]
    fn client_cert_exact_beats_wildcard() {
        let mut b = ClientCertStoreBuilder::new();
        b.add_client_cert("api.example.com", cfg(b"exact-ca"));
        b.add_client_cert("*.example.com", cfg(b"wildcard-ca"));
        let store = b.build();
        match store.find_config("api.example.com").unwrap().as_ref() {
            ClientCertConfigState::Config(c) => assert_eq!(c.ca_pem, b"exact-ca"),
            _ => panic!("expected Config"),
        }
    }

    #[test]
    fn client_cert_no_match_returns_none() {
        let store = ClientCertStoreBuilder::new().build();
        assert!(store.find_config("example.com").is_none());
    }

    #[test]
    fn client_cert_default_fallback() {
        let mut b = ClientCertStoreBuilder::new();
        b.add_client_cert("*", cfg(b"default-ca"));
        let store = b.build();
        assert!(store.find_config("anything.example.com").is_some());
    }

    #[test]
    fn client_cert_unavailable_variant_stored() {
        let mut b = ClientCertStoreBuilder::new();
        b.add_client_cert("broken.example.com", unavailable());
        let store = b.build();
        assert!(matches!(
            store.find_config("broken.example.com").unwrap().as_ref(),
            ClientCertConfigState::Unavailable
        ));
    }

    #[test]
    fn client_cert_partial_eq_same_bytes() {
        let s1 = {
            let mut b = ClientCertStoreBuilder::new();
            b.add_client_cert("example.com", cfg(b"ca"));
            b.build()
        };
        let s2 = {
            let mut b = ClientCertStoreBuilder::new();
            b.add_client_cert("example.com", cfg(b"ca"));
            b.build()
        };
        assert_eq!(s1, s2);
    }

    #[test]
    fn client_cert_partial_eq_different_bytes() {
        let s1 = {
            let mut b = ClientCertStoreBuilder::new();
            b.add_client_cert("example.com", cfg(b"ca-a"));
            b.build()
        };
        let s2 = {
            let mut b = ClientCertStoreBuilder::new();
            b.add_client_cert("example.com", cfg(b"ca-b"));
            b.build()
        };
        assert_ne!(s1, s2);
    }

    #[test]
    fn client_cert_wildcard_sorted_longest_first() {
        let mut b = ClientCertStoreBuilder::new();
        b.add_client_cert("*.example.com", cfg(b"short"));
        b.add_client_cert("*.api.example.com", cfg(b"long"));
        let store = b.build();
        match store.find_config("v1.api.example.com").unwrap().as_ref() {
            ClientCertConfigState::Config(c) => assert_eq!(c.ca_pem, b"long"),
            _ => panic!("expected Config"),
        }
        match store.find_config("web.example.com").unwrap().as_ref() {
            ClientCertConfigState::Config(c) => assert_eq!(c.ca_pem, b"short"),
            _ => panic!("expected Config"),
        }
    }

    #[test]
    fn client_cert_host_count() {
        let mut b = ClientCertStoreBuilder::new();
        b.add_client_cert("a.com", cfg(b"ca"));
        b.add_client_cert("*.b.com", cfg(b"ca"));
        b.add_client_cert("*", cfg(b"ca"));
        assert_eq!(b.build().host_count(), 3);
    }
}
