//! TLS certificate store and builder — maps SNI host patterns to PEM cert/key pairs.

use crate::shared::Shared;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

/// Key algorithm of the TLS certificate's public key.
///
/// Classified once at load time from the Subject Public Key Info (SPKI) of
/// the leaf certificate. Used by the proxy to prefer ECDSA over RSA when both
/// are available for the same SNI — mirroring Envoy's key-type selection logic.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyAlgorithm {
    /// RSA public key.
    Rsa,
    /// EC (ECDSA) public key.
    Ecdsa,
    /// Unknown or unclassified algorithm.
    #[default]
    Other,
}

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
    /// Public key algorithm, classified from the SPKI of the leaf certificate.
    ///
    /// `Other` when no algorithm classification was performed (e.g. Ingress
    /// certs loaded before GEP-851 multi-cert support was wired in). The proxy
    /// uses this to prefer ECDSA over RSA when both are available for an SNI.
    pub key_algorithm: KeyAlgorithm,
}

impl TlsCert {
    /// Construct a [`TlsCert`] from raw PEM bytes and a diagnostic source label.
    ///
    /// Use [`TlsCert::with_not_after`] and [`TlsCert::with_key_algorithm`] to
    /// attach parsed metadata on the returned cert.
    pub fn new(cert_pem: Vec<u8>, key_pem: Vec<u8>, source: String) -> Self {
        Self {
            cert_pem,
            key_pem,
            source,
            not_after: None,
            key_algorithm: KeyAlgorithm::Other,
        }
    }

    /// Builder-style setter for the leaf certificate's `notAfter` expiry.
    #[must_use]
    pub fn with_not_after(mut self, not_after: Option<SystemTime>) -> Self {
        self.not_after = not_after;
        self
    }

    /// Builder-style setter for the public key algorithm.
    ///
    /// Set from the SPKI OID of the leaf certificate at load time.
    #[must_use]
    pub fn with_key_algorithm(mut self, key_algorithm: KeyAlgorithm) -> Self {
        self.key_algorithm = key_algorithm;
        self
    }
}

/// PEM bytes only; `source`, `not_after`, and `key_algorithm` are diagnostic /
/// derived and excluded so a cert moving between owners does not trigger an
/// unnecessary `ArcSwap` store.
impl PartialEq for TlsCert {
    fn eq(&self, other: &Self) -> bool {
        self.cert_pem == other.cert_pem && self.key_pem == other.key_pem
    }
}

/// Immutable snapshot of all TLS certs indexed by host pattern.
///
/// Each host pattern maps to a **sorted** `Vec` of certs: ECDSA first, then RSA,
/// then Other; within the same algorithm, newest `notAfter` first; then by
/// `source` for a fully deterministic order. The sort is established once at
/// [`TlsStoreBuilder::build`] time and never mutated.
#[non_exhaustive]
#[derive(Debug, Default, PartialEq)]
pub struct TlsStore {
    exact: HashMap<String, Vec<Arc<TlsCert>>>,
    /// Sorted most-specific (longest suffix) first.
    wildcard: Vec<(String, Vec<Arc<TlsCert>>)>,
    /// Fallback certs for listeners with no hostname restriction (Gateway API
    /// allows HTTPS listeners without a `hostname` — they match any SNI).
    default: Vec<Arc<TlsCert>>,
}

impl TlsStore {
    /// SNI cert lookup — returns all certs registered for the matching pattern.
    ///
    /// Lookup precedence: exact host wins over wildcard suffix, wildcard over
    /// default. Returns an empty slice when no cert matches.
    pub fn find_certs(&self, sni: &str) -> &[Arc<TlsCert>] {
        if let Some(certs) = self.exact.get(sni) {
            return certs.as_slice();
        }
        if let Some((_, certs)) = self
            .wildcard
            .iter()
            .find(|(suffix, _)| wildcard_matches(sni, suffix))
        {
            return certs.as_slice();
        }
        self.default.as_slice()
    }

    /// Compatibility wrapper: returns the first (highest-priority) cert for
    /// `sni`, or `None` when no cert matches.
    ///
    /// Callers that need all available certs (e.g. the proxy algorithm-selection
    /// path) should use [`Self::find_certs`] instead.
    pub fn find_cert(&self, sni: &str) -> Option<Arc<TlsCert>> {
        self.find_certs(sni).first().map(Arc::clone)
    }

    /// Total number of certificates across all buckets (exact + wildcard + default).
    pub fn cert_count(&self) -> usize {
        self.exact.values().map(Vec::len).sum::<usize>()
            + self.wildcard.iter().map(|(_, v)| v.len()).sum::<usize>()
            + self.default.len()
    }

    /// `(exact, wildcard, default)` cert counts — feeds the
    /// `*_tls_certs_loaded{bucket}` gauge.
    pub fn cert_counts(&self) -> (usize, usize, usize) {
        (
            self.exact.values().map(Vec::len).sum(),
            self.wildcard.iter().map(|(_, v)| v.len()).sum(),
            self.default.len(),
        )
    }

    /// Iterate over all exact-hostname → cert mappings, in unspecified order.
    ///
    /// Returns the **first** (highest-priority) cert per pattern. Compat
    /// wrapper; callers that need all certs per pattern should use
    /// [`Self::iter_exact_all`].
    pub fn iter_exact(&self) -> impl Iterator<Item = (&str, &Arc<TlsCert>)> {
        self.exact
            .iter()
            .filter_map(|(h, certs)| certs.first().map(|c| (h.as_str(), c)))
    }

    /// Iterate over all exact-hostname → **all certs** mappings, in unspecified order.
    ///
    /// Used by the multi-cert discovery wire serialiser.
    pub fn iter_exact_all(&self) -> impl Iterator<Item = (&str, &[Arc<TlsCert>])> {
        self.exact
            .iter()
            .map(|(h, certs)| (h.as_str(), certs.as_slice()))
    }

    /// Iterate over all wildcard-suffix → cert mappings (suffix without the `*.`
    /// prefix), in longest-suffix-first order (the same precedence order as
    /// [`Self::find_certs`]).
    ///
    /// Returns the **first** (highest-priority) cert per pattern. Compat
    /// wrapper; callers that need all certs per pattern should use
    /// [`Self::iter_wildcard_all`].
    pub fn iter_wildcard(&self) -> impl Iterator<Item = (&str, &Arc<TlsCert>)> {
        self.wildcard
            .iter()
            .filter_map(|(s, certs)| certs.first().map(|c| (s.as_str(), c)))
    }

    /// Iterate over all wildcard-suffix → **all certs** mappings, in
    /// longest-suffix-first order.
    ///
    /// Used by the multi-cert discovery wire serialiser.
    pub fn iter_wildcard_all(&self) -> impl Iterator<Item = (&str, &[Arc<TlsCert>])> {
        self.wildcard
            .iter()
            .map(|(s, certs)| (s.as_str(), certs.as_slice()))
    }

    /// The highest-priority default (catch-all) certificate, if one is configured.
    ///
    /// Compat wrapper; callers needing all default certs should use [`Self::default_certs`].
    pub fn default_cert(&self) -> Option<&Arc<TlsCert>> {
        self.default.first()
    }

    /// All default (catch-all) certificates, in sorted order.
    ///
    /// Used by the multi-cert discovery wire serialiser.
    pub fn default_certs(&self) -> &[Arc<TlsCert>] {
        self.default.as_slice()
    }

    /// `(sni_label, source, not_after)` triples for every cert with a parsed
    /// expiry. Used by the proxy-pod
    /// `*_tls_cert_expiry_seconds{sni,source}` gauge. Certs whose `not_after`
    /// is `None` (PEM parse failure) are omitted.
    ///
    /// - `sni_label`: exact patterns are themselves; wildcard patterns are
    ///   `"*.suffix"`; the default certs are `"*"`.
    /// - `source`: the `"namespace/secret-name"` label from the cert —
    ///   disambiguates co-located RSA+ECDSA certs on the same SNI.
    pub fn expiries(&self) -> Vec<(String, String, SystemTime)> {
        let mut out = Vec::with_capacity(self.cert_count());
        for (sni, certs) in &self.exact {
            for cert in certs {
                if let Some(t) = cert.not_after {
                    out.push((sni.clone(), cert.source.clone(), t));
                }
            }
        }
        for (suffix, certs) in &self.wildcard {
            for cert in certs {
                if let Some(t) = cert.not_after {
                    out.push((format!("*.{suffix}"), cert.source.clone(), t));
                }
            }
        }
        for cert in &self.default {
            if let Some(t) = cert.not_after {
                out.push(("*".to_string(), cert.source.clone(), t));
            }
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

/// Sort order for [`KeyAlgorithm`] during per-pattern cert sorting: ECDSA first,
/// then RSA, then Other.
fn algo_sort_key(ka: KeyAlgorithm) -> u8 {
    match ka {
        KeyAlgorithm::Ecdsa => 0,
        KeyAlgorithm::Rsa => 1,
        KeyAlgorithm::Other => 2,
    }
}

/// Sort a cert vec in-place: ECDSA → RSA → Other; within algorithm, newest
/// `not_after` first (certs without expiry last); then `source` alphabetically
/// for a fully deterministic, byte-stable order.
fn sort_cert_vec(certs: &mut [Arc<TlsCert>]) {
    certs.sort_by(|a, b| {
        algo_sort_key(a.key_algorithm)
            .cmp(&algo_sort_key(b.key_algorithm))
            .then_with(|| {
                // Descending not_after: None is treated as epoch 0 (sorts last).
                b.not_after.cmp(&a.not_after)
            })
            .then_with(|| a.source.cmp(&b.source))
    });
}

/// Deduplicate a cert vec in-place, keeping the first occurrence of each unique
/// PEM pair and discarding exact duplicates. Order is preserved for the
/// surviving elements.
fn dedup_cert_vec(certs: &mut Vec<Arc<TlsCert>>) {
    let mut i = 0;
    while i < certs.len() {
        let is_dup = (0..i).any(|j| certs[j].as_ref() == certs[i].as_ref());
        if is_dup {
            certs.remove(i);
        } else {
            i += 1;
        }
    }
}

/// Builder for [`TlsStore`]. Not thread-safe; used only inside the debounced rebuild.
#[non_exhaustive]
#[derive(Default)]
pub struct TlsStoreBuilder {
    exact: HashMap<String, Vec<Arc<TlsCert>>>,
    /// Keyed by suffix (e.g. `"example.com"` for the pattern `"*.example.com"`).
    wildcard: HashMap<String, Vec<Arc<TlsCert>>>,
    default: Vec<Arc<TlsCert>>,
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
    /// - `""` or `"*"` → default fallback (served when no exact/wildcard matches).
    ///
    /// Multiple certs for the same pattern are all registered (supports dual-
    /// algorithm RSA+ECDSA and rotation overlap). Exact-duplicate PEM bytes within
    /// a pattern are silently skipped to avoid churn.
    ///
    /// Call order within a pattern does not affect selection order — certs are
    /// sorted deterministically at [`Self::build`] time.
    pub fn add_cert(&mut self, host_pattern: &str, cert: Arc<TlsCert>) {
        if host_pattern.is_empty() || host_pattern == "*" {
            self.default.push(cert);
            return;
        }
        if let Some(suffix) = host_pattern.strip_prefix("*.") {
            self.wildcard
                .entry(suffix.to_string())
                .or_default()
                .push(cert);
        } else {
            self.exact
                .entry(host_pattern.to_string())
                .or_default()
                .push(cert);
        }
    }

    /// Compile accumulated certs into an immutable [`TlsStore`].
    ///
    /// Each pattern's cert vec is deduplicated (same PEM bytes → keep first)
    /// then sorted: ECDSA first, then RSA, then Other; newest `notAfter` first
    /// within an algorithm; `source` alphabetically as the final tiebreaker.
    pub fn build(self) -> TlsStore {
        let exact: HashMap<String, Vec<Arc<TlsCert>>> = self
            .exact
            .into_iter()
            .map(|(h, mut certs)| {
                dedup_cert_vec(&mut certs);
                sort_cert_vec(&mut certs);
                (h, certs)
            })
            .collect();

        let mut wildcard: Vec<(String, Vec<Arc<TlsCert>>)> = self
            .wildcard
            .into_iter()
            .map(|(suffix, mut certs)| {
                dedup_cert_vec(&mut certs);
                sort_cert_vec(&mut certs);
                (suffix, certs)
            })
            .collect();
        // Longest suffix first (most specific first).
        wildcard.sort_by_key(|(suffix, _)| Reverse(suffix.len()));

        let mut default = self.default;
        dedup_cert_vec(&mut default);
        sort_cert_vec(&mut default);

        TlsStore {
            exact,
            wildcard,
            default,
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

/// Per-host client-certificate mTLS state resolved from an Ingress annotation or
/// a Gateway `spec.tls.frontend.default.validation` block.
///
/// Keyed by SNI host pattern in [`ClientCertStore`] and read by the proxy during
/// every TLS handshake. The enum is crypto-free; PEM parsing happens at reconcile
/// time (reflector) and at handshake time (proxy).
#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum ClientCertConfigState {
    /// mTLS configured and the CA bundle was resolved successfully.
    Config(ClientCertConfig),
    /// The annotation or ref is present but the CA bundle was missing, unlabeled,
    /// lacked a `ca.crt` key, or held unparseable PEM. Fail-closed: the proxy
    /// aborts every TLS handshake to this host until the source is corrected.
    Unavailable,
}

/// Resolved client-certificate mTLS configuration for a single host.
///
/// Sources: Ingress `auth-tls-*` annotations (via [`ClientCertStoreBuilder`]) or
/// Gateway `spec.tls.frontend.default.validation` (GEP-91, #86).
#[non_exhaustive]
#[derive(Debug)]
pub struct ClientCertConfig {
    /// PEM-encoded CA certificate bundle.
    pub ca_pem: Vec<u8>,
    /// Maximum client-certificate chain verification depth. Default is `1`
    /// (leaf certificate only, matching Istio's default for `tls.mode: MUTUAL`).
    pub verify_depth: u32,
    /// When `true` the verified client certificate is forwarded to the upstream
    /// as `X-SSL-Client-Cert` (URL-encoded PEM).
    pub pass_to_upstream: bool,
    /// When `true`, the proxy uses `AllowInsecureFallback` semantics (GEP-91):
    /// the CA is installed and the client cert is requested, but a missing or
    /// invalid cert does **not** abort the TLS handshake. Authorization is
    /// delegated to the backend. Default is `false` (AllowValidOnly).
    pub allow_insecure_fallback: bool,
}

impl ClientCertConfig {
    /// Construct a new [`ClientCertConfig`] with `allow_insecure_fallback = false`.
    pub fn new(ca_pem: Vec<u8>, verify_depth: u32, pass_to_upstream: bool) -> Self {
        Self {
            ca_pem,
            verify_depth,
            pass_to_upstream,
            allow_insecure_fallback: false,
        }
    }

    /// Set the insecure-fallback mode (GEP-91 `AllowInsecureFallback`).
    ///
    /// When `true`, a missing or invalid client cert does not abort the handshake.
    #[must_use]
    pub fn with_insecure_fallback(mut self, value: bool) -> Self {
        self.allow_insecure_fallback = value;
        self
    }
}

/// Equality compares PEM bytes, depth, pass flag, and fallback mode. A fallback-mode
/// flip must churn the [`ArcSwap`] so the proxy re-applies BoringSSL verify flags.
/// The diagnostic `source` label (if any) is excluded — same pattern as [`TlsCert`].
///
/// [`ArcSwap`]: arc_swap::ArcSwap
impl PartialEq for ClientCertConfig {
    fn eq(&self, other: &Self) -> bool {
        self.ca_pem == other.ca_pem
            && self.verify_depth == other.verify_depth
            && self.pass_to_upstream == other.pass_to_upstream
            && self.allow_insecure_fallback == other.allow_insecure_fallback
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

// ---------------------------------------------------------------------------
// Listener-hostnames snapshot — GEP-3567 misdirected-request detection (#96)
// ---------------------------------------------------------------------------

/// Returns `true` when `host` matches the Gateway-listener hostname `pattern`.
///
/// - `*.suffix` → single-label wildcard via [`wildcard_matches`].
/// - Any other pattern → exact string equality.
fn listener_pattern_matches(host: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        wildcard_matches(host, suffix)
    } else {
        host == pattern
    }
}

/// Sort key for listener hostname patterns: most-specific first.
///
/// - Exact hostname → [`usize::MAX`] (always more specific than any wildcard).
/// - `*.suffix` → suffix length (longer suffix = more specific).
///
/// The match-all (`""`) listener is excluded from the sorted patterns vec and
/// tracked separately via [`PortListeners::has_match_all`].
fn listener_specificity(pattern: &str) -> usize {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        suffix.len()
    } else {
        usize::MAX
    }
}

/// Listener identity for the GEP-3567 misdirected-request equality check.
///
/// `Pattern(s)` borrows the stored hostname pattern string from the
/// [`ListenerHostnames`] snapshot. Because Gateway API requires distinct
/// hostname patterns per port, the pattern string is a unique listener key.
/// `MatchAll` represents the no-hostname (`""`) Gateway HTTPS listener.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum ListenerId<'a> {
    /// A named hostname pattern (exact or wildcard) identifies the listener.
    Pattern(&'a str),
    /// The no-hostname (`""`) catch-all listener on this port.
    MatchAll,
}

/// Per-port set of HTTPS Gateway-listener hostname patterns.
#[derive(Debug, Default, PartialEq)]
struct PortListeners {
    /// Exact and wildcard patterns sorted most-specific first (exact before
    /// wildcard, wildcards in descending suffix-length order).
    ///
    /// The match-all (`""`) listener is excluded — tracked by `has_match_all`.
    patterns: Vec<Box<str>>,
    /// `true` iff this port has a no-hostname (`""`) HTTPS Gateway listener.
    has_match_all: bool,
}

/// Immutable per-port snapshot of HTTPS Gateway-listener hostname patterns,
/// used to detect misdirected HTTP/2 connections (GEP-3567, #96).
///
/// Built once per reconcile cycle by [`ListenerHostnamesBuilder`] and shared
/// read-only with the proxy via [`SharedListenerHostnames`]. The
/// [`Self::resolve`] / [`Self::resolve_sni`] lookups are zero-allocation: they
/// iterate a pre-sorted `Vec<Box<str>>` of borrowed comparisons and return a
/// borrowed [`ListenerId`].
///
/// Empty by default — non-HTTPS ports and Ingress-only deployments leave the
/// snapshot empty so [`Self::has_https_port`] short-circuits with no allocation
/// overhead on the request hot-path.
#[non_exhaustive]
#[derive(Debug, Default, PartialEq)]
pub struct ListenerHostnames {
    ports: HashMap<u16, PortListeners>,
}

impl ListenerHostnames {
    /// Returns the identity of the most-specific HTTPS Gateway listener whose
    /// hostname pattern matches `host` on `port`.
    ///
    /// - `Some(ListenerId::Pattern(pat))` — a named listener matched.
    /// - `Some(ListenerId::MatchAll)` — no named pattern matched; the port's
    ///   no-hostname listener is the fallback.
    /// - `None` — `port` carries no HTTPS Gateway listeners (check inactive).
    ///
    /// All returned references borrow `self`. Zero allocation per call.
    pub fn resolve<'a>(&'a self, port: u16, host: &str) -> Option<ListenerId<'a>> {
        let p = self.ports.get(&port)?;
        for pat in &p.patterns {
            if listener_pattern_matches(host, pat) {
                return Some(ListenerId::Pattern(pat));
            }
        }
        p.has_match_all.then_some(ListenerId::MatchAll)
    }

    /// Resolves the most-specific listener for the negotiated TLS `sni`.
    ///
    /// Like [`Self::resolve`] but accepts `Option<&str>`: `None` means the
    /// TLS client sent no SNI extension (legal per RFC 6066). When no named
    /// pattern matches the SNI *and* the port has a no-hostname listener,
    /// returns `Some(MatchAll)` — the GEP-3567 step-1 fallback rule.
    ///
    /// Returns `None` when `port` carries no HTTPS Gateway listeners, disabling
    /// the misdirected-request check for that port entirely.
    pub fn resolve_sni<'a>(&'a self, port: u16, sni: Option<&str>) -> Option<ListenerId<'a>> {
        let p = self.ports.get(&port)?;
        if let Some(sni) = sni {
            for pat in &p.patterns {
                if listener_pattern_matches(sni, pat) {
                    return Some(ListenerId::Pattern(pat));
                }
            }
        }
        p.has_match_all.then_some(ListenerId::MatchAll)
    }

    /// Returns `true` when `port` has at least one HTTPS Gateway listener,
    /// indicating that the misdirected-request check is active for this port.
    #[must_use]
    pub fn has_https_port(&self, port: u16) -> bool {
        self.ports.contains_key(&port)
    }
}

/// Builder for [`ListenerHostnames`]. Not thread-safe; used only inside the
/// debounced reconcile rebuild, mirroring [`TlsStoreBuilder`].
#[non_exhaustive]
#[derive(Default)]
pub struct ListenerHostnamesBuilder {
    ports: HashMap<u16, (Vec<String>, bool)>,
}

impl ListenerHostnamesBuilder {
    /// Construct an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a Gateway listener's `hostname` and `port`.
    ///
    /// - `hostname == ""` or `"*"` → the no-hostname catch-all for this port.
    /// - `hostname` starting with `*.` → wildcard pattern.
    /// - Any other `hostname` → exact pattern.
    /// - `is_https == false` → silently ignored; only HTTPS-terminating
    ///   listeners participate in misdirected-request detection.
    pub fn add_listener(&mut self, port: u16, hostname: &str, is_https: bool) {
        if !is_https {
            return;
        }
        let (patterns, has_match_all) = self.ports.entry(port).or_default();
        if hostname.is_empty() || hostname == "*" {
            *has_match_all = true;
        } else {
            patterns.push(hostname.to_string());
        }
    }

    /// Compile accumulated listeners into an immutable [`ListenerHostnames`] snapshot.
    pub fn build(self) -> ListenerHostnames {
        let ports = self
            .ports
            .into_iter()
            .map(|(port, (mut patterns, has_match_all))| {
                patterns.sort_by_key(|p| Reverse(listener_specificity(p)));
                let patterns = patterns.into_iter().map(String::into_boxed_str).collect();
                (
                    port,
                    PortListeners {
                        patterns,
                        has_match_all,
                    },
                )
            })
            .collect();
        ListenerHostnames { ports }
    }
}

/// A cheaply-cloneable handle to the active per-port HTTPS listener-hostname
/// snapshot.
///
/// Published by the reflector after each Gateway reconcile and consumed
/// lock-free by the proxy on every HTTPS request to detect misdirected
/// connections (GEP-3567,
/// [#96](https://github.com/coxswain-labs/coxswain/issues/96)).
pub type SharedListenerHostnames = Shared<ListenerHostnames>;

#[cfg(test)]
mod tests {
    use crate::tls::*;
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    /// Cert with identical PEM bytes regardless of `source`. Used when the test
    /// cares about SNI/precedence but not about distinguishing cert content.
    fn cert(source: &str) -> Arc<TlsCert> {
        Arc::new(TlsCert::new(
            b"cert".to_vec(),
            b"key".to_vec(),
            source.to_string(),
        ))
    }

    /// Cert with unique PEM bytes derived from `id`. Used when the test needs to
    /// distinguish multiple certs by content (e.g. multi-cert per pattern tests).
    fn cert_id(id: u8, source: &str) -> Arc<TlsCert> {
        Arc::new(TlsCert::new(
            vec![id, b'c'],
            vec![id, b'k'],
            source.to_string(),
        ))
    }

    /// Cert with unique bytes, a set key algorithm, and an optional not_after.
    fn cert_algo(
        id: u8,
        source: &str,
        algo: KeyAlgorithm,
        not_after_secs: Option<u64>,
    ) -> Arc<TlsCert> {
        let not_after = not_after_secs.map(|s| UNIX_EPOCH + Duration::from_secs(s));
        Arc::new(
            TlsCert::new(vec![id, b'c'], vec![id, b'k'], source.to_string())
                .with_key_algorithm(algo)
                .with_not_after(not_after),
        )
    }

    // ── TlsStore lookups ──────────────────────────────────────────────────────

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
        b.add_cert("api.example.com", cert_id(1, "exact"));
        b.add_cert("*.example.com", cert_id(2, "wildcard"));
        let store = b.build();
        let found = store.find_cert("api.example.com").unwrap();
        assert_eq!(found.source, "exact");
    }

    #[test]
    fn no_match_returns_none() {
        let store = TlsStoreBuilder::new().build();
        assert!(store.find_cert("example.com").is_none());
        assert!(store.find_certs("example.com").is_empty());
    }

    #[test]
    fn default_cert_is_fallback_only() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("example.com", cert_id(1, "exact"));
        b.add_cert("", cert_id(2, "default"));
        let store = b.build();
        assert_eq!(store.find_cert("example.com").unwrap().source, "exact");
        assert_eq!(store.find_cert("other.com").unwrap().source, "default");
    }

    #[test]
    fn wildcard_sorted_longest_suffix_first() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("*.example.com", cert_id(1, "short"));
        b.add_cert("*.api.example.com", cert_id(2, "long"));
        let store = b.build();
        assert_eq!(
            store.find_cert("v1.api.example.com").unwrap().source,
            "long"
        );
        assert_eq!(store.find_cert("web.example.com").unwrap().source, "short");
    }

    // ── multi-cert per pattern ────────────────────────────────────────────────

    #[test]
    fn multi_cert_exact_host_both_stored() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("example.com", cert_id(1, "first"));
        b.add_cert("example.com", cert_id(2, "second"));
        let store = b.build();
        assert_eq!(
            store.find_certs("example.com").len(),
            2,
            "both certs stored"
        );
        let sources: Vec<&str> = store
            .find_certs("example.com")
            .iter()
            .map(|c| c.source.as_str())
            .collect();
        assert!(sources.contains(&"first") && sources.contains(&"second"));
    }

    #[test]
    fn multi_cert_wildcard_both_stored() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("*.example.com", cert_id(1, "first"));
        b.add_cert("*.example.com", cert_id(2, "second"));
        let store = b.build();
        assert_eq!(
            store.find_certs("api.example.com").len(),
            2,
            "both wildcard certs stored"
        );
    }

    #[test]
    fn multi_cert_default_both_stored() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("", cert_id(1, "first"));
        b.add_cert("*", cert_id(2, "second"));
        let store = b.build();
        assert_eq!(store.find_certs("anything.example.com").len(), 2);
    }

    #[test]
    fn find_certs_returns_empty_slice_for_no_match() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("other.com", cert("ns/s1"));
        let store = b.build();
        assert!(store.find_certs("example.com").is_empty());
    }

    #[test]
    fn find_cert_compat_wrapper_returns_first() {
        let mut b = TlsStoreBuilder::new();
        // ECDSA sorts first, so it should be the find_cert() result.
        b.add_cert(
            "example.com",
            cert_algo(1, "rsa-cert", KeyAlgorithm::Rsa, None),
        );
        b.add_cert(
            "example.com",
            cert_algo(2, "ecdsa-cert", KeyAlgorithm::Ecdsa, None),
        );
        let store = b.build();
        // find_cert returns first of sorted vec — ECDSA sorts before RSA.
        assert_eq!(store.find_cert("example.com").unwrap().source, "ecdsa-cert");
    }

    // ── deduplication ─────────────────────────────────────────────────────────

    #[test]
    fn dedup_same_pem_exact_host() {
        let mut b = TlsStoreBuilder::new();
        // cert() produces identical PEM bytes regardless of source.
        b.add_cert("example.com", cert("first"));
        b.add_cert("example.com", cert("second"));
        let store = b.build();
        // Same PEM → deduplicated to 1.
        assert_eq!(store.find_certs("example.com").len(), 1);
    }

    #[test]
    fn dedup_same_pem_wildcard() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("*.example.com", cert("first"));
        b.add_cert("*.example.com", cert("second"));
        let store = b.build();
        assert_eq!(store.find_certs("api.example.com").len(), 1);
    }

    #[test]
    fn dedup_same_pem_default() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("", cert("first"));
        b.add_cert("*", cert("second"));
        let store = b.build();
        // Both have same PEM bytes → deduplicated.
        assert_eq!(store.find_certs("anything.io").len(), 1);
        assert_eq!(store.cert_count(), 1);
    }

    // ── cert_count / cert_counts ──────────────────────────────────────────────

    #[test]
    fn cert_count_sums_all_vecs() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert("example.com", cert_id(1, "e1"));
        b.add_cert("example.com", cert_id(2, "e2"));
        b.add_cert("*.example.com", cert_id(3, "w1"));
        b.add_cert("", cert_id(4, "d1"));
        let store = b.build();
        assert_eq!(store.cert_count(), 4);
        let (exact, wildcard, default) = store.cert_counts();
        assert_eq!((exact, wildcard, default), (2, 1, 1));
    }

    // ── sort order ────────────────────────────────────────────────────────────

    #[test]
    fn certs_sorted_ecdsa_before_rsa_before_other() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert(
            "example.com",
            cert_algo(1, "other", KeyAlgorithm::Other, None),
        );
        b.add_cert("example.com", cert_algo(2, "rsa", KeyAlgorithm::Rsa, None));
        b.add_cert(
            "example.com",
            cert_algo(3, "ecdsa", KeyAlgorithm::Ecdsa, None),
        );
        let store = b.build();
        let certs = store.find_certs("example.com");
        assert_eq!(certs.len(), 3);
        assert_eq!(certs[0].source, "ecdsa");
        assert_eq!(certs[1].source, "rsa");
        assert_eq!(certs[2].source, "other");
    }

    #[test]
    fn certs_same_algo_sorted_newest_first() {
        let mut b = TlsStoreBuilder::new();
        // older cert
        b.add_cert(
            "example.com",
            cert_algo(1, "old", KeyAlgorithm::Rsa, Some(1_000_000)),
        );
        // newer cert
        b.add_cert(
            "example.com",
            cert_algo(2, "new", KeyAlgorithm::Rsa, Some(2_000_000)),
        );
        let store = b.build();
        let certs = store.find_certs("example.com");
        assert_eq!(certs[0].source, "new", "newest not_after first");
        assert_eq!(certs[1].source, "old");
    }

    #[test]
    fn certs_no_expiry_sorted_last() {
        let mut b = TlsStoreBuilder::new();
        b.add_cert(
            "example.com",
            cert_algo(1, "no-expiry", KeyAlgorithm::Rsa, None),
        );
        b.add_cert(
            "example.com",
            cert_algo(2, "has-expiry", KeyAlgorithm::Rsa, Some(1_000_000)),
        );
        let store = b.build();
        let certs = store.find_certs("example.com");
        assert_eq!(certs[0].source, "has-expiry");
        assert_eq!(certs[1].source, "no-expiry");
    }

    // ── PartialEq ─────────────────────────────────────────────────────────────

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

    // ── ClientCertStore tests ─────────────────────────────────────────────────

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

    // ── ListenerHostnames tests ───────────────────────────────────────────────

    /// Builds the four-listener topology from the v1.5.1 conformance test
    /// `GatewayHTTPSListenerDetectMisdirectedRequests`:
    ///   `https`                              → no-hostname (catch-all)
    ///   `https-with-hostname`                → `second-example.org`
    ///   `https-with-wildcard-hostname`       → `*.wildcard.org`
    ///   `https-with-hostname-matching-wildcard` → `fourth-example.wildcard.org`
    /// All listeners are on port 443.
    fn conformance_topology() -> ListenerHostnames {
        let mut b = ListenerHostnamesBuilder::new();
        b.add_listener(443, "", true);
        b.add_listener(443, "second-example.org", true);
        b.add_listener(443, "*.wildcard.org", true);
        b.add_listener(443, "fourth-example.wildcard.org", true);
        b.build()
    }

    #[test]
    fn listener_hostnames_all_15_conformance_cases() {
        let lh = conformance_topology();

        // Returns true when the misdirected check would fire (421).
        let misdirected = |sni: Option<&str>, host: &str| -> bool {
            lh.resolve_sni(443, sni) != lh.resolve(443, host)
        };

        // Case 1: SNI=example.org, Host=example.org → both MatchAll → proceed
        assert!(!misdirected(Some("example.org"), "example.org"), "case 1");
        // Case 2: SNI=example.org, Host=second-example.org → MatchAll vs Pattern → 421
        assert!(
            misdirected(Some("example.org"), "second-example.org"),
            "case 2"
        );
        // Case 3: SNI=example.org, Host=unknown-example.org → both MatchAll → proceed (404 later)
        assert!(
            !misdirected(Some("example.org"), "unknown-example.org"),
            "case 3"
        );
        // Case 4: SNI=second-example.org, Host=second-example.org → same Pattern → proceed
        assert!(
            !misdirected(Some("second-example.org"), "second-example.org"),
            "case 4"
        );
        // Case 5: SNI=second-example.org, Host=example.org → Pattern vs MatchAll → 421
        assert!(
            misdirected(Some("second-example.org"), "example.org"),
            "case 5"
        );
        // Case 6: SNI=second-example.org, Host=unknown → Pattern vs MatchAll → 421
        assert!(
            misdirected(Some("second-example.org"), "unknown-example.org"),
            "case 6"
        );
        // Case 7: SNI=third-example.wildcard.org, Host=third → same *.wildcard.org → proceed
        assert!(
            !misdirected(
                Some("third-example.wildcard.org"),
                "third-example.wildcard.org"
            ),
            "case 7"
        );
        // Case 8: SNI=third, Host=fith → both *.wildcard.org listener → proceed (SNI≠Host ok)
        assert!(
            !misdirected(
                Some("third-example.wildcard.org"),
                "fith-example.wildcard.org"
            ),
            "case 8"
        );
        // Case 9: SNI=third, Host=fourth → *.wildcard.org vs fourth-example.wildcard.org → 421
        assert!(
            misdirected(
                Some("third-example.wildcard.org"),
                "fourth-example.wildcard.org"
            ),
            "case 9"
        );
        // Case 10: SNI=third, Host=second-example.org → *.wildcard.org vs Pattern(second) → 421
        assert!(
            misdirected(Some("third-example.wildcard.org"), "second-example.org"),
            "case 10"
        );
        // Case 11: SNI=third, Host=unknown → *.wildcard.org vs MatchAll → 421
        assert!(
            misdirected(Some("third-example.wildcard.org"), "unknown-example.org"),
            "case 11"
        );
        // Case 12: SNI=fourth, Host=fourth → same Pattern → proceed
        assert!(
            !misdirected(
                Some("fourth-example.wildcard.org"),
                "fourth-example.wildcard.org"
            ),
            "case 12"
        );
        // Case 13: SNI=fourth, Host=fith → fourth-exact vs *.wildcard.org → 421
        assert!(
            misdirected(
                Some("fourth-example.wildcard.org"),
                "fith-example.wildcard.org"
            ),
            "case 13"
        );
        // Case 14: SNI=unknown, Host=example.org → both MatchAll → proceed
        assert!(
            !misdirected(Some("unknown-example.org"), "example.org"),
            "case 14"
        );
        // Case 15: SNI=unknown, Host=unknown → both MatchAll → proceed (404 later)
        assert!(
            !misdirected(Some("unknown-example.org"), "unknown-example.org"),
            "case 15"
        );
    }

    #[test]
    fn listener_hostnames_no_sni_falls_back_to_match_all() {
        let mut b = ListenerHostnamesBuilder::new();
        b.add_listener(443, "", true);
        b.add_listener(443, "second-example.org", true);
        let lh = b.build();
        assert_eq!(lh.resolve_sni(443, None), Some(ListenerId::MatchAll));
    }

    #[test]
    fn listener_hostnames_no_sni_without_match_all_returns_none() {
        let mut b = ListenerHostnamesBuilder::new();
        b.add_listener(443, "example.org", true);
        let lh = b.build();
        assert_eq!(lh.resolve_sni(443, None), None);
    }

    #[test]
    fn listener_hostnames_non_https_listener_excluded() {
        let mut b = ListenerHostnamesBuilder::new();
        b.add_listener(80, "example.org", false);
        let lh = b.build();
        assert!(!lh.has_https_port(80));
        assert!(lh.resolve(80, "example.org").is_none());
    }

    #[test]
    fn listener_hostnames_empty_snapshot_is_inactive() {
        let lh = ListenerHostnames::default();
        assert!(!lh.has_https_port(443));
        assert!(lh.resolve_sni(443, Some("example.org")).is_none());
        assert!(lh.resolve(443, "example.org").is_none());
    }

    #[test]
    fn listener_hostnames_exact_beats_wildcard_on_same_port() {
        let mut b = ListenerHostnamesBuilder::new();
        b.add_listener(443, "*.wildcard.org", true);
        b.add_listener(443, "fourth-example.wildcard.org", true);
        let lh = b.build();
        assert_eq!(
            lh.resolve(443, "fourth-example.wildcard.org"),
            Some(ListenerId::Pattern("fourth-example.wildcard.org"))
        );
        assert_eq!(
            lh.resolve(443, "other.wildcard.org"),
            Some(ListenerId::Pattern("*.wildcard.org"))
        );
    }

    #[test]
    fn listener_hostnames_longer_wildcard_beats_shorter() {
        let mut b = ListenerHostnamesBuilder::new();
        b.add_listener(443, "*.org", true);
        b.add_listener(443, "*.wildcard.org", true);
        let lh = b.build();
        assert_eq!(
            lh.resolve(443, "foo.wildcard.org"),
            Some(ListenerId::Pattern("*.wildcard.org"))
        );
        assert_eq!(
            lh.resolve(443, "foo.org"),
            Some(ListenerId::Pattern("*.org"))
        );
    }

    #[test]
    fn listener_hostnames_port_isolation() {
        let mut b = ListenerHostnamesBuilder::new();
        b.add_listener(443, "example.org", true);
        b.add_listener(8443, "other.org", true);
        let lh = b.build();
        assert!(lh.has_https_port(443));
        assert!(lh.has_https_port(8443));
        // Port 443's listener doesn't bleed into port 8443's lookup.
        assert!(lh.resolve(8443, "example.org").is_none());
        assert!(lh.resolve(443, "other.org").is_none());
    }
}
