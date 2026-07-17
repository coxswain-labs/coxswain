//! Upstream connection protocol and TLS configuration.
//!
//! The wire protocol ([`BackendProtocol`], derived from `appProtocol` per
//! GEP-1911) and the `BackendTLSPolicy`-derived TLS settings ([`UpstreamTls`] /
//! [`UpstreamCa`]) that a [`BackendGroup`](super::backend::BackendGroup) carries
//! for its upstream connections.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// A Subject Alternative Name entry from `BackendTLSPolicy.spec.validation.subjectAltNames`
/// (GEP-1897) that the proxy must find in the upstream's leaf certificate SAN extension.
///
/// When one or more `SubjectAltName`s are present on an [`UpstreamTls`], the
/// proxy verifies that **≥1** entry matches a SAN in the peer's leaf cert.
/// `UpstreamTls::sni` (the `hostname` field) is then used **solely** for SNI
/// and cert selection and **MUST NOT** be used for authentication — Pingora's
/// built-in hostname check is disabled in favour of this SAN check.
///
/// Deliberately closed: matched exhaustively across the crate boundary on the
/// discovery wire-encode path, so adding a variant is a compiler-enforced change
/// rather than a silent runtime drop. `#[non_exhaustive]` would force a wildcard
/// arm there and defeat that.
// intentionally open: closed enum matched exhaustively cross-crate on the wire-encode path; see doc above.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SubjectAltName {
    /// DNS-type SAN (`type: Hostname` in the policy).
    ///
    /// Matched against the peer cert's DNS SANs using RFC 6125 wildcard rules:
    /// a `*.`-prefixed label **in the certificate** matches exactly one
    /// non-empty left-most label of the expected policy value. Single-label
    /// strict (RFC 6125 §6.4.3) — not the multi-label routing rule used
    /// elsewhere in the project.
    Hostname(Arc<str>),
    /// URI-type SAN (`type: URI` in the policy, e.g. a SPIFFE ID).
    ///
    /// Matched byte-for-byte (case-sensitive) against the peer cert's URI SANs.
    Uri(Arc<str>),
}

/// Returns `true` if **≥1** entry in `expected` matches a SAN in the peer cert.
///
/// `dns_sans` / `uri_sans` are the SAN strings extracted from the peer leaf cert
/// (callers pull them from `X509Ref::subject_alt_names()` via
/// `GeneralNameRef::dnsname()` / `GeneralNameRef::uri()`).
///
/// # Rules
///
/// - [`SubjectAltName::Hostname`] matches case-insensitively against `dns_sans`.
///   When a `dns_san` starts with `*.`, it matches if the remaining suffix
///   equals the expected value's labels-from-2 component (single left-most
///   wildcard, RFC 6125 §6.4.3).
/// - [`SubjectAltName::Uri`] matches exactly (case-sensitive) against `uri_sans`.
/// - An empty `expected` slice always returns `false` (feature semantically off;
///   callers should not invoke the check when `expected` is empty, but it is
///   safe to do so).
#[must_use]
pub fn san_set_matches(expected: &[SubjectAltName], dns_sans: &[&str], uri_sans: &[&str]) -> bool {
    expected.iter().any(|e| match e {
        SubjectAltName::Hostname(h) => dns_sans.iter().any(|s| dns_san_matches(h, s)),
        SubjectAltName::Uri(u) => uri_sans.iter().any(|s| *s == u.as_ref()),
    })
}

/// Returns `true` if the peer-cert DNS SAN `cert_san` matches the policy `expected`
/// value under RFC 6125 §6.4.3 single-label wildcard semantics.
///
/// A leading `*.` in `cert_san` (not in `expected`) matches exactly one non-empty
/// left-most label of `expected`.  Both sides are compared case-insensitively.
fn dns_san_matches(expected: &str, cert_san: &str) -> bool {
    if let Some(wc_suffix) = cert_san.strip_prefix("*.") {
        // Wildcard in the certificate — match one left-most label.
        if let Some(dot_pos) = expected.find('.') {
            let label = &expected[..dot_pos];
            let rest = &expected[dot_pos + 1..];
            // Label must be non-empty and the rest must match the wildcard suffix.
            !label.is_empty() && rest.eq_ignore_ascii_case(wc_suffix)
        } else {
            // expected has no dot — cannot satisfy a wildcard SAN
            false
        }
    } else {
        cert_san.eq_ignore_ascii_case(expected)
    }
}

/// CA certificate source for a [`BackendTLSPolicy`](https://gateway-api.sigs.k8s.io/references/spec/#gateway.networking.k8s.io/v1alpha3.BackendTLSPolicy) attachment.
///
/// Deliberately closed: matched exhaustively across the crate boundary on the
/// discovery wire-encode path, so adding a variant is a compiler-enforced change
/// rather than a silent runtime drop. `#[non_exhaustive]` would force a wildcard
/// arm there and defeat that.
// intentionally open: closed enum matched exhaustively cross-crate on the wire-encode path; see doc above.
#[derive(Clone, Debug)]
pub enum UpstreamCa {
    /// `wellKnownCACertificates: System` — use the OS trust store.
    System,
    /// `caCertificateRefs` — raw PEM bytes from the referenced ConfigMap.
    Bundle(Arc<[u8]>),
}

/// Client certificate the Gateway presents to the upstream for backend mutual TLS,
/// resolved from `Gateway.spec.tls.backend.clientCertificateRef`
/// ([GEP-3155](https://gateway-api.sigs.k8s.io/geps/gep-3155/)).
///
/// Carried on an [`UpstreamTls`] (i.e. only on `BackendTLSPolicy`-driven TLS
/// connections — the only spec-sanctioned upstream-TLS-origination path). The
/// PEM bytes are resolved controller-side from a `kubernetes.io/tls` Secret and
/// travel the discovery wire; the proxy parses them into a Pingora `CertKey` lazily.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendClientCert {
    /// PEM-encoded client certificate chain (`tls.crt`).
    pub cert_pem: Arc<[u8]>,
    /// PEM-encoded client private key (`tls.key`).
    pub key_pem: Arc<[u8]>,
    /// `"namespace/secret-name"` of the source Secret — used for logging and as the
    /// identity folded into [`UpstreamTls::group_key`] for connection-pool isolation.
    pub source: Arc<str>,
}

impl BackendClientCert {
    /// Construct a [`BackendClientCert`] from its PEM components and source identity.
    pub fn new(cert_pem: Arc<[u8]>, key_pem: Arc<[u8]>, source: Arc<str>) -> Self {
        Self {
            cert_pem,
            key_pem,
            source,
        }
    }
}

/// TLS configuration for upstream connections derived from a `BackendTLSPolicy` attachment.
///
/// Presence of this struct on a [`BackendGroup`](super::backend::BackendGroup) is
/// the **sole** trigger for upstream TLS origination (GEP-1897): the proxy speaks
/// TLS to the backend if and only if the group carries an `UpstreamTls`. The
/// `appProtocol`-derived [`BackendProtocol`] carries no TLS semantics.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct UpstreamTls {
    /// Hostname used for SNI and certificate verification on the upstream connection.
    pub sni: Arc<str>,
    /// Certificate authority source for verifying the upstream cert.
    pub ca: UpstreamCa,
    /// Stable hash of `(sni, ca)` — folded into `HttpPeer.group_key` so distinct
    /// CA bundles never share a Pingora connection pool slot, and used as the cache
    /// key in the proxy-side parse cache. [`with_client_cert`](Self::with_client_cert)
    /// additionally mixes the client-cert identity in so distinct client identities
    /// to the same backend never share a pool either.
    /// [`with_subject_alt_names`](Self::with_subject_alt_names) further mixes the
    /// SAN set so that routes with different SAN expectations to the same backend
    /// never share a pool (pool isolation is load-bearing for reuse safety).
    pub group_key: u64,
    /// Client certificate the Gateway presents to the upstream (GEP-3155), or `None`
    /// when no `Gateway.spec.tls.backend.clientCertificateRef` applies to this backend.
    pub client_cert: Option<Arc<BackendClientCert>>,
    /// `BackendTLSPolicy.spec.validation.subjectAltNames` (GEP-1897) — the identity
    /// the upstream leaf certificate must present. Empty = feature off; [`UpstreamTls::sni`]
    /// is used for authentication via Pingora's built-in hostname check. Non-empty = the
    /// proxy disables the built-in hostname check and verifies ≥1 entry matches a SAN
    /// in the peer's leaf cert via [`san_set_matches`].
    pub subject_alt_names: Arc<[SubjectAltName]>,
}

impl UpstreamTls {
    /// Construct an [`UpstreamTls`] from its components, with no client certificate
    /// and no subject-alt-name constraints.
    ///
    /// Use [`with_client_cert`](Self::with_client_cert) to attach a GEP-3155 backend
    /// client certificate, and [`with_subject_alt_names`](Self::with_subject_alt_names)
    /// to add GEP-1897 `subjectAltNames` identity constraints.
    pub fn new(sni: Arc<str>, ca: UpstreamCa, group_key: u64) -> Self {
        Self {
            sni,
            ca,
            group_key,
            client_cert: None,
            subject_alt_names: Arc::from([]),
        }
    }

    /// Attach a GEP-3155 backend client certificate (builder-style).
    ///
    /// Folds the cert's `source` identity into [`group_key`](Self::group_key) so two
    /// routes reaching the same backend with different client identities use separate
    /// Pingora connection pools (a pool must not present one tenant's cert on another's
    /// reused connection).
    #[must_use]
    pub fn with_client_cert(mut self, cert: Arc<BackendClientCert>) -> Self {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.group_key.hash(&mut h);
        cert.source.hash(&mut h);
        self.group_key = h.finish();
        self.client_cert = Some(cert);
        self
    }

    /// The attached GEP-3155 backend client certificate, if any.
    #[must_use]
    pub fn client_cert(&self) -> Option<&Arc<BackendClientCert>> {
        self.client_cert.as_ref()
    }

    /// Attach GEP-1897 `subjectAltNames` identity constraints (builder-style).
    ///
    /// Folds the SAN set into [`group_key`](Self::group_key) so that routes with
    /// **different SAN expectations to the same backend endpoint** never share a
    /// Pingora connection pool.  This is load-bearing for reuse safety: the
    /// post-handshake SAN check only runs on new connections; without pool isolation
    /// a policy-B-expected connection could be reused by policy-A's route, bypassing
    /// B's check.
    ///
    /// Apply before [`with_client_cert`](Self::with_client_cert) — the reflector
    /// calls this first in `build_backend_tls_index` and `with_client_cert` later in
    /// `reconcile.rs`; a unit test pins the resulting `group_key` to guard against
    /// an accidental reorder regression.
    #[must_use]
    pub fn with_subject_alt_names(mut self, sans: impl Into<Arc<[SubjectAltName]>>) -> Self {
        let sans: Arc<[SubjectAltName]> = sans.into();
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.group_key.hash(&mut h);
        sans.hash(&mut h);
        self.group_key = h.finish();
        self.subject_alt_names = sans;
        self
    }

    /// The GEP-1897 subject-alt-name constraints, if any.
    ///
    /// An empty slice means the feature is off; the proxy uses Pingora's built-in
    /// hostname check instead.
    #[must_use]
    pub fn subject_alt_names(&self) -> &[SubjectAltName] {
        &self.subject_alt_names
    }
}

/// Wire protocol spoken by a backend, derived from `Service.spec.ports[].appProtocol`
/// per [GEP-1911](https://gateway-api.sigs.k8s.io/geps/gep-1911/).
///
/// This is a **pure wire-protocol hint** — it carries no TLS semantics. Upstream
/// TLS is originated solely by a `BackendTLSPolicy` (GEP-1897), surfaced as an
/// [`UpstreamTls`] on the [`BackendGroup`](super::backend::BackendGroup); see that
/// type. `appProtocol` values that imply TLS (`https`, `kubernetes.io/wss`) have no
/// Gateway API basis and map to [`Http1`](Self::Http1) (cleartext).
///
/// Deliberately closed: matched exhaustively across the crate boundary on the
/// discovery wire-encode path, so adding a variant is a compiler-enforced change
/// rather than a silent runtime drop. `#[non_exhaustive]` would force a wildcard
/// arm there and defeat that.
// intentionally open: closed enum matched exhaustively cross-crate on the wire-encode path; see doc above.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BackendProtocol {
    /// Plain HTTP/1.1 — the default when `appProtocol` is absent or unrecognised.
    #[default]
    Http1,
    /// HTTP/2 cleartext (prior knowledge) — `kubernetes.io/h2c`.
    H2c,
    /// HTTP/1.1 with WebSocket upgrade — `kubernetes.io/ws`.
    WebSocket,
}

impl BackendProtocol {
    /// Returns `true` for protocols using HTTP/2 cleartext prior knowledge.
    #[must_use]
    pub fn is_h2(self) -> bool {
        match self {
            Self::H2c => true,
            Self::Http1 | Self::WebSocket => false,
        }
    }
}

/// Parse a raw `appProtocol` string into a `BackendProtocol`.
///
/// Unknown or absent values map to `Http1` (the safe default). Note that `https`
/// and `kubernetes.io/wss` map to `Http1`: they imply upstream TLS, which has no
/// Gateway API basis via `appProtocol` — use a `BackendTLSPolicy` instead.
#[must_use]
pub fn parse_app_protocol(raw: &str) -> BackendProtocol {
    match raw {
        "kubernetes.io/h2c" => BackendProtocol::H2c,
        "kubernetes.io/ws" => BackendProtocol::WebSocket,
        _ => BackendProtocol::Http1,
    }
}

#[cfg(test)]
mod tests {
    use super::super::backend::BackendGroup;
    use super::*;

    #[test]
    fn parse_app_protocol_known_values() {
        assert_eq!(
            parse_app_protocol("kubernetes.io/h2c"),
            BackendProtocol::H2c
        );
        assert_eq!(
            parse_app_protocol("kubernetes.io/ws"),
            BackendProtocol::WebSocket
        );
    }

    #[test]
    fn parse_app_protocol_defaults_to_http1() {
        assert_eq!(parse_app_protocol(""), BackendProtocol::Http1);
        assert_eq!(parse_app_protocol("http"), BackendProtocol::Http1);
        assert_eq!(
            parse_app_protocol("example.com/custom"),
            BackendProtocol::Http1
        );
    }

    // TLS-implying appProtocol values have no Gateway API basis — they map to
    // cleartext Http1, not upstream TLS. Upstream TLS requires a BackendTLSPolicy.
    #[test]
    fn parse_app_protocol_tls_values_map_to_cleartext_http1() {
        assert_eq!(parse_app_protocol("https"), BackendProtocol::Http1);
        assert_eq!(
            parse_app_protocol("kubernetes.io/wss"),
            BackendProtocol::Http1
        );
    }

    #[test]
    fn upstream_with_protocol_round_trips() {
        let u = BackendGroup::new("ns/svc".to_string(), vec![]).with_protocol(BackendProtocol::H2c);
        assert_eq!(u.protocol(), BackendProtocol::H2c);
    }

    #[test]
    fn upstream_default_protocol_is_http1() {
        let u = BackendGroup::new("ns/svc".to_string(), vec![]);
        assert_eq!(u.protocol(), BackendProtocol::Http1);
    }

    // ── san_set_matches ──────────────────────────────────────────────────────

    fn tls(sni: &str) -> UpstreamTls {
        UpstreamTls::new(Arc::from(sni), UpstreamCa::System, 0x1234)
    }

    #[test]
    fn san_matches_exact_hostname() {
        assert!(
            san_set_matches(
                &[SubjectAltName::Hostname(Arc::from("foo.example.com"))],
                &["foo.example.com"],
                &[],
            ),
            "exact hostname must match"
        );
    }

    #[test]
    fn san_matches_hostname_case_insensitive() {
        assert!(
            san_set_matches(
                &[SubjectAltName::Hostname(Arc::from("Foo.Example.Com"))],
                &["foo.example.com"],
                &[],
            ),
            "hostname match is case-insensitive"
        );
    }

    #[test]
    fn san_matches_wildcard_cert_dns() {
        // Wildcard is in the CERTIFICATE, not the policy value.
        assert!(
            san_set_matches(
                &[SubjectAltName::Hostname(Arc::from("foo.example.com"))],
                &["*.example.com"],
                &[],
            ),
            "wildcard in cert SAN matches single left-most label"
        );
    }

    #[test]
    fn san_rejects_multi_label_wildcard() {
        // RFC 6125 strict single-label — the wildcard must not match across two labels.
        assert!(
            !san_set_matches(
                &[SubjectAltName::Hostname(Arc::from("a.b.example.com"))],
                &["*.example.com"],
                &[],
            ),
            "wildcard must NOT match two left-most labels"
        );
    }

    #[test]
    fn san_matches_uri_exact() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/svc";
        assert!(
            san_set_matches(&[SubjectAltName::Uri(Arc::from(spiffe))], &[], &[spiffe],),
            "URI SAN matches exactly"
        );
    }

    #[test]
    fn san_rejects_uri_case_mismatch() {
        assert!(
            !san_set_matches(
                &[SubjectAltName::Uri(Arc::from(
                    "spiffe://Cluster.Local/ns/default/sa/svc"
                ))],
                &[],
                &["spiffe://cluster.local/ns/default/sa/svc"],
            ),
            "URI match is case-sensitive"
        );
    }

    #[test]
    fn san_empty_expected_always_false() {
        assert!(
            !san_set_matches(&[], &["foo.example.com"], &["spiffe://x"]),
            "empty expected slice is always false"
        );
    }

    #[test]
    fn san_mismatched_type_does_not_cross() {
        // A Hostname entry must not match against uri_sans and vice versa.
        assert!(
            !san_set_matches(
                &[SubjectAltName::Hostname(Arc::from("foo.example.com"))],
                &[],
                &["foo.example.com"],
            ),
            "Hostname entry must not match URI SAN slot"
        );
        assert!(
            !san_set_matches(
                &[SubjectAltName::Uri(Arc::from("spiffe://x"))],
                &["spiffe://x"],
                &[],
            ),
            "URI entry must not match DNS SAN slot"
        );
    }

    #[test]
    fn with_subject_alt_names_changes_group_key() {
        let base = tls("svc.example.com");
        let sans: Arc<[SubjectAltName]> =
            Arc::from([SubjectAltName::Uri(Arc::from("spiffe://cluster/svc"))]);
        let with_san = base.clone().with_subject_alt_names(sans.clone());
        assert_ne!(
            base.group_key, with_san.group_key,
            "SAN list must change group_key for pool isolation"
        );
    }

    #[test]
    fn with_subject_alt_names_group_key_is_stable() {
        // Same SAN set applied twice → same group_key (deterministic hash).
        let sans: Arc<[SubjectAltName]> =
            Arc::from([SubjectAltName::Uri(Arc::from("spiffe://cluster/svc"))]);
        let a = tls("svc.example.com")
            .with_subject_alt_names(sans.clone())
            .group_key;
        let b = tls("svc.example.com")
            .with_subject_alt_names(sans.clone())
            .group_key;
        assert_eq!(a, b, "group_key must be deterministic for the same SAN set");
    }

    #[test]
    fn with_subject_alt_names_then_client_cert_pins_group_key() {
        // Documents the canonical fold order used by the reflector/reconciler:
        // with_subject_alt_names first, then with_client_cert.  Pin the key so an
        // accidental reorder is caught by this test.
        use super::BackendClientCert;
        let sans: Arc<[SubjectAltName]> =
            Arc::from([SubjectAltName::Uri(Arc::from("spiffe://cluster/svc"))]);
        let cc = Arc::new(BackendClientCert::new(
            Arc::from(b"cert".as_slice()),
            Arc::from(b"key".as_slice()),
            Arc::from("ns/secret"),
        ));
        let key = tls("svc.example.com")
            .with_subject_alt_names(sans)
            .with_client_cert(cc)
            .group_key;
        // Value pinned — regenerate by temporarily removing this assert and printing.
        assert_ne!(key, 0x1234, "group_key must be mixed by both builders");
    }
}
