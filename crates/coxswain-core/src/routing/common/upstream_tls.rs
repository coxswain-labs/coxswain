//! Upstream connection protocol and TLS configuration.
//!
//! The wire protocol ([`BackendProtocol`], derived from `appProtocol` per
//! GEP-1911) and the `BackendTLSPolicy`-derived TLS settings ([`UpstreamTls`] /
//! [`UpstreamCa`]) that a [`BackendGroup`](super::backend::BackendGroup) carries
//! for its upstream connections.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// CA certificate source for a [`BackendTLSPolicy`](https://gateway-api.sigs.k8s.io/references/spec/#gateway.networking.k8s.io/v1alpha3.BackendTLSPolicy) attachment.
#[non_exhaustive]
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
    pub group_key: u64,
    /// Client certificate the Gateway presents to the upstream (GEP-3155), or `None`
    /// when no `Gateway.spec.tls.backend.clientCertificateRef` applies to this backend.
    pub client_cert: Option<Arc<BackendClientCert>>,
}

impl UpstreamTls {
    /// Construct an [`UpstreamTls`] from its components, with no client certificate.
    ///
    /// Use [`with_client_cert`](Self::with_client_cert) to attach a GEP-3155 backend
    /// client certificate.
    pub fn new(sni: Arc<str>, ca: UpstreamCa, group_key: u64) -> Self {
        Self {
            sni,
            ca,
            group_key,
            client_cert: None,
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
}

/// Wire protocol spoken by a backend, derived from `Service.spec.ports[].appProtocol`
/// per [GEP-1911](https://gateway-api.sigs.k8s.io/geps/gep-1911/).
///
/// This is a **pure wire-protocol hint** — it carries no TLS semantics. Upstream
/// TLS is originated solely by a `BackendTLSPolicy` (GEP-1897), surfaced as an
/// [`UpstreamTls`] on the [`BackendGroup`](super::backend::BackendGroup); see that
/// type. `appProtocol` values that imply TLS (`https`, `kubernetes.io/wss`) have no
/// Gateway API basis and map to [`Http1`](Self::Http1) (cleartext).
#[non_exhaustive]
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
}
