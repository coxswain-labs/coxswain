//! Upstream connection protocol and TLS configuration.
//!
//! The wire protocol ([`BackendProtocol`], derived from `appProtocol` per
//! GEP-1911) and the `BackendTLSPolicy`-derived TLS settings ([`UpstreamTls`] /
//! [`UpstreamCa`]) that a [`BackendGroup`](super::backend::BackendGroup) carries
//! for its upstream connections.

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

/// TLS configuration for upstream connections derived from a `BackendTLSPolicy` attachment.
///
/// When present on a [`BackendGroup`](super::backend::BackendGroup), the proxy
/// overrides `appProtocol`-based TLS decisions and uses these settings for every
/// connection to that backend.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct UpstreamTls {
    /// Hostname used for SNI and certificate verification on the upstream connection.
    pub sni: Arc<str>,
    /// Certificate authority source for verifying the upstream cert.
    pub ca: UpstreamCa,
    /// Stable hash of `(sni, ca)` — folded into `HttpPeer.group_key` so distinct
    /// CA bundles never share a Pingora connection pool slot, and used as the cache
    /// key in the proxy-side parse cache.
    pub group_key: u64,
}

impl UpstreamTls {
    /// Construct an [`UpstreamTls`] from its components.
    pub fn new(sni: Arc<str>, ca: UpstreamCa, group_key: u64) -> Self {
        Self { sni, ca, group_key }
    }
}

/// Wire protocol spoken by a backend, derived from `Service.spec.ports[].appProtocol`
/// per [GEP-1911](https://gateway-api.sigs.k8s.io/geps/gep-1911/).
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
    /// HTTPS (TLS to upstream) — `https`.
    Https,
    /// WebSocket over TLS — `kubernetes.io/wss`.
    WebSocketTls,
}

impl BackendProtocol {
    /// Returns `true` for protocols that require TLS to the upstream.
    #[must_use]
    pub fn is_tls(self) -> bool {
        match self {
            Self::Https | Self::WebSocketTls => true,
            Self::Http1 | Self::H2c | Self::WebSocket => false,
        }
    }

    /// Returns `true` for protocols using HTTP/2 cleartext prior knowledge.
    #[must_use]
    pub fn is_h2(self) -> bool {
        match self {
            Self::H2c => true,
            Self::Http1 | Self::Https | Self::WebSocket | Self::WebSocketTls => false,
        }
    }
}

/// Parse a raw `appProtocol` string into a `BackendProtocol`.
///
/// Unknown or absent values map to `Http1` (the safe default).
#[must_use]
pub fn parse_app_protocol(raw: &str) -> BackendProtocol {
    match raw {
        "kubernetes.io/h2c" => BackendProtocol::H2c,
        "kubernetes.io/ws" => BackendProtocol::WebSocket,
        "kubernetes.io/wss" => BackendProtocol::WebSocketTls,
        "https" => BackendProtocol::Https,
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
        assert_eq!(
            parse_app_protocol("kubernetes.io/wss"),
            BackendProtocol::WebSocketTls
        );
        assert_eq!(parse_app_protocol("https"), BackendProtocol::Https);
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
