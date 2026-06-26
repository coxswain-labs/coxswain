//! SNI-driven certificate selector and per-SNI client-certificate mTLS for the Pingora TLS listener.

use async_trait::async_trait;
use coxswain_core::tls::{ClientCertConfigState, SharedClientCertStore, SharedTlsStore};
use pingora_core::listeners::TlsAccept;
use pingora_core::protocols::tls::TlsRef;
use pingora_core::tls::{
    ext,
    pkey::PKey,
    ssl::{NameType, SslVerifyMode},
    x509::{X509, store::X509StoreBuilder},
};
use std::any::Any;
use std::sync::Arc;

/// Information about the verified client certificate, stored as a nested field
/// inside [`ConnTlsInfo`] after a successful mTLS handshake.
pub(crate) struct ClientCertInfo {
    /// PEM-encoded client certificate as presented by the peer.
    pub(crate) cert_pem: String,
}

/// TLS connection metadata stored in `SslDigest.extension` after every
/// successful handshake.
///
/// Stored unconditionally for all TLS connections so the request path can
/// read the negotiated SNI for misdirected-request detection (GEP-3567, #96)
/// even when mTLS is not configured.
pub(crate) struct ConnTlsInfo {
    /// The SNI hostname the client sent during the handshake (`None` when the
    /// client sent no SNI extension — legal per RFC 6066).
    pub(crate) sni: Option<Box<str>>,
    /// Verified peer certificate, present iff mTLS was configured for the SNI
    /// and the client passed the CA verification.
    pub(crate) client_cert: Option<ClientCertInfo>,
}

/// SNI-driven certificate selector for the Pingora TLS listener.
///
/// On every handshake:
/// 1. Selects the server certificate by SNI.
/// 2. If the SNI maps to a client-cert mTLS config, configures BoringSSL to
///    request and verify a peer certificate.  The exact verify mode depends on
///    the configured [`coxswain_core::tls::ClientCertConfig::allow_insecure_fallback`]:
///    - `false` (default, GEP-91 `AllowValidOnly`): `PEER | FAIL_IF_NO_PEER_CERT`.
///      A missing, invalid, or over-depth cert aborts the TLS handshake (Istio
///      MUTUAL semantics).
///    - `true` (GEP-91 `AllowInsecureFallback`): `PEER` with a permissive verify
///      callback that always returns `true`.  The client cert is requested and
///      validated, but a missing or invalid cert does **not** abort the handshake.
///      The CA store is still installed so backends receive the cert if presented.
/// 3. An `Unavailable` config (CA missing / unlabeled) is fail-closed: every
///    handshake to that host is rejected.
///
/// Cheaply clonable: the underlying stores are `Arc`-backed.
#[non_exhaustive]
#[derive(Clone)]
pub struct SniCertSelector {
    tls: SharedTlsStore,
    client_certs: SharedClientCertStore,
}

impl SniCertSelector {
    /// Wrap a [`SharedTlsStore`] and [`SharedClientCertStore`] in an SNI certificate selector.
    pub fn new(tls: SharedTlsStore, client_certs: SharedClientCertStore) -> Self {
        Self { tls, client_certs }
    }

    /// Returns `true` when a **specific** (exact or wildcard) terminate cert is
    /// registered for `sni` — the hostname-less default/catch-all bucket does
    /// **not** count.
    ///
    /// The hybrid-port accept path uses this when no passthrough route matches:
    /// a specific HTTPS listener claims this SNI (`true`) → fall through to TLS
    /// terminate; no specific listener claims it (`false`) → reject the
    /// connection rather than answer with a catch-all/default cert (GEP-2643 /
    /// #70). A connection with no SNI can never match a hostname'd listener, so
    /// `None` returns `false`.
    #[must_use]
    pub fn has_cert_for(&self, sni: Option<&str>) -> bool {
        sni.is_some_and(|s| self.tls.load().has_specific_cert(s))
    }
}

#[async_trait]
impl TlsAccept for SniCertSelector {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        // Clone immediately to drop the immutable borrow before the mutable
        // ssl_use_certificate / ssl_use_private_key calls below.
        let Some(sni) = ssl.servername(NameType::HOST_NAME).map(str::to_owned) else {
            tracing::debug!("TLS handshake with no SNI — no cert installed");
            return;
        };

        // ── Server certificate ────────────────────────────────────────────────
        let store = self.tls.load();
        let certs = store.find_certs(&sni);
        if certs.is_empty() {
            tracing::debug!(sni, "No TLS cert for SNI — handshake will fail");
            return;
        }
        // Install the first (highest-priority) cert for this SNI.
        //
        // `TlsStoreBuilder::build()` sorts certs ECDSA→RSA→Other so a dual-cert
        // listener serves ECDSA by default.  Full client-sigalg-based selection
        // (fall back to RSA for RSA-only clients) would require calling
        // `SSL_get0_peer_verify_algorithms` via FFI, which the project bans via
        // `unsafe_code = "deny"`.  Track in #72 for a follow-up once boring
        // exposes a safe wrapper.
        let cert = &certs[0];

        let x509 = match X509::from_pem(&cert.cert_pem) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(sni, source = %cert.source, error = %e, "cert PEM parse failed");
                return;
            }
        };
        let pkey = match PKey::private_key_from_pem(&cert.key_pem) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(sni, source = %cert.source, error = %e, "key PEM parse failed");
                return;
            }
        };
        if let Err(e) = ext::ssl_use_certificate(ssl, &x509) {
            tracing::warn!(sni, error = %e, "ssl_use_certificate failed");
            return;
        }
        if let Err(e) = ext::ssl_use_private_key(ssl, &pkey) {
            tracing::warn!(sni, error = %e, "ssl_use_private_key failed");
            return;
        }

        // ── Per-SNI client certificate mTLS (#267) ────────────────────────────
        //
        // `find_config` is None when the SNI has no mTLS annotation —
        // the connection proceeds as a standard one-way TLS handshake.
        let cc_store = self.client_certs.load();
        let Some(config_state) = cc_store.find_config(&sni) else {
            return;
        };

        match config_state.as_ref() {
            ClientCertConfigState::Config(cfg) => {
                // Build an X509Store from the operator-supplied CA PEM bundle.
                // On failure, fall through: no CA store installed means BoringSSL
                // rejects every client cert regardless of verify mode (fail-closed).
                match build_ca_store(&cfg.ca_pem, &sni) {
                    Ok(ca_store) => {
                        if let Err(e) = ext::ssl_set_verify_cert_store(ssl, &ca_store) {
                            tracing::warn!(sni, error = %e, "ssl_set_verify_cert_store failed — fail-closing mTLS");
                        }
                        ssl.set_verify_depth(cfg.verify_depth);
                    }
                    Err(e) => {
                        tracing::warn!(sni, error = %e, "CA store build failed — fail-closing mTLS");
                    }
                }

                if cfg.allow_insecure_fallback {
                    // GEP-91 AllowInsecureFallback: request the client cert and
                    // validate it against the CA, but never abort the handshake
                    // on a missing or invalid cert.  Authorization is delegated
                    // to the backend.
                    //
                    // `set_verify_callback` is a safe boring `SslRef` method —
                    // no `unsafe` is required.
                    ssl.set_verify_callback(SslVerifyMode::PEER, |_preverify_ok, _ctx| true);
                    tracing::debug!(
                        sni,
                        depth = cfg.verify_depth,
                        "mTLS: AllowInsecureFallback — cert optional"
                    );
                } else {
                    // GEP-91 AllowValidOnly (default): abort the handshake on a
                    // missing, invalid, or over-depth cert.
                    ssl.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
                    tracing::debug!(
                        sni,
                        depth = cfg.verify_depth,
                        "mTLS: AllowValidOnly — requiring client cert"
                    );
                }
            }
            ClientCertConfigState::Unavailable => {
                // CA missing/unlabeled/unparseable — fail-closed: every
                // handshake to this SNI will fail (no CA store, but verify mode
                // requires a valid cert).
                ssl.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
                tracing::warn!(
                    sni,
                    "mTLS: CA Unavailable — fail-closing all client handshakes"
                );
            }
            // Forward-compatible: future variants are treated as no mTLS for this SNI.
            _ => {}
        }
    }

    async fn handshake_complete_callback(
        &self,
        ssl: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        // Capture the negotiated SNI and, if mTLS was configured and the client
        // passed verification, the verified peer certificate.  Both are stored
        // in the connection's `SslDigest.extension` as `ConnTlsInfo`.
        //
        // This callback fires for every TLS connection, so we return `Some`
        // unconditionally: even connections without mTLS need the SNI
        // propagated for the misdirected-request check (GEP-3567, #96).
        let sni = ssl.servername(NameType::HOST_NAME).map(Box::<str>::from);

        let client_cert = ssl.peer_certificate().and_then(|peer| match peer.to_pem() {
            Ok(pem) => Some(ClientCertInfo {
                cert_pem: String::from_utf8_lossy(&pem).into_owned(),
            }),
            Err(e) => {
                tracing::warn!(error = %e, "peer_certificate().to_pem() failed — not forwarding");
                None
            }
        });

        Some(Arc::new(ConnTlsInfo { sni, client_cert }))
    }
}

/// Build an [`X509Store`] from a PEM-encoded CA bundle.
///
/// # Errors
///
/// Returns an error if any certificate in the PEM bundle cannot be parsed or
/// if the `X509Store` cannot be created.
fn build_ca_store(
    ca_pem: &[u8],
    sni: &str,
) -> Result<pingora_core::tls::x509::store::X509Store, Box<dyn std::error::Error + Send + Sync>> {
    let certs = X509::stack_from_pem(ca_pem).map_err(|e| {
        tracing::warn!(sni, error = %e, "CA PEM parse failed");
        e
    })?;
    let mut builder = X509StoreBuilder::new().map_err(|e| {
        tracing::warn!(sni, error = %e, "X509StoreBuilder::new() failed");
        e
    })?;
    for cert in certs {
        builder.add_cert(cert).map_err(|e| {
            tracing::warn!(sni, error = %e, "X509Store::add_cert failed");
            e
        })?;
    }
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::tls::{SharedClientCertStore, SharedTlsStore, TlsCert, TlsStoreBuilder};
    use std::sync::Arc;

    fn selector_with(host_pattern: &str) -> SniCertSelector {
        let mut builder = TlsStoreBuilder::new();
        builder.add_cert(
            host_pattern,
            Arc::new(TlsCert::new(
                b"cert".to_vec(),
                b"key".to_vec(),
                "test".into(),
            )),
        );
        let tls = SharedTlsStore::new();
        tls.store(Arc::new(builder.build()));
        SniCertSelector::new(tls, SharedClientCertStore::new())
    }

    #[test]
    fn has_cert_for_matches_exact_and_wildcard() {
        let sel = selector_with("abc.example.com");
        assert!(sel.has_cert_for(Some("abc.example.com")), "exact match");

        let wc = selector_with("*.example.com");
        assert!(wc.has_cert_for(Some("foo.example.com")), "wildcard match");
    }

    #[test]
    fn has_cert_for_rejects_unmatched_and_missing_sni() {
        let sel = selector_with("abc.example.com");
        // GEP-2643 (#70): a non-matching SNI on a hybrid port has no terminate
        // cert, so the accept path rejects the connection instead of answering
        // with the context default cert.
        assert!(
            !sel.has_cert_for(Some("non.matching.com")),
            "no matching cert"
        );
        assert!(
            !sel.has_cert_for(None),
            "no SNI cannot match a hostname'd listener"
        );
    }

    #[test]
    fn has_cert_for_ignores_catchall_default_cert() {
        // A hostname-less ("") listener populates the default/catch-all bucket.
        // On a hybrid port it must NOT rescue an arbitrary SNI: the connection
        // was destined for the port's passthrough routes, so a non-matching SNI
        // is rejected even though a default cert exists (GEP-2643 / #70 —
        // TLSRouteHostnameIntersection "should not reach backend").
        let sel = selector_with("");
        assert!(
            !sel.has_cert_for(Some("non.matching.com")),
            "default/catch-all cert must not count as a specific match"
        );
    }
}
