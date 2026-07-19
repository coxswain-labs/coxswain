//! SNI-driven certificate selector and per-SNI client-certificate mTLS for the Pingora TLS listener.

use async_trait::async_trait;
use coxswain_core::tls::{ClientCertConfigState, SharedClientCertStore, SharedPortTlsStore};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
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

// NOTE: server cert/key PEM and the mTLS CA bundle are parsed per handshake
// (below, in `certificate_callback`). An earlier revision cached the parsed
// handles process-wide keyed by the PEM bytes; that was reverted because it
// (a) retained rotated-away private-key material in process memory until a
// wholesale cap-clear a stable install never reaches, (b) allocated and
// memcpy'd the full PEM on every cache probe, and (c) serialized every
// handshake through one global mutex. The dominant per-connection CPU sink was
// the BoringSSL `SslAcceptor` rebuild, which is now cached once per process
// (see `edge/accept.rs::cached_acceptor`); the residual X509/PKey parse is
// cheap relative to the handshake crypto itself. If profiling later justifies
// caching the parsed handles, do it at snapshot-apply time in the cert store
// (parse-at-construction) so rotation invalidates it — not on the hot path.

/// Information about the verified client certificate, stored as a nested field
/// inside [`ConnTlsInfo`] after a successful mTLS handshake.
pub(crate) struct ClientCertInfo {
    /// Pre-rendered `X-SSL-Client-Cert` header value: the peer's PEM,
    /// percent-encoded (`NON_ALPHANUMERIC`, nginx-ingress convention), built
    /// **once per connection** here instead of on every request. The per-request
    /// path (`upstream_request_filter`) only clones this `HeaderValue` — a cheap
    /// `Bytes` refcount bump — rather than re-cloning a multi-KB PEM `String` and
    /// re-encoding it (a ~2-3x blowup) per request on mTLS routes (#620).
    pub(crate) forward_header: http::HeaderValue,
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
///
/// The selector is scoped to the **bind port** the connection was accepted on
/// (#472): cert selection only consults that port's [`coxswain_core::tls::TlsStore`],
/// so a shared-mode Gateway's VIP port can never present a sibling Gateway's
/// overlapping-SNI cert. The acceptor builds an unscoped selector once and calls
/// [`Self::for_port`] per connection.
#[derive(Clone)]
pub struct SniCertSelector {
    tls: SharedPortTlsStore,
    client_certs: SharedClientCertStore,
    /// Bind port whose per-port store this selector consults. `0` (the unscoped
    /// default) never matches a real listener, so it presents no cert — correct
    /// for the acceptor's eager build-time validation, which never handshakes.
    port: u16,
}

impl SniCertSelector {
    /// Wrap a [`SharedPortTlsStore`] and [`SharedClientCertStore`] in an
    /// (initially unscoped) SNI certificate selector. Scope it to a connection's
    /// accepted port with [`Self::for_port`] before serving a handshake.
    pub fn new(tls: SharedPortTlsStore, client_certs: SharedClientCertStore) -> Self {
        Self {
            tls,
            client_certs,
            port: 0,
        }
    }

    /// Return a clone of this selector scoped to bind `port` (#472). Cert lookups
    /// then consult only that port's per-port store.
    #[must_use]
    pub fn for_port(&self, port: u16) -> Self {
        Self {
            tls: self.tls.clone(),
            client_certs: self.client_certs.clone(),
            port,
        }
    }

    /// Returns `true` when a **specific** (exact or wildcard) terminate cert is
    /// registered for `sni` on this selector's bind port — the hostname-less
    /// default/catch-all bucket does **not** count.
    ///
    /// The hybrid-port accept path uses this when no passthrough route matches:
    /// a specific HTTPS listener claims this SNI (`true`) → fall through to TLS
    /// terminate; no specific listener claims it (`false`) → reject the
    /// connection rather than answer with a catch-all/default cert (GEP-2643 /
    /// #70). A connection with no SNI can never match a hostname'd listener, so
    /// `None` returns `false`.
    #[must_use]
    pub fn has_cert_for(&self, sni: Option<&str>) -> bool {
        sni.is_some_and(|s| {
            self.tls
                .load()
                .port(self.port)
                .is_some_and(|store| store.has_specific_cert(s))
        })
    }
}

/// This connection's SNI, lowercased, or `None` when the client sent none.
///
/// openssl parses the ClientHello itself on the terminate path, so this never
/// passes through [`crate::edge::passthrough::peek_sni`] and has to normalize
/// independently. It must: the cert store, the mTLS client-cert config store and
/// the GEP-3567 misdirected-request check are all keyed by the lowercase
/// hostnames the reconciler wrote, while RFC 6066 defers to DNS — a peer may
/// legitimately send `App.Example.Com` and expect `app.example.com`'s
/// certificate. Costs nothing over the owned copy each caller already needed.
fn normalized_sni(ssl: &TlsRef) -> Option<String> {
    ssl.servername(NameType::HOST_NAME)
        .map(str::to_ascii_lowercase)
}

#[async_trait]
impl TlsAccept for SniCertSelector {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        // Clone immediately to drop the immutable borrow before the mutable
        // ssl_use_certificate / ssl_use_private_key calls below.
        let Some(sni) = normalized_sni(ssl) else {
            tracing::debug!("TLS handshake with no SNI — no cert installed");
            return;
        };

        // ── Server certificate ────────────────────────────────────────────────
        // Scoped to this connection's bind port (#472): only that port's certs
        // are eligible, so cross-Gateway SNI overlap can't present a sibling's cert.
        let port_store = self.tls.load();
        let Some(store) = port_store.port(self.port) else {
            tracing::debug!(
                sni,
                port = self.port,
                "No TLS certs on this port — handshake will fail"
            );
            return;
        };
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
        // Scoped to this connection's bind port like the server-cert lookup
        // above (#472): only this port's configs apply, so a sibling Gateway
        // declaring the same hostname can never supply the CA or the
        // AllowInsecureFallback mode for this Gateway's handshakes.
        let cc_store = self.client_certs.load();
        let Some(config_state) = cc_store.find_config(self.port, &sni) else {
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
        let sni = normalized_sni(ssl).map(Box::<str>::from);

        let client_cert = ssl.peer_certificate().and_then(|peer| match peer.to_pem() {
            Ok(pem) => {
                // Percent-encode once, here, per connection — not per request.
                let encoded =
                    utf8_percent_encode(&String::from_utf8_lossy(&pem), NON_ALPHANUMERIC)
                        .to_string();
                // Encoded output is `%XX`/alphanumeric only, so it is always a
                // valid header value; degrade to not forwarding if that ever
                // changes rather than panicking on the data plane.
                match http::HeaderValue::from_str(&encoded) {
                    Ok(forward_header) => Some(ClientCertInfo { forward_header }),
                    Err(e) => {
                        tracing::warn!(error = %e, "client-cert header encode failed — not forwarding");
                        None
                    }
                }
            }
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
    use coxswain_core::tls::{
        PortTlsStoreBuilder, SharedClientCertStore, SharedPortTlsStore, TlsCert,
    };
    use std::sync::Arc;

    const TEST_PORT: u16 = 443;

    fn selector_with(host_pattern: &str) -> SniCertSelector {
        let mut builder = PortTlsStoreBuilder::new();
        builder.add_cert(
            TEST_PORT,
            host_pattern,
            Arc::new(TlsCert::new(
                b"cert".to_vec(),
                b"key".to_vec(),
                "test".into(),
            )),
        );
        let tls = SharedPortTlsStore::new();
        tls.store(Arc::new(builder.build()));
        // Scope to the port the certs were registered on (#472).
        SniCertSelector::new(tls, SharedClientCertStore::new()).for_port(TEST_PORT)
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
    fn has_cert_for_is_isolated_per_port() {
        // #472: a cert registered on TEST_PORT must NOT be visible to a selector
        // scoped to a different bind port — this is the HTTPS-terminate half of
        // cross-Gateway isolation. Reusing the same store, only the port differs.
        let mut builder = PortTlsStoreBuilder::new();
        builder.add_cert(
            TEST_PORT,
            "abc.example.com",
            Arc::new(TlsCert::new(b"c".to_vec(), b"k".to_vec(), "test".into())),
        );
        let tls = SharedPortTlsStore::new();
        tls.store(Arc::new(builder.build()));
        let base = SniCertSelector::new(tls, SharedClientCertStore::new());

        assert!(
            base.for_port(TEST_PORT)
                .has_cert_for(Some("abc.example.com")),
            "cert visible on its own port"
        );
        assert!(
            !base.for_port(30001).has_cert_for(Some("abc.example.com")),
            "cert NOT visible on a sibling Gateway's internal port"
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
