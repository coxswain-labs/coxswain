//! Per-Ingress client-certificate (mTLS) enforcement (#267): the request-time
//! cross-SNI guard and the `X-SSL-Client-Cert` upstream forwarding it feeds.

use crate::ctx::ProxyCtx;
use crate::edge::tls::ConnTlsInfo;
use coxswain_core::tls::{ClientCertConfigState, SharedClientCertStore};
use pingora_core::{HTTPStatus, Result};
use pingora_http::RequestHeader;
use pingora_proxy::Session;

/// Enforce the per-Ingress mTLS cross-SNI guard for the matched host.
///
/// If this Host requires mTLS, the connection MUST carry a verified client cert
/// in the [`ConnTlsInfo`] stored in the TLS digest extension. A TLS connection
/// whose SNI matched a different (non-mTLS) host will have no peer cert; this
/// returns `421 Misdirected Request` so the client reconnects on the correct
/// SNI, which triggers the mTLS handshake. Plain-HTTP connections (no
/// `ssl_digest`) are exempt — the operator forces HTTPS via `ssl-redirect`.
///
/// GEP-91 AllowInsecureFallback (#86): when the host's frontend validation runs
/// in insecure-fallback mode, a missing/invalid cert is NOT rejected here —
/// authorization is delegated to the backend, mirroring the TLS layer, which
/// already allowed the handshake to complete without a cert.
///
/// On the pass-through path, when the config sets `pass_to_upstream` and a cert
/// is present, the forward header is stashed on `ctx` for [`forward_client_cert`].
///
/// # Errors
///
/// Returns `Error::explain(421, …)` when the host mandates a client certificate
/// (not in insecure-fallback mode) and the connection presented none.
pub(crate) fn enforce_client_cert(
    session: &Session,
    client_certs: &SharedClientCertStore,
    port: u16,
    host: &str,
    ctx: &mut ProxyCtx,
) -> Result<()> {
    let cc_store = client_certs.load();
    let Some(config_state) = cc_store.find_config(port, host) else {
        return Ok(());
    };
    let Some(ssl_digest) = session
        .as_downstream()
        .digest()
        .and_then(|d| d.ssl_digest.as_ref())
    else {
        return Ok(());
    };
    let cert_info = ssl_digest
        .extension
        .get::<ConnTlsInfo>()
        .and_then(|t| t.client_cert.as_ref());
    let insecure_fallback = matches!(
        config_state.as_ref(),
        ClientCertConfigState::Config(cc) if cc.allow_insecure_fallback
    );
    if cert_info.is_none() && !insecure_fallback {
        return Err(pingora_core::Error::explain(
            HTTPStatus(421),
            "client certificate required for this host",
        ));
    }
    if let ClientCertConfigState::Config(cc_cfg) = config_state.as_ref()
        && cc_cfg.pass_to_upstream
        && let Some(ci) = cert_info
    {
        ctx.client_cert_header = Some(ci.forward_header.clone());
    }
    Ok(())
}

/// Forward the verified client certificate upstream as `X-SSL-Client-Cert` when
/// [`enforce_client_cert`] stashed one on `ctx` (`pass_to_upstream`).
pub(crate) fn forward_client_cert(upstream_request: &mut RequestHeader, ctx: &mut ProxyCtx) {
    if let Some(hv) = ctx.client_cert_header.take() {
        let _ = upstream_request.insert_header("x-ssl-client-cert", hv);
    }
}
