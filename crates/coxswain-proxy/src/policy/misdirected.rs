//! GEP-3567 misdirected-request guard (#96): reject HTTP/2 connection coalescing
//! that targets a Gateway listener disjoint from the one the TLS SNI negotiated.

use crate::edge::tls::ConnTlsInfo;
use coxswain_core::tls::SharedListenerHostnames;
use pingora_core::{HTTPStatus, Result};
use pingora_proxy::Session;

/// Return `421 Misdirected Request` when, on an HTTPS port carrying named
/// Gateway listeners, the request Host resolves to a different listener than the
/// one selected by the negotiated TLS SNI. This blocks HTTP/2 connection
/// coalescing from sending a request for host B over a connection whose
/// certificate and listener were negotiated for a disjoint host A.
///
/// A no-op for plain-HTTP requests, Ingress-only deployments, and ports with no
/// HTTPS Gateway listeners (`has_https_port` miss → default empty snapshot).
///
/// # Errors
///
/// Returns `Error::explain(421, …)` when the SNI-selected listener and the
/// Host-selected listener differ on an HTTPS port with named listeners.
pub(crate) fn check_misdirected(
    session: &Session,
    listener_hostnames: &SharedListenerHostnames,
    port: u16,
    host: &str,
    proto: &str,
) -> Result<()> {
    if proto != "https" {
        return Ok(());
    }
    let lh = listener_hostnames.load();
    if !lh.has_https_port(port) {
        return Ok(());
    }
    let sni = session
        .as_downstream()
        .digest()
        .and_then(|d| d.ssl_digest.as_ref())
        .and_then(|d| d.extension.get::<ConnTlsInfo>())
        .and_then(|t| t.sni.as_deref());
    if lh.resolve_sni(port, sni) != lh.resolve(port, host) {
        return Err(pingora_core::Error::explain(
            HTTPStatus(421),
            "request host resolves to a different listener than the negotiated SNI",
        ));
    }
    Ok(())
}
