//! TLS-terminate L4 handler for TLSRoute `mode: Terminate` (#481).
//!
//! Terminates the incoming TLS connection using the listener's SNI-selected
//! certificate, then L4-splices the decrypted byte stream to a plaintext TCP
//! backend — no HTTP parsing is involved.
//!
//! All failure paths close the connection and return — nothing on this path
//! may panic or call `unwrap` (data-plane zero-crash bar).

use std::net::SocketAddr;
use std::time::Duration;

use pingora_core::protocols::l4::stream::Stream as L4Stream;
use pingora_core::protocols::tls::server::handshake_with_callback;
use tokio::io::copy_bidirectional_with_sizes;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use coxswain_core::routing::{Selected, SharedTlsPassthroughTable};

use crate::SniCertSelector;
use crate::edge::accept::{AcceptorBuildError, build_tls_context, observe_tls_handshake};
use crate::edge::passthrough::peek_sni;

/// Buffer size for each direction of the TCP splice (~16 KiB).
const SPLICE_BUF: usize = 16 * 1024;

/// Handle one accepted TCP connection on a TLS-terminate listener.
///
/// Peeks the ClientHello via [`peek_sni`] (MSG_PEEK — bytes stay in the kernel
/// queue), selects the listener certificate via SNI, terminates TLS, then
/// splices the decrypted stream bidirectionally to the matched plaintext backend.
///
/// All failure paths log at `debug` level and return — the connection is closed
/// when the streams are dropped.
///
/// # Errors
///
/// This function handles all errors internally; it logs at debug and returns
/// rather than propagating (data-plane zero-crash requirement).
pub(crate) async fn handle_terminate(
    tcp: TcpStream,
    peer_addr: SocketAddr,
    table: &SharedTlsPassthroughTable,
    selector: &SniCertSelector,
    listener_port: u16,
    dial_timeout: Duration,
) {
    let sni = match peek_sni(&tcp).await {
        Ok(s) => s,
        Err(e) => {
            debug!(
                peer = %peer_addr,
                error = %e,
                "TLS terminate: failed to read ClientHello SNI"
            );
            return;
        }
    };

    let snapshot = table.load();
    let router = match snapshot.port(listener_port) {
        Some(r) => r,
        None => {
            debug!(
                peer = %peer_addr,
                port = listener_port,
                "TLS terminate: no routes for listener port"
            );
            return;
        }
    };

    let backend = match router.match_sni(sni.as_deref()) {
        Some(bg) => bg,
        None => {
            debug!(
                peer = %peer_addr,
                sni = ?sni,
                "TLS terminate: no backend matched SNI"
            );
            return;
        }
    };

    let Selected {
        addr: backend_addr, ..
    } = match backend.select_upstream(None) {
        Some(s) => s,
        None => {
            debug!(
                peer = %peer_addr,
                sni = ?sni,
                "TLS terminate: backend group is empty"
            );
            return;
        }
    };

    // Build a TLS context for the scoped listener port. No ALPN/h2 advertisement:
    // this is an L4 splice, not HTTP.
    let tls_ctx = match build_tls_context(&selector.for_port(listener_port), false) {
        Ok(ctx) => ctx,
        Err(AcceptorBuildError::TlsAcceptorBuild(e)) => {
            debug!(
                peer = %peer_addr,
                error = %e,
                "TLS terminate: failed to build TLS context"
            );
            return;
        }
    };

    let l4: L4Stream = tcp.into();
    let mut downstream =
        match handshake_with_callback(&tls_ctx.acceptor, l4, tls_ctx.callbacks.as_ref()).await {
            Ok(stream) => {
                observe_tls_handshake("ok");
                stream
            }
            Err(e) => {
                observe_tls_handshake("fail");
                debug!(
                    peer = %peer_addr,
                    error = %e,
                    "TLS terminate: handshake failed"
                );
                return;
            }
        };

    let mut upstream = match timeout(dial_timeout, TcpStream::connect(backend_addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!(
                peer = %peer_addr,
                backend = %backend_addr,
                error = %e,
                "TLS terminate: failed to connect to backend"
            );
            return;
        }
        Err(_) => {
            debug!(
                peer = %peer_addr,
                backend = %backend_addr,
                timeout = ?dial_timeout,
                "TLS terminate: backend connect timed out"
            );
            return;
        }
    };

    if let Err(e) =
        copy_bidirectional_with_sizes(&mut downstream, &mut upstream, SPLICE_BUF, SPLICE_BUF).await
    {
        debug!(
            peer = %peer_addr,
            backend = %backend_addr,
            error = %e,
            "TLS terminate: splice ended"
        );
    }
}
