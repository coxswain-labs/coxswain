//! Raw-TCP proxy handler for TCPRoute / GEP-1901.
//!
//! Unlike TLS passthrough there is no ClientHello to peek and no SNI to match —
//! a `TCPRoute` binds a listener port straight to a backend. On accept, the
//! connection is dialled to the matched backend and spliced bidirectionally via
//! [`tokio::io::copy_bidirectional_with_sizes`].
//!
//! All failure paths close the connection and return — nothing on this path may
//! panic or call `unwrap` (data-plane zero-crash bar).

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::copy_bidirectional_with_sizes;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use coxswain_core::routing::{Selected, SharedTcpRouteTable};

/// Buffer size for each direction of the TCP splice (~16 KiB). Matches the TLS
/// passthrough splice buffer — both paths move raw bytes with no protocol parsing.
const SPLICE_BUF: usize = 16 * 1024;

/// Handle one accepted TCP connection on a `protocol: TCP` listener.
///
/// Looks up the bound backend for `listener_port`, dials it, and splices bytes
/// bidirectionally. No SNI peek, no TLS — the raw stream is forwarded as-is.
///
/// All failure paths log at `debug` level and return — the connection is closed
/// when the `TcpStream` is dropped.
pub(crate) async fn handle_tcp_proxy(
    tcp: TcpStream,
    peer_addr: SocketAddr,
    table: &SharedTcpRouteTable,
    listener_port: u16,
    dial_timeout: Duration,
) {
    let snapshot = table.load();
    let backend = match snapshot.port(listener_port) {
        Some(bg) => bg,
        None => {
            debug!(
                peer = %peer_addr,
                port = listener_port,
                "TCP proxy: no route for listener port"
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
                port = listener_port,
                "TCP proxy: backend group is empty"
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
                "TCP proxy: failed to connect to backend"
            );
            return;
        }
        Err(_) => {
            debug!(
                peer = %peer_addr,
                backend = %backend_addr,
                timeout = ?dial_timeout,
                "TCP proxy: backend connect timed out"
            );
            return;
        }
    };

    let mut downstream = tcp;
    if let Err(e) =
        copy_bidirectional_with_sizes(&mut downstream, &mut upstream, SPLICE_BUF, SPLICE_BUF).await
    {
        // Connection-reset and EOF errors are normal.
        debug!(
            peer = %peer_addr,
            backend = %backend_addr,
            error = %e,
            "TCP proxy: splice ended"
        );
    }
}
