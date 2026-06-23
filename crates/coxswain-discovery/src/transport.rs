//! TLS transport helper for serving the discovery gRPC service.
//!
//! The discovery and bootstrap listeners need a *custom* rustls config — the
//! mTLS `Stream` listener uses [`crate::auth::DiscoveryServerTls`]'s
//! `SpiffeClientCertVerifier`, which tonic's built-in `ServerTlsConfig` cannot
//! express.  So instead of `tls_config`, we accept each TCP connection through a
//! pre-built [`TlsAcceptor`] and feed the resulting TLS streams to tonic via
//! `serve_with_incoming_shutdown`.
//!
//! This helper lives here (not in `coxswain-bin`) so the TLS-serving logic sits
//! beside the auth types it depends on and the bin layer needs no extra deps.

use std::future::Future;
use std::net::SocketAddr;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::TcpListenerStream;

use crate::proto::v1::discovery_server::{Discovery, DiscoveryServer};

/// Serve a [`Discovery`] service on `addr`, wrapping every connection in `acceptor`.
///
/// Returns when `shutdown` resolves (graceful drain) or the server errors.
///
/// # Errors
///
/// Returns an I/O error if the listener cannot bind to `addr`, or the tonic
/// server exits with a transport error (the error is wrapped via
/// [`std::io::Error::other`]).
pub async fn serve_discovery_with_tls<S>(
    addr: SocketAddr,
    acceptor: TlsAcceptor,
    service: DiscoveryServer<S>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()>
where
    S: Discovery,
{
    let listener = TcpListener::bind(addr).await?;

    // Per-connection TLS handshake: a handshake failure drops that one
    // connection (mapped to an `Err` item) without tearing down the listener.
    let incoming = TcpListenerStream::new(listener).then(move |conn| {
        let acceptor = acceptor.clone();
        async move {
            let stream = conn?;
            acceptor.accept(stream).await
        }
    });

    tonic::transport::Server::builder()
        .add_service(service)
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await
        .map_err(std::io::Error::other)
}
