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
//!
//! ## Peer SVID extraction
//!
//! `serve_discovery_with_tls` wraps each accepted [`tokio_rustls::server::TlsStream`]
//! in a `PeerSvidStream` newtype.  `PeerSvidStream` implements
//! [`tonic::transport::server::Connected`] — tonic calls `connect_info()` on
//! each stream and stores the returned [`crate::auth::PeerSvid`] in request
//! extensions, making it available to the `stream()` gRPC handler via
//! `request.extensions().get::<PeerSvid>()`.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::server::Connected;

use crate::auth::{PeerSvid, uri_sans};
use crate::proto::v1::discovery_server::{Discovery, DiscoveryServer};

// ── PeerSvidStream ─────────────────────────────────────────────────────────────

/// Thin wrapper over a server-side TLS stream that implements
/// [`tonic::transport::server::Connected`] with [`PeerSvid`] as the connect-info
/// type.
///
/// tonic calls `connect_info()` on every accepted stream and stores the result
/// in request extensions.  The [`crate::server::DiscoveryService`] handler then
/// reads it with `request.extensions().get::<PeerSvid>()` to enforce the
/// Gateway scope-binding check (#427).
pub(crate) struct PeerSvidStream(pub(crate) tokio_rustls::server::TlsStream<TcpStream>);

impl Connected for PeerSvidStream {
    type ConnectInfo = PeerSvid;

    /// Extract URI SANs from the peer's end-entity certificate.
    ///
    /// Returns a `PeerSvid` with the URI SANs from the first peer certificate
    /// in the TLS session.  Returns an empty `PeerSvid` (fail-open) if no peer
    /// certificate is present or if DER parsing fails — production mTLS always
    /// provides a cert (client auth is mandatory), so the empty case is test/
    /// degraded-mode only.
    fn connect_info(&self) -> PeerSvid {
        let (_, session) = self.0.get_ref();
        let uri_sans = session
            .peer_certificates()
            .and_then(|certs| certs.first())
            .and_then(|cert| uri_sans(cert.as_ref()).ok())
            .unwrap_or_default();
        PeerSvid { uri_sans }
    }
}

// Delegate AsyncRead to the inner TlsStream.  The inner type is Unpin so
// Pin::new() is safe.
impl AsyncRead for PeerSvidStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for PeerSvidStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

// ── serve_discovery_with_tls ──────────────────────────────────────────────────

/// Serve a [`Discovery`] service on `addr`, wrapping every connection in `acceptor`.
///
/// Each accepted TLS stream is wrapped in `PeerSvidStream`, which implements
/// [`Connected`] and injects [`PeerSvid`] into request extensions — the
/// discovery handler uses it to enforce the Gateway scope-binding check.
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
    // Each successfully accepted TlsStream is wrapped in PeerSvidStream so
    // tonic can extract the peer SVID URI SANs via Connected::connect_info().
    let incoming = TcpListenerStream::new(listener).then(move |conn| {
        let acceptor = acceptor.clone();
        async move {
            let stream = conn?;
            let tls = acceptor.accept(stream).await?;
            Ok::<_, io::Error>(PeerSvidStream(tls))
        }
    });

    tonic::transport::Server::builder()
        .add_service(service)
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await
        .map_err(std::io::Error::other)
}
