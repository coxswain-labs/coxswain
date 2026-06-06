//! PROXY-protocol acceptor and connection handler.
//!
//! Activated only when `--proxy-accept-proxy-protocol` is set. Listens on one or
//! more `(addr, protocol)` pairs, reads HAProxy PROXY protocol v1/v2 headers, and
//! hands the resulting sessions to a shared [`HttpProxy`].
//!
//! Each listening socket is bound in [`ProxyAcceptor::new`] — before the Pingora
//! runtime starts — so that bind failures surface as a structured [`AcceptorBuildError`]
//! rather than a runtime panic inside an async task.
//!
//! In-flight connection tasks (PROXY header read + optional TLS handshake) are capped
//! at [`MAX_CONCURRENT_CONNECTIONS`] via a `Semaphore`; excess connections are dropped
//! with a warning rather than queued unboundedly. Shutdown is propagated through both
//! the header read and the TLS handshake.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ipnet::IpNet;
use pingora_core::apps::HttpServerApp;
use pingora_core::protocols::http::ServerSession;
use pingora_core::protocols::l4::stream::Stream as L4Stream;
use pingora_core::protocols::tls::server::handshake_with_callback;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::Service;
use pingora_core::tls::ssl::{SslAcceptor, SslMethod};
use pingora_proxy::HttpProxy;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::SniCertSelector;
use crate::proxy::{CONN_INFO, ConnectionInfo, Proxy};

/// Maximum number of in-flight per-connection tasks (PROXY header read + TLS handshake).
/// Connections beyond this limit are dropped with a warning rather than queued.
const MAX_CONCURRENT_CONNECTIONS: usize = 4096;

/// Error returned by [`ProxyAcceptor::new`].
#[derive(Debug, Error)]
pub enum AcceptorBuildError {
    /// A listen address could not be bound.
    #[error("failed to bind {addr}: {source}")]
    BindFailed {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    /// The TLS acceptor builder could not be initialised.
    #[error("failed to build TLS acceptor: {0}")]
    TlsAcceptorBuild(String),
}

/// Typed errors from reading a PROXY protocol v1 or v2 header.
#[derive(Debug, Error)]
pub(crate) enum ProxyHeaderError {
    #[error("proxy header read timed out")]
    Timeout,
    #[error("proxy header i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("proxy v2 address block too large ({0} bytes)")]
    TooLarge(usize),
    #[error("no proxy protocol header (strict mode)")]
    BadPreamble,
    #[error("proxy v1 header exceeds 108 bytes")]
    V1TooLarge,
    #[error("proxy v1 header is not valid utf-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("proxy v1 malformed: {0}")]
    MalformedV1(&'static str),
    #[error("proxy v1 unknown protocol: {0}")]
    UnknownProtocol(String),
}

/// Bundles the TLS acceptor and SNI callbacks together so they can only be used
/// as a pair — eliminating the separate-`Option` footgun from the prior design.
#[derive(Clone)]
struct TlsContext {
    acceptor: Arc<SslAcceptor>,
    callbacks: Arc<pingora_core::listeners::TlsAcceptCallbacks>,
}

impl TlsContext {
    fn new(selector: SniCertSelector) -> Result<Self, AcceptorBuildError> {
        let builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
            .map_err(|e| AcceptorBuildError::TlsAcceptorBuild(e.to_string()))?;
        let callbacks: pingora_core::listeners::TlsAcceptCallbacks = Box::new(selector);
        Ok(Self {
            acceptor: Arc::new(builder.build()),
            callbacks: Arc::new(callbacks),
        })
    }
}

/// A socket bound before the Pingora runtime starts, kept until `start_service`
/// converts it to a tokio listener.
struct BoundListener {
    /// Non-blocking standard TCP socket; converted to tokio in `start_service`.
    std_tcp: std::net::TcpListener,
    config: ListenerConfig,
}

/// Per-listener configuration passed into each connection handler.
#[derive(Clone)]
struct ListenerConfig {
    /// Present iff this listener speaks TLS.
    tls: Option<TlsContext>,
    proto: &'static str,
    local_addr: SocketAddr,
}

/// CIDR allow-list for peers permitted to send PROXY protocol headers.
pub struct TrustedSources {
    nets: Vec<IpNet>,
}

impl TrustedSources {
    pub fn new(nets: Vec<IpNet>) -> Self {
        Self { nets }
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(ip))
    }
}

/// Whether a listener speaks plain HTTP or HTTPS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerProtocol {
    Http,
    Https,
}

/// One listen address with its associated protocol.
#[derive(Clone, Debug)]
pub struct ListenerSpec {
    pub addr: SocketAddr,
    pub protocol: ListenerProtocol,
}

impl ListenerSpec {
    pub fn http(addr: SocketAddr) -> Self {
        Self {
            addr,
            protocol: ListenerProtocol::Http,
        }
    }

    pub fn https(addr: SocketAddr) -> Self {
        Self {
            addr,
            protocol: ListenerProtocol::Https,
        }
    }
}

/// Listens on one or more `(addr, protocol)` pairs, reads HAProxy PROXY protocol
/// v1/v2 headers, and hands the resulting sessions to a shared [`HttpProxy`].
///
/// Activated only when `--proxy-accept-proxy-protocol` is set. When the flag is
/// off, the standard `http_proxy_service_with_name` path is used instead.
pub struct ProxyAcceptor {
    proxy: Arc<HttpProxy<Proxy>>,
    listeners: Vec<BoundListener>,
    trusted: Arc<TrustedSources>,
}

impl ProxyAcceptor {
    /// Bind all listener sockets and build the TLS context.
    ///
    /// Binding is synchronous so that port-in-use and permission errors surface as
    /// a structured [`AcceptorBuildError`] before the Pingora runtime starts, rather
    /// than panicking inside an async task.
    pub fn new(
        proxy: Arc<HttpProxy<Proxy>>,
        specs: Vec<ListenerSpec>,
        trusted: Arc<TrustedSources>,
        tls_selector: SniCertSelector,
    ) -> Result<Self, AcceptorBuildError> {
        // Build the TLS context once; share across all HTTPS listeners via Clone (Arc bumps).
        let tls_ctx = if specs.iter().any(|s| s.protocol == ListenerProtocol::Https) {
            Some(TlsContext::new(tls_selector)?)
        } else {
            None
        };

        let mut listeners = Vec::with_capacity(specs.len());
        for spec in specs {
            let std_tcp = std::net::TcpListener::bind(spec.addr).map_err(|source| {
                AcceptorBuildError::BindFailed {
                    addr: spec.addr,
                    source,
                }
            })?;
            std_tcp
                .set_nonblocking(true)
                .map_err(|source| AcceptorBuildError::BindFailed {
                    addr: spec.addr,
                    source,
                })?;
            let local_addr = std_tcp.local_addr().unwrap_or(spec.addr);
            let proto = match spec.protocol {
                ListenerProtocol::Http => "http",
                ListenerProtocol::Https => "https",
            };
            let tls = if spec.protocol == ListenerProtocol::Https {
                tls_ctx.clone()
            } else {
                None
            };
            listeners.push(BoundListener {
                std_tcp,
                config: ListenerConfig {
                    tls,
                    proto,
                    local_addr,
                },
            });
        }

        Ok(Self {
            proxy,
            listeners,
            trusted,
        })
    }
}

#[async_trait]
impl Service for ProxyAcceptor {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<pingora_core::server::ListenFds>,
        shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        let mut handles = Vec::new();

        for bound in self.listeners.drain(..) {
            let tcp = tokio::net::TcpListener::from_std(bound.std_tcp).unwrap_or_else(|e| {
                panic!("pre-bound non-blocking std listener must convert — this is a bug: {e}")
            });
            let config = bound.config;
            let local_addr = config.local_addr;

            let proxy = self.proxy.clone();
            let trusted = self.trusted.clone();
            let sem = Arc::clone(&sem);
            let mut sd = shutdown.clone();

            handles.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = sd.changed() => return,
                        result = tcp.accept() => match result {
                            Ok((stream, peer)) => {
                                match Arc::clone(&sem).try_acquire_owned() {
                                    Ok(permit) => {
                                        let proxy = proxy.clone();
                                        let trusted = trusted.clone();
                                        let config = config.clone();
                                        let sd = sd.clone();
                                        tokio::spawn(async move {
                                            let _permit = permit;
                                            handle_connection(stream, peer, proxy, trusted, config, sd)
                                                .await;
                                        });
                                    }
                                    Err(_) => {
                                        tracing::warn!(
                                            peer = %peer,
                                            limit = MAX_CONCURRENT_CONNECTIONS,
                                            "connection limit reached, dropping"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!(addr = %local_addr, error = %e, "accept error")
                            }
                        }
                    }
                }
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }
    }

    fn name(&self) -> &str {
        "proxy (PROXY protocol)"
    }
}

async fn handle_connection(
    mut tcp: TcpStream,
    peer_addr: SocketAddr,
    proxy: Arc<HttpProxy<Proxy>>,
    trusted: Arc<TrustedSources>,
    cfg: ListenerConfig,
    mut shutdown: ShutdownWatch,
) {
    if !trusted.contains(&peer_addr.ip()) {
        tracing::debug!(peer = %peer_addr, "rejecting connection from untrusted source");
        return;
    }

    // Honour shutdown during the PROXY header read so a stuck client cannot
    // block graceful drain.
    let real_addr = tokio::select! {
        _ = shutdown.changed() => return,
        result = read_proxy_header(&mut tcp, peer_addr) => match result {
            Ok(addr) => addr,
            Err(e) => {
                tracing::debug!(peer = %peer_addr, error = %e, "PROXY header read failed, dropping connection");
                return;
            }
        }
    };

    let conn_info = ConnectionInfo {
        real_addr,
        local_addr: cfg.local_addr,
        proto: cfg.proto,
    };

    let stream: pingora_core::protocols::Stream = match cfg.tls {
        Some(ctx) => {
            let l4: L4Stream = tcp.into();
            // Honour shutdown during TLS handshake for the same reason.
            let tls_result = tokio::select! {
                _ = shutdown.changed() => return,
                result = handshake_with_callback(&ctx.acceptor, l4, ctx.callbacks.as_ref()) => result,
            };
            match tls_result {
                Ok(tls_stream) => Box::new(tls_stream),
                Err(e) => {
                    tracing::debug!(peer = %peer_addr, error = %e, "TLS handshake failed");
                    return;
                }
            }
        }
        None => {
            let l4: L4Stream = tcp.into();
            Box::new(l4)
        }
    };

    let mut session = ServerSession::new_http1(stream);
    session.set_keepalive(Some(60));

    let mut session = Some(session);
    while let Some(current) = session.take() {
        let reused = CONN_INFO
            .scope(
                conn_info.clone(),
                proxy.process_new_http(current, &shutdown),
            )
            .await;
        match reused {
            Some(reused) => {
                let (stream, _persistent) = reused.consume();
                session = Some(ServerSession::new_http1(stream));
            }
            None => break,
        }
    }
}

/// Read a PROXY protocol v1 or v2 header from the stream.
///
/// Returns the real source [`SocketAddr`] from the header, or the TCP peer
/// address when the header carries `UNKNOWN` / `LOCAL` (no address info).
/// Returns `Err` if no valid PROXY header is found (strict mode: drop connection).
async fn read_proxy_header(
    tcp: &mut TcpStream,
    fallback: SocketAddr,
) -> Result<SocketAddr, ProxyHeaderError> {
    const V2_SIG: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
    const TIMEOUT: Duration = Duration::from_secs(5);

    let mut preamble = [0u8; 12];
    // Double ? : outer converts Elapsed → Timeout; inner converts io::Error → Io.
    tokio::time::timeout(TIMEOUT, tcp.read_exact(&mut preamble))
        .await
        .map_err(|_| ProxyHeaderError::Timeout)??;

    if &preamble == V2_SIG {
        parse_proxy_v2(tcp, fallback).await
    } else if preamble.starts_with(b"PROXY ") {
        parse_proxy_v1(tcp, &preamble, fallback).await
    } else {
        Err(ProxyHeaderError::BadPreamble)
    }
}

async fn parse_proxy_v2(
    tcp: &mut TcpStream,
    fallback: SocketAddr,
) -> Result<SocketAddr, ProxyHeaderError> {
    // Read 4 bytes: ver+cmd, family+proto, 2-byte address-block length.
    let mut hdr = [0u8; 4];
    tcp.read_exact(&mut hdr).await?;

    let cmd = hdr[0] & 0x0f;
    let family = (hdr[1] >> 4) & 0x0f;
    let proto = hdr[1] & 0x0f;
    let addr_len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;

    if addr_len > 536 {
        return Err(ProxyHeaderError::TooLarge(addr_len));
    }

    let mut addr_block = vec![0u8; addr_len];
    tcp.read_exact(&mut addr_block).await?;

    // cmd == 0 means LOCAL (health checks, etc.) — use TCP peer as fallback.
    if cmd == 0 {
        return Ok(fallback);
    }

    match (family, proto) {
        // AF_INET (1) + STREAM (1): src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) = 12 bytes
        (1, 1) if addr_len >= 12 => {
            let src_ip = std::net::Ipv4Addr::from([
                addr_block[0],
                addr_block[1],
                addr_block[2],
                addr_block[3],
            ]);
            let src_port = u16::from_be_bytes([addr_block[8], addr_block[9]]);
            Ok(SocketAddr::new(src_ip.into(), src_port))
        }
        // AF_INET6 (2) + STREAM (1): src_ip(16) + dst_ip(16) + src_port(2) + dst_port(2) = 36 bytes
        (2, 1) if addr_len >= 36 => {
            let src_ip_bytes: [u8; 16] = addr_block[0..16]
                .try_into()
                .unwrap_or_else(|_| panic!("guarded by addr_len >= 36 check above"));
            let src_ip = std::net::Ipv6Addr::from(src_ip_bytes);
            let src_port = u16::from_be_bytes([addr_block[32], addr_block[33]]);
            Ok(SocketAddr::new(src_ip.into(), src_port))
        }
        // UNSPEC or UNIX socket: no routable address, use TCP peer.
        _ => Ok(fallback),
    }
}

async fn parse_proxy_v1(
    tcp: &mut TcpStream,
    preamble: &[u8; 12],
    fallback: SocketAddr,
) -> Result<SocketAddr, ProxyHeaderError> {
    // We already have the first 12 bytes. Read byte-by-byte until \r\n.
    let mut line: Vec<u8> = preamble.to_vec();
    loop {
        let mut byte = [0u8; 1];
        tcp.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if line.len() > 108 {
            return Err(ProxyHeaderError::V1TooLarge);
        }
        if line.ends_with(b"\r\n") {
            break;
        }
    }

    // The loop only exits when `line` ends with \r\n.
    let header = line
        .strip_suffix(b"\r\n")
        .unwrap_or_else(|| panic!("loop exits only when ends_with(\\r\\n)"));
    let s = std::str::from_utf8(header)?;
    let parts: Vec<&str> = s.split(' ').collect();

    // Format: "PROXY TCP4 src dst sport dport" or "PROXY UNKNOWN ..."
    if parts.len() < 2 {
        return Err(ProxyHeaderError::MalformedV1("too few fields"));
    }

    match parts[1] {
        "TCP4" | "TCP6" => {
            if parts.len() != 6 {
                return Err(ProxyHeaderError::MalformedV1("expected 6 fields for TCP"));
            }
            let src_ip: IpAddr = parts[2]
                .parse()
                .map_err(|_| ProxyHeaderError::MalformedV1("invalid source IP"))?;
            let src_port: u16 = parts[4]
                .parse()
                .map_err(|_| ProxyHeaderError::MalformedV1("invalid source port"))?;
            Ok(SocketAddr::new(src_ip, src_port))
        }
        "UNKNOWN" => Ok(fallback),
        other => Err(ProxyHeaderError::UnknownProtocol(other.to_owned())),
    }
}
