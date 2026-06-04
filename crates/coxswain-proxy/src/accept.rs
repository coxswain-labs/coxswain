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
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use crate::SniCertSelector;
use crate::proxy::{CONN_INFO, ConnectionInfo, Proxy};

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

/// Listens on one or more `(addr, protocol)` pairs, reads HAProxy PROXY protocol v1/v2
/// headers, and hands the resulting sessions to a shared [`HttpProxy`].
///
/// Activated only when `--proxy-accept-proxy-protocol` is set. When the flag is
/// off, the standard `http_proxy_service_with_name` path is used instead.
pub struct ProxyAcceptor {
    proxy: Arc<HttpProxy<Proxy>>,
    listeners: Vec<ListenerSpec>,
    trusted: Arc<TrustedSources>,
    ssl_acceptor: Arc<SslAcceptor>,
    tls_callbacks: Arc<pingora_core::listeners::TlsAcceptCallbacks>,
}

impl ProxyAcceptor {
    pub fn new(
        proxy: Arc<HttpProxy<Proxy>>,
        listeners: Vec<ListenerSpec>,
        trusted: Arc<TrustedSources>,
        tls: SniCertSelector,
    ) -> anyhow::Result<Self> {
        let ssl_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
            .map_err(|e| anyhow::anyhow!("failed to create TLS acceptor: {e}"))?;
        let ssl_acceptor = Arc::new(ssl_builder.build());
        let tls_callbacks: pingora_core::listeners::TlsAcceptCallbacks = Box::new(tls);
        Ok(Self {
            proxy,
            listeners,
            trusted,
            ssl_acceptor,
            tls_callbacks: Arc::new(tls_callbacks),
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
        let proxy = self.proxy.clone();
        let trusted = self.trusted.clone();
        let ssl_acceptor = self.ssl_acceptor.clone();
        let tls_callbacks = self.tls_callbacks.clone();

        let mut handles = Vec::new();
        for spec in &self.listeners {
            let listener = match spec.protocol {
                ListenerProtocol::Http => TcpListener::bind(spec.addr).await.unwrap_or_else(|e| {
                    panic!("bind HTTP listener {} for PROXY protocol: {e}", spec.addr)
                }),
                ListenerProtocol::Https => TcpListener::bind(spec.addr).await.unwrap_or_else(|e| {
                    panic!("bind HTTPS listener {} for PROXY protocol: {e}", spec.addr)
                }),
            };
            let local_addr = listener.local_addr().unwrap_or(spec.addr);
            let proto: &'static str = match spec.protocol {
                ListenerProtocol::Http => "http",
                ListenerProtocol::Https => "https",
            };
            let is_tls = spec.protocol == ListenerProtocol::Https;

            let proxy = proxy.clone();
            let trusted = trusted.clone();
            let ssl = if is_tls {
                Some(ssl_acceptor.clone())
            } else {
                None
            };
            let cb = if is_tls {
                Some(tls_callbacks.clone())
            } else {
                None
            };
            let mut sd = shutdown.clone();

            handles.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = sd.changed() => return,
                        result = listener.accept() => match result {
                            Ok((tcp, peer)) => {
                                let proxy = proxy.clone();
                                let trusted = trusted.clone();
                                let ssl = ssl.clone();
                                let cb = cb.clone();
                                let sd = sd.clone();
                                let args = ConnectionArgs {
                                    ssl_acceptor: ssl,
                                    tls_callbacks: cb,
                                    proto,
                                    local_addr,
                                };
                                tokio::spawn(async move {
                                    handle_connection(tcp, peer, proxy, trusted, args, sd).await;
                                });
                            }
                            Err(e) => tracing::error!(addr = %local_addr, error = %e, "accept error"),
                        },
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

struct ConnectionArgs {
    ssl_acceptor: Option<Arc<SslAcceptor>>,
    tls_callbacks: Option<Arc<pingora_core::listeners::TlsAcceptCallbacks>>,
    proto: &'static str,
    local_addr: SocketAddr,
}

async fn handle_connection(
    mut tcp: TcpStream,
    peer_addr: SocketAddr,
    proxy: Arc<HttpProxy<Proxy>>,
    trusted: Arc<TrustedSources>,
    args: ConnectionArgs,
    shutdown: ShutdownWatch,
) {
    let ConnectionArgs {
        ssl_acceptor,
        tls_callbacks,
        proto,
        local_addr,
    } = args;
    if !trusted.contains(&peer_addr.ip()) {
        tracing::debug!(
            peer = %peer_addr,
            "rejecting connection from untrusted source"
        );
        return;
    }

    let real_addr = match read_proxy_header(&mut tcp, peer_addr).await {
        Ok(addr) => addr,
        Err(e) => {
            tracing::debug!(peer = %peer_addr, error = %e, "PROXY header read failed, dropping connection");
            return;
        }
    };

    let conn_info = ConnectionInfo {
        real_addr,
        local_addr,
        proto,
    };

    let stream: pingora_core::protocols::Stream = match ssl_acceptor {
        Some(acceptor) => {
            let l4: L4Stream = tcp.into();
            let callbacks = tls_callbacks.as_deref().unwrap();
            match handshake_with_callback(&acceptor, l4, callbacks).await {
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
    loop {
        let current = session.take().unwrap();
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
/// Returns the real source `SocketAddr` from the header, or the TCP peer address
/// when the header carries `UNKNOWN` / `LOCAL` (no address info).
/// Returns `Err` if no valid PROXY header is found (strict mode: drop connection).
async fn read_proxy_header(
    tcp: &mut TcpStream,
    fallback: SocketAddr,
) -> anyhow::Result<SocketAddr> {
    const V2_SIG: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
    const TIMEOUT: Duration = Duration::from_secs(5);

    let mut preamble = [0u8; 12];
    tokio::time::timeout(TIMEOUT, tcp.read_exact(&mut preamble))
        .await
        .map_err(|_| anyhow::anyhow!("PROXY header read timed out"))?
        .map_err(|e| anyhow::anyhow!("PROXY header read error: {e}"))?;

    if &preamble == V2_SIG {
        parse_proxy_v2(tcp, fallback).await
    } else if preamble.starts_with(b"PROXY ") {
        parse_proxy_v1(tcp, &preamble, fallback).await
    } else {
        Err(anyhow::anyhow!("no PROXY protocol header (strict mode)"))
    }
}

async fn parse_proxy_v2(tcp: &mut TcpStream, fallback: SocketAddr) -> anyhow::Result<SocketAddr> {
    // Read 4 bytes: ver+cmd, family+proto, 2-byte address-block length
    let mut hdr = [0u8; 4];
    tcp.read_exact(&mut hdr).await?;

    let cmd = hdr[0] & 0x0f;
    let family = (hdr[1] >> 4) & 0x0f;
    let proto = hdr[1] & 0x0f;
    let addr_len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;

    if addr_len > 536 {
        return Err(anyhow::anyhow!(
            "PROXY v2 address block too large: {addr_len}"
        ));
    }

    let mut addr_block = vec![0u8; addr_len];
    tcp.read_exact(&mut addr_block).await?;

    // cmd == 0 means LOCAL (health checks etc.) — use TCP peer as fallback
    if cmd == 0 {
        return Ok(fallback);
    }

    match (family, proto) {
        // AF_INET (1) + STREAM (1): 4+4+2+2 = 12 bytes
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
        // AF_INET6 (2) + STREAM (1): 16+16+2+2 = 36 bytes
        (2, 1) if addr_len >= 36 => {
            let src_ip_bytes: [u8; 16] = addr_block[0..16]
                .try_into()
                .map_err(|_| anyhow::anyhow!("IPv6 slice error"))?;
            let src_ip = std::net::Ipv6Addr::from(src_ip_bytes);
            let src_port = u16::from_be_bytes([addr_block[32], addr_block[33]]);
            Ok(SocketAddr::new(src_ip.into(), src_port))
        }
        // UNSPEC or UNIX socket: no routable address, use TCP peer
        _ => Ok(fallback),
    }
}

async fn parse_proxy_v1(
    tcp: &mut TcpStream,
    preamble: &[u8; 12],
    fallback: SocketAddr,
) -> anyhow::Result<SocketAddr> {
    // We already have the first 12 bytes. Read byte-by-byte until \r\n.
    let mut line: Vec<u8> = preamble.to_vec();
    loop {
        let mut byte = [0u8; 1];
        tcp.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if line.len() > 108 {
            return Err(anyhow::anyhow!("PROXY v1 header exceeds 108 bytes"));
        }
        if line.ends_with(b"\r\n") {
            break;
        }
    }

    // Strip \r\n and parse
    let s = std::str::from_utf8(&line[..line.len() - 2])
        .map_err(|e| anyhow::anyhow!("PROXY v1 non-UTF8: {e}"))?;
    let parts: Vec<&str> = s.split(' ').collect();

    // "PROXY TCP4 src dst sport dport" or "PROXY UNKNOWN ..."
    if parts.len() < 2 {
        return Err(anyhow::anyhow!("PROXY v1 malformed: too few fields"));
    }

    match parts[1] {
        "TCP4" | "TCP6" => {
            if parts.len() != 6 {
                return Err(anyhow::anyhow!("PROXY v1 TCP malformed: expected 6 fields"));
            }
            let src_ip: IpAddr = parts[2]
                .parse()
                .map_err(|e| anyhow::anyhow!("PROXY v1 src IP parse: {e}"))?;
            let src_port: u16 = parts[4]
                .parse()
                .map_err(|e| anyhow::anyhow!("PROXY v1 src port parse: {e}"))?;
            Ok(SocketAddr::new(src_ip, src_port))
        }
        "UNKNOWN" => Ok(fallback),
        other => Err(anyhow::anyhow!("PROXY v1 unknown protocol: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn trusted_sources_contains_ip_in_range() {
        let net: IpNet = "192.168.1.0/24".parse().unwrap();
        let ts = TrustedSources::new(vec![net]);
        assert!(ts.contains(&"192.168.1.100".parse::<IpAddr>().unwrap()));
        assert!(!ts.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn trusted_sources_loopback() {
        let net: IpNet = "127.0.0.1/32".parse().unwrap();
        let ts = TrustedSources::new(vec![net]);
        assert!(ts.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!ts.contains(&"192.168.0.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn trusted_sources_empty_rejects_all() {
        let ts = TrustedSources::new(vec![]);
        assert!(!ts.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }
}
