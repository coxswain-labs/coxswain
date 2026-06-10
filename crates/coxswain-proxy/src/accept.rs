//! Dynamic proxy acceptor — binds, reconciles, and drains listeners in-process.
//!
//! [`ProxyAcceptor`] owns a desired set of [`ListenerSpec`]s driven by a
//! `tokio::sync::watch::Receiver<HashSet<ListenerSpec>>`.  It reconciles that
//! set on every change: newly-desired specs are bound and start accepting;
//! removed specs stop accepting and drain in-flight connections within
//! `--proxy-listener-drain-timeout` before the socket is released.
//!
//! This replaces the earlier `hot_reload.rs` fork+exec restart mechanism.
//! The invariant is "no dropped connections or requests during a listener
//! add/remove cycle": connections on surviving ports are unaffected; those on
//! removed ports drain naturally within the timeout window.
//!
//! # Protocol support
//!
//! - **Plain HTTP and HTTPS (SNI-TLS)**: handled via Pingora's
//!   [`ServerApp::process_new`], which detects ALPN and supports both
//!   HTTP/1.1 and HTTP/2 transparently.
//! - **HAProxy PROXY protocol** (opt-in via `--proxy-accept-proxy-protocol`):
//!   header is parsed before TLS and upstream dispatch; HTTP/1.1 only on this
//!   path (existing behaviour; not regressed by this rewrite).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ipnet::IpNet;
use pingora_core::apps::{HttpServerApp, ServerApp};
use pingora_core::protocols::http::ServerSession;
use pingora_core::protocols::l4::stream::Stream as L4Stream;
use pingora_core::protocols::tls::server::handshake_with_callback;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::Service;
use pingora_core::tls::ssl::{SslAcceptor, SslMethod};
use pingora_proxy::{HttpProxy, ProxyHttp};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use crate::SniCertSelector;
use crate::common::ctx::{CONN_INFO, ConnectionInfo};
use crate::metrics;

/// Maximum number of in-flight per-connection tasks per listener.
/// Connections beyond this limit are dropped with a warning rather than queued.
const MAX_CONCURRENT_CONNECTIONS: usize = 4096;

// ── Public types ─────────────────────────────────────────────────────────────

/// Error returned when building a [`ProxyAcceptor`].
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum AcceptorBuildError {
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

/// CIDR allow-list for peers permitted to send PROXY protocol headers.
pub struct TrustedSources {
    nets: Vec<IpNet>,
}

impl TrustedSources {
    /// Build a new allow-list from a set of CIDR ranges.
    pub fn new(nets: Vec<IpNet>) -> Self {
        Self { nets }
    }

    /// Returns `true` if `ip` is covered by at least one of the trusted CIDR ranges.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(ip))
    }
}

/// Whether a listener speaks plain HTTP or HTTPS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ListenerProtocol {
    /// Plain HTTP/1.1 (no TLS).
    Http,
    /// HTTPS with SNI-based certificate selection.
    Https,
}

/// One listen address with its associated protocol.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ListenerSpec {
    /// The socket address to bind.
    pub addr: SocketAddr,
    /// Whether this listener speaks HTTP or HTTPS.
    pub protocol: ListenerProtocol,
}

impl ListenerSpec {
    /// Create an HTTP listener spec for the given address.
    pub fn http(addr: SocketAddr) -> Self {
        Self {
            addr,
            protocol: ListenerProtocol::Http,
        }
    }

    /// Create an HTTPS listener spec for the given address.
    pub fn https(addr: SocketAddr) -> Self {
        Self {
            addr,
            protocol: ListenerProtocol::Https,
        }
    }
}

/// Dynamically-managed proxy acceptor for a single [`ProxyHttp`] implementation.
///
/// Drives a reconcilable set of TCP listeners described by
/// `specs_rx: watch::Receiver<HashSet<ListenerSpec>>`.  On each change it
/// computes the delta, binds newly-desired listeners, and begins draining
/// removed ones — all in-process, with no process restart.
///
/// When `trusted_sources` is `Some`, every accepted connection must carry a
/// valid HAProxy PROXY-protocol header from the allow-listed CIDR set.  When
/// it is `None` (the common case), standard Pingora connection handling is
/// used, supporting both HTTP/1.1 and HTTP/2 via ALPN.
pub struct ProxyAcceptor<P>
where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    proxy: Arc<HttpProxy<P>>,
    /// Current desired listener set; `None` means static (never changes).
    specs_rx: Option<watch::Receiver<HashSet<ListenerSpec>>>,
    /// Initial desired set (used as the permanent set when `specs_rx` is `None`).
    initial_specs: HashSet<ListenerSpec>,
    /// When `Some`, require PROXY-protocol headers and only from these sources.
    trusted: Option<Arc<TrustedSources>>,
    tls_selector: SniCertSelector,
    drain_timeout: Duration,
}

impl<P> ProxyAcceptor<P>
where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    /// Build an acceptor.
    ///
    /// * `initial_specs` — listeners to bind immediately when the service
    ///   starts; used as the permanent set when `specs_rx` is `None`.
    /// * `specs_rx` — if `Some`, the acceptor watches this receiver for
    ///   desired-set changes and reconciles dynamically.  Pass `None` for a
    ///   static listener set.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptorBuildError::TlsAcceptorBuild`] when the TLS acceptor
    /// context cannot be initialised (reported eagerly so the process fails
    /// fast rather than at first HTTPS connection).
    pub fn new(
        proxy: Arc<HttpProxy<P>>,
        initial_specs: HashSet<ListenerSpec>,
        specs_rx: Option<watch::Receiver<HashSet<ListenerSpec>>>,
        trusted: Option<Arc<TrustedSources>>,
        tls_selector: SniCertSelector,
        drain_timeout: Duration,
    ) -> Result<Self, AcceptorBuildError> {
        // Validate the TLS acceptor eagerly so bind failures surface before runtime.
        if initial_specs
            .iter()
            .any(|s| s.protocol == ListenerProtocol::Https)
        {
            build_tls_context(&tls_selector)?;
        }

        Ok(Self {
            proxy,
            specs_rx,
            initial_specs,
            trusted,
            tls_selector,
            drain_timeout,
        })
    }
}

#[async_trait]
impl<P> Service for ProxyAcceptor<P>
where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<pingora_core::server::ListenFds>,
        mut shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        let mut active: HashMap<SocketAddr, ListenerHandle> = HashMap::new();
        // All listener tasks (active + draining) live here so we can await them on shutdown.
        let mut all_tasks: JoinSet<()> = JoinSet::new();

        let cfg = ListenerConfig {
            proxy: Arc::clone(&self.proxy),
            trusted: self.trusted.clone(),
            tls_selector: self.tls_selector.clone(),
            drain_timeout: self.drain_timeout,
        };

        // Bind the initial desired set.
        reconcile_listeners(
            &mut active,
            &mut all_tasks,
            self.initial_specs.clone(),
            &cfg,
            shutdown.clone(),
        )
        .await;

        loop {
            tokio::select! {
                biased;

                // Global process shutdown: drain all active listeners.
                _ = shutdown.changed() => {
                    signal_all_drain(&active);
                    break;
                }

                // Desired listener set changed.
                changed = async {
                    if let Some(rx) = self.specs_rx.as_mut() {
                        rx.changed().await
                    } else {
                        // Static mode: never fire.
                        std::future::pending::<Result<(), watch::error::RecvError>>().await
                    }
                } => {
                    if changed.is_err() {
                        // Sender dropped — treat as static; stop watching.
                        self.specs_rx = None;
                        continue;
                    }
                    let desired = self.specs_rx.as_ref()
                        .map(|rx| rx.borrow().clone())
                        .unwrap_or_default();
                    reconcile_listeners(
                        &mut active,
                        &mut all_tasks,
                        desired,
                        &cfg,
                        shutdown.clone(),
                    ).await;
                }

                // Reap completed listener tasks.
                Some(_) = all_tasks.join_next() => {}
            }
        }

        // Wait for all listener tasks (each carries its own drain timeout).
        while all_tasks.join_next().await.is_some() {}
    }

    fn name(&self) -> &str {
        "proxy-acceptor"
    }
}

// ── Per-listener handle ───────────────────────────────────────────────────────

/// Signals that allow the reconciler to stop accepting on a listener and drain
/// its in-flight connections.
struct ListenerHandle {
    /// Set `true` to stop the accept loop (no new connections on this listener).
    drain_tx: watch::Sender<bool>,
    /// Set `true` to signal all active connections to close after their
    /// current request completes (Pingora will stop keepalive and close idle
    /// connections on the next loop iteration).
    conn_shutdown_tx: watch::Sender<bool>,
}

/// Shared proxy + trust + TLS configuration used when spawning a new listener
/// or handling connections.  Groups the fields that would otherwise exceed the
/// `clippy::too_many_arguments` limit on the inner helper functions.
struct ListenerConfig<P>
where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    proxy: Arc<HttpProxy<P>>,
    trusted: Option<Arc<TrustedSources>>,
    tls_selector: SniCertSelector,
    drain_timeout: Duration,
}

/// Per-connection handler state: the proxy, trust policy, and TLS selector
/// together with the listener address metadata needed to seed [`CONN_INFO`] on
/// the PROXY-protocol path.
struct ConnHandler<P>
where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    proxy: Arc<HttpProxy<P>>,
    trusted: Option<Arc<TrustedSources>>,
    tls_selector: SniCertSelector,
    local_addr: SocketAddr,
    protocol: ListenerProtocol,
}

// ── Reconcile helpers ─────────────────────────────────────────────────────────

/// Compute the delta between `active` and `desired` and apply it:
/// - Spawn a listener task for each added spec.
/// - Signal drain for each removed spec.
async fn reconcile_listeners<P>(
    active: &mut HashMap<SocketAddr, ListenerHandle>,
    all_tasks: &mut JoinSet<()>,
    desired: HashSet<ListenerSpec>,
    cfg: &ListenerConfig<P>,
    global_shutdown: ShutdownWatch,
) where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    let desired_addrs: HashSet<SocketAddr> = desired.iter().map(|s| s.addr).collect();
    let current_addrs: HashSet<SocketAddr> = active.keys().copied().collect();

    // Signal drain for removed listeners.
    for addr in current_addrs.difference(&desired_addrs) {
        if let Some(handle) = active.remove(addr) {
            tracing::info!(addr = %addr, "Removing listener; draining in-flight connections");
            metrics::lifecycle().with_label_values(&["removed"]).inc();
            metrics::listeners_active()
                .with_label_values(&["serving"])
                .dec();
            metrics::listeners_active()
                .with_label_values(&["draining"])
                .inc();
            // Stop accepting new connections on this listener.
            let _ = handle.drain_tx.send(true);
            // Signal existing connections: no more keepalive.
            let _ = handle.conn_shutdown_tx.send(true);
            // The listener task is already in `all_tasks`; it will run its
            // drain timeout internally and exit.
        }
    }

    // Spawn tasks for newly-desired listeners.
    for spec in desired
        .into_iter()
        .filter(|s| !current_addrs.contains(&s.addr))
    {
        let tcp = match tokio::net::TcpListener::bind(spec.addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(
                    addr = %spec.addr,
                    error = %e,
                    "Cannot bind new listener; skipping"
                );
                continue;
            }
        };
        let (drain_tx, drain_rx) = watch::channel(false);
        let (conn_shutdown_tx, conn_shutdown_rx) = watch::channel(false);

        let listener_cfg = ListenerConfig {
            proxy: Arc::clone(&cfg.proxy),
            trusted: cfg.trusted.clone(),
            tls_selector: cfg.tls_selector.clone(),
            drain_timeout: cfg.drain_timeout,
        };
        let addr = spec.addr;
        let protocol = spec.protocol;

        tracing::info!(addr = %addr, "Binding new listener");
        metrics::lifecycle().with_label_values(&["added"]).inc();
        metrics::listeners_active()
            .with_label_values(&["serving"])
            .inc();

        all_tasks.spawn(run_listener(
            tcp,
            addr,
            protocol,
            listener_cfg,
            drain_rx,
            conn_shutdown_rx,
            global_shutdown.clone(),
        ));

        active.insert(
            addr,
            ListenerHandle {
                drain_tx,
                conn_shutdown_tx,
            },
        );
    }
}

/// Signal all active listeners to stop accepting and start draining.
fn signal_all_drain(active: &HashMap<SocketAddr, ListenerHandle>) {
    for handle in active.values() {
        let _ = handle.drain_tx.send(true);
        let _ = handle.conn_shutdown_tx.send(true);
    }
}

// ── Listener task ─────────────────────────────────────────────────────────────

/// Drives the accept loop for one listener and manages its per-connection
/// tasks.  Transitions to drain mode when `drain_rx` fires or the global
/// `shutdown` fires, then waits up to `cfg.drain_timeout` for in-flight
/// connections to complete.
async fn run_listener<P>(
    tcp: tokio::net::TcpListener,
    addr: SocketAddr,
    protocol: ListenerProtocol,
    cfg: ListenerConfig<P>,
    mut drain_rx: watch::Receiver<bool>,
    conn_shutdown_rx: watch::Receiver<bool>,
    mut global_shutdown: ShutdownWatch,
) where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let mut conn_set: JoinSet<()> = JoinSet::new();

    // Accept loop.
    loop {
        tokio::select! {
            biased;

            // Stop accepting: explicit drain signal.
            Ok(()) = drain_rx.changed() => {
                if *drain_rx.borrow() { break; }
            }
            // Stop accepting: global process shutdown.
            Ok(()) = global_shutdown.changed() => { break; }

            // Accept a new connection.
            result = tcp.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        match Arc::clone(&sem).try_acquire_owned() {
                            Ok(permit) => {
                                let handler = ConnHandler {
                                    proxy: Arc::clone(&cfg.proxy),
                                    trusted: cfg.trusted.clone(),
                                    tls_selector: cfg.tls_selector.clone(),
                                    local_addr: addr,
                                    protocol,
                                };
                                let conn_sd = conn_shutdown_rx.clone();
                                conn_set.spawn(async move {
                                    let _permit = permit;
                                    handle_connection(stream, peer, handler, conn_sd).await;
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
                        tracing::error!(addr = %addr, error = %e, "accept error");
                    }
                }
            }

            // Reap completed connection tasks.
            Some(_) = conn_set.join_next(), if !conn_set.is_empty() => {}
        }
    }

    // Accept stopped. Begin drain window.
    let drain_start = Instant::now();

    let force_closed = tokio::select! {
        _ = async { while conn_set.join_next().await.is_some() {} } => {
            // All connections completed within the drain window.
            let elapsed = drain_start.elapsed().as_secs_f64();
            metrics::drain_duration().with_label_values::<&str>(&[]).observe(elapsed);
            metrics::lifecycle().with_label_values(&["drain_completed"]).inc();
            metrics::listeners_active().with_label_values(&["draining"]).dec();
            tracing::info!(addr = %addr, elapsed_s = elapsed, "Listener drain completed");
            0u64
        }
        _ = tokio::time::sleep(cfg.drain_timeout) => {
            let n = conn_set.len() as u64;
            conn_set.abort_all();
            let elapsed = drain_start.elapsed().as_secs_f64();
            metrics::drain_duration().with_label_values::<&str>(&[]).observe(elapsed);
            metrics::lifecycle().with_label_values(&["drain_exceeded"]).inc();
            metrics::listeners_active().with_label_values(&["draining"]).dec();
            if n > 0 {
                metrics::requests_force_closed()
                    .with_label_values(&["drain_exceeded"])
                    .inc_by(n);
                tracing::warn!(
                    addr = %addr,
                    force_closed = n,
                    drain_timeout_s = cfg.drain_timeout.as_secs_f64(),
                    "Listener drain timeout exceeded; force-closed connections"
                );
            }
            n
        }
    };

    let _ = force_closed; // already reported via metrics + log above
}

// ── Connection handler ────────────────────────────────────────────────────────

/// Handle one accepted TCP connection.
///
/// Dispatches to either the **PROXY-protocol path** (when `trusted` is
/// `Some`) or the **standard Pingora path** (when `trusted` is `None`).
///
/// Standard path: calls [`ServerApp::process_new`] which handles ALPN,
/// supports HTTP/1.1 and HTTP/2, and manages keepalive internally.
///
/// PROXY-protocol path: reads the PROXY header, then runs an HTTP/1.1
/// keepalive loop via [`HttpServerApp::process_new_http`].  HTTP/2 is not
/// supported on this path (existing behaviour, not regressed by this
/// rewrite).
async fn handle_connection<P>(
    tcp: TcpStream,
    peer_addr: SocketAddr,
    handler: ConnHandler<P>,
    conn_shutdown: watch::Receiver<bool>,
) where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    if let Some(trusted) = handler.trusted {
        handle_proxy_protocol(
            tcp,
            peer_addr,
            handler.local_addr,
            handler.protocol,
            ProxyProtocolConn {
                proxy: handler.proxy,
                trusted,
                tls_selector: handler.tls_selector,
            },
            conn_shutdown,
        )
        .await;
    } else {
        handle_standard(
            tcp,
            handler.protocol,
            handler.proxy,
            handler.tls_selector,
            conn_shutdown,
        )
        .await;
    }
}

/// Standard (non-PROXY-protocol) connection handler.
///
/// Builds the [`pingora_core::protocols::Stream`], hands it to Pingora's
/// [`ServerApp::process_new`] — which detects ALPN and handles h1/h2.
async fn handle_standard<P>(
    tcp: TcpStream,
    protocol: ListenerProtocol,
    proxy: Arc<HttpProxy<P>>,
    tls_selector: SniCertSelector,
    conn_shutdown: watch::Receiver<bool>,
) where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    let stream: pingora_core::protocols::Stream = match protocol {
        ListenerProtocol::Https => {
            let tls_ctx = match build_tls_context(&tls_selector) {
                Ok(ctx) => ctx,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to build TLS context; dropping connection");
                    return;
                }
            };
            let l4: L4Stream = tcp.into();
            match handshake_with_callback(&tls_ctx.acceptor, l4, tls_ctx.callbacks.as_ref()).await {
                Ok(tls_stream) => Box::new(tls_stream),
                Err(e) => {
                    tracing::debug!(error = %e, "TLS handshake failed");
                    return;
                }
            }
        }
        ListenerProtocol::Http => Box::new(L4Stream::from(tcp)),
    };

    // `process_new` handles ALPN detection (h1/h2), keepalive, and shutdown
    // internally.  `conn_shutdown` is the per-listener shutdown watch — when
    // fired, Pingora stops accepting keepalive requests on this connection.
    let _ = proxy.process_new(stream, &conn_shutdown).await;
}

/// Aggregated inputs for the PROXY-protocol connection handler, grouping the
/// proxy, trust policy, and TLS selector so the function stays under the
/// argument-count limit.
struct ProxyProtocolConn<P>
where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    proxy: Arc<HttpProxy<P>>,
    trusted: Arc<TrustedSources>,
    tls_selector: SniCertSelector,
}

/// PROXY-protocol connection handler (h1 only).
///
/// Reads the PROXY v1/v2 header, seeds [`CONN_INFO`] with the real client
/// address, then drives an HTTP/1.1 keepalive loop via
/// [`HttpServerApp::process_new_http`].
async fn handle_proxy_protocol<P>(
    mut tcp: TcpStream,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    protocol: ListenerProtocol,
    conn: ProxyProtocolConn<P>,
    mut conn_shutdown: watch::Receiver<bool>,
) where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    if !conn.trusted.contains(&peer_addr.ip()) {
        tracing::debug!(peer = %peer_addr, "rejecting connection from untrusted source");
        return;
    }

    // Honour shutdown during the PROXY header read so a stuck client cannot
    // block graceful drain.
    let real_addr = tokio::select! {
        _ = conn_shutdown.changed() => return,
        result = read_proxy_header(&mut tcp, peer_addr) => match result {
            Ok(addr) => addr,
            Err(e) => {
                tracing::debug!(peer = %peer_addr, error = %e, "PROXY header read failed, dropping connection");
                return;
            }
        }
    };

    let proto_str = match protocol {
        ListenerProtocol::Http => "http",
        ListenerProtocol::Https => "https",
    };
    let conn_info = ConnectionInfo {
        real_addr,
        local_addr,
        proto: proto_str,
    };

    let stream: pingora_core::protocols::Stream = match protocol {
        ListenerProtocol::Https => {
            let tls_ctx = match build_tls_context(&conn.tls_selector) {
                Ok(ctx) => ctx,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to build TLS context; dropping PROXY connection");
                    return;
                }
            };
            let l4: L4Stream = tcp.into();
            let tls_result = tokio::select! {
                _ = conn_shutdown.changed() => return,
                result = handshake_with_callback(&tls_ctx.acceptor, l4, tls_ctx.callbacks.as_ref()) => result,
            };
            match tls_result {
                Ok(tls_stream) => Box::new(tls_stream),
                Err(e) => {
                    tracing::debug!(peer = %peer_addr, error = %e, "TLS handshake failed");
                    return;
                }
            }
        }
        ListenerProtocol::Http => Box::new(L4Stream::from(tcp)),
    };

    let mut session = ServerSession::new_http1(stream);
    session.set_keepalive(Some(60));

    let mut session = Some(session);
    while let Some(current) = session.take() {
        let reused = CONN_INFO
            .scope(
                conn_info.clone(),
                conn.proxy.process_new_http(current, &conn_shutdown),
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

// ── TLS context ───────────────────────────────────────────────────────────────

/// Bundled TLS acceptor + SNI callbacks for HTTPS listeners.
#[derive(Clone)]
struct TlsContext {
    acceptor: Arc<SslAcceptor>,
    callbacks: Arc<pingora_core::listeners::TlsAcceptCallbacks>,
}

fn build_tls_context(selector: &SniCertSelector) -> Result<TlsContext, AcceptorBuildError> {
    let builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| AcceptorBuildError::TlsAcceptorBuild(e.to_string()))?;
    let callbacks: pingora_core::listeners::TlsAcceptCallbacks = Box::new(selector.clone());
    Ok(TlsContext {
        acceptor: Arc::new(builder.build()),
        callbacks: Arc::new(callbacks),
    })
}

// ── PROXY protocol parsing ────────────────────────────────────────────────────

/// Read a PROXY protocol v1 or v2 header from the stream.
///
/// Returns the real source [`SocketAddr`] from the header, or the TCP peer
/// address when the header carries `UNKNOWN` / `LOCAL` (no address info).
///
/// # Errors
///
/// Returns [`ProxyHeaderError`] if no valid PROXY header is found (strict
/// mode: drop connection).
async fn read_proxy_header(
    tcp: &mut TcpStream,
    fallback: SocketAddr,
) -> Result<SocketAddr, ProxyHeaderError> {
    const V2_SIG: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
    const TIMEOUT: Duration = Duration::from_secs(5);

    let mut preamble = [0u8; 12];
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

    if cmd == 0 {
        return Ok(fallback);
    }

    match (family, proto) {
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
        (2, 1) if addr_len >= 36 => {
            let src_ip_bytes: [u8; 16] = addr_block[0..16]
                .try_into()
                .unwrap_or_else(|_| panic!("guarded by addr_len >= 36 check above"));
            let src_ip = std::net::Ipv6Addr::from(src_ip_bytes);
            let src_port = u16::from_be_bytes([addr_block[32], addr_block[33]]);
            Ok(SocketAddr::new(src_ip.into(), src_port))
        }
        _ => Ok(fallback),
    }
}

async fn parse_proxy_v1(
    tcp: &mut TcpStream,
    preamble: &[u8; 12],
    fallback: SocketAddr,
) -> Result<SocketAddr, ProxyHeaderError> {
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

    let header = line
        .strip_suffix(b"\r\n")
        .unwrap_or_else(|| panic!("loop exits only when ends_with(\\r\\n)"));
    let s = std::str::from_utf8(header)?;
    let parts: Vec<&str> = s.split(' ').collect();

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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_spec_equality_and_hash() {
        let a = ListenerSpec::http("127.0.0.1:80".parse().unwrap());
        let b = ListenerSpec::http("127.0.0.1:80".parse().unwrap());
        let c = ListenerSpec::https("127.0.0.1:443".parse().unwrap());
        assert_eq!(a, b);
        assert_ne!(a, c);

        let mut set = HashSet::new();
        set.insert(a.clone());
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }

    #[test]
    fn listener_spec_in_hashset_dedup() {
        let specs: HashSet<ListenerSpec> = [
            ListenerSpec::http("0.0.0.0:8080".parse().unwrap()),
            ListenerSpec::http("0.0.0.0:8080".parse().unwrap()), // duplicate
            ListenerSpec::https("0.0.0.0:8443".parse().unwrap()),
        ]
        .into_iter()
        .collect();
        assert_eq!(specs.len(), 2);
    }

    #[test]
    fn reconcile_delta_add_and_remove() {
        let addr_a: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:8081".parse().unwrap();

        let current: HashSet<SocketAddr> = [addr_a].into_iter().collect();
        let desired: HashSet<ListenerSpec> = [
            ListenerSpec::http(addr_b), // new
        ]
        .into_iter()
        .collect();

        let desired_addrs: HashSet<SocketAddr> = desired.iter().map(|s| s.addr).collect();

        let to_remove: Vec<SocketAddr> = current.difference(&desired_addrs).copied().collect();
        let to_add: Vec<&ListenerSpec> = desired
            .iter()
            .filter(|s| !current.contains(&s.addr))
            .collect();

        assert_eq!(to_remove, vec![addr_a]);
        assert_eq!(to_add.len(), 1);
        assert_eq!(to_add[0].addr, addr_b);
    }
}
