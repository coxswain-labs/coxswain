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
//! - **Plain HTTP**: h1 and h2c (prior-knowledge) handled via Pingora's
//!   [`ServerApp::process_new`].  h2c prior-knowledge is always enabled —
//!   the detection is a non-destructive peek; HTTP/1.1 clients are unaffected.
//! - **HTTPS (SNI-TLS)**: h1 and h2 via ALPN negotiation.  The acceptor
//!   advertises `h2` and `http/1.1`; TLS clients that don't offer `h2` fall
//!   back to HTTP/1.1.
//! - **HAProxy PROXY protocol** (opt-in via `--proxy-accept-proxy-protocol`):
//!   header is parsed before TLS and upstream dispatch; HTTP/1.1 only on this
//!   path (h2c detection and h2 ALPN are disabled for PROXY-wrapped
//!   connections; see issue #32 for the follow-up).

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
use pingora_core::protocols::{ALPN, GetSocketDigest, SocketDigest};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::Service;
use pingora_core::tls::ssl::{AlpnError, SslAcceptor, SslMethod, SslRef, select_next_proto};
use pingora_proxy::{HttpProxy, ProxyHttp};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use coxswain_core::routing::SharedTlsPassthroughTable;

use crate::SniCertSelector;
use crate::ctx::{CONN_INFO, ConnectionInfo};
use crate::edge::passthrough::{handle_passthrough, peek_sni};
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

/// Groups the TLS-passthrough parameters for [`ProxyAcceptor::new`].
///
/// Extracted into a struct so `ProxyAcceptor::new` stays under the 7-argument
/// workspace limit enforced by `clippy::too_many_arguments`.
// intentionally open: callers construct this directly in coxswain-bin.
pub struct PassthroughConfig {
    /// SNI-keyed routing table for `TlsPassthrough` listeners.
    ///
    /// An empty table causes all passthrough connections to be closed
    /// immediately (no matching backend).
    pub table: SharedTlsPassthroughTable,
    /// How long to wait when connecting to a passthrough backend.
    pub dial_timeout: Duration,
}

/// CIDR allow-list for peers permitted to send PROXY protocol headers.
#[non_exhaustive]
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

/// Whether a listener speaks plain HTTP, HTTPS, or TLS passthrough.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ListenerProtocol {
    /// Plain HTTP/1.1 (no TLS).
    Http,
    /// HTTPS with SNI-based certificate selection.
    Https,
    /// Raw TLS passthrough: route by SNI without terminating TLS (TLSRoute / GEP-2643).
    TlsPassthrough,
    /// Port shared between TLS passthrough (TLSRoute) and HTTPS terminate listeners.
    ///
    /// On accept: peek the ClientHello SNI via MSG_PEEK. If the SNI matches a
    /// `TlsPassthrough` route, splice to that backend (bytes stay in the kernel
    /// queue — no replay needed). If not, fall through to standard TLS-terminate
    /// processing (`Https`).
    TlsHybrid,
}

/// One listen address with its associated protocol.
// intentionally open: field-literal constructed in crates/coxswain-bin/src/main.rs while assembling the desired listener set.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ListenerSpec {
    /// The socket address to bind.
    pub addr: SocketAddr,
    /// Whether this listener speaks HTTP, HTTPS, or TLS passthrough.
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

    /// Create a TLS passthrough listener spec for the given address (TLSRoute / GEP-2643).
    pub fn tls_passthrough(addr: SocketAddr) -> Self {
        Self {
            addr,
            protocol: ListenerProtocol::TlsPassthrough,
        }
    }

    /// Create a hybrid TLS listener spec for a port shared between TLS passthrough and HTTPS.
    ///
    /// Peeks the ClientHello SNI on accept: routes to passthrough if matched,
    /// falls through to TLS-terminate otherwise.
    pub fn tls_hybrid(addr: SocketAddr) -> Self {
        Self {
            addr,
            protocol: ListenerProtocol::TlsHybrid,
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
///
/// TLS passthrough listeners (`ListenerProtocol::TlsPassthrough`) bypass the
/// HTTP proxy entirely and forward raw encrypted streams by SNI, using the
/// [`SharedTlsPassthroughTable`] snapshot.
#[non_exhaustive]
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
    /// SNI-keyed passthrough routing table for `TlsPassthrough` listeners.
    passthrough_table: SharedTlsPassthroughTable,
    /// Timeout for dialling a passthrough backend.
    passthrough_dial_timeout: Duration,
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
    /// * `passthrough` — routing table and dial timeout for
    ///   `TlsPassthrough` listeners; see [`PassthroughConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`AcceptorBuildError::TlsAcceptorBuild`] when the TLS acceptor
    /// context cannot be initialised (reported eagerly so the process fails
    /// fast rather than at first HTTPS connection).
    #[must_use = "the constructed ProxyAcceptor must be used to serve connections"]
    pub fn new(
        proxy: Arc<HttpProxy<P>>,
        initial_specs: HashSet<ListenerSpec>,
        specs_rx: Option<watch::Receiver<HashSet<ListenerSpec>>>,
        trusted: Option<Arc<TrustedSources>>,
        tls_selector: SniCertSelector,
        drain_timeout: Duration,
        passthrough: PassthroughConfig,
    ) -> Result<Self, AcceptorBuildError> {
        // Validate the TLS acceptor eagerly so bind failures surface before runtime.
        // ALPN h2 advertisement only applies to the standard path (`handle_standard`);
        // the PROXY-protocol path (`handle_proxy_protocol`) runs an h1-only keepalive
        // loop so we must not advertise h2 there.
        let advertise_h2 = trusted.is_none();
        if initial_specs
            .iter()
            .any(|s| s.protocol == ListenerProtocol::Https)
        {
            build_tls_context(&tls_selector, advertise_h2)?;
        }

        Ok(Self {
            proxy,
            specs_rx,
            initial_specs,
            trusted,
            tls_selector,
            drain_timeout,
            passthrough_table: passthrough.table,
            passthrough_dial_timeout: passthrough.dial_timeout,
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
            passthrough_table: self.passthrough_table.clone(),
            passthrough_dial_timeout: self.passthrough_dial_timeout,
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
    drain_token: CancellationToken,
    /// Set `true` to signal all active connections to close after their
    /// current request completes (Pingora will stop keepalive and close idle
    /// connections on the next loop iteration).
    conn_shutdown_tx: watch::Sender<bool>,
    /// Current dispatch protocol for new connections on this listener.
    ///
    /// A Gateway-listener change can flip a port's protocol in place — e.g. a
    /// port serving `Https` terminate becomes `TlsHybrid` once a `TLSRoute`
    /// passthrough listener is added to the same port. The reconciler pushes the
    /// new protocol here so the running accept loop applies it to subsequent
    /// connections without rebinding the socket (which would race the draining
    /// old listener for the address). The current value also records the
    /// listener's protocol for the next reconcile's delta.
    proto_tx: watch::Sender<ListenerProtocol>,
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
    passthrough_table: SharedTlsPassthroughTable,
    passthrough_dial_timeout: Duration,
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
    passthrough_table: SharedTlsPassthroughTable,
    passthrough_dial_timeout: Duration,
}

// ── Reconcile helpers ─────────────────────────────────────────────────────────

/// The three disjoint actions a reconcile pass must take to converge the active
/// listener set to the desired set. Pure output of [`plan_listener_changes`] so
/// the delta logic is unit-testable without binding sockets.
#[derive(Debug, Default, PartialEq, Eq)]
struct ListenerPlan {
    /// Addresses to drain and stop accepting on (gone from desired).
    remove: Vec<SocketAddr>,
    /// Addresses already bound whose protocol changed — switch in place, no rebind.
    reprotocol: Vec<ListenerSpec>,
    /// Newly-desired addresses to bind and spawn.
    add: Vec<ListenerSpec>,
}

/// Partition `desired` against the currently-bound `active` protocols into a
/// [`ListenerPlan`].
///
/// An address present in both with a *different* protocol lands in `reprotocol`,
/// not `remove`+`add`: the socket stays bound and the running listener switches
/// protocol for new connections. Rebinding instead would race the draining old
/// listener for the address (the socket is held through its drain window, and no
/// `SO_REUSEPORT` is set), dropping the port entirely — the exact failure that
/// left `protocol: TLS` passthrough listeners stuck terminating on a port first
/// bound as `Https` (GEP-2643 / #70).
fn plan_listener_changes(
    active: &HashMap<SocketAddr, ListenerProtocol>,
    desired: &HashSet<ListenerSpec>,
) -> ListenerPlan {
    let desired_addrs: HashSet<SocketAddr> = desired.iter().map(|s| s.addr).collect();
    let mut plan = ListenerPlan::default();
    for addr in active.keys() {
        if !desired_addrs.contains(addr) {
            plan.remove.push(*addr);
        }
    }
    for spec in desired {
        match active.get(&spec.addr) {
            None => plan.add.push(spec.clone()),
            Some(&proto) if proto != spec.protocol => plan.reprotocol.push(spec.clone()),
            Some(_) => {}
        }
    }
    plan
}

/// Compute the delta between `active` and `desired` and apply it:
/// - Spawn a listener task for each added spec.
/// - Switch protocol in place for each spec whose port is already bound.
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
    let active_protos: HashMap<SocketAddr, ListenerProtocol> = active
        .iter()
        .map(|(addr, h)| (*addr, *h.proto_tx.borrow()))
        .collect();
    let plan = plan_listener_changes(&active_protos, &desired);

    // Signal drain for removed listeners.
    for addr in &plan.remove {
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
            handle.drain_token.cancel();
            // Signal existing connections: no more keepalive.
            let _ = handle.conn_shutdown_tx.send(true);
            // The listener task is already in `all_tasks`; it will run its
            // drain timeout internally and exit.
        }
    }

    // Switch protocol in place for ports that stayed bound but changed protocol.
    for spec in &plan.reprotocol {
        if let Some(handle) = active.get(&spec.addr) {
            tracing::info!(
                addr = %spec.addr,
                protocol = ?spec.protocol,
                "Switching listener protocol in place"
            );
            // `watch::Sender::send` only errors when every receiver is gone; the
            // listener task holds one, so a live listener always applies this.
            let _ = handle.proto_tx.send(spec.protocol);
        }
    }

    // Spawn tasks for newly-desired listeners.
    for spec in plan.add {
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
        let drain_token = CancellationToken::new();
        let (conn_shutdown_tx, conn_shutdown_rx) = watch::channel(false);
        let (proto_tx, proto_rx) = watch::channel(spec.protocol);

        let listener_cfg = ListenerConfig {
            proxy: Arc::clone(&cfg.proxy),
            trusted: cfg.trusted.clone(),
            tls_selector: cfg.tls_selector.clone(),
            drain_timeout: cfg.drain_timeout,
            passthrough_table: cfg.passthrough_table.clone(),
            passthrough_dial_timeout: cfg.passthrough_dial_timeout,
        };
        let addr = spec.addr;

        tracing::info!(addr = %addr, "Binding new listener");
        metrics::lifecycle().with_label_values(&["added"]).inc();
        metrics::listeners_active()
            .with_label_values(&["serving"])
            .inc();

        all_tasks.spawn(run_listener(
            tcp,
            addr,
            proto_rx,
            listener_cfg,
            drain_token.clone(),
            conn_shutdown_rx,
            global_shutdown.clone(),
        ));

        active.insert(
            addr,
            ListenerHandle {
                drain_token,
                conn_shutdown_tx,
                proto_tx,
            },
        );
    }
}

/// Signal all active listeners to stop accepting and start draining.
fn signal_all_drain(active: &HashMap<SocketAddr, ListenerHandle>) {
    for handle in active.values() {
        handle.drain_token.cancel();
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
    proto_rx: watch::Receiver<ListenerProtocol>,
    cfg: ListenerConfig<P>,
    drain_token: CancellationToken,
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
            _ = drain_token.cancelled() => {
                break;
            }
            // Stop accepting: global process shutdown.
            Ok(()) = global_shutdown.changed() => { break; }

            // Accept a new connection.
            result = tcp.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        match Arc::clone(&sem).try_acquire_owned() {
                            Ok(permit) => {
                                // Read the live protocol: a reconcile may have
                                // switched this port (e.g. Https → TlsHybrid) since
                                // the listener was bound, without rebinding it.
                                let protocol = *proto_rx.borrow();
                                let handler = ConnHandler {
                                    proxy: Arc::clone(&cfg.proxy),
                                    trusted: cfg.trusted.as_ref().map(Arc::clone),
                                    tls_selector: cfg.tls_selector.clone(),
                                    local_addr: addr,
                                    protocol,
                                    passthrough_table: cfg.passthrough_table.clone(),
                                    passthrough_dial_timeout: cfg.passthrough_dial_timeout,
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
/// Dispatches based on protocol and trust configuration:
/// - `TlsPassthrough`: peek SNI, match routing table, splice to backend — no HTTP involved.
/// - PROXY-protocol path (when `trusted` is `Some`): read PROXY header, run HTTP/1.1 loop.
/// - Standard Pingora path (when `trusted` is `None`): ALPN, HTTP/1.1 and HTTP/2.
async fn handle_connection<P>(
    tcp: TcpStream,
    peer_addr: SocketAddr,
    handler: ConnHandler<P>,
    conn_shutdown: watch::Receiver<bool>,
) where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    let _conn_guard = ConnectionGuard::new(handler.local_addr.port());

    // TLS passthrough is independent of the PROXY-protocol setting — it never runs
    // through the HTTP proxy layer.
    if handler.protocol == ListenerProtocol::TlsPassthrough {
        handle_passthrough(
            tcp,
            peer_addr,
            &handler.passthrough_table,
            handler.local_addr.port(),
            handler.passthrough_dial_timeout,
        )
        .await;
        return;
    }

    // Hybrid port: peek SNI (MSG_PEEK — bytes stay in kernel queue) and route to
    // passthrough if a TLSRoute matches. Otherwise fall through as HTTPS terminate.
    if handler.protocol == ListenerProtocol::TlsHybrid {
        let port = handler.local_addr.port();
        let sni = peek_sni(&tcp).await.ok().flatten();
        let snapshot = handler.passthrough_table.load();
        let has_passthrough_match = snapshot
            .port(port)
            .is_some_and(|router| router.match_sni(sni.as_deref()).is_some());
        if has_passthrough_match {
            handle_passthrough(
                tcp,
                peer_addr,
                &handler.passthrough_table,
                port,
                handler.passthrough_dial_timeout,
            )
            .await;
            return;
        }
        // No passthrough route matched. Fall through to TLS terminate only if a
        // real HTTPS listener serves this SNI; otherwise no Gateway listener on
        // this hybrid port accepts the connection, so reject it by dropping the
        // socket (the client observes a connection reset / EOF). Answering with
        // the TLS context's default cert instead would leave a non-matching SNI
        // looking "connectable", which GEP-2643 hostname-intersection forbids
        // (TLSRoute-standard: a request must reach a backend only for an
        // intersecting hostname).
        if !handler.tls_selector.has_cert_for(sni.as_deref()) {
            tracing::debug!(
                port,
                sni = ?sni,
                "Hybrid port: no passthrough route and no terminate cert for SNI — rejecting connection"
            );
            return;
        }
        // SNI has a terminate cert: fall through to TLS terminate.
        // Peeked bytes are still in the kernel queue — no replay needed.
    }

    // For TlsHybrid that fell through (no passthrough match), treat as Https.
    let effective_protocol = match handler.protocol {
        ListenerProtocol::TlsHybrid => ListenerProtocol::Https,
        p => p,
    };

    if let Some(trusted) = handler.trusted {
        handle_proxy_protocol(
            tcp,
            peer_addr,
            handler.local_addr,
            effective_protocol,
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
            effective_protocol,
            handler.proxy,
            handler.tls_selector,
            conn_shutdown,
        )
        .await;
    }
}

/// RAII guard: increments `coxswain_proxy_connections_active{listener}` on
/// construction, decrements it on drop, and observes
/// `coxswain_proxy_connection_duration_seconds{listener}`. Used by
/// [`handle_connection`] so the gauges and histogram stay accurate across
/// every connection-termination path (clean close, drain abort, TLS failure,
/// panic).
struct ConnectionGuard {
    port: u16,
    start: Instant,
}

impl ConnectionGuard {
    fn new(port: u16) -> Self {
        let mut buf = itoa::Buffer::new();
        let listener = buf.format(port);
        metrics::connections_total()
            .with_label_values(&[listener])
            .inc();
        metrics::connections_active()
            .with_label_values(&[listener])
            .inc();
        Self {
            port,
            start: Instant::now(),
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut buf = itoa::Buffer::new();
        let listener = buf.format(self.port);
        metrics::connections_active()
            .with_label_values(&[listener])
            .dec();
        metrics::connection_duration_seconds()
            .with_label_values(&[listener])
            .observe(self.start.elapsed().as_secs_f64());
    }
}

/// Observe one TLS handshake outcome on
/// `coxswain_proxy_tls_handshakes_total{result, version}`.
///
/// The `version` label is currently emitted as `"unknown"` for both
/// outcomes — the underlying `tls_stream` exposes the negotiated version
/// only after the request layer extracts the digest; surfacing it here is a
/// follow-up. Operators still get the `result` dimension (ok vs fail) which
/// is the higher-value signal during incidents.
fn observe_tls_handshake(result: &'static str) {
    metrics::tls_handshakes_total()
        .with_label_values(&[result, "unknown"])
        .inc();
}

/// Standard (non-PROXY-protocol) connection handler.
///
/// For HTTPS connections: routes based on the ALPN selected during the TLS
/// handshake.  ALPN h2 → [`ServerApp::process_new`] (correct: `h2c = true`
/// in server options causes Pingora to take the h2 branch).  ALPN h1 or no
/// ALPN → [`HttpServerApp::process_new_http`] keepalive loop (bypasses
/// Pingora's h2c detection, which malfunctions on TLS streams that do not
/// support read-and-rewind peeking).  For plain HTTP: [`ServerApp::process_new`]
/// with `h2c = true` — peeking works on L4 streams, h2c detection is correct.
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
    // Mirror what Pingora's own `l4::Listener::accept` does: build a
    // `SocketDigest` from the raw fd so that `session.server_addr()` returns
    // the correct local port for routing-table lookups.
    let raw_fd = {
        use std::os::unix::io::AsRawFd as _;
        tcp.as_raw_fd()
    };

    match protocol {
        ListenerProtocol::Https => {
            let tls_ctx = match build_tls_context(&tls_selector, true) {
                Ok(ctx) => ctx,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to build TLS context; dropping connection");
                    return;
                }
            };
            let mut l4: L4Stream = tcp.into();
            l4.set_socket_digest(SocketDigest::from_raw_fd(raw_fd));
            let stream: pingora_core::protocols::Stream =
                match handshake_with_callback(&tls_ctx.acceptor, l4, tls_ctx.callbacks.as_ref())
                    .await
                {
                    Ok(tls_stream) => {
                        observe_tls_handshake("ok");
                        Box::new(tls_stream)
                    }
                    Err(e) => {
                        observe_tls_handshake("fail");
                        tracing::debug!(error = %e, "TLS handshake failed");
                        return;
                    }
                };
            // `h2c = true` in the proxy's `HttpServerOptions` causes Pingora's
            // `process_new` to remain in h2 mode for TLS streams even when ALPN
            // did NOT negotiate h2.  TLS streams return `Ok(false)` from
            // `try_peek` (no read-and-rewind support), so the h2c preface check
            // is skipped and h2c stays true — Pingora then attempts an h2
            // handshake regardless of what ALPN actually selected.
            //
            // Fix: route based on the ALPN selection we know from the TLS
            // handshake.  When the client negotiated h2 via ALPN, process_new
            // is correct (h2c=true causes the h2 branch, which matches what
            // ALPN said).  For h1 clients (or clients that sent no ALPN at
            // all), bypass process_new and run the h1 keepalive loop directly —
            // the same pattern used by `handle_proxy_protocol`.
            match stream.selected_alpn_proto() {
                Some(ALPN::H2) => {
                    let _ = proxy.process_new(stream, &conn_shutdown).await;
                }
                _ => {
                    let mut session = ServerSession::new_http1(stream);
                    session.set_keepalive(Some(60));
                    let mut session = Some(session);
                    while let Some(current) = session.take() {
                        match proxy.process_new_http(current, &conn_shutdown).await {
                            Some(reused) => {
                                let (s, _) = reused.consume();
                                session = Some(ServerSession::new_http1(s));
                            }
                            None => break,
                        }
                    }
                }
            }
        }
        ListenerProtocol::Http => {
            let mut l4 = L4Stream::from(tcp);
            l4.set_socket_digest(SocketDigest::from_raw_fd(raw_fd));
            let stream: pingora_core::protocols::Stream = Box::new(l4);
            // `process_new` handles h2c detection (peek + rewind on L4 streams
            // works correctly), ALPN, keepalive, and shutdown.
            let _ = proxy.process_new(stream, &conn_shutdown).await;
        }
        // Passthrough and hybrid connections are dispatched before reaching this function.
        ListenerProtocol::TlsPassthrough | ListenerProtocol::TlsHybrid => {}
    }
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
        // Passthrough / hybrid connections are dispatched before reaching this function.
        ListenerProtocol::TlsPassthrough | ListenerProtocol::TlsHybrid => return,
    };
    let conn_info = ConnectionInfo {
        real_addr,
        local_addr,
        proto: proto_str,
    };

    let stream: pingora_core::protocols::Stream = match protocol {
        ListenerProtocol::Https => {
            let tls_ctx = match build_tls_context(&conn.tls_selector, false) {
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
                Ok(tls_stream) => {
                    observe_tls_handshake("ok");
                    Box::new(tls_stream)
                }
                Err(e) => {
                    observe_tls_handshake("fail");
                    tracing::debug!(peer = %peer_addr, error = %e, "TLS handshake failed");
                    return;
                }
            }
        }
        ListenerProtocol::Http => Box::new(L4Stream::from(tcp)),
        // Passthrough / hybrid connections are dispatched before reaching this function.
        ListenerProtocol::TlsPassthrough | ListenerProtocol::TlsHybrid => return,
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

/// Build a TLS acceptor for an HTTPS listener.
///
/// When `advertise_h2` is `true`, the acceptor registers an ALPN-select
/// callback that prefers `h2` over `http/1.1`, enabling transparent HTTP/2
/// negotiation with TLS clients.  Pass `false` for the PROXY-protocol path,
/// which runs an h1-only keepalive loop and must not advertise h2.
fn build_tls_context(
    selector: &SniCertSelector,
    advertise_h2: bool,
) -> Result<TlsContext, AcceptorBuildError> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| AcceptorBuildError::TlsAcceptorBuild(e.to_string()))?;
    if advertise_h2 {
        builder.set_alpn_select_callback(
            |_ssl: &mut SslRef, client: &[u8]| -> Result<&[u8], AlpnError> {
                // Wire-format: length-prefixed list — "\x02h2\x08http/1.1"
                // prefers h2 and falls back to http/1.1.
                select_next_proto(b"\x02h2\x08http/1.1", client).ok_or(AlpnError::NOACK)
            },
        );
    }
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
    fn plan_listener_changes_add_and_remove() {
        let addr_a: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:8081".parse().unwrap();

        let active: HashMap<SocketAddr, ListenerProtocol> =
            [(addr_a, ListenerProtocol::Http)].into_iter().collect();
        let desired: HashSet<ListenerSpec> = [ListenerSpec::http(addr_b)].into_iter().collect();

        let plan = plan_listener_changes(&active, &desired);

        assert_eq!(plan.remove, vec![addr_a]);
        assert!(plan.reprotocol.is_empty());
        assert_eq!(plan.add, vec![ListenerSpec::http(addr_b)]);
    }

    #[test]
    fn plan_listener_changes_detects_in_place_protocol_switch() {
        // GEP-2643 (#70): a port first bound as `Https` terminate becomes
        // `TlsHybrid` once a passthrough listener is added on the same port. The
        // address is unchanged, so it must be a `reprotocol` (switch in place),
        // never a no-op (which left passthrough stuck terminating) nor a
        // remove+add (which races the draining old listener for the socket).
        let addr: SocketAddr = "0.0.0.0:443".parse().unwrap();
        let active: HashMap<SocketAddr, ListenerProtocol> =
            [(addr, ListenerProtocol::Https)].into_iter().collect();
        let desired: HashSet<ListenerSpec> = [ListenerSpec::tls_hybrid(addr)].into_iter().collect();

        let plan = plan_listener_changes(&active, &desired);

        assert!(plan.remove.is_empty(), "socket must stay bound");
        assert!(plan.add.is_empty(), "no rebind");
        assert_eq!(plan.reprotocol, vec![ListenerSpec::tls_hybrid(addr)]);
    }

    #[test]
    fn plan_listener_changes_noop_when_protocol_unchanged() {
        let addr: SocketAddr = "0.0.0.0:443".parse().unwrap();
        let active: HashMap<SocketAddr, ListenerProtocol> =
            [(addr, ListenerProtocol::TlsHybrid)].into_iter().collect();
        let desired: HashSet<ListenerSpec> = [ListenerSpec::tls_hybrid(addr)].into_iter().collect();

        let plan = plan_listener_changes(&active, &desired);

        assert_eq!(plan, ListenerPlan::default(), "stable set: no churn");
    }

    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn trusted_sources_contains_ip_in_range() {
        let net: ipnet::IpNet = "192.168.1.0/24".parse().unwrap();
        let ts = TrustedSources::new(vec![net]);
        assert!(ts.contains(&"192.168.1.100".parse::<IpAddr>().unwrap()));
        assert!(!ts.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn trusted_sources_loopback() {
        let net: ipnet::IpNet = "127.0.0.1/32".parse().unwrap();
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
