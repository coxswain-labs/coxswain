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
//! - **HAProxy PROXY protocol** (opt-in per-listener via `ClientTrafficPolicy`
//!   CRD, or via `--ingress-accept-proxy-protocol` for Ingress-origin listeners):
//!   header is parsed and stripped before TLS/SNI dispatch; HTTP/1.1 only on
//!   this path (h2c detection and h2 ALPN are disabled for PROXY-wrapped
//!   connections; see issue #32 for the follow-up). TLS passthrough and
//!   terminate listeners strip the PROXY header before the SNI peek so the
//!   raw TLS stream reaches the backend unchanged.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora_core::apps::{HttpServerApp, ServerApp};
use pingora_core::protocols::http::ServerSession;
use pingora_core::protocols::l4::stream::Stream as L4Stream;
use pingora_core::protocols::tls::server::handshake_with_callback;
use pingora_core::protocols::{ALPN, GetSocketDigest, SocketDigest};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::Service;
use pingora_core::tls::ssl::{
    AlpnError, SslAcceptor, SslMethod, SslOptions, SslRef, SslSessionCacheMode, select_next_proto,
};
use pingora_proxy::{HttpProxy, ProxyHttp};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use coxswain_core::listener_status::ProxyProtocolListenerConfig;
use coxswain_core::routing::{SharedTcpRouteTable, SharedTlsPassthroughTable};
use ppp::PartialResult as _;

use crate::SniCertSelector;
use crate::ctx::{CONN_INFO, ConnectionInfo};
use crate::edge::passthrough::{handle_passthrough, peek_sni};
use crate::edge::tcp::handle_tcp_proxy;
use crate::edge::terminate::handle_terminate;
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
#[non_exhaustive]
#[derive(Debug, Error)]
pub(crate) enum ProxyHeaderError {
    /// No complete header arrived within the 5 s deadline.
    #[error("proxy header read timed out")]
    Timeout,
    /// Connection closed or I/O error while peeking or draining.
    #[error("proxy header i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// Peek buffer reached [`MAX_PROXY_PEEK`] without a parseable header.
    ///
    /// The inner value is the cap (`MAX_PROXY_PEEK`), not the byte count seen.
    #[error("PROXY header exceeds maximum peek size ({0} bytes)")]
    TooLarge(usize),
    /// Bytes present do not form a valid PROXY v1 or v2 header (strict mode).
    #[error("no valid PROXY protocol header (strict mode)")]
    BadPreamble,
}

/// Groups the TLS L4 parameters for [`ProxyAcceptor::new`].
///
/// Extracted into a struct so `ProxyAcceptor::new` stays under the 7-argument
/// workspace limit enforced by `clippy::too_many_arguments`.
// intentionally open: callers construct this directly in coxswain-bin.
pub struct PassthroughConfig {
    /// SNI-keyed routing table for TLSRoute `mode: Passthrough` listeners.
    ///
    /// An empty table causes all passthrough connections to be closed
    /// immediately (no matching backend).
    pub table: SharedTlsPassthroughTable,
    /// SNI-keyed routing table for TLSRoute `mode: Terminate` listeners (#481).
    ///
    /// An empty table causes all terminate connections to be closed immediately.
    pub terminate_table: SharedTlsPassthroughTable,
    /// Port-keyed routing table for TCPRoute listeners (#505). No SNI dimension.
    ///
    /// An empty table causes all TCP-proxy connections to be closed immediately.
    pub tcp_table: SharedTcpRouteTable,
    /// How long to wait when connecting to a passthrough, terminate, or TCP-proxy backend.
    pub dial_timeout: Duration,
}

/// Maximum number of bytes peeked while searching for a complete PROXY header.
///
/// v1 max is 108 bytes. v2 fixed header is 16 bytes + address block: up to 12 bytes
/// (IPv4), 36 bytes (IPv6), or 216 bytes (Unix). We cap at 552 to leave headroom for
/// small TLVs. Headers with TLV payloads that push the total beyond this cap are
/// rejected as `TooLarge`; TLV content is not inspected.
const MAX_PROXY_PEEK: usize = 552;

/// Whether a listener speaks plain HTTP, HTTPS, or TLS L4 (passthrough and/or terminate).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ListenerProtocol {
    /// Plain HTTP/1.1 (no TLS).
    Http,
    /// HTTPS with SNI-based certificate selection.
    Https,
    /// Raw TLS L4: peek SNI, consult the passthrough and/or terminate routing
    /// tables, splice to the matched backend.  Never falls through to HTTP.
    /// Covers TLSRoute `mode: Passthrough`, `mode: Terminate`, or both on the
    /// same port (TLSRouteModeTerminate / TLSRouteModeMixed, #481).
    TlsL4,
    /// Port shared between TLS L4 (TLSRoute) and HTTPS terminate listeners.
    ///
    /// On accept: peek the ClientHello SNI via MSG_PEEK. If the SNI matches a
    /// passthrough or terminate TLSRoute, handle it as L4. If not, fall through
    /// to standard TLS-terminate processing (`Https`).
    TlsHybrid,
    /// Raw TCP proxy (TCPRoute, GEP-1901): dial the bound backend and splice —
    /// no SNI peek, no TLS, no HTTP layer. Unlike `TlsL4` there is no
    /// passthrough-vs-terminate split and no hybrid fallthrough: a `TCP`
    /// listener never shares a port with another protocol (Gateway API
    /// port-compatibility rules exclude the combination).
    Tcp,
}

/// One listen address with its associated protocol and per-listener PROXY config.
// intentionally open: field-literal constructed in crates/coxswain-bin/src/main.rs while assembling the desired listener set.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ListenerSpec {
    /// The socket address to bind.
    pub addr: SocketAddr,
    /// Whether this listener speaks HTTP, HTTPS, or TLS passthrough.
    pub protocol: ListenerProtocol,
    /// Per-listener PROXY protocol configuration.
    ///
    /// `None` means PROXY protocol is disabled for this listener. `Some` carries
    /// both the `enabled` flag and the trusted-peer CIDR list.  When `enabled` is
    /// `true`, every accepted connection must present a valid PROXY header from a
    /// trusted source; connections without it are dropped.
    ///
    /// Gateway-origin listeners are seeded from the resolved `ClientTrafficPolicy`
    /// CRD. Ingress-origin listeners are seeded from `--ingress-accept-proxy-protocol`
    /// / `--ingress-proxy-trusted-sources` flags. The two mechanisms are disjoint.
    pub proxy_protocol: Option<ProxyProtocolListenerConfig>,
}

impl ListenerSpec {
    /// Create an HTTP listener spec for the given address with no PROXY protocol.
    pub fn http(addr: SocketAddr) -> Self {
        Self {
            addr,
            protocol: ListenerProtocol::Http,
            proxy_protocol: None,
        }
    }

    /// Create an HTTPS listener spec for the given address with no PROXY protocol.
    pub fn https(addr: SocketAddr) -> Self {
        Self {
            addr,
            protocol: ListenerProtocol::Https,
            proxy_protocol: None,
        }
    }

    /// Create a TLS L4 listener spec for a port serving TLSRoute passthrough and/or terminate.
    ///
    /// Peeks the ClientHello SNI on accept: routes to the matching passthrough or
    /// terminate backend.  Never falls through to HTTP.
    pub fn tls_l4(addr: SocketAddr) -> Self {
        Self {
            addr,
            protocol: ListenerProtocol::TlsL4,
            proxy_protocol: None,
        }
    }

    /// Create a hybrid TLS listener spec for a port shared between TLS L4 and HTTPS.
    ///
    /// Peeks the ClientHello SNI on accept: routes to passthrough or terminate if
    /// matched, falls through to TLS-terminate (HTTPS) otherwise.
    pub fn tls_hybrid(addr: SocketAddr) -> Self {
        Self {
            addr,
            protocol: ListenerProtocol::TlsHybrid,
            proxy_protocol: None,
        }
    }

    /// Create a raw TCP proxy listener spec for a port serving a `TCPRoute` (#505).
    pub fn tcp(addr: SocketAddr) -> Self {
        Self {
            addr,
            protocol: ListenerProtocol::Tcp,
            proxy_protocol: None,
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
/// PROXY protocol acceptance is per-listener, governed by
/// [`ListenerSpec::proxy_protocol`] (derived from `ClientTrafficPolicy` CRD
/// for Gateway listeners, or `--ingress-*` flags for Ingress listeners).
/// When a listener has PROXY config with `enabled: true`, every accepted
/// connection must present a valid HAProxy PROXY header from a trusted CIDR;
/// connections without it or from untrusted peers are dropped. When the
/// listener has no PROXY config, standard Pingora handling (h1+h2, ALPN)
/// is used.
///
/// TLS passthrough listeners (`ListenerProtocol::TlsL4`) bypass the
/// HTTP proxy entirely and forward raw encrypted streams by SNI, using the
/// [`SharedTlsPassthroughTable`] snapshot. If PROXY config is enabled on a
/// TLS L4 listener, the PROXY header is stripped before SNI peeking.
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
    tls_selector: SniCertSelector,
    drain_timeout: Duration,
    /// SNI-keyed passthrough routing table for TLSRoute passthrough listeners.
    passthrough_table: SharedTlsPassthroughTable,
    /// SNI-keyed terminate routing table for TLSRoute terminate listeners (#481).
    terminate_table: SharedTlsPassthroughTable,
    /// Port-keyed routing table for TCPRoute listeners (#505).
    tcp_table: SharedTcpRouteTable,
    /// Timeout for dialling a passthrough, terminate, or TCP-proxy backend.
    l4_dial_timeout: Duration,
    /// Publishes the set of ports with a live accept loop after every listener
    /// reconcile (#531). `None` (default) = no reporting. The discovery client
    /// forwards changes to the controller as `NodeStatus`, feeding the Gateway
    /// `Programmed` readiness gate.
    bound_ports_tx: Option<watch::Sender<BTreeSet<u16>>>,
}

impl<P> ProxyAcceptor<P>
where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    /// Build an acceptor.
    ///
    /// * `initial_specs` — listeners to bind immediately when the service
    ///   starts; used as the permanent set when `specs_rx` is `None`. Each
    ///   spec carries its own per-listener [`ProxyProtocolListenerConfig`].
    /// * `specs_rx` — if `Some`, the acceptor watches this receiver for
    ///   desired-set changes and reconciles dynamically.  Pass `None` for a
    ///   static listener set.
    /// * `passthrough` — routing tables (passthrough + terminate) and dial
    ///   timeout for TLS L4 listeners; see [`PassthroughConfig`].
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
        tls_selector: SniCertSelector,
        drain_timeout: Duration,
        passthrough: PassthroughConfig,
    ) -> Result<Self, AcceptorBuildError> {
        // Validate the TLS acceptor eagerly so bind failures surface before runtime.
        // PROXY-protocol listeners run h1-only (`handle_proxy_protocol` does not
        // advertise h2), but since PROXY config is per-listener we validate with
        // `advertise_h2 = true` (the most restrictive build path, i.e. the same
        // context the non-PROXY listeners will use).
        if initial_specs
            .iter()
            .any(|s| s.protocol == ListenerProtocol::Https)
        {
            build_tls_context(&tls_selector, true)?;
        }

        Ok(Self {
            proxy,
            specs_rx,
            initial_specs,
            tls_selector,
            drain_timeout,
            passthrough_table: passthrough.table,
            terminate_table: passthrough.terminate_table,
            tcp_table: passthrough.tcp_table,
            l4_dial_timeout: passthrough.dial_timeout,
            bound_ports_tx: None,
        })
    }

    /// Report actually-bound listener ports on `tx` after every reconcile (#531).
    ///
    /// The published set contains exactly the ports with a live accept loop:
    /// bind failures never enter it and draining listeners leave it at
    /// drain-start. A transient shrink during a rebind is expected and legal —
    /// the controller-side consumer anti-flaps.
    #[must_use]
    pub fn with_bound_ports_tx(mut self, tx: watch::Sender<BTreeSet<u16>>) -> Self {
        self.bound_ports_tx = Some(tx);
        self
    }
}

/// Publish the current bound-port set derived from `active` (#531).
///
/// `send_if_modified` suppresses no-op publishes so spec flips that rebind
/// nothing (e.g. an in-place PROXY-config change) do not wake the discovery
/// client.
fn publish_bound_ports(
    tx: Option<&watch::Sender<BTreeSet<u16>>>,
    active: &HashMap<SocketAddr, ListenerHandle>,
) {
    let Some(tx) = tx else { return };
    let ports: BTreeSet<u16> = active.keys().map(SocketAddr::port).collect();
    tx.send_if_modified(|current| {
        if *current == ports {
            false
        } else {
            *current = ports;
            true
        }
    });
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
            tls_selector: self.tls_selector.clone(),
            drain_timeout: self.drain_timeout,
            passthrough_table: self.passthrough_table.clone(),
            terminate_table: self.terminate_table.clone(),
            tcp_table: self.tcp_table.clone(),
            l4_dial_timeout: self.l4_dial_timeout,
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
        publish_bound_ports(self.bound_ports_tx.as_ref(), &active);

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
                    publish_bound_ports(self.bound_ports_tx.as_ref(), &active);
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
    /// Per-listener PROXY protocol config, pushed in place when the
    /// `ClientTrafficPolicy` changes (or the `--ingress-*` flag is toggled) so
    /// the running accept loop picks up the new config for subsequent connections
    /// without rebinding the socket.
    proxy_config_tx: watch::Sender<Option<ProxyProtocolListenerConfig>>,
}

/// Per-listener runtime signals for [`run_listener`]: drain + protocol +
/// PROXY-config receivers, all updatable in place without rebinding the socket.
struct ListenerSignals {
    drain_token: CancellationToken,
    proto_rx: watch::Receiver<ListenerProtocol>,
    proxy_config_rx: watch::Receiver<Option<ProxyProtocolListenerConfig>>,
    conn_shutdown_rx: watch::Receiver<bool>,
}

/// Shared proxy + TLS configuration used when spawning a new listener or
/// handling connections.  Groups the fields that would otherwise exceed the
/// `clippy::too_many_arguments` limit on the inner helper functions.
///
/// Per-listener PROXY config is NOT stored here; it flows via the
/// `proxy_config_tx`/`proxy_config_rx` watch channel pair on `ListenerHandle`
/// and `run_listener` so it can be updated in place without rebinding.
struct ListenerConfig<P>
where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    proxy: Arc<HttpProxy<P>>,
    tls_selector: SniCertSelector,
    drain_timeout: Duration,
    passthrough_table: SharedTlsPassthroughTable,
    terminate_table: SharedTlsPassthroughTable,
    tcp_table: SharedTcpRouteTable,
    l4_dial_timeout: Duration,
}

/// Per-connection handler state: the proxy, per-listener PROXY config, and TLS
/// selector together with the listener address metadata needed to seed
/// [`CONN_INFO`] on the PROXY-protocol path.
struct ConnHandler<P>
where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    proxy: Arc<HttpProxy<P>>,
    /// Snapshot of the listener's PROXY protocol configuration at the moment
    /// this connection was accepted.  `None` → no PROXY protocol; `Some` with
    /// `enabled: true` → strict PROXY mode.
    proxy_protocol: Option<ProxyProtocolListenerConfig>,
    tls_selector: SniCertSelector,
    local_addr: SocketAddr,
    protocol: ListenerProtocol,
    passthrough_table: SharedTlsPassthroughTable,
    terminate_table: SharedTlsPassthroughTable,
    tcp_table: SharedTcpRouteTable,
    l4_dial_timeout: Duration,
}

// ── Reconcile helpers ─────────────────────────────────────────────────────────

/// The four disjoint actions a reconcile pass must take to converge the active
/// listener set to the desired set. Pure output of [`plan_listener_changes`] so
/// the delta logic is unit-testable without binding sockets.
#[derive(Debug, Default, PartialEq, Eq)]
struct ListenerPlan {
    /// Addresses to drain and stop accepting on (gone from desired).
    remove: Vec<SocketAddr>,
    /// Addresses already bound whose protocol changed — switch in place, no rebind.
    reprotocol: Vec<ListenerSpec>,
    /// Addresses already bound whose PROXY config changed but whose protocol did
    /// not — update config in place via `proxy_config_tx`, no rebind.
    reproxy: Vec<ListenerSpec>,
    /// Newly-desired addresses to bind and spawn.
    add: Vec<ListenerSpec>,
}

/// Snapshot of the active state for one listener, used by [`plan_listener_changes`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActiveListenerState {
    pub(crate) protocol: ListenerProtocol,
    pub(crate) proxy_protocol: Option<ProxyProtocolListenerConfig>,
}

/// Partition `desired` against the currently-bound `active` state into a
/// [`ListenerPlan`].
///
/// An address present in both with a *different* protocol lands in `reprotocol`,
/// not `remove`+`add`: the socket stays bound and the running listener switches
/// protocol for new connections. Rebinding instead would race the draining old
/// listener for the address (the socket is held through its drain window, and no
/// `SO_REUSEPORT` is set), dropping the port entirely — the exact failure that
/// left `protocol: TLS` passthrough listeners stuck terminating on a port first
/// bound as `Https` (GEP-2643 / #70).
///
/// An address with matching protocol but changed PROXY config lands in `reproxy`:
/// the config is pushed over the `proxy_config_tx` watch channel without rebinding.
fn plan_listener_changes(
    active: &HashMap<SocketAddr, ActiveListenerState>,
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
            Some(state) if state.protocol != spec.protocol => plan.reprotocol.push(spec.clone()),
            Some(state) if state.proxy_protocol != spec.proxy_protocol => {
                plan.reproxy.push(spec.clone());
            }
            Some(_) => {}
        }
    }
    plan
}

/// Compute the delta between `active` and `desired` and apply it:
/// - Spawn a listener task for each added spec.
/// - Switch protocol in place for each spec whose port is already bound.
/// - Push updated PROXY config for specs whose port is bound but PROXY config changed.
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
    let active_state: HashMap<SocketAddr, ActiveListenerState> = active
        .iter()
        .map(|(addr, h)| {
            (
                *addr,
                ActiveListenerState {
                    protocol: *h.proto_tx.borrow(),
                    proxy_protocol: h.proxy_config_tx.borrow().clone(),
                },
            )
        })
        .collect();
    let plan = plan_listener_changes(&active_state, &desired);

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
            // Also push the new PROXY config (protocol change may coincide).
            let _ = handle.proxy_config_tx.send(spec.proxy_protocol.clone());
        }
    }

    // Push updated PROXY config for ports whose protocol is unchanged.
    for spec in &plan.reproxy {
        if let Some(handle) = active.get(&spec.addr) {
            tracing::debug!(
                addr = %spec.addr,
                enabled = spec.proxy_protocol.as_ref().is_some_and(|pp| pp.enabled),
                "Updating PROXY protocol config in place"
            );
            let _ = handle.proxy_config_tx.send(spec.proxy_protocol.clone());
        }
    }

    // Spawn tasks for newly-desired listeners. The stock tokio bind sets
    // SO_REUSEADDR (so a re-add whose predecessor left TIME_WAIT remnants still
    // succeeds) but NOT SO_REUSEPORT — a second process binding the same port
    // must still fail loudly with EADDRINUSE rather than silently split traffic
    // with a stale proxy. The dark-port race that an earlier SO_REUSEPORT
    // experiment targeted is instead closed at the source: `run_listener`
    // releases its listening socket the instant it stops accepting (before the
    // drain window), so by the time a later reconcile re-adds the port the
    // socket is already free.
    for spec in plan.add {
        let tcp = match tokio::net::TcpListener::bind(spec.addr).await {
            Ok(l) => l,
            Err(e) => {
                // A dark port is a routing outage for that Gateway until a
                // later reconcile retries the bind (the addr stays in
                // `desired` and out of `active`, so every pass re-attempts).
                // Loud on purpose (error + metric): with drain-start socket
                // release this should be a rare, transient collision.
                tracing::error!(
                    addr = %spec.addr,
                    error = %e,
                    "Cannot bind new listener; port dark until a later reconcile succeeds"
                );
                metrics::lifecycle()
                    .with_label_values(&["bind_failed"])
                    .inc();
                continue;
            }
        };
        let drain_token = CancellationToken::new();
        let (conn_shutdown_tx, conn_shutdown_rx) = watch::channel(false);
        let (proto_tx, proto_rx) = watch::channel(spec.protocol);
        let (proxy_config_tx, proxy_config_rx) = watch::channel(spec.proxy_protocol.clone());

        let listener_cfg = ListenerConfig {
            proxy: Arc::clone(&cfg.proxy),
            tls_selector: cfg.tls_selector.clone(),
            drain_timeout: cfg.drain_timeout,
            passthrough_table: cfg.passthrough_table.clone(),
            terminate_table: cfg.terminate_table.clone(),
            tcp_table: cfg.tcp_table.clone(),
            l4_dial_timeout: cfg.l4_dial_timeout,
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
            ListenerSignals {
                drain_token: drain_token.clone(),
                proto_rx,
                proxy_config_rx,
                conn_shutdown_rx,
            },
            listener_cfg,
            global_shutdown.clone(),
        ));

        active.insert(
            addr,
            ListenerHandle {
                drain_token,
                conn_shutdown_tx,
                proto_tx,
                proxy_config_tx,
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
    signals: ListenerSignals,
    cfg: ListenerConfig<P>,
    mut global_shutdown: ShutdownWatch,
) where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    let ListenerSignals {
        drain_token,
        proto_rx,
        proxy_config_rx,
        conn_shutdown_rx,
    } = signals;
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
                                // Snapshot the live protocol and PROXY config.  A
                                // reconcile may have switched either (e.g. Https →
                                // TlsHybrid, or new ClientTrafficPolicy) since the
                                // listener was bound, without rebinding the socket.
                                let protocol = *proto_rx.borrow();
                                let proxy_protocol = proxy_config_rx.borrow().clone();
                                let handler = ConnHandler {
                                    proxy: Arc::clone(&cfg.proxy),
                                    proxy_protocol,
                                    tls_selector: cfg.tls_selector.clone(),
                                    local_addr: addr,
                                    protocol,
                                    passthrough_table: cfg.passthrough_table.clone(),
                                    terminate_table: cfg.terminate_table.clone(),
                                    tcp_table: cfg.tcp_table.clone(),
                                    l4_dial_timeout: cfg.l4_dial_timeout,
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

    // Accept stopped. Release the listening socket IMMEDIATELY — in-flight
    // connections are independent fds and drain below regardless. Holding the
    // listener through the (up to 30 s) drain window would keep the port bound
    // with nobody accepting: a re-added listener on the same port either hits
    // EADDRINUSE (without SO_REUSEPORT) or, worse, the kernel keeps completing
    // handshakes into this dead socket's backlog and those connections hang
    // until the drop. Releasing here shrinks the reuse overlap to the
    // microseconds between the drain signal and this poll.
    drop(tcp);

    // Begin drain window for in-flight connections.
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

/// Dispatch one connection on a TLS L4 port (passthrough or terminate, no HTTP layer).
///
/// When the listener has PROXY protocol enabled and the peer is trusted, the
/// PROXY header is stripped first via `peek_and_drain_proxy_header` so the
/// remaining stream starts at the raw TLS ClientHello. The ClientHello bytes are
/// still in the kernel queue after the drain (MSG_PEEK leaves them intact;
/// `read_exact` drains only the header).
///
/// After any PROXY stripping, peeks the ClientHello SNI via MSG_PEEK.
/// Checks the passthrough table first, then the terminate table. When
/// `allow_https_fallthrough` is `true` (hybrid port) and neither table
/// matches, falls through to HTTPS only if the port has a certificate for
/// this SNI — otherwise drops the connection (GEP-2643 hostname-intersection).
///
/// Returns `None` when the connection is fully handled (consumed or dropped),
/// or `Some(tcp)` when the caller should fall through to the HTTPS path
/// (only possible when `allow_https_fallthrough` is `true`).
async fn dispatch_tls_l4<P>(
    mut tcp: TcpStream,
    peer_addr: SocketAddr,
    handler: &ConnHandler<P>,
    allow_https_fallthrough: bool,
) -> Option<TcpStream>
where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    // Strip PROXY header before SNI peeking (#471).  Must come first so the
    // SNI-peek sees the raw TLS ClientHello bytes, not the PROXY preamble.
    if let Some(pp) = handler.proxy_protocol.as_ref().filter(|pp| pp.enabled) {
        if !pp.is_trusted(&peer_addr.ip()) {
            tracing::debug!(peer = %peer_addr, "TLS L4: rejecting connection from untrusted source (PROXY enabled)");
            return None;
        }
        match peek_and_drain_proxy_header(&mut tcp, peer_addr).await {
            Ok(real_addr) => {
                // The L4 splice path has no HTTP layer and no CONN_INFO task-local,
                // so `real_addr` appears only in the debug log below (sufficient for
                // diagnosing PROXY-header issues on passthrough listeners).
                tracing::debug!(
                    peer = %peer_addr,
                    real = %real_addr,
                    "TLS L4: stripped PROXY header"
                );
            }
            Err(e) => {
                tracing::debug!(
                    peer = %peer_addr,
                    error = %e,
                    "TLS L4: PROXY header read failed, dropping connection"
                );
                return None;
            }
        }
    }

    let port = handler.local_addr.port();
    let sni = match peek_sni(&tcp).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(
                peer = %peer_addr,
                error = %e,
                "TLS L4 dispatch: failed to read ClientHello SNI — dropping connection"
            );
            return None;
        }
    };

    // Check passthrough table.
    {
        let snapshot = handler.passthrough_table.load();
        let has_match = snapshot
            .port(port)
            .is_some_and(|r| r.match_sni(sni.as_deref()).is_some());
        if has_match {
            handle_passthrough(
                tcp,
                peer_addr,
                &handler.passthrough_table,
                port,
                handler.l4_dial_timeout,
            )
            .await;
            return None;
        }
    }

    // Check terminate table (#481).
    {
        let snapshot = handler.terminate_table.load();
        let has_match = snapshot
            .port(port)
            .is_some_and(|r| r.match_sni(sni.as_deref()).is_some());
        if has_match {
            handle_terminate(
                tcp,
                peer_addr,
                &handler.terminate_table,
                &handler.tls_selector,
                port,
                handler.l4_dial_timeout,
            )
            .await;
            return None;
        }
    }

    // No L4 route matched. On a hybrid port, fall through to HTTPS only when a
    // certificate is configured for this SNI; otherwise reject by dropping.
    if allow_https_fallthrough {
        if handler
            .tls_selector
            .for_port(port)
            .has_cert_for(sni.as_deref())
        {
            // Peeked bytes are still in the kernel queue — no replay needed.
            return Some(tcp);
        }
        tracing::debug!(
            port,
            sni = ?sni,
            "Hybrid port: no L4 route and no terminate cert for SNI — rejecting connection"
        );
    }
    // TlsL4 (non-hybrid) with no match: drop by returning None without a handler.
    None
}

/// Dispatch one connection on a `protocol: TCP` port (TCPRoute, GEP-1901).
///
/// When the listener has PROXY protocol enabled and the peer is trusted, the
/// PROXY header is stripped first via `peek_and_drain_proxy_header`. After any
/// PROXY stripping, the connection is spliced straight to the bound backend —
/// no SNI peek, no TLS, no hybrid fallthrough (a `TCP` listener never shares a
/// port with another protocol; see [`ListenerProtocol::Tcp`]).
async fn dispatch_tcp<P>(mut tcp: TcpStream, peer_addr: SocketAddr, handler: &ConnHandler<P>)
where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    if let Some(pp) = handler.proxy_protocol.as_ref().filter(|pp| pp.enabled) {
        if !pp.is_trusted(&peer_addr.ip()) {
            tracing::debug!(peer = %peer_addr, "TCP proxy: rejecting connection from untrusted source (PROXY enabled)");
            return;
        }
        match peek_and_drain_proxy_header(&mut tcp, peer_addr).await {
            Ok(real_addr) => {
                tracing::debug!(
                    peer = %peer_addr,
                    real = %real_addr,
                    "TCP proxy: stripped PROXY header"
                );
            }
            Err(e) => {
                tracing::debug!(
                    peer = %peer_addr,
                    error = %e,
                    "TCP proxy: PROXY header read failed, dropping connection"
                );
                return;
            }
        }
    }

    let port = handler.local_addr.port();
    handle_tcp_proxy(
        tcp,
        peer_addr,
        &handler.tcp_table,
        port,
        handler.l4_dial_timeout,
    )
    .await;
}

/// Handle one accepted TCP connection.
///
/// Dispatches based on protocol and PROXY-protocol configuration:
/// - `TlsL4`: strip PROXY header (if enabled), peek SNI, splice passthrough or terminate.
/// - `TlsHybrid`: same as `TlsL4` but falls through to HTTPS if no L4 route matches.
/// - `Tcp`: strip PROXY header (if enabled), splice straight to the bound backend —
///   no SNI peek, no TLS, no HTTP layer.
/// - PROXY-protocol path (when `proxy_protocol` is `Some` and `enabled`): strip PROXY header,
///   inject real client address, then run the Pingora HTTP loop.
/// - Standard Pingora path: ALPN, HTTP/1.1 and HTTP/2 without PROXY handling.
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

    // Raw TCP proxy ports never run through the HTTP proxy layer or any TLS/SNI
    // logic — dispatch and return immediately.
    if handler.protocol == ListenerProtocol::Tcp {
        dispatch_tcp(tcp, peer_addr, &handler).await;
        return;
    }

    // TLS L4 and hybrid ports are independent of the PROXY-protocol setting — they
    // never run through the HTTP proxy layer.
    let tcp = if matches!(
        handler.protocol,
        ListenerProtocol::TlsL4 | ListenerProtocol::TlsHybrid
    ) {
        let allow_https_fallthrough = handler.protocol == ListenerProtocol::TlsHybrid;
        match dispatch_tls_l4(tcp, peer_addr, &handler, allow_https_fallthrough).await {
            None => return,
            // Hybrid fallthrough: no L4 match, SNI has a terminate cert — proceed as HTTPS.
            Some(fallthrough_tcp) => fallthrough_tcp,
        }
    } else {
        tcp
    };

    // For TlsHybrid that fell through (no L4 route match), treat as Https.
    let effective_protocol = match handler.protocol {
        ListenerProtocol::TlsHybrid => ListenerProtocol::Https,
        p => p,
    };

    // Scope the cert selector to the bind port this connection arrived on (#472)
    // so TLS-terminate only consults that port's certs.
    let scoped_selector = handler.tls_selector.for_port(handler.local_addr.port());
    if let Some(pp) = handler.proxy_protocol.filter(|pp| pp.enabled) {
        handle_proxy_protocol(
            tcp,
            peer_addr,
            handler.local_addr,
            effective_protocol,
            ProxyProtocolConn {
                proxy: handler.proxy,
                proxy_protocol: pp,
                tls_selector: scoped_selector,
            },
            conn_shutdown,
        )
        .await;
    } else {
        handle_standard(
            tcp,
            effective_protocol,
            handler.proxy,
            scoped_selector,
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
pub(crate) fn observe_tls_handshake(result: &'static str) {
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
        // L4 and hybrid connections are dispatched before reaching this function.
        ListenerProtocol::TlsL4 | ListenerProtocol::TlsHybrid | ListenerProtocol::Tcp => {}
    }
}

/// Aggregated inputs for the PROXY-protocol connection handler, grouping the
/// proxy, per-listener PROXY config, and TLS selector so the function stays
/// under the argument-count limit.
struct ProxyProtocolConn<P>
where
    P: ProxyHttp + Send + Sync + 'static,
    <P as ProxyHttp>::CTX: Send + Sync,
{
    proxy: Arc<HttpProxy<P>>,
    proxy_protocol: ProxyProtocolListenerConfig,
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
    if !conn.proxy_protocol.is_trusted(&peer_addr.ip()) {
        tracing::debug!(peer = %peer_addr, "rejecting connection from untrusted source");
        return;
    }

    // Honour shutdown during the PROXY header read so a stuck client cannot
    // block graceful drain.
    let real_addr = tokio::select! {
        _ = conn_shutdown.changed() => return,
        result = peek_and_drain_proxy_header(&mut tcp, peer_addr) => match result {
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
        ListenerProtocol::TlsL4 | ListenerProtocol::TlsHybrid | ListenerProtocol::Tcp => return,
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
        ListenerProtocol::TlsL4 | ListenerProtocol::TlsHybrid | ListenerProtocol::Tcp => return,
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
pub(crate) struct TlsContext {
    pub(crate) acceptor: Arc<SslAcceptor>,
    pub(crate) callbacks: Arc<pingora_core::listeners::TlsAcceptCallbacks>,
}

/// Process-wide cached `SslAcceptor`s, one per ALPN flavour (h2-advertising
/// and h1-only). The acceptor holds NO certificate state — certs, keys, and
/// mTLS CA stores are installed per handshake by [`SniCertSelector`]'s
/// callback against the live cert store — so one immutable acceptor per
/// flavour serves every connection for the process lifetime. Building one is
/// pure cipher/protocol configuration (BoringSSL `mozilla_intermediate_v5`),
/// which used to run PER CONNECTION and was a measurable CPU sink on the
/// acceptor runtime under HTTPS load. `OnceLock` gives lock-free reads after
/// the first build and collapses the cold-start build race to a single winner.
static ACCEPTOR_H2: std::sync::OnceLock<Arc<SslAcceptor>> = std::sync::OnceLock::new();
static ACCEPTOR_H1: std::sync::OnceLock<Arc<SslAcceptor>> = std::sync::OnceLock::new();

/// Get (building on first use) the process-wide acceptor for the flavour.
/// A build failure is returned uncached — the next connection retries.
///
/// SECURITY: TLS session resumption (tickets + server session cache) is
/// disabled on these acceptors. One `SSL_CTX` is now shared across every
/// listener of a flavour, including a non-mTLS HTTPS Gateway and an
/// mTLS-required one; with resumption enabled a client could full-handshake
/// against the non-mTLS SNI, obtain a ticket, and resume against the mTLS SNI
/// on an abbreviated handshake that skips BoringSSL's certificate callback —
/// where [`SniCertSelector`] installs `SSL_VERIFY_PEER | FAIL_IF_NO_PEER_CERT`
/// — yielding an mTLS bypass. The prior per-connection acceptor made
/// resumption structurally impossible (a fresh `SSL_CTX`/ticket key per
/// connection); disabling it here preserves that property while keeping the
/// build-once CPU win. It also removes a process-lifetime shared ticket key
/// (a forward-secrecy erosion). Coxswain does not rely on resumption.
fn cached_acceptor(advertise_h2: bool) -> Result<Arc<SslAcceptor>, AcceptorBuildError> {
    let slot = if advertise_h2 {
        &ACCEPTOR_H2
    } else {
        &ACCEPTOR_H1
    };
    if let Some(acceptor) = slot.get() {
        return Ok(Arc::clone(acceptor));
    }
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| AcceptorBuildError::TlsAcceptorBuild(e.to_string()))?;
    // Disable resumption: no server session cache, no session tickets. See the
    // SECURITY note above — cross-SNI resumption on a shared SSL_CTX would let a
    // resumed handshake skip per-SNI mTLS enforcement.
    builder.set_session_cache_mode(SslSessionCacheMode::OFF);
    builder.set_options(SslOptions::NO_TICKET);
    if advertise_h2 {
        builder.set_alpn_select_callback(
            |_ssl: &mut SslRef, client: &[u8]| -> Result<&[u8], AlpnError> {
                // Wire-format: length-prefixed list — "\x02h2\x08http/1.1"
                // prefers h2 and falls back to http/1.1.
                select_next_proto(b"\x02h2\x08http/1.1", client).ok_or(AlpnError::NOACK)
            },
        );
    }
    let acceptor = Arc::new(builder.build());
    // A racing builder is harmless: whichever `set` wins, both acceptors are
    // valid and equivalent; `get_or_init`-style dedup via set().unwrap_or.
    let _ = slot.set(Arc::clone(&acceptor));
    Ok(slot.get().map_or(acceptor, Arc::clone))
}

/// Build a TLS context for an HTTPS listener: the process-wide cached
/// acceptor for the flavour plus this connection's SNI-callback handle.
///
/// When `advertise_h2` is `true`, the acceptor registers an ALPN-select
/// callback that prefers `h2` over `http/1.1`, enabling transparent HTTP/2
/// negotiation with TLS clients.  Pass `false` for the PROXY-protocol path,
/// which runs an h1-only keepalive loop and must not advertise h2.
/// Per-connection cost is two `Arc` clones; the BoringSSL acceptor itself is
/// built once per process per flavour (see [`cached_acceptor`]).
pub(crate) fn build_tls_context(
    selector: &SniCertSelector,
    advertise_h2: bool,
) -> Result<TlsContext, AcceptorBuildError> {
    let acceptor = cached_acceptor(advertise_h2)?;
    let callbacks: pingora_core::listeners::TlsAcceptCallbacks = Box::new(selector.clone());
    Ok(TlsContext {
        acceptor,
        callbacks: Arc::new(callbacks),
    })
}

// ── PROXY protocol parsing ────────────────────────────────────────────────────

/// Peek-then-drain a PROXY protocol v1 or v2 header from `tcp`.
///
/// Uses `MSG_PEEK` to detect and measure the header, then `read_exact` to
/// consume exactly those bytes so the payload (TLS ClientHello or HTTP data)
/// remains in the kernel queue for the caller's subsequent `read` / `peek_sni`.
///
/// Returns the real source [`SocketAddr`] carried by the header, or `fallback`
/// for `LOCAL` commands and `UNKNOWN` / unspecified address families.
///
/// # Errors
///
/// - [`ProxyHeaderError::Timeout`] — no complete header within 5 s.
/// - [`ProxyHeaderError::Io`] — connection closed or I/O error.
/// - [`ProxyHeaderError::TooLarge`] — peek buffer grew to [`MAX_PROXY_PEEK`]
///   without completing a parse.
/// - [`ProxyHeaderError::BadPreamble`] — the bytes present do not form a valid
///   PROXY v1 or v2 header (strict mode: drop the connection).
async fn peek_and_drain_proxy_header(
    tcp: &mut TcpStream,
    fallback: SocketAddr,
) -> Result<SocketAddr, ProxyHeaderError> {
    const TIMEOUT: Duration = Duration::from_secs(5);

    tokio::time::timeout(TIMEOUT, async move {
        let mut buf = vec![0u8; 32]; // start small, double when buffer fills

        // Grow-and-peek loop: expand `buf` until ppp can parse a complete header.
        //
        // When `ppp` says incomplete we must wait for new data before re-peeking.
        // Without `tcp.readable().await`, re-peeking immediately returns the same
        // partial bytes already in the kernel buffer — the buffer would grow to
        // `MAX_PROXY_PEEK` in microseconds and spuriously report `TooLarge` on a
        // legitimately fragmented PROXY header.
        let (real_addr, header_len) = loop {
            let n = tcp.peek(&mut buf).await.map_err(ProxyHeaderError::Io)?;
            if n == 0 {
                return Err(ProxyHeaderError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before PROXY header",
                )));
            }

            let result = ppp::HeaderResult::parse(&buf[..n]);

            if result.is_incomplete() {
                // Only grow when the buffer was full; if n < buf.len() the current
                // capacity is already sufficient, just waiting for more bytes.
                if n == buf.len() {
                    if buf.len() >= MAX_PROXY_PEEK {
                        return Err(ProxyHeaderError::TooLarge(MAX_PROXY_PEEK));
                    }
                    buf.resize((buf.len() * 2).min(MAX_PROXY_PEEK), 0);
                }
                // Wait for the kernel to deliver more bytes before re-peeking.
                // After `tcp.peek` consumes the readiness event, `readable()` blocks
                // until a new EPOLLIN fires (i.e., fresh bytes have arrived).
                tcp.readable().await.map_err(ProxyHeaderError::Io)?;
                continue;
            }

            // Parse completed.  Extract the source address and header byte length
            // before the borrow on `buf` ends.
            let pair = match result {
                ppp::HeaderResult::V1(Ok(ref hdr)) => {
                    use ppp::v1::Addresses;
                    let addr = match &hdr.addresses {
                        Addresses::Tcp4(a) => {
                            SocketAddr::new(std::net::IpAddr::V4(a.source_address), a.source_port)
                        }
                        Addresses::Tcp6(a) => {
                            SocketAddr::new(std::net::IpAddr::V6(a.source_address), a.source_port)
                        }
                        Addresses::Unknown => fallback,
                    };
                    (addr, hdr.header.len())
                }
                ppp::HeaderResult::V2(Ok(ref hdr)) => {
                    use ppp::v2::{Addresses, Command};
                    let addr = if matches!(hdr.command, Command::Local) {
                        fallback
                    } else {
                        match &hdr.addresses {
                            Addresses::IPv4(a) => SocketAddr::new(
                                std::net::IpAddr::V4(a.source_address),
                                a.source_port,
                            ),
                            Addresses::IPv6(a) => SocketAddr::new(
                                std::net::IpAddr::V6(a.source_address),
                                a.source_port,
                            ),
                            // Unix sockets and unspecified → no client address info.
                            _ => fallback,
                        }
                    };
                    (addr, hdr.header.len())
                }
                // Parse failed: not a PROXY v1 or v2 header.
                ppp::HeaderResult::V1(Err(_)) | ppp::HeaderResult::V2(Err(_)) => {
                    return Err(ProxyHeaderError::BadPreamble);
                }
            };
            break pair;
        };

        // Drain exactly the header bytes from the kernel queue.
        // The payload (TLS ClientHello or HTTP) stays for the next read/peek.
        let mut drain = vec![0u8; header_len];
        tcp.read_exact(&mut drain)
            .await
            .map_err(ProxyHeaderError::Io)?;

        Ok(real_addr)
    })
    .await
    .map_err(|_| ProxyHeaderError::Timeout)?
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn active_state(
        protocol: ListenerProtocol,
        proxy_protocol: Option<ProxyProtocolListenerConfig>,
    ) -> ActiveListenerState {
        ActiveListenerState {
            protocol,
            proxy_protocol,
        }
    }

    fn dummy_handle() -> ListenerHandle {
        ListenerHandle {
            drain_token: CancellationToken::new(),
            conn_shutdown_tx: watch::Sender::new(false),
            proto_tx: watch::Sender::new(ListenerProtocol::Http),
            proxy_config_tx: watch::Sender::new(None),
        }
    }

    fn active_map(ports: &[u16]) -> HashMap<SocketAddr, ListenerHandle> {
        ports
            .iter()
            .map(|p| {
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), *p);
                (addr, dummy_handle())
            })
            .collect()
    }

    // ── publish_bound_ports (#531) ───────────────────────────────────────────────

    #[test]
    fn publish_bound_ports_without_sender_is_noop() {
        publish_bound_ports(None, &active_map(&[8080]));
    }

    #[test]
    fn publish_bound_ports_reports_active_listener_ports() {
        let tx = watch::Sender::new(BTreeSet::new());
        let mut rx = tx.subscribe();
        publish_bound_ports(Some(&tx), &active_map(&[8443, 8080]));
        assert!(rx.has_changed().unwrap_or(false));
        let got = rx.borrow_and_update().clone();
        assert_eq!(got, [8080u16, 8443].into_iter().collect::<BTreeSet<_>>());
    }

    #[test]
    fn publish_bound_ports_suppresses_identical_republish() {
        let tx = watch::Sender::new(BTreeSet::new());
        let mut rx = tx.subscribe();
        publish_bound_ports(Some(&tx), &active_map(&[8080]));
        rx.borrow_and_update();
        // Same set again — e.g. an in-place PROXY-config flip that rebinds nothing.
        publish_bound_ports(Some(&tx), &active_map(&[8080]));
        assert!(
            !rx.has_changed().unwrap_or(true),
            "identical set must not wake the discovery client"
        );
    }

    #[test]
    fn publish_bound_ports_reports_empty_when_all_drained() {
        let tx = watch::Sender::new(BTreeSet::new());
        let mut rx = tx.subscribe();
        publish_bound_ports(Some(&tx), &active_map(&[8080]));
        rx.borrow_and_update();
        publish_bound_ports(Some(&tx), &active_map(&[]));
        assert!(rx.has_changed().unwrap_or(false));
        assert!(
            rx.borrow_and_update().is_empty(),
            "drain-to-zero is an affirmative empty report, not a suppressed publish"
        );
    }

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

        let active: HashMap<SocketAddr, ActiveListenerState> =
            [(addr_a, active_state(ListenerProtocol::Http, None))]
                .into_iter()
                .collect();
        let desired: HashSet<ListenerSpec> = [ListenerSpec::http(addr_b)].into_iter().collect();

        let plan = plan_listener_changes(&active, &desired);

        assert_eq!(plan.remove, vec![addr_a]);
        assert!(plan.reprotocol.is_empty());
        assert!(plan.reproxy.is_empty());
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
        let active: HashMap<SocketAddr, ActiveListenerState> =
            [(addr, active_state(ListenerProtocol::Https, None))]
                .into_iter()
                .collect();
        let desired: HashSet<ListenerSpec> = [ListenerSpec::tls_hybrid(addr)].into_iter().collect();

        let plan = plan_listener_changes(&active, &desired);

        assert!(plan.remove.is_empty(), "socket must stay bound");
        assert!(plan.add.is_empty(), "no rebind");
        assert!(plan.reproxy.is_empty());
        assert_eq!(plan.reprotocol, vec![ListenerSpec::tls_hybrid(addr)]);
    }

    #[test]
    fn plan_listener_changes_noop_when_protocol_unchanged() {
        let addr: SocketAddr = "0.0.0.0:443".parse().unwrap();
        let active: HashMap<SocketAddr, ActiveListenerState> =
            [(addr, active_state(ListenerProtocol::TlsHybrid, None))]
                .into_iter()
                .collect();
        let desired: HashSet<ListenerSpec> = [ListenerSpec::tls_hybrid(addr)].into_iter().collect();

        let plan = plan_listener_changes(&active, &desired);

        assert_eq!(plan, ListenerPlan::default(), "stable set: no churn");
    }

    #[test]
    fn plan_listener_changes_detects_reproxy_without_rebind() {
        // When the protocol is unchanged but the PROXY config changes (e.g. a new
        // ClientTrafficPolicy enables PROXY on a port), the plan must produce a
        // `reproxy` entry — not `reprotocol` or `add` — so the socket stays bound
        // and only the in-process config is updated.
        let addr: SocketAddr = "0.0.0.0:443".parse().unwrap();
        let active: HashMap<SocketAddr, ActiveListenerState> =
            [(addr, active_state(ListenerProtocol::Https, None))]
                .into_iter()
                .collect();

        let net: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let pp = ProxyProtocolListenerConfig::new(true, vec![net]);
        let desired: HashSet<ListenerSpec> = [ListenerSpec {
            addr,
            protocol: ListenerProtocol::Https,
            proxy_protocol: Some(pp),
        }]
        .into_iter()
        .collect();

        let plan = plan_listener_changes(&active, &desired);

        assert!(plan.remove.is_empty(), "socket must stay bound");
        assert!(plan.add.is_empty(), "no rebind");
        assert!(plan.reprotocol.is_empty(), "protocol unchanged");
        assert_eq!(plan.reproxy.len(), 1, "proxy config changed in place");
        assert_eq!(plan.reproxy[0].addr, addr);
    }

    // ── ProxyProtocolListenerConfig tests ────────────────────────────────────

    #[test]
    fn proxy_protocol_config_is_trusted_checks_cidrs() {
        let net: ipnet::IpNet = "192.168.1.0/24".parse().unwrap();
        let pp = ProxyProtocolListenerConfig::new(true, vec![net]);
        assert!(pp.is_trusted(&"192.168.1.100".parse::<IpAddr>().unwrap()));
        assert!(!pp.is_trusted(&"10.0.0.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn proxy_protocol_config_loopback() {
        let net: ipnet::IpNet = "127.0.0.1/32".parse().unwrap();
        let pp = ProxyProtocolListenerConfig::new(true, vec![net]);
        assert!(pp.is_trusted(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!pp.is_trusted(&"192.168.0.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn proxy_protocol_config_empty_rejects_all() {
        let pp = ProxyProtocolListenerConfig::new(true, vec![]);
        assert!(!pp.is_trusted(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }
}
