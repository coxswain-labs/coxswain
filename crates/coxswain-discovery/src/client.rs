//! Discovery gRPC client: runs inside the proxy role.
//!
//! Owns the reconnect supervisor (jittered exponential backoff 250ms → 30s),
//! sends `Subscribe` on connect, drives `Ack`/`Nack` after each snapshot, and
//! feeds the decoded wire DTO into the proxy's [`Shared`] routing cells. The
//! cells are **never zeroed** during reconnect; the last-good snapshot is served
//! throughout.
//!
//! [`Shared`]: coxswain_core::Shared

use std::sync::Arc;
use std::time::Duration;

use coxswain_core::health::SubsystemHandle;
use coxswain_core::listener_status::GatewayListenerStatusHandle;
use coxswain_core::routing::{
    SharedGatewayRoutingTable, SharedIngressRoutingTable, SharedTcpRouteTable,
    SharedTlsPassthroughTable, SharedUdpRouteTable,
};
use coxswain_core::tls::{SharedClientCertStore, SharedListenerHostnames, SharedPortTlsStore};
use tokio::sync::{Notify, broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint};
use tracing::{debug, warn};

use tokio::sync::watch;

use crate::apply::{RoutingApplier, SnapshotApplier};
use crate::auth::{DiscoveryClientTls, SpiffeMatcher};
use crate::error::DiscoveryError;
use crate::proto::v1::{
    self as p, client_message::Kind as CKind, discovery_client::DiscoveryClient as TonicClient,
    server_message::Kind as SKind,
};
use crate::subscription::Scope;
use crate::svid::SharedSvid;
use crate::upstream::{SharedUpstream, UpstreamTarget, expected_server_matcher};
use crate::version::WIRE_VERSION;

/// Configuration for the discovery gRPC client supervisor.
///
/// Construct with [`DiscoveryClientConfig::new`] for sensible defaults, or fill
/// all fields explicitly via a struct literal.
pub struct DiscoveryClientConfig {
    /// Controller discovery Service endpoints (`"http://host:port"` strings).
    ///
    /// More than one endpoint enables high-availability: [`Channel::balance_list`]
    /// distributes RPCs across all controller replicas. Must not be empty.
    pub endpoints: Vec<String>,
    /// Stable identity of this proxy node (pod UID or hostname).
    pub node_id: String,
    /// Subscription scope.
    ///
    /// Controls which endpoints and gateways are pushed by the controller.
    pub scope: Scope,
    /// HTTP/2 keep-alive ping interval (default: 30 s).
    pub http2_keep_alive_interval: Duration,
    /// HTTP/2 keep-alive timeout: how long to wait for the ping response before
    /// treating the connection as dead (default: 5 s).
    pub keep_alive_timeout: Duration,
    /// Maximum time a single TCP+TLS connect attempt may take before it is
    /// treated as failed and the supervisor backs off (default: 5 s).
    ///
    /// The discovery endpoint is a Service ClusterIP. During a controller
    /// rollout that ClusterIP can momentarily route to a terminating pod (the
    /// SYN is black-holed) — without an explicit bound the connect hangs on the
    /// OS default (tens of seconds), so the reconnect supervisor cannot cycle
    /// and the proxy stays `Degraded` long after the controller is back. A short
    /// bound makes a wasted attempt fail fast and the next retry hit a live
    /// endpoint.
    pub connect_timeout: Duration,
    /// Initial backoff duration; doubles on each failed attempt (default: 250 ms).
    pub backoff_base: Duration,
    /// Maximum backoff ceiling; full-jitter stays within `[0, cap]` (default: 30 s).
    pub backoff_cap: Duration,
    /// Static mTLS configuration for the discovery channel.
    ///
    /// When `Some`, the channel is established with mutual TLS and both sides'
    /// certificates are verified against the configured CA bundle and SPIFFE
    /// URI SAN pattern. When `None` (default), the channel runs plaintext h2c;
    /// this should only be used in test environments.
    ///
    /// Mutually exclusive with `svid_cell`: prefer `svid_cell` in production
    /// so the supervisor picks up SVID rotations automatically.
    pub tls: Option<DiscoveryClientTls>,
    /// Dynamic SVID cell populated by the proxy-side bootstrap loop.
    ///
    /// When `Some`, `build_channel` reads the current SVID from this cell on
    /// every connect attempt so SVID rotation flows automatically on reconnect.
    /// Takes precedence over `tls` when both are set.
    pub svid_cell: Option<SharedSvid>,
    /// Expected SPIFFE identity of the controller, used when `svid_cell` is set
    /// to construct [`DiscoveryClientTls`] from the raw PEM material.
    pub expected_server: Option<SpiffeMatcher>,
    /// Receives a new value each time the bootstrap loop issues a fresh SVID.
    ///
    /// When `Some`, the supervisor forces a clean reconnect (and re-reads the
    /// SVID cell) on the next generation tick.
    pub svid_rotated: Option<watch::Receiver<u64>>,
    /// Receives the proxy acceptor's actually-bound listener-port set (#531).
    ///
    /// When `Some`, the supervisor reports the current set to the controller as
    /// a `NodeStatus` message immediately after `Subscribe` on every stream
    /// open, and again on every change — feeding the controller's Gateway
    /// `Programmed` readiness gate. `None` (default) = no reporting.
    pub bound_ports_rx: Option<watch::Receiver<std::collections::BTreeSet<u16>>>,
    /// Receives a relay's downstream leaf roster (#585).
    ///
    /// When `Some` (relay roles only), the supervisor pushes a `RosterReport` to
    /// the controller immediately after `Subscribe` on every stream open, and
    /// again whenever the roster changes — folding leaf state into the
    /// controller's registry for the #531 gate and the topology panel. `None`
    /// (default) = no reporting (leaf proxies and the controller never report).
    pub roster_rx: Option<watch::Receiver<coxswain_core::node_registry::NodeRegistry>>,
    /// Runtime-swappable routing-stream upstream (#601).
    ///
    /// When `Some`, `build_channel` reads the current target (endpoints +
    /// expected-server matcher) from this cell on every connect attempt, taking
    /// precedence over the static `endpoints`/`expected_server`. Populated by the
    /// bootstrap loop (the upstream pointer rides the bootstrap response) and by a
    /// live `PreferredUpstream` directive on the stream. Empty until the first
    /// bootstrap → `build_channel` returns [`DiscoveryError::NoUpstream`] and the
    /// supervisor backs off until `upstream_changed` fires.
    pub upstream_cell: Option<SharedUpstream>,
    /// Fires when the bootstrap loop writes a fresh upstream into `upstream_cell`
    /// (#601). Mirrors `svid_rotated`: the supervisor forces a clean reconnect to
    /// the new target on the next tick. A live `PreferredUpstream` directive is
    /// handled inline by the stream loop (no watch tick needed) — this watch is
    /// only the bootstrap-delivered path.
    pub upstream_changed: Option<watch::Receiver<u64>>,
    /// Pokes the bootstrap loop to re-bootstrap immediately (#601 fallback).
    ///
    /// When `Some`, the supervisor notifies it after repeated failed reconnects
    /// to the current upstream (e.g. a relay torn down in a race), so a fresh
    /// bootstrap re-resolves the best upstream (now the controller). `None` =
    /// no re-bootstrap poke (static/no-bootstrap path).
    pub re_bootstrap: Option<Arc<Notify>>,
    /// SPIFFE trust domain, used to rebuild the expected-server matcher when a
    /// live `PreferredUpstream` directive names a new `(endpoint, sa)` (#601).
    pub trust_domain: String,
    /// Namespace to attribute an upstream whose endpoint is not cluster service
    /// DNS (test loopback) when rebuilding a matcher from a directive (#601).
    pub fallback_namespace: String,
    /// How this client handles a `PreferredUpstream` directive (#601): a leaf
    /// repoints its own upstream; a relay forwards it downstream. Defaults to
    /// [`UpstreamDirectiveHandler::RepointSelf`].
    pub upstream_directive_handler: UpstreamDirectiveHandler,
}

/// How a client reacts to a server-pushed `PreferredUpstream` directive (#601).
pub enum UpstreamDirectiveHandler {
    /// Leaf proxy: apply the directive to this client's own upstream — write the
    /// new target into `upstream_cell` and force a reconnect to it.
    RepointSelf,
    /// Relay: fan the controller-originated directive to the relay's downstream
    /// `DiscoveryService` instead of repointing the relay's own upstream (a relay
    /// always streams from the controller). Each downstream leaf stream subscribes
    /// to this broadcast and forwards the directive to the leaf whose Gateway scope
    /// matches the directive's target.
    Forward(broadcast::Sender<p::PreferredUpstream>),
}

impl DiscoveryClientConfig {
    /// Construct with required fields; optional fields get their defaults.
    #[must_use]
    pub fn new(endpoints: Vec<String>, node_id: impl Into<String>) -> Self {
        Self {
            endpoints,
            node_id: node_id.into(),
            scope: Scope::SharedPool,
            http2_keep_alive_interval: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            backoff_base: Duration::from_millis(250),
            backoff_cap: Duration::from_secs(30),
            tls: None,
            svid_cell: None,
            expected_server: None,
            svid_rotated: None,
            bound_ports_rx: None,
            roster_rx: None,
            upstream_cell: None,
            upstream_changed: None,
            re_bootstrap: None,
            trust_domain: "cluster.local".to_owned(),
            fallback_namespace: String::new(),
            upstream_directive_handler: UpstreamDirectiveHandler::RepointSelf,
        }
    }
}

/// Discovery gRPC client: wraps five [`Shared`] routing-table cells and a
/// background supervisor that keeps them up to date from pushed controller
/// snapshots.
///
/// Implements [`coxswain_core::RoutingSource`] so it can be passed directly to
/// `wire_proxy_services` / `wire_gateway_only_proxy_services` in place of
/// `KubernetesSource`. The [`listener_status`] accessor provides the fifth cell
/// that drives the proxy's dynamic Gateway listener port bind/unbind.
///
/// The [`Shared`] cells are **never zeroed**: the supervisor serves the
/// last-good snapshot throughout every reconnect window.
///
/// [`Shared`]: coxswain_core::Shared
/// [`listener_status`]: DiscoveryClient::listener_status
pub struct DiscoveryClient {
    ingress_routes: SharedIngressRoutingTable,
    gateway_routes: SharedGatewayRoutingTable,
    tls_store: SharedPortTlsStore,
    client_cert_store: SharedClientCertStore,
    listener_status: GatewayListenerStatusHandle,
    listener_hostnames: SharedListenerHostnames,
    /// SNI-keyed TLS passthrough routing table for TLSRoute / GEP-2643 (#70).
    passthrough_routes: SharedTlsPassthroughTable,
    /// SNI-keyed TLS terminate routing table for TLSRouteModeTerminate (#481).
    terminate_routes: SharedTlsPassthroughTable,
    /// Port-keyed TCP routing table for TCPRoute / GEP-1901 (#505).
    tcp_routes: SharedTcpRouteTable,
    /// Port-keyed UDP routing table for UDPRoute / GEP-2645 (#506).
    udp_routes: SharedUdpRouteTable,
}

impl DiscoveryClient {
    /// Build the routing-table cells and the (not-yet-running) reconnect
    /// [`Supervisor`], without spawning a task.
    ///
    /// Use this when the caller is **not** already inside a Tokio runtime (e.g.
    /// the synchronous `coxswain-bin` startup path before Pingora creates its
    /// runtimes): construct the client, wire the returned cells into the proxy
    /// acceptors, then drive the [`Supervisor`] from a Pingora background
    /// service via [`Supervisor::run`]. Use [`DiscoveryClient::spawn`] instead
    /// when a runtime is already active.
    ///
    /// `health` must come from a [`coxswain_core::health::HealthRegistry`] that
    /// registered this subsystem with at least the `health_check` name. The
    /// supervisor drives the following health transitions:
    ///
    /// - Before first snapshot: `Pending` → `/readyz` 503 (NotReady).
    /// - After first snapshot applied: `Ready`.
    /// - On disconnect after first snapshot: `Degraded` (last-good snapshot served;
    ///   `/readyz` stays 200).
    /// - On reconnect + new snapshot: `Ready` again.
    /// - On NACK (bad DTO): health stays `Ready` — last-good config is still valid.
    ///
    /// The returned [`Supervisor`] must be driven within a Tokio runtime.
    /// Register it as a Pingora background service so it starts after the runtime
    /// is up — calling [`Supervisor::run`] outside a runtime panics.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError::InvalidEndpoint`] if any configured endpoint string is
    /// not a valid URI — surfaced here, at construction, so a misconfigured
    /// endpoint fails loudly at start-up rather than panicking inside the
    /// reconnect supervisor on every attempt.
    #[must_use = "the discovery client and its supervisor must be wired in and driven, or the proxy never receives routing"]
    pub fn new(
        config: DiscoveryClientConfig,
        health: SubsystemHandle,
        health_check: &str,
    ) -> Result<(Self, Supervisor), DiscoveryError> {
        // Endpoint URIs are validated once, inside `Supervisor::with_applier`
        // below (parse-don't-validate), so a misconfigured endpoint fails loudly
        // at construction and the reconnect supervisor's `build_channel` never
        // fails on the URI axis.

        // The proxy applies received snapshots into flat routing cells; build
        // the applier and keep clones of the same `Arc` cells for the client's
        // read paths (proxy acceptors read via the `RoutingSource` accessors).
        let (applier, cells) = RoutingApplier::new();
        // The proxy ignores the rebuild-generation signal (no downstream
        // subscriber); only a relay wires it into a `DiscoveryService`.
        let (supervisor, _rebuild_rx) =
            Supervisor::with_applier(config, health, health_check, Box::new(applier))?;

        let client = Self {
            ingress_routes: cells.ingress,
            gateway_routes: cells.gateway,
            tls_store: cells.tls,
            client_cert_store: cells.client_certs,
            listener_status: cells.listener_status,
            listener_hostnames: cells.listener_hostnames,
            passthrough_routes: cells.passthrough,
            terminate_routes: cells.terminate,
            tcp_routes: cells.tcp,
            udp_routes: cells.udp,
        };

        Ok((client, supervisor))
    }

    /// Spawn the supervised reconnect loop and return a handle to the routing cells.
    ///
    /// Convenience wrapper over [`DiscoveryClient::new`] that immediately
    /// `tokio::spawn`s the supervisor — **requires an active Tokio runtime**.
    /// The returned [`DiscoverySupervisor`] must have `.run()` awaited.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError::InvalidEndpoint`] if any configured endpoint string is
    /// not a valid URI (see [`DiscoveryClient::new`]).
    #[must_use = "the discovery supervisor must have .run() awaited, or the proxy never receives routing"]
    pub fn spawn(
        config: DiscoveryClientConfig,
        health: SubsystemHandle,
        health_check: &str,
    ) -> Result<(Self, DiscoverySupervisor), DiscoveryError> {
        let (client, supervisor) = Self::new(config, health, health_check)?;
        Ok((client, DiscoverySupervisor(supervisor)))
    }

    /// Handle to the Ingress routing table [`Shared`] cell.
    ///
    /// [`Shared`]: coxswain_core::Shared
    #[must_use]
    pub fn ingress_routes(&self) -> SharedIngressRoutingTable {
        self.ingress_routes.clone()
    }

    /// Handle to the Gateway-API routing table [`Shared`] cell.
    ///
    /// [`Shared`]: coxswain_core::Shared
    #[must_use]
    pub fn gateway_routes(&self) -> SharedGatewayRoutingTable {
        self.gateway_routes.clone()
    }

    /// Handle to the TLS certificate store [`Shared`] cell.
    ///
    /// [`Shared`]: coxswain_core::Shared
    #[must_use]
    pub fn tls_store(&self) -> SharedPortTlsStore {
        self.tls_store.clone()
    }

    /// Handle to the client-certificate mTLS config store [`Shared`] cell.
    ///
    /// [`Shared`]: coxswain_core::Shared
    #[must_use]
    pub fn client_cert_store(&self) -> SharedClientCertStore {
        self.client_cert_store.clone()
    }

    /// Handle to the Gateway listener status map.
    ///
    /// Used by the proxy's `ListenerSpecsAdapter` to drive dynamic Gateway
    /// listener port bind/unbind without any Kubernetes API access.
    #[must_use]
    pub fn listener_status(&self) -> GatewayListenerStatusHandle {
        self.listener_status.clone()
    }

    /// Handle to the per-port HTTPS listener-hostname snapshot (GEP-3567, #96).
    ///
    /// Derived from the Gateway listener status that the discovery server
    /// transmits; updated atomically with every applied snapshot.
    #[must_use]
    pub fn listener_hostnames(&self) -> SharedListenerHostnames {
        self.listener_hostnames.clone()
    }

    /// Handle to the TLS passthrough routing table snapshot for TLSRoute / GEP-2643 (#70).
    ///
    /// Updated atomically with every applied snapshot from the controller.
    #[must_use]
    pub fn passthrough_routes(&self) -> SharedTlsPassthroughTable {
        self.passthrough_routes.clone()
    }

    /// Handle to the TLS terminate routing table snapshot for TLSRouteModeTerminate (#481).
    ///
    /// Updated atomically with every applied snapshot from the controller.
    #[must_use]
    pub fn terminate_routes(&self) -> SharedTlsPassthroughTable {
        self.terminate_routes.clone()
    }

    /// Handle to the port-keyed TCP routing table snapshot for TCPRoute / GEP-1901 (#505).
    ///
    /// Updated atomically with every applied snapshot from the controller.
    #[must_use]
    pub fn tcp_routes(&self) -> SharedTcpRouteTable {
        self.tcp_routes.clone()
    }

    /// Handle to the port-keyed UDP routing table snapshot for UDPRoute / GEP-2645 (#506).
    ///
    /// Updated atomically with every applied snapshot from the controller.
    #[must_use]
    pub fn udp_routes(&self) -> SharedUdpRouteTable {
        self.udp_routes.clone()
    }
}

impl coxswain_core::RoutingSource for DiscoveryClient {
    fn ingress_routes(&self) -> SharedIngressRoutingTable {
        self.ingress_routes.clone()
    }

    fn gateway_routes(&self) -> SharedGatewayRoutingTable {
        self.gateway_routes.clone()
    }

    fn tls_store(&self) -> SharedPortTlsStore {
        self.tls_store.clone()
    }

    fn client_cert_store(&self) -> SharedClientCertStore {
        self.client_cert_store.clone()
    }

    fn listener_hostnames(&self) -> SharedListenerHostnames {
        self.listener_hostnames.clone()
    }

    fn passthrough_routes(&self) -> SharedTlsPassthroughTable {
        self.passthrough_routes.clone()
    }

    fn terminate_routes(&self) -> SharedTlsPassthroughTable {
        self.terminate_routes.clone()
    }

    fn tcp_routes(&self) -> SharedTcpRouteTable {
        self.tcp_routes.clone()
    }

    fn udp_routes(&self) -> SharedUdpRouteTable {
        self.udp_routes.clone()
    }
}

// ── supervisor ──────────────────────────────────────────────────────────────

/// The discovery reconnect supervisor returned by [`DiscoveryClient::new`].
///
/// Owns the reconnect/backoff loop and the routing-cell write handles. Drive it
/// by awaiting [`Supervisor::run`] — typically from a Pingora background service
/// so it runs on a Pingora runtime. `run` never returns under normal operation
/// (it loops across reconnects for the process lifetime).
pub struct Supervisor {
    config: DiscoveryClientConfig,
    /// The pluggable apply target (#583). A proxy holds a
    /// [`RoutingApplier`] (flat routing cells); a relay holds a demux applier.
    /// It persists across reconnects so its materialized cache stays the
    /// last-Acked world (invariant `cache ≡ what it serves ≡ last Acked`).
    applier: Box<dyn SnapshotApplier>,
    /// Rebuild-generation signal (#583): bumped after every successful apply so
    /// a downstream consumer (a relay's `DiscoveryService`) re-materializes and
    /// pushes deltas. Inert for a proxy (no subscriber). Over-signalling on an
    /// unchanged world is safe — the downstream diff is empty and sends nothing.
    rebuild_tx: watch::Sender<u64>,
    health: SubsystemHandle,
    health_check: String,
    has_snapshot: bool,
}

/// Opaque reconnect supervisor returned by [`DiscoveryClient::spawn`].
///
/// Must be driven inside a Tokio runtime — register it as a Pingora background
/// service so it starts after the runtime is up. Dropping it stops the reconnect
/// loop and ceases snapshot delivery.
pub struct DiscoverySupervisor(Supervisor);

impl DiscoverySupervisor {
    /// Run the jittered-reconnect supervisor loop until dropped.
    pub async fn run(self) {
        self.0.run().await
    }
}

impl Supervisor {
    /// Build a supervisor around a caller-supplied [`SnapshotApplier`] (#583).
    ///
    /// The shared constructor behind [`DiscoveryClient::new`] (proxy, flat
    /// [`RoutingApplier`]) and the relay glue in [`crate::relay`] (which plugs a
    /// namespace-demux applier). Returns the supervisor plus the rebuild-
    /// generation receiver that fires after every successful apply.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError::InvalidEndpoint`] if any configured endpoint string is
    /// not a valid URI — surfaced here so a misconfigured endpoint fails at
    /// start-up, not inside the reconnect loop.
    pub(crate) fn with_applier(
        config: DiscoveryClientConfig,
        health: SubsystemHandle,
        health_check: &str,
        applier: Box<dyn SnapshotApplier>,
    ) -> Result<(Self, watch::Receiver<u64>), DiscoveryError> {
        validate_endpoints(&config.endpoints)?;
        let (rebuild_tx, rebuild_rx) = watch::channel(0);
        let supervisor = Self {
            config,
            applier,
            rebuild_tx,
            health,
            health_check: health_check.to_owned(),
            has_snapshot: false,
        };
        Ok((supervisor, rebuild_rx))
    }

    /// Run the reconnect/backoff loop until the process exits.
    pub async fn run(mut self) {
        // Pull the rotation + bound-ports receivers out of config so they do
        // not conflict with the mutable borrow of `self` inside
        // `stream_until_closed`.
        let mut svid_rotation_rx: Option<watch::Receiver<u64>> = self.config.svid_rotated.take();
        // Upstream-repoint watch (#601): fires when the bootstrap loop delivers a
        // fresh upstream. A live directive on the stream is handled inline (it
        // returns `repoint`), so this watch covers only the bootstrap-delivered
        // path — but it force-reconnects the same way SVID rotation does.
        let mut upstream_changed_rx: Option<watch::Receiver<u64>> =
            self.config.upstream_changed.take();
        // Fallback re-bootstrap trigger (#601): pokes the bootstrap loop after
        // repeated failed reconnects to the current upstream (a relay torn down
        // in a race), so a fresh bootstrap re-resolves the best upstream.
        let re_bootstrap: Option<Arc<Notify>> = self.config.re_bootstrap.take();
        let mut bound_ports_rx: Option<watch::Receiver<std::collections::BTreeSet<u16>>> =
            self.config.bound_ports_rx.take();
        let mut roster_rx: Option<watch::Receiver<coxswain_core::node_registry::NodeRegistry>> =
            self.config.roster_rx.take();
        let mut attempt: u32 = 0;
        let mut consecutive_not_leader: u32 = 0;

        // Pending until the first snapshot lands; published so the proxy
        // `/metrics` reflects channel state from process start.
        crate::metrics::client_state().set(crate::metrics::STATE_PENDING);

        let mut first_connect = true;
        loop {
            // Every iteration past the first is a reconnect (channel rebuild
            // after a drop or an SVID rotation).
            if first_connect {
                first_connect = false;
            } else {
                crate::metrics::client_reconnects_total().inc();
            }

            // Rebuild the channel on every iteration so a fresh SVID from
            // the bootstrap loop is picked up after a rotation-triggered
            // reconnect. A TLS-config failure here (e.g. a rotation that wrote
            // malformed material) is treated like a failed connect — degrade to
            // the last-good snapshot and back off — never a crash.
            const FAILED: StreamEnd = StreamEnd {
                applied: false,
                not_leader: false,
                repoint: false,
            };
            let end = match build_channel(&self.config) {
                Ok(channel) => {
                    let mut grpc = TonicClient::new(channel);
                    // Both the SVID-rotation and the bootstrap-delivered-upstream
                    // watches force a clean reconnect; a `pending` future stands in
                    // for an unwired receiver so the select shape is uniform.
                    tokio::select! {
                        result = self.stream_until_closed(&mut grpc, bound_ports_rx.as_mut(), roster_rx.as_mut()) => result,
                        Ok(()) = wait_changed(&mut svid_rotation_rx) => {
                            debug!("discovery client: SVID rotated; forcing reconnect with fresh SVID");
                            FAILED.forced()
                        }
                        Ok(()) = wait_changed(&mut upstream_changed_rx) => {
                            debug!("discovery client: upstream repointed at bootstrap; forcing reconnect to new target");
                            FAILED.forced()
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "discovery client: channel build failed; backing off");
                    FAILED
                }
            };
            // A forced reconnect (SVID rotation, a bootstrap-delivered upstream,
            // or an inline `PreferredUpstream` directive) is intentional, not a
            // failure — it must not bump the backoff exponent.
            let forced_reconnect = end.repoint;

            if self.has_snapshot {
                self.health.degraded(
                    &self.health_check,
                    "disconnected from discovery server, serving last-good snapshot",
                );
                crate::metrics::client_state().set(crate::metrics::STATE_DEGRADED);
            }

            // Reset the backoff exponent if the session delivered at least one
            // snapshot, or if this was a rotation-triggered reconnect (not a
            // failure), so kube-proxy propagation lag does not grow the backoff
            // to the cap before the SVID arrives. A not-leader rejection is an
            // expected routing outcome (#531): it neither resets nor bumps the
            // exponent, and takes the fast-retry band instead of the
            // exponential delay.
            if end.applied || forced_reconnect {
                attempt = 0;
            } else if !end.not_leader {
                attempt = attempt.saturating_add(1);
            }
            if end.not_leader {
                consecutive_not_leader = consecutive_not_leader.saturating_add(1);
            } else {
                consecutive_not_leader = 0;
            }

            // Fallback re-bootstrap (#601): repeated failed reconnects to the
            // current upstream mean it is gone (a relay torn down in a race). Poke
            // the bootstrap loop so a fresh bootstrap re-resolves the best upstream
            // — now the controller, the always-up anchor. Fires only on genuine
            // failures (not forced reconnects or not-leader fast-retries) once the
            // exponent crosses the threshold; the bootstrap loop coalesces pokes.
            if attempt >= REBOOTSTRAP_AFTER_ATTEMPTS
                && let Some(notify) = re_bootstrap.as_ref()
            {
                debug!(
                    attempt,
                    "discovery client: upstream unreachable; poking re-bootstrap to re-resolve upstream"
                );
                notify.notify_one();
            }

            // While serving a last-good snapshot, clamp the exponential
            // ceiling (#531): after a hard leader kill the leader-selected
            // Service refuses dials instantly (zero endpoints) until the new
            // leader labels itself, and those refusals must not escalate the
            // delay toward the 30 s cap — the new leader's readiness registry
            // repopulates only when this proxy re-lands. Refused dials are
            // cheap; a proxy that never connected keeps the full escalation
            // (a genuinely absent controller should be dialled gently).
            let effective_attempt = if self.has_snapshot {
                attempt.min(RECONNECT_ATTEMPT_CLAMP_WITH_SNAPSHOT)
            } else {
                attempt
            };
            let delay = if end.not_leader {
                not_leader_retry_delay(consecutive_not_leader)
            } else {
                backoff_jitter(
                    effective_attempt,
                    self.config.backoff_base,
                    self.config.backoff_cap,
                )
            };
            debug!(
                delay_ms = delay.as_millis(),
                "discovery client backing off before reconnect"
            );
            // Make the backoff interruptible by a fresh SVID or a repointed
            // upstream: either wakes the supervisor immediately instead of
            // sleeping the full exponential delay (which at cap is 30 s). A
            // re-bootstrap poked above delivers a fresh upstream through
            // `upstream_changed`, so this same arm cuts the backoff short.
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                Ok(()) = wait_changed(&mut svid_rotation_rx) => {
                    debug!("discovery client: SVID arrived during backoff; reconnecting immediately");
                }
                Ok(()) = wait_changed(&mut upstream_changed_rx) => {
                    debug!("discovery client: upstream repointed during backoff; reconnecting immediately");
                }
            }
        }
    }

    /// Run one stream session until the stream closes or errors.
    ///
    /// The returned [`StreamEnd`] tells the supervisor whether at least one
    /// snapshot was applied (resets the backoff exponent) and whether the
    /// session ended on the leader gate's rejection (fast retry, #531).
    ///
    /// When `bound_ports` is `Some`, a `NodeStatus` carrying the current
    /// bound-port set is queued right after `Subscribe` (so a reconnected
    /// leader rebuilds its readiness view immediately) and re-sent on every
    /// change of the watched set for the life of the session (#531).
    ///
    /// When `roster` is `Some` (relay roles), a `RosterReport` carrying the
    /// relay's downstream leaf registry is queued after `Subscribe` and re-sent
    /// on every roster change, on the same pre-queue + re-send rationale (#585).
    async fn stream_until_closed(
        &mut self,
        grpc: &mut TonicClient<Channel>,
        mut bound_ports: Option<&mut watch::Receiver<std::collections::BTreeSet<u16>>>,
        mut roster: Option<&mut watch::Receiver<coxswain_core::node_registry::NodeRegistry>>,
    ) -> StreamEnd {
        const CLOSED: StreamEnd = StreamEnd {
            applied: false,
            not_leader: false,
            repoint: false,
        };
        let (tx, rx) = mpsc::channel::<p::ClientMessage>(4);

        // Pre-queue Subscribe *before* opening the stream. The server reads the
        // Subscribe (`read_subscribe`) before it returns its response, so it does
        // not send response headers until the first client message arrives — and
        // `grpc.stream(..).await` does not resolve until those response headers
        // arrive. Sending Subscribe only *after* awaiting the call therefore
        // deadlocks: client waits for headers, server waits for Subscribe. The
        // bounded channel has capacity, so this enqueue never blocks; the body
        // stream flushes it as soon as the h2 request opens.
        let subscribe = p::ClientMessage {
            kind: Some(CKind::Subscribe(p::Subscribe {
                node_id: self.config.node_id.clone(),
                wire_version: WIRE_VERSION,
                scope: Some(crate::wire::scope_to_wire(&self.config.scope)),
            })),
        };
        if tx.send(subscribe).await.is_err() {
            warn!("discovery client: outbound channel closed before stream open");
            return CLOSED;
        }

        // Queue the initial bound-port report behind Subscribe (#531). Same
        // pre-queue rationale: the bounded channel has spare capacity and the
        // body stream flushes both as soon as the h2 request opens. On a
        // reconnect after leader failover this is what rebuilds the new
        // leader's readiness registry without waiting for a bind change.
        if let Some(rx) = bound_ports.as_mut() {
            let ports = rx.borrow_and_update().clone();
            if tx.send(node_status_message(&ports)).await.is_err() {
                warn!("discovery client: outbound channel closed before stream open");
                return CLOSED;
            }
        }

        // Queue the initial leaf roster behind Subscribe (#585). On a reconnect
        // this rebuilds the (possibly new) leader's view of this relay's subtree
        // without waiting for a downstream registry change.
        if let Some(rx) = roster.as_mut() {
            let registry = rx.borrow_and_update().clone();
            if tx.send(roster_report_message(&registry)).await.is_err() {
                warn!("discovery client: outbound channel closed before stream open");
                return CLOSED;
            }
        }

        let response = match grpc.stream(ReceiverStream::new(rx)).await {
            Ok(r) => r,
            Err(e) if is_not_leader(&e) => {
                debug!(
                    "discovery client: dialled a standby replica; fast-retrying to reach the leader"
                );
                return StreamEnd {
                    applied: false,
                    not_leader: true,
                    repoint: false,
                };
            }
            Err(e) => {
                warn!(error = %e, "discovery client: failed to open stream");
                return CLOSED;
            }
        };
        let mut inbound = response.into_inner();

        let mut applied_this_session = false;
        let mut ended_not_leader = false;
        // Invariant 1: the first message of every session must be a full snapshot.
        // Reset true per session (the server's per-stream acked baseline is not
        // replica-portable across a reconnect); cleared after the first successful
        // apply so subsequent deltas are accepted. The cache itself persists across
        // sessions on `self`.
        let mut expect_full = true;

        loop {
            let msg = tokio::select! {
                result = inbound.message() => match result {
                    Ok(Some(m)) => m,
                    Ok(None) => {
                        debug!("discovery stream closed by server");
                        break;
                    }
                    Err(e) if is_not_leader(&e) => {
                        // Mid-stream demotion: the (ex-)leader terminated the
                        // stream so we re-land on the new leader (#531).
                        debug!("discovery client: server demoted mid-stream; fast-retrying to reach the new leader");
                        ended_not_leader = true;
                        break;
                    }
                    Err(e) => {
                        warn!(error = %e, "discovery stream error");
                        break;
                    }
                },

                // Bound-port set changed mid-session — report it (#531). The
                // arm is inert (`pending`) when no receiver is wired.
                changed = async {
                    match bound_ports.as_mut() {
                        Some(rx) => rx.changed().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match changed {
                        Ok(()) => {
                            let Some(rx) = bound_ports.as_mut() else { continue };
                            let ports = rx.borrow_and_update().clone();
                            debug!(?ports, "discovery client: bound-port set changed; sending NodeStatus");
                            if tx.send(node_status_message(&ports)).await.is_err() {
                                debug!("discovery client: outbound channel closed after NodeStatus");
                                break;
                            }
                        }
                        Err(_) => {
                            // Acceptor sender dropped (proxy shutting down) —
                            // stop watching; the stream will close shortly.
                            debug!("discovery client: bound-port sender dropped; no further NodeStatus reports");
                            bound_ports = None;
                        }
                    }
                    continue;
                }

                // Downstream leaf roster changed mid-session — report it (#585).
                // Inert (`pending`) when no receiver is wired (leaf/controller).
                changed = async {
                    match roster.as_mut() {
                        Some(rx) => rx.changed().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match changed {
                        Ok(()) => {
                            let Some(rx) = roster.as_mut() else { continue };
                            // Build the report from the watch borrow directly — no
                            // owned registry clone (#621) — then drop the borrow
                            // before the `.await` so it never spans a send.
                            let message = {
                                let registry = rx.borrow_and_update();
                                debug!(
                                    children = registry.nodes.len(),
                                    "discovery client: leaf roster changed; sending RosterReport"
                                );
                                roster_report_message(&registry)
                            };
                            if tx.send(message).await.is_err() {
                                debug!("discovery client: outbound channel closed after RosterReport");
                                break;
                            }
                        }
                        Err(_) => {
                            // Roster sender dropped (relay shutting down) — stop
                            // watching; the stream will close shortly.
                            debug!("discovery client: roster sender dropped; no further RosterReport");
                            roster = None;
                        }
                    }
                    continue;
                }
            };

            let snapshot = match msg.kind {
                Some(SKind::Snapshot(s)) => s,
                // Live upstream-repoint directive (#601).
                Some(SKind::PreferredUpstream(directive)) => {
                    match &self.config.upstream_directive_handler {
                        // Leaf: repoint this client's own upstream and break the
                        // stream so the supervisor reconnects to the new target.
                        // The data-plane cells are untouched — routing keeps
                        // serving the last-good snapshot across the reconnect.
                        UpstreamDirectiveHandler::RepointSelf => {
                            if self.apply_repoint(&directive) {
                                return StreamEnd {
                                    applied: applied_this_session,
                                    not_leader: false,
                                    repoint: true,
                                };
                            }
                            continue;
                        }
                        // Relay: fan the controller-originated directive to the
                        // downstream leaf streams; the relay itself always streams
                        // from the controller, so it never repoints here. A send
                        // error means no leaf is currently subscribed — nothing to
                        // forward to, which is fine.
                        UpstreamDirectiveHandler::Forward(tx) => {
                            let _ = tx.send(directive);
                            continue;
                        }
                    }
                }
                _ => continue,
            };

            let version = snapshot.version.clone();
            let nonce = snapshot.nonce.clone();

            // #513/#383: proxy-apply stage — stage the wire resources into the
            // materialized cache, compile the changed world, and publish the
            // routing cells. Timed regardless of outcome: a rejected (Nack'd)
            // apply still pays most of this cost before failing. `expect_full`
            // gates the first message of the session to a full snapshot
            // (invariant 1); it is cleared below on the first successful apply.
            let apply_start = std::time::Instant::now();
            let apply_result = self.applier.apply(&snapshot, expect_full);
            crate::metrics::snapshot_apply_seconds().observe(apply_start.elapsed().as_secs_f64());
            match apply_result {
                // `ApplyStats` (partition recompile/reuse tallies) is mirrored
                // into the process metrics inside `apply_message`; the stream loop
                // only needs Ack-vs-Nack, so the stats are not threaded further.
                Ok(_stats) => {
                    debug!(version, "discovery snapshot applied; sending Ack");
                    // Count the applied snapshot by kind (full|delta). A healthy
                    // steady state climbs `delta` with a near-static `full`.
                    crate::metrics::client_snapshots_applied_total()
                        .with_label_values(&[if snapshot.full { "full" } else { "delta" }])
                        .inc();
                    let ack = p::ClientMessage {
                        kind: Some(CKind::Ack(p::Ack { version, nonce })),
                    };
                    if tx.send(ack).await.is_err() {
                        debug!("discovery client: outbound channel closed after Ack");
                        break;
                    }
                    // Invariant 1 satisfied for this session: subsequent messages
                    // may be deltas.
                    expect_full = false;
                    applied_this_session = true;
                    self.has_snapshot = true;
                    // Mark Ready on every applied snapshot, not just the first:
                    // after a disconnect flips the subsystem to Degraded, the
                    // post-reconnect snapshot must clear it back to Ready (the
                    // documented transition). `ready()` is idempotent, so
                    // re-marking on steady-state applies is a no-op.
                    self.health.ready(&self.health_check);
                    crate::metrics::client_state().set(crate::metrics::STATE_READY);
                    // Signal downstream re-materialization (#583). Bumped on
                    // every applied snapshot; a relay's `DiscoveryService`
                    // re-diffs and pushes deltas to its leaves. Inert for a
                    // proxy (no subscriber holds the receiver).
                    self.rebuild_tx.send_modify(|g| *g = g.wrapping_add(1));
                }
                Err(e) => {
                    // Last-good snapshot is retained; health stays as-is because the
                    // proxy is still serving valid configuration from the prior apply.
                    warn!(error = %e, version, "discovery snapshot rejected (NACK); retaining last-good routing tables");
                    let nack = p::ClientMessage {
                        kind: Some(CKind::Nack(p::Nack {
                            version,
                            nonce,
                            detail: e.to_string(),
                        })),
                    };
                    if tx.send(nack).await.is_err() {
                        debug!("discovery client: outbound channel closed after Nack");
                        break;
                    }
                }
            }
        }

        StreamEnd {
            applied: applied_this_session,
            not_leader: ended_not_leader,
            repoint: false,
        }
    }

    /// Apply a `PreferredUpstream` directive to this client's own upstream cell
    /// (#601). Returns `true` when the directive was applied (the caller then
    /// breaks the stream to reconnect to the new target), `false` when it was
    /// ignored (no cell wired, or an empty endpoint) so the caller keeps the
    /// current session.
    fn apply_repoint(&self, directive: &p::PreferredUpstream) -> bool {
        let Some(cell) = self.config.upstream_cell.as_ref() else {
            warn!(
                "discovery client: received PreferredUpstream but no upstream cell is wired; ignoring"
            );
            return false;
        };
        if directive.endpoint.is_empty() {
            warn!("discovery client: received PreferredUpstream with empty endpoint; ignoring");
            return false;
        }
        let matcher = expected_server_matcher(
            &self.config.trust_domain,
            &directive.endpoint,
            &directive.expected_server_sa,
            &self.config.fallback_namespace,
        );
        let target = UpstreamTarget::new(directive.endpoint.clone(), matcher);
        debug!(
            endpoint = %directive.endpoint,
            expected_server_sa = %directive.expected_server_sa,
            "discovery client: applying PreferredUpstream directive; repointing routing upstream"
        );
        cell.store(Arc::new(Some(target)));
        true
    }
}

/// Build a lazy-connect [`Channel`] from the configured endpoints.
///
/// TLS priority: `svid_cell` (dynamic SVID) > `tls` (static config) > plaintext.
///
/// When `svid_cell` is `Some` and contains a non-None SVID, constructs
/// [`DiscoveryClientTls`] from the cell's cert/key/CA material and the
/// `expected_server` matcher.  When the cell is empty (bootstrap not yet
/// complete), falls back to plaintext — the supervisor will reconnect once the
/// SVID rotation watch fires.
///
/// # Errors
///
/// - [`DiscoveryError::InvalidEndpoint`] if an endpoint string is not a valid
///   URI. In practice unreachable after [`validate_endpoints`] runs at
///   construction, but handled here too so this never panics.
/// - [`DiscoveryError::TlsConfig`] if the current SVID/cert material fails to
///   build a TLS config (reachable when a rotation writes malformed material).
///   The supervisor treats this like a failed connect: degrade to the last-good
///   snapshot, back off, and retry on the next rotation.
fn build_channel(config: &DiscoveryClientConfig) -> Result<Channel, DiscoveryError> {
    // Resolve the current upstream target (#601): the runtime cell — populated by
    // the bootstrap loop or a live directive — wins; otherwise the static
    // `endpoints` + `expected_server` (no-bootstrap/unit-test path).
    let runtime_target: Option<UpstreamTarget> = config
        .upstream_cell
        .as_ref()
        .and_then(|cell| (*cell.load()).clone());
    let (endpoints, expected_server): (&[String], Option<SpiffeMatcher>) = match &runtime_target {
        Some(target) => (&target.endpoints, Some(target.expected_server.clone())),
        None => (config.endpoints.as_slice(), config.expected_server.clone()),
    };

    // A bootstrap-anchored client whose cell is not yet populated has no target;
    // surface it as a distinct, non-crashing error so the supervisor backs off
    // and reconnects the instant `upstream_changed` fires (mirrors the empty-SVID
    // path). Never build an endpoint-less `Channel::balance_list`.
    if endpoints.is_empty() {
        return Err(DiscoveryError::NoUpstream);
    }

    // Resolve which TLS config to use for this connection attempt. The SPIFFE
    // matcher comes from the resolved upstream target (relay vs controller
    // identity), not a fixed config value.
    let resolved_tls: Option<DiscoveryClientTls> = config
        .svid_cell
        .as_ref()
        .and_then(|cell| {
            let svid = cell.load();
            let material = svid.as_ref().as_ref()?;
            let matcher = expected_server.clone()?;
            Some(DiscoveryClientTls {
                client_cert_pem: material.cert_pem.clone(),
                client_key_pem: material.key_pem.clone(),
                server_ca_pem: material.ca_bundle_pem.clone(),
                expected_server: matcher,
            })
        })
        .or_else(|| {
            config.tls.as_ref().map(|t| DiscoveryClientTls {
                client_cert_pem: t.client_cert_pem.clone(),
                client_key_pem: t.client_key_pem.clone(),
                server_ca_pem: t.server_ca_pem.clone(),
                expected_server: t.expected_server.clone(),
            })
        });

    let configure = |uri: &str| -> Result<Endpoint, DiscoveryError> {
        let ep = Endpoint::from_shared(uri.to_owned())
            .map_err(|source| DiscoveryError::InvalidEndpoint {
                uri: uri.to_owned(),
                source,
            })?
            .http2_keep_alive_interval(config.http2_keep_alive_interval)
            .keep_alive_timeout(config.keep_alive_timeout)
            .keep_alive_while_idle(true)
            .connect_timeout(config.connect_timeout);
        match &resolved_tls {
            Some(tls) => Ok(tls.apply(ep)?),
            None => Ok(ep),
        }
    };

    if endpoints.len() == 1 {
        Ok(configure(&endpoints[0])?.connect_lazy())
    } else {
        let endpoints = endpoints
            .iter()
            .map(|u| configure(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Channel::balance_list(endpoints.into_iter()))
    }
}

/// Build the `NodeStatus` client message for a bound-port set (#531).
///
/// `BTreeSet` iteration yields the sorted-ascending order the wire contract
/// documents.
fn node_status_message(ports: &std::collections::BTreeSet<u16>) -> p::ClientMessage {
    p::ClientMessage {
        kind: Some(CKind::NodeStatus(p::NodeStatus {
            bound_ports: ports.iter().map(|port| u32::from(*port)).collect(),
        })),
    }
}

/// Unix seconds for a [`SystemTime`], clamped: a pre-epoch time reads 0 and a
/// far-future one saturates `i64` rather than panicking on the cast.
fn system_time_to_unix(t: std::time::SystemTime) -> i64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Encode a core [`NodeScope`] as the wire [`Scope`] for a `RosterEntry` (#585).
///
/// [`NodeScope`]: coxswain_core::node_registry::NodeScope
/// [`Scope`]: p::Scope
fn node_scope_to_wire(scope: &coxswain_core::node_registry::NodeScope) -> p::Scope {
    use coxswain_core::node_registry::NodeScope;
    let kind = match scope {
        NodeScope::Gateway { namespace, name } => p::scope::Kind::Gateway(p::GatewayScope {
            namespace: namespace.clone(),
            name: name.clone(),
        }),
        NodeScope::Namespace { namespace } => p::scope::Kind::Namespace(p::NamespaceScope {
            namespace: namespace.clone(),
        }),
        NodeScope::SharedPool => p::scope::Kind::SharedPool(p::SharedPoolScope {}),
    };
    p::Scope { kind: Some(kind) }
}

/// Build a `RosterReport` client message from a relay's downstream registry
/// (#585): every leaf becomes a `RosterEntry`, carrying the state the
/// controller's #531 gate and topology panel fold in.
fn roster_report_message(
    registry: &coxswain_core::node_registry::NodeRegistry,
) -> p::ClientMessage {
    let children = registry
        .nodes
        .values()
        .map(|e| p::RosterEntry {
            node_id: e.node_id.clone(),
            scope: Some(node_scope_to_wire(&e.scope)),
            acked_version: e.last_acked_version.clone(),
            target_version: e.target_version.clone(),
            acked_seq: e.last_acked_seq,
            // Preserve the None/Some(∅) distinction the gate relies on.
            bound_reported: e.bound_ports.is_some(),
            bound_ports: e
                .bound_ports
                .as_ref()
                .map(|s| s.iter().map(|port| u32::from(*port)).collect())
                .unwrap_or_default(),
            connected_since_unix: system_time_to_unix(e.connected_since),
            last_ack_at_unix: e.last_ack_at.map(system_time_to_unix),
        })
        .collect();
    p::ClientMessage {
        kind: Some(CKind::RosterReport(p::RosterReport { children })),
    }
}

/// Validate every configured endpoint string parses as a URI, at construction.
///
/// `parse-don't-validate`: proves the URI invariant once at start-up so the
/// reconnect supervisor's [`build_channel`] never fails on the URI axis. A bad
/// endpoint is operator misconfiguration and should fail loudly at boot, not
/// loop forever in the supervisor.
///
/// # Errors
///
/// [`DiscoveryError::InvalidEndpoint`] for the first endpoint that fails to parse.
fn validate_endpoints(endpoints: &[String]) -> Result<(), DiscoveryError> {
    for uri in endpoints {
        if let Err(source) = Endpoint::from_shared(uri.clone()) {
            return Err(DiscoveryError::InvalidEndpoint {
                uri: uri.clone(),
                source,
            });
        }
    }
    Ok(())
}

// ── not-leader fast retry (#531) ─────────────────────────────────────────────

/// Fast-retry band for not-leader rejections: `[250 ms, 500 ms]`.
///
/// A rejection from a standby replica is an expected, cheap outcome while the
/// deterministic leader-label Service routing catches up — retrying fast makes
/// re-pinning to the leader converge in O(replicas) dials. Escalating the
/// exponential backoff here would stretch a routine leader handover toward the
/// 30 s cap.
const NOT_LEADER_RETRY_MIN_MS: u64 = 250;
const NOT_LEADER_RETRY_MAX_MS: u64 = 500;
/// After this many consecutive not-leader results (~5–10 s of dialling, i.e.
/// most of a 15 s lease TTL), assume a persistent leaderless window and widen
/// the retry band to [`NOT_LEADER_RETRY_SLOW_MIN_MS`, `NOT_LEADER_RETRY_SLOW_MAX_MS`]
/// so proxies do not hammer standbys indefinitely. Resets on any other outcome.
const NOT_LEADER_ESCALATE_AFTER: u32 = 20;
const NOT_LEADER_RETRY_SLOW_MIN_MS: u64 = 500;
const NOT_LEADER_RETRY_SLOW_MAX_MS: u64 = 2_000;

/// Exponent clamp for reconnect backoff while a last-good snapshot is being
/// served (#531): ceiling `base * 2^4` = 4 s at the 250 ms default, keeping
/// post-failover re-landing prompt. Applies only to `has_snapshot` proxies;
/// cold clients escalate to the full cap.
const RECONNECT_ATTEMPT_CLAMP_WITH_SNAPSHOT: u32 = 4;

/// Outcome of one stream session, as the supervisor's backoff input (#531).
struct StreamEnd {
    /// At least one snapshot was applied this session (resets the exponential
    /// backoff — the connection was healthy).
    applied: bool,
    /// The session ended with the server's not-leader rejection (at accept or
    /// via mid-stream demotion) — retry fast instead of backing off.
    not_leader: bool,
    /// The session ended because a `PreferredUpstream` directive repointed this
    /// client (#601), or a forced-reconnect watch fired. An intentional
    /// reconnect: reset the backoff exponent and dial the new target.
    repoint: bool,
}

impl StreamEnd {
    /// Mark an end as a forced (intentional) reconnect — used when a
    /// force-reconnect watch (SVID rotation, bootstrap-delivered upstream) wins
    /// the connect select.
    const fn forced(self) -> Self {
        Self {
            applied: self.applied,
            not_leader: self.not_leader,
            repoint: true,
        }
    }
}

/// Await a change on an optional watch receiver, standing in a never-resolving
/// future for an unwired receiver so it can share a `select!` arm (#601, #531).
async fn wait_changed(
    rx: &mut Option<watch::Receiver<u64>>,
) -> Result<(), watch::error::RecvError> {
    match rx.as_mut() {
        Some(r) => r.changed().await,
        None => std::future::pending().await,
    }
}

/// Failed reconnects to the current upstream before the supervisor pokes a
/// re-bootstrap to re-resolve it (#601). Three attempts ≈ the first
/// second of backoff — long enough to ride out a transient blip, short enough
/// that a genuinely-gone relay is abandoned for the controller promptly.
const REBOOTSTRAP_AFTER_ATTEMPTS: u32 = 3;

/// Whether a stream error is the leader gate's rejection (#531).
///
/// `FAILED_PRECONDITION` alone is ambiguous (wire-version mismatch shares the
/// code), so the message text is matched too, via the same needle constant the
/// server builds [`crate::server::NOT_LEADER_MSG`] from — a rewording cannot
/// silently break the classification (though controller and proxy binaries
/// skew across upgrades, so the needle must stay wire-stable regardless).
fn is_not_leader(status: &tonic::Status) -> bool {
    status.code() == tonic::Code::FailedPrecondition
        && status.message().contains(crate::server::NOT_LEADER_NEEDLE)
}

/// Uniform jittered delay for not-leader retries: the fast band until
/// [`NOT_LEADER_ESCALATE_AFTER`] consecutive rejections, the slow band after.
fn not_leader_retry_delay(consecutive: u32) -> Duration {
    let (min_ms, max_ms) = if consecutive > NOT_LEADER_ESCALATE_AFTER {
        (NOT_LEADER_RETRY_SLOW_MIN_MS, NOT_LEADER_RETRY_SLOW_MAX_MS)
    } else {
        (NOT_LEADER_RETRY_MIN_MS, NOT_LEADER_RETRY_MAX_MS)
    };
    let span = max_ms.saturating_sub(min_ms);
    Duration::from_millis(min_ms + jitter_seed() % (span + 1))
}

/// Uniform-jitter seed: a monotone counter XOR'd with subsecond nanos, shared
/// by [`backoff_jitter`] and [`not_leader_retry_delay`]. The counter
/// guarantees unique seeds for rapid successive calls in the same nanosecond
/// (correlated delays across a fleet defeat the point of jitter); the nanos
/// add per-process entropy. Not a security primitive.
fn jitter_seed() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    splitmix64(seq ^ nanos)
}

/// Full-jitter exponential backoff delay.
///
/// Returns a duration uniformly drawn from `[0, min(cap, base * 2^attempt)]`.
/// The exponent is capped at 7 doublings (128×) to avoid `u64` overflow; further
/// failed attempts keep the same ceiling.
fn backoff_jitter(attempt: u32, base: Duration, cap: Duration) -> Duration {
    let base_ms = base.as_millis() as u64;
    let cap_ms = cap.as_millis() as u64;
    let ceiling = cap_ms.min(base_ms.saturating_mul(1u64 << attempt.min(7)));
    if ceiling == 0 {
        return Duration::ZERO;
    }
    Duration::from_millis(jitter_seed() % (ceiling + 1))
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

// ── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::proto::v1::{
        BackendGroup, ClientMessage, HostEntry, LoadBalance, Resource, RouteEntry,
        RouteHostResource, RouteKind, RouteTableKind, ServerMessage, Snapshot, WeightedBackend,
        discovery_server::{Discovery, DiscoveryServer},
        host_entry::Pattern,
        load_balance::Algorithm,
        resource::Payload,
        server_message::Kind as SrvKind,
    };
    use coxswain_core::health::HealthRegistry;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc as tpsc;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;
    use tonic::{Request, Response, Status, Streaming};

    // ── fake server ──────────────────────────────────────────────────────────

    /// Each time a client connects, the fake server hands the test a pair of
    /// channels: one to drive what the server sends, one to observe what the
    /// client sends.
    type ConnectPair = (
        tpsc::Sender<Result<ServerMessage, Status>>,
        tpsc::Receiver<ClientMessage>,
    );

    struct FakeDiscovery {
        /// Notified for every incoming `Stream` call.
        connect_tx: tpsc::Sender<ConnectPair>,
    }

    #[async_trait::async_trait]
    impl Discovery for FakeDiscovery {
        type StreamStream = ReceiverStream<Result<ServerMessage, Status>>;

        async fn bootstrap(
            &self,
            _req: Request<crate::proto::v1::BootstrapRequest>,
        ) -> Result<Response<crate::proto::v1::BootstrapResponse>, Status> {
            Err(Status::unimplemented("test stub"))
        }

        async fn stream(
            &self,
            request: Request<Streaming<ClientMessage>>,
        ) -> Result<Response<Self::StreamStream>, Status> {
            let (server_tx, server_rx) = tpsc::channel(16);
            let (client_tx, client_rx) = tpsc::channel(16);

            let mut inbound = request.into_inner();

            // Mirror the production server (`DiscoveryService::stream` →
            // `read_subscribe`): read the first client message (Subscribe)
            // *before* returning the response. The real server gates its
            // response headers on receiving Subscribe, so a client that waits
            // for `grpc.stream(..).await` to resolve before sending Subscribe
            // deadlocks. Reading here makes that deadlock reproducible in tests
            // rather than papering over it by responding immediately.
            match inbound.message().await {
                Ok(Some(msg)) => {
                    let _ = client_tx.send(msg).await;
                }
                _ => return Err(Status::unavailable("client closed before Subscribe")),
            }

            // Drain the remaining inbound messages (Acks/Nacks) into `client_tx`.
            tokio::spawn(async move {
                while let Ok(Some(msg)) = inbound.message().await {
                    if client_tx.send(msg).await.is_err() {
                        break;
                    }
                }
            });

            // Clone before any `.await` so the future does not borrow `self` across
            // the suspension point (channel capacity is sufficient for test traffic).
            let connect_tx = self.connect_tx.clone();
            let _ = connect_tx.send((server_tx, client_rx)).await;
            Ok(Response::new(ReceiverStream::new(server_rx)))
        }
    }

    /// Bind a tonic server on a random port and return its address.
    async fn start_server() -> (SocketAddr, tpsc::Receiver<ConnectPair>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (connect_tx, connect_rx) = tpsc::channel(8);
        let service = FakeDiscovery { connect_tx };
        tokio::spawn(
            Server::builder()
                .add_service(DiscoveryServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        (addr, connect_rx)
    }

    /// Extract a snapshot message's `version` for an Ack/Nack assertion.
    fn snapshot_version_of(m: &ServerMessage) -> String {
        let Some(SrvKind::Snapshot(s)) = &m.kind else {
            unreachable!("test helper called on a non-snapshot message")
        };
        s.version.clone()
    }

    /// Minimal valid full snapshot (empty routing world) — WIRE_VERSION 2. The
    /// `version` is the real content hash (F6), so the client's self-check passes;
    /// the `_label` argument is kept only to document each call site.
    fn empty_snapshot(_label: &str, nonce: Vec<u8>) -> ServerMessage {
        let resources = Vec::new();
        ServerMessage {
            kind: Some(SrvKind::Snapshot(Snapshot {
                version: crate::bench_internals::snapshot_version(&resources),
                nonce,
                full: true,
                resources,
                removed_resources: Vec::new(),
                publish_seq: 0,
            })),
        }
    }

    /// A full snapshot carrying one Ingress route-host resource for `host` backed
    /// by a keyed endpoint `ns/svc/port`, plus the matching `EndpointResource`.
    /// Real content-hash `version`.
    fn keyed_route_snapshot(
        nonce: Vec<u8>,
        host: &str,
        ns: &str,
        svc: &str,
        port: u32,
        addr: &str,
    ) -> ServerMessage {
        let resources = vec![
            endpoint_resource(ns, svc, port, &[addr]),
            keyed_route_resource(host, ns, svc, port),
        ];
        ServerMessage {
            kind: Some(SrvKind::Snapshot(Snapshot {
                version: crate::bench_internals::snapshot_version(&resources),
                nonce,
                full: true,
                resources,
                removed_resources: Vec::new(),
                publish_seq: 0,
            })),
        }
    }

    /// A delta upserting one changed `EndpointResource` for `ns/svc/port`. The
    /// `version` is computed over the whole post-apply world (`route` + the new
    /// endpoint), matching what a real server stamps.
    fn endpoint_delta(
        nonce: Vec<u8>,
        host: &str,
        ns: &str,
        svc: &str,
        port: u32,
        new_addr: &str,
    ) -> ServerMessage {
        let ep = endpoint_resource(ns, svc, port, &[new_addr]);
        let post = [ep.clone(), keyed_route_resource(host, ns, svc, port)];
        ServerMessage {
            kind: Some(SrvKind::Snapshot(Snapshot {
                version: crate::bench_internals::snapshot_version(&post),
                nonce,
                full: false,
                resources: vec![ep],
                removed_resources: Vec::new(),
                publish_seq: 0,
            })),
        }
    }

    /// One `EndpointResource` DTO (`ns/svc/port` → `addrs`).
    fn endpoint_resource(ns: &str, svc: &str, port: u32, addrs: &[&str]) -> Resource {
        Resource {
            payload: Some(Payload::Endpoints(crate::proto::v1::EndpointResource {
                namespace: ns.to_owned(),
                service: svc.to_owned(),
                port,
                app_protocol: 0,
                service_exists: true,
                addrs: addrs.iter().map(|s| (*s).to_owned()).collect(),
            })),
            ..Default::default()
        }
    }

    /// One Ingress exact-host route-host resource whose single prefix route is
    /// backed by a keyed endpoint reference.
    fn keyed_route_resource(host: &str, ns: &str, svc: &str, port: u32) -> Resource {
        Resource {
            payload: Some(Payload::RouteHost(RouteHostResource {
                table: RouteTableKind::Ingress as i32,
                port: 80,
                host: Some(HostEntry {
                    pattern: Some(Pattern::Exact(host.to_owned())),
                    routes: vec![RouteEntry {
                        kind: RouteKind::Prefix as i32,
                        path: "/".to_owned(),
                        backend_group: Some(BackendGroup {
                            name: format!("{ns}/{svc}"),
                            weighted: vec![WeightedBackend {
                                addrs: Vec::new(),
                                weight: 1,
                                endpoint_ref: Some(crate::proto::v1::EndpointRef {
                                    namespace: ns.to_owned(),
                                    service: svc.to_owned(),
                                    port,
                                }),
                            }],
                            load_balance: Some(LoadBalance {
                                algorithm: Some(Algorithm::RoundRobin(true)),
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            })),
            ..Default::default()
        }
    }

    /// Full snapshot carrying one Ingress route-host resource with an invalid
    /// regex path; `decode_world` rejects it with `WireError::InvalidRegex`, so
    /// the client must Nack and retain its last-good tables (#383).
    fn bad_regex_snapshot(version: &str, nonce: Vec<u8>) -> ServerMessage {
        let bad_route = RouteEntry {
            kind: RouteKind::Regex as i32,
            path: "[unclosed".to_owned(), // invalid regex — rejected at build()
            // A valid literal backend so decode reaches the regex-compile step.
            backend_group: Some(BackendGroup {
                name: "ns/svc".to_owned(),
                weighted: vec![WeightedBackend {
                    addrs: vec!["10.0.0.1:80".to_owned()],
                    weight: 1,
                    endpoint_ref: None,
                }],
                load_balance: Some(LoadBalance {
                    algorithm: Some(Algorithm::RoundRobin(true)),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let host = HostEntry {
            pattern: Some(Pattern::Catchall(true)),
            routes: vec![bad_route],
            ..Default::default()
        };
        let resource = Resource {
            payload: Some(Payload::RouteHost(RouteHostResource {
                table: RouteTableKind::Ingress as i32,
                port: 80,
                host: Some(host),
            })),
            ..Default::default()
        };
        // Real content-hash version so the F6 self-check PASSES and the failure the
        // test exercises is the regex compile (not a version mismatch). `_label`
        // documents the call site only.
        let _ = version;
        let resources = vec![resource];
        ServerMessage {
            kind: Some(SrvKind::Snapshot(Snapshot {
                version: crate::bench_internals::snapshot_version(&resources),
                nonce,
                full: true,
                resources,
                removed_resources: Vec::new(),
                publish_seq: 0,
            })),
        }
    }

    fn test_config(addr: SocketAddr) -> DiscoveryClientConfig {
        DiscoveryClientConfig {
            endpoints: vec![format!("http://{addr}")],
            node_id: "test-node".to_owned(),
            scope: Scope::SharedPool,
            http2_keep_alive_interval: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            // Tiny backoff so reconnect tests complete quickly.
            backoff_base: Duration::from_millis(10),
            backoff_cap: Duration::from_millis(50),
            tls: None,
            bound_ports_rx: None,
            roster_rx: None,
            svid_cell: None,
            expected_server: None,
            svid_rotated: None,
            upstream_cell: None,
            upstream_changed: None,
            re_bootstrap: None,
            trust_domain: "cluster.local".to_owned(),
            fallback_namespace: String::new(),
            upstream_directive_handler: UpstreamDirectiveHandler::RepointSelf,
        }
    }

    #[test]
    fn new_rejects_malformed_endpoint() {
        // A bad endpoint URI is operator misconfiguration: it must fail
        // construction loudly, not panic inside the reconnect supervisor on
        // every attempt (parse-don't-validate).
        let registry = HealthRegistry::new();
        let handle = registry.register("disc", &["conn"]);
        let config =
            DiscoveryClientConfig::new(vec!["http://invalid host".to_owned()], "n".to_owned());
        let result = DiscoveryClient::new(config, handle, "conn");
        assert!(
            matches!(result, Err(DiscoveryError::InvalidEndpoint { .. })),
            "a malformed endpoint URI must fail construction with InvalidEndpoint"
        );
    }

    #[test]
    fn build_channel_surfaces_tls_error_instead_of_panicking() {
        // A rotation that wrote malformed CA material must NOT crash the data
        // plane. build_channel returns Err so the supervisor degrades to the
        // last-good snapshot and retries on the next rotation, rather than the
        // former `panic!("invariant: discovery TLS config must be valid")`.
        let mut config =
            DiscoveryClientConfig::new(vec!["http://127.0.0.1:50051".to_owned()], "n".to_owned());
        config.tls = Some(DiscoveryClientTls {
            client_cert_pem: b"not a cert".to_vec(),
            client_key_pem: b"not a key".to_vec(),
            server_ca_pem: b"not a ca bundle".to_vec(),
            expected_server: SpiffeMatcher::Exact("spiffe://example.org/ns/x/sa/y".to_owned()),
        });
        assert!(
            matches!(build_channel(&config), Err(DiscoveryError::TlsConfig(_))),
            "malformed TLS material must surface as TlsConfig, never panic"
        );
    }

    /// Poll `f` until it returns `Some(T)` or the timeout elapses.
    async fn poll_until<F, T>(timeout: Duration, mut f: F) -> T
    where
        F: FnMut() -> Option<T>,
    {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(v) = f() {
                return v;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "poll_until: timed out waiting for condition"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    // ── test cases ───────────────────────────────────────────────────────────

    /// Client sends Subscribe, server sends two snapshots, client Acks each in order.
    /// Server gates the second snapshot until the first Ack arrives.
    #[tokio::test]
    async fn subscribes_then_acks_each_snapshot_in_order() {
        let (addr, mut connect_rx) = start_server().await;

        let registry = HealthRegistry::new();
        let handle = registry.register("disc", &["conn"]);
        let (client, supervisor) = DiscoveryClient::spawn(test_config(addr), handle, "conn")
            .expect("test endpoints are valid URIs");
        let _task = tokio::spawn(supervisor.run());

        // Wait for the client to connect and send Subscribe.
        let (srv_tx, mut cli_rx) = tokio::time::timeout(Duration::from_secs(2), connect_rx.recv())
            .await
            .expect("timed out waiting for client connection")
            .expect("channel closed");

        let first = tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .expect("timed out waiting for Subscribe")
            .expect("channel closed");
        assert!(
            matches!(first.kind, Some(CKind::Subscribe(_))),
            "expected Subscribe as first client message"
        );

        // Send snapshot #1 (empty world) and capture its real content-hash version.
        let snap1 = empty_snapshot("v1", vec![1]);
        let v1 = snapshot_version_of(&snap1);
        srv_tx.send(Ok(snap1)).await.unwrap();

        // Wait for Ack #1 — the client echoes the applied version.
        let ack1 = tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .expect("timed out waiting for Ack #1")
            .expect("channel closed");
        assert!(
            matches!(&ack1.kind, Some(CKind::Ack(a)) if a.version == v1),
            "expected Ack for {v1}, got: {ack1:?}"
        );

        // Only now send snapshot #2 (distinct content → distinct version).
        let snap2 =
            keyed_route_snapshot(vec![2], "svc.example.com", "ns", "svc", 80, "10.0.0.1:8080");
        let v2 = snapshot_version_of(&snap2);
        assert_ne!(v1, v2, "distinct content must hash to distinct versions");
        srv_tx.send(Ok(snap2)).await.unwrap();

        let ack2 = tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .expect("timed out waiting for Ack #2")
            .expect("channel closed");
        assert!(
            matches!(&ack2.kind, Some(CKind::Ack(a)) if a.version == v2),
            "expected Ack for {v2}, got: {ack2:?}"
        );

        // Both tables reflect the applied snapshot (non-default handle set).
        let _ = client.ingress_routes().load();
    }

    /// With a bound-ports receiver wired, the client reports its current set as
    /// a NodeStatus immediately after Subscribe on stream open, and again on
    /// every change of the watched set (#531).
    #[tokio::test]
    async fn reports_node_status_on_stream_open_and_on_bound_set_change() {
        let (addr, mut connect_rx) = start_server().await;

        let registry = HealthRegistry::new();
        let handle = registry.register("disc", &["conn"]);
        let bound_tx = watch::Sender::new(
            [8080u16]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
        );
        let mut config = test_config(addr);
        config.bound_ports_rx = Some(bound_tx.subscribe());
        let (_client, supervisor) =
            DiscoveryClient::spawn(config, handle, "conn").expect("test endpoints are valid URIs");
        let _task = tokio::spawn(supervisor.run());

        let (srv_tx, mut cli_rx) = tokio::time::timeout(Duration::from_secs(2), connect_rx.recv())
            .await
            .expect("timed out waiting for client connection")
            .expect("channel closed");

        let first = tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .expect("timed out waiting for Subscribe")
            .expect("channel closed");
        assert!(
            matches!(first.kind, Some(CKind::Subscribe(_))),
            "expected Subscribe as first client message, got: {first:?}"
        );

        let second = tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .expect("timed out waiting for initial NodeStatus")
            .expect("channel closed");
        assert!(
            matches!(&second.kind, Some(CKind::NodeStatus(ns)) if ns.bound_ports == vec![8080]),
            "expected initial NodeStatus [8080] right after Subscribe, got: {second:?}"
        );

        // Mid-session change → a fresh NodeStatus with the new full set.
        bound_tx.send_modify(|set| {
            set.insert(8443);
        });
        let third = tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .expect("timed out waiting for changed NodeStatus")
            .expect("channel closed");
        assert!(
            matches!(&third.kind, Some(CKind::NodeStatus(ns)) if ns.bound_ports == vec![8080, 8443]),
            "expected NodeStatus [8080, 8443] after the set changed, got: {third:?}"
        );

        // Keep the server side alive until the assertions are done.
        drop(srv_tx);
    }

    // ── not-leader fast retry (#531) ─────────────────────────────────────────

    /// Fake server that rejects the first N `Stream` calls with the leader
    /// gate's `FAILED_PRECONDITION` before accepting like [`FakeDiscovery`].
    struct RejectingDiscovery {
        remaining_rejections: std::sync::atomic::AtomicU32,
        connect_tx: tpsc::Sender<ConnectPair>,
    }

    #[async_trait::async_trait]
    impl Discovery for RejectingDiscovery {
        type StreamStream = ReceiverStream<Result<ServerMessage, Status>>;

        async fn bootstrap(
            &self,
            _req: Request<crate::proto::v1::BootstrapRequest>,
        ) -> Result<Response<crate::proto::v1::BootstrapResponse>, Status> {
            Err(Status::unimplemented("test stub"))
        }

        async fn stream(
            &self,
            request: Request<Streaming<ClientMessage>>,
        ) -> Result<Response<Self::StreamStream>, Status> {
            use std::sync::atomic::Ordering;
            let prior = self
                .remaining_rejections
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .unwrap_or(0);
            if prior > 0 {
                return Err(Status::failed_precondition(crate::server::NOT_LEADER_MSG));
            }

            let (server_tx, server_rx) = tpsc::channel(16);
            let (client_tx, client_rx) = tpsc::channel(16);
            let mut inbound = request.into_inner();
            match inbound.message().await {
                Ok(Some(msg)) => {
                    let _ = client_tx.send(msg).await;
                }
                _ => return Err(Status::unavailable("client closed before Subscribe")),
            }
            tokio::spawn(async move {
                while let Ok(Some(msg)) = inbound.message().await {
                    if client_tx.send(msg).await.is_err() {
                        break;
                    }
                }
            });
            let connect_tx = self.connect_tx.clone();
            let _ = connect_tx.send((server_tx, client_rx)).await;
            Ok(Response::new(ReceiverStream::new(server_rx)))
        }
    }

    /// Not-leader rejections take the fast-retry band and bypass the
    /// exponential backoff entirely: with a prohibitive exponential base the
    /// client must still chew through the rejections and connect quickly.
    #[tokio::test]
    async fn not_leader_rejections_fast_retry_without_backoff_escalation() {
        const REJECTIONS: u32 = 3;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (connect_tx, mut connect_rx) = tpsc::channel(8);
        let service = RejectingDiscovery {
            remaining_rejections: std::sync::atomic::AtomicU32::new(REJECTIONS),
            connect_tx,
        };
        tokio::spawn(
            Server::builder()
                .add_service(DiscoveryServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );

        let registry = HealthRegistry::new();
        let handle = registry.register("disc", &["conn"]);
        let mut config = test_config(addr);
        // Prohibitive exponential band: if the not-leader path escalated the
        // exponential backoff, three retries would take tens of seconds and
        // the accept below would time out. Fast retries are ≤ 500 ms each.
        config.backoff_base = Duration::from_secs(30);
        config.backoff_cap = Duration::from_secs(30);
        let (_client, supervisor) =
            DiscoveryClient::spawn(config, handle, "conn").expect("test endpoints are valid URIs");
        let started = tokio::time::Instant::now();
        let _task = tokio::spawn(supervisor.run());

        let (srv_tx, mut cli_rx) = tokio::time::timeout(Duration::from_secs(5), connect_rx.recv())
            .await
            .expect("client did not reach the accepting server — fast retry not taken")
            .expect("channel closed");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(4),
            "three not-leader rejections must retry within the fast band, took {elapsed:?}"
        );

        let first = tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .expect("timed out waiting for Subscribe")
            .expect("channel closed");
        assert!(
            matches!(first.kind, Some(CKind::Subscribe(_))),
            "expected Subscribe after the accepted dial, got: {first:?}"
        );
        drop(srv_tx);
    }

    /// After the server closes the stream, the client reconnects; routing cells
    /// keep the last-good snapshot throughout the reconnect window.
    #[tokio::test]
    async fn serves_last_good_snapshot_across_server_bounce() {
        let (addr, mut connect_rx) = start_server().await;

        let registry = HealthRegistry::new();
        let handle = registry.register("disc", &["conn"]);
        let (client, supervisor) = DiscoveryClient::spawn(test_config(addr), handle, "conn")
            .expect("test endpoints are valid URIs");
        let _task = tokio::spawn(supervisor.run());

        // Session #1: push one snapshot, confirm Ack.
        let (srv_tx, mut cli_rx) = tokio::time::timeout(Duration::from_secs(2), connect_rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Drain Subscribe.
        tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .unwrap()
            .unwrap();

        srv_tx
            .send(Ok(empty_snapshot("v1", vec![1])))
            .await
            .unwrap();
        let ack = tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(&ack.kind, Some(CKind::Ack(_))));

        // Capture load of ingress table before bounce.
        let before_bounce = client.ingress_routes().load();

        // Drop the server-side sender to close the stream (simulates server bounce).
        drop(srv_tx);

        // Wait for the client to reconnect (a new connect pair arrives).
        let (_srv_tx2, mut cli_rx2) =
            tokio::time::timeout(Duration::from_secs(5), connect_rx.recv())
                .await
                .expect("client did not reconnect within timeout")
                .unwrap();

        // Cells must NOT be zeroed during reconnect; they hold the last-good snapshot.
        let during_reconnect = client.ingress_routes().load();
        assert!(
            Arc::ptr_eq(&before_bounce, &during_reconnect),
            "routing cell was zeroed or replaced during reconnect window"
        );

        // Second connection should start with Subscribe.
        let sub2 = tokio::time::timeout(Duration::from_secs(2), cli_rx2.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(sub2.kind, Some(CKind::Subscribe(_))),
            "expected Subscribe on reconnect, got: {sub2:?}"
        );
    }

    /// A delta as the FIRST message of a *reconnected* session Nacks with
    /// `DeltaBeforeFullSnapshot`, even though the client's resource cache still
    /// holds the prior session's full. The server's per-stream acked baseline is
    /// not replica-portable across a reconnect, so `expect_full` must reset to
    /// `true` per session end-to-end — this proves the reset survives the supervisor
    /// loop (not just the in-session flag flip).
    #[tokio::test]
    async fn delta_first_after_bounce_nacks_delta_before_full() {
        let (addr, mut connect_rx) = start_server().await;

        let registry = HealthRegistry::new();
        let handle = registry.register("disc", &["conn"]);
        let (_client, supervisor) = DiscoveryClient::spawn(test_config(addr), handle, "conn")
            .expect("test endpoints are valid URIs");
        let _task = tokio::spawn(supervisor.run());

        // Session #1: establish a full baseline (so the persisted cache has_full).
        let (srv_tx, mut cli_rx) = tokio::time::timeout(Duration::from_secs(2), connect_rx.recv())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .unwrap()
            .unwrap(); // drain Subscribe
        srv_tx
            .send(Ok(empty_snapshot("v1", vec![1])))
            .await
            .unwrap();
        let ack = tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(&ack.kind, Some(CKind::Ack(_))));

        // Bounce the stream.
        drop(srv_tx);

        // Session #2: reconnect, drain Subscribe, then send a DELTA as the very
        // first message.
        let (srv_tx2, mut cli_rx2) =
            tokio::time::timeout(Duration::from_secs(5), connect_rx.recv())
                .await
                .expect("client did not reconnect within timeout")
                .unwrap();
        let sub2 = tokio::time::timeout(Duration::from_secs(2), cli_rx2.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(sub2.kind, Some(CKind::Subscribe(_))));

        let delta_first = ServerMessage {
            kind: Some(SrvKind::Snapshot(Snapshot {
                version: "irrelevant-rejected-before-version-check".to_owned(),
                nonce: vec![2],
                full: false,
                resources: Vec::new(),
                removed_resources: Vec::new(),
                publish_seq: 0,
            })),
        };
        srv_tx2.send(Ok(delta_first)).await.unwrap();

        // The client must Nack it as delta-before-full — the invariant-1 guard
        // fires before any staging or version check.
        let nack = tokio::time::timeout(Duration::from_secs(2), cli_rx2.recv())
            .await
            .expect("timed out waiting for Nack")
            .unwrap();
        assert!(
            matches!(
                &nack.kind,
                Some(CKind::Nack(n))
                    if n.detail == crate::error::WireError::DeltaBeforeFullSnapshot.to_string()
            ),
            "expected a DeltaBeforeFullSnapshot Nack on the reconnected session, got: {nack:?}"
        );
    }

    /// When a snapshot fails to rebuild, the client sends Nack and retains the
    /// last-good routing tables.
    #[tokio::test]
    async fn retains_last_good_when_snapshot_fails_to_rebuild() {
        let (addr, mut connect_rx) = start_server().await;

        let registry = HealthRegistry::new();
        let handle = registry.register("disc", &["conn"]);
        let (client, supervisor) = DiscoveryClient::spawn(test_config(addr), handle, "conn")
            .expect("test endpoints are valid URIs");
        let _task = tokio::spawn(supervisor.run());

        let (srv_tx, mut cli_rx) = tokio::time::timeout(Duration::from_secs(2), connect_rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Drain Subscribe.
        tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Push a valid snapshot first to establish a last-good baseline.
        srv_tx
            .send(Ok(empty_snapshot("good-v1", vec![1])))
            .await
            .unwrap();
        let ack1 = tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(&ack1.kind, Some(CKind::Ack(_))));

        let last_good = client.ingress_routes().load();

        // Push a bad snapshot (invalid regex). Its version is a real content hash,
        // so the client passes the F6 self-check and fails at the regex compile —
        // the Nack echoes that version.
        let bad = bad_regex_snapshot("bad-v2", vec![2]);
        let bad_version = snapshot_version_of(&bad);
        srv_tx.send(Ok(bad)).await.unwrap();

        // Client should Nack.
        let nack = tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .expect("timed out waiting for Nack")
            .unwrap();
        assert!(
            matches!(&nack.kind, Some(CKind::Nack(n)) if n.version == bad_version),
            "expected Nack for {bad_version}, got: {nack:?}"
        );

        // Routing cells must still hold the last-good snapshot.
        let after_nack = client.ingress_routes().load();
        assert!(
            Arc::ptr_eq(&last_good, &after_nack),
            "routing cell was replaced after Nack — last-good invariant violated"
        );
    }

    /// End-to-end delta path over the fake server: a full establishes the keyed
    /// baseline, then a version-correct endpoint delta Acks and republishes the
    /// ingress table (the referencing partition recompiled), and the
    /// `{kind="delta"}` counter advances. A malformed delta then Nacks and the
    /// last-good table is retained.
    #[tokio::test]
    async fn applies_endpoint_delta_then_nacks_malformed_delta() {
        let (addr, mut connect_rx) = start_server().await;

        let registry = HealthRegistry::new();
        let handle = registry.register("disc", &["conn"]);
        let (client, supervisor) = DiscoveryClient::spawn(test_config(addr), handle, "conn")
            .expect("test endpoints are valid URIs");
        let _task = tokio::spawn(supervisor.run());

        let (srv_tx, mut cli_rx) = tokio::time::timeout(Duration::from_secs(2), connect_rx.recv())
            .await
            .unwrap()
            .unwrap();
        // Drain Subscribe.
        tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Full baseline: route svc.example.com → keyed endpoint ns/svc/80.
        let full =
            keyed_route_snapshot(vec![1], "svc.example.com", "ns", "svc", 80, "10.0.0.1:8080");
        let full_version = snapshot_version_of(&full);
        srv_tx.send(Ok(full)).await.unwrap();
        let ack1 = tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .expect("timed out waiting for full Ack")
            .unwrap();
        assert!(
            matches!(&ack1.kind, Some(CKind::Ack(a)) if a.version == full_version),
            "expected Ack for the full, got: {ack1:?}"
        );

        let table_after_full = client.ingress_routes().load();
        let deltas_before = crate::metrics::client_snapshots_applied_total()
            .with_label_values(&["delta"])
            .get();

        // Delta: the endpoint moves to a new address. Only the endpoint resource is
        // on the wire; the version is over the whole post-apply world.
        let d = endpoint_delta(vec![2], "svc.example.com", "ns", "svc", 80, "10.0.0.2:8080");
        let delta_version = snapshot_version_of(&d);
        assert_ne!(delta_version, full_version, "the delta changes the world");
        srv_tx.send(Ok(d)).await.unwrap();
        let ack2 = tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .expect("timed out waiting for delta Ack")
            .unwrap();
        assert!(
            matches!(&ack2.kind, Some(CKind::Ack(a)) if a.version == delta_version),
            "expected Ack for the delta, got: {ack2:?}"
        );

        // The referencing partition recompiled, so the ingress cell was republished.
        let table_after_delta = client.ingress_routes().load();
        assert!(
            !Arc::ptr_eq(&table_after_full, &table_after_delta),
            "the endpoint delta must republish the ingress routing table"
        );
        // The delta counter advanced (>= to tolerate concurrent tests).
        let deltas_after = crate::metrics::client_snapshots_applied_total()
            .with_label_values(&["delta"])
            .get();
        assert!(
            deltas_after > deltas_before,
            "the {{kind=delta}} counter must advance on a delta apply"
        );

        // A malformed delta (unparsable tombstone key) Nacks; last-good is retained.
        let bad_delta = ServerMessage {
            kind: Some(SrvKind::Snapshot(Snapshot {
                version: "irrelevant".to_owned(),
                nonce: vec![3],
                full: false,
                resources: Vec::new(),
                removed_resources: vec!["not-a-canonical-key".to_owned()],
                publish_seq: 0,
            })),
        };
        srv_tx.send(Ok(bad_delta)).await.unwrap();
        let nack = tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .expect("timed out waiting for Nack")
            .unwrap();
        assert!(
            matches!(&nack.kind, Some(CKind::Nack(_))),
            "expected Nack for the malformed delta, got: {nack:?}"
        );
        assert!(
            Arc::ptr_eq(&table_after_delta, &client.ingress_routes().load()),
            "the ingress table must be retained across a rejected delta"
        );
    }

    /// Readiness transitions: Pending → Ready on first snapshot;
    /// Degraded (not Pending/Failed) on disconnect after first snapshot.
    #[tokio::test]
    async fn readiness_transitions_are_correct() {
        use coxswain_core::health::CheckState;

        let (addr, mut connect_rx) = start_server().await;

        let registry = HealthRegistry::new();
        let handle = registry.register("disc", &["conn"]);
        let (_, supervisor) = DiscoveryClient::spawn(test_config(addr), handle, "conn")
            .expect("test endpoints are valid URIs");
        let _task = tokio::spawn(supervisor.run());

        // Before first snapshot: registry reports not ready.
        assert!(
            !registry.is_ready(),
            "registry must be NotReady before first snapshot"
        );

        let (srv_tx, mut cli_rx) = tokio::time::timeout(Duration::from_secs(2), connect_rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Drain Subscribe.
        tokio::time::timeout(Duration::from_secs(2), cli_rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Push first snapshot.
        srv_tx
            .send(Ok(empty_snapshot("v1", vec![1])))
            .await
            .unwrap();

        // Wait until registry becomes ready.
        poll_until(Duration::from_secs(2), || registry.is_ready().then_some(())).await;

        // Drop the stream to simulate disconnect.
        drop(srv_tx);
        drop(cli_rx);

        // Wait until the registry transitions to Degraded.
        poll_until(Duration::from_secs(5), || {
            let snap = registry.snapshot();
            let disc = snap.subsystems.get("disc")?;
            matches!(disc.state, CheckState::Degraded { .. }).then_some(())
        })
        .await;

        // Degraded counts as "ready" (is_ok() == true; /readyz stays 200).
        assert!(
            registry.is_ready(),
            "registry must report is_ready() == true when Degraded"
        );

        // Reconnect: the supervisor retries against the still-listening server.
        // Accept the new stream, drain its Subscribe, and push a fresh snapshot.
        let (srv_tx2, mut cli_rx2) =
            tokio::time::timeout(Duration::from_secs(5), connect_rx.recv())
                .await
                .unwrap()
                .unwrap();
        tokio::time::timeout(Duration::from_secs(2), cli_rx2.recv())
            .await
            .unwrap()
            .unwrap();
        srv_tx2
            .send(Ok(empty_snapshot("v2", vec![2])))
            .await
            .unwrap();

        // The post-reconnect snapshot must clear Degraded back to Ready — the
        // documented transition. Before the fix this never fired (health.ready
        // was gated on the first snapshot only), so the subsystem stayed
        // Degraded for the process lifetime.
        poll_until(Duration::from_secs(5), || {
            let snap = registry.snapshot();
            let disc = snap.subsystems.get("disc")?;
            matches!(disc.state, CheckState::Ready).then_some(())
        })
        .await;
    }

    /// `backoff_jitter` always returns a value within `[0, min(cap, base * 2^attempt)]`.
    #[test]
    fn backoff_stays_within_bounds() {
        let base = Duration::from_millis(250);
        let cap = Duration::from_secs(30);

        for attempt in 0u32..=12 {
            let ceiling_ms = 30_000u64.min(250u64.saturating_mul(1u64 << attempt.min(7)));
            // Sample many times to catch out-of-range values.
            for _ in 0..50 {
                let d = backoff_jitter(attempt, base, cap);
                assert!(
                    d.as_millis() as u64 <= ceiling_ms,
                    "attempt={attempt}: jitter {d:?} exceeded ceiling {ceiling_ms}ms"
                );
            }
        }
    }

    /// Backoff ceiling saturates at `cap` for high attempt numbers.
    #[test]
    fn backoff_caps_at_maximum() {
        let base = Duration::from_millis(250);
        let cap = Duration::from_millis(500);

        for attempt in 8u32..=20 {
            let d = backoff_jitter(attempt, base, cap);
            assert!(
                d <= cap,
                "attempt={attempt}: jitter {d:?} exceeded cap {cap:?}"
            );
        }
    }
}
