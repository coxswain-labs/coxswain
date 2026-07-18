//! Shared-proxy reconciler: cluster-wide watches feeding the shared-pool data
//! plane (`serve proxy --shared`).
//!
//! Owns the debounced watch + rebuild pipeline that turns reflector snapshots
//! into the full set of outputs the shared pool needs: Ingress + Gateway
//! routing tables, the TLS cert store, the per-listener status map (consumed
//! by `HotReloader`), the per-route and per-policy status maps (consumed by
//! the controller's status writer), and the cluster summary.
//!
//! Sibling reconcilers in this module narrow the scope:
//!
//! - `ControllerReconciler` (Step 7) — cluster-wide watches but no routing
//!   tables or TLS store; status-only output set.

use super::dedicated::{
    DedicatedBuildInputs, IngressBuildConfig, OwnedResources, build_dedicated_gateway_snapshot,
    compute_ownership, gateway_is_cut_over,
};
use super::route_builder::{
    RouteAttachKind, RouteBuildIo, build_client_certs, build_passthrough_routes, build_routes,
    build_tcp_routes, build_terminate_routes, build_tls, build_udp_routes, count_attached_routes,
    merge_backend_client_cert_health, resolve_backend_client_certs,
};
use crate::cluster::{ClusterSummaryInputs, build_cluster_summary};
use crate::gateway_api::{
    BackendPolicyIndex, BackendTlsIndex, GatewayApiReconciler, GrpcRouteReconciler,
    build_backend_policy_index, build_backend_tls_index, effective_proxy_config,
    resolve_client_traffic_policies,
};
use crate::gw_types::BackendTlsPolicy;
use crate::gw_types::GrpcRoute;
use crate::gw_types::HttpRoute;
use crate::gw_types::ListenerSet;
use crate::gw_types::TcpRoute;
use crate::gw_types::TlsRoute;
use crate::gw_types::UdpRoute;
use crate::gw_types::v::gatewayclasses::GatewayClass;
use crate::gw_types::v::gateways::Gateway;
use crate::gw_types::v::referencegrants::ReferenceGrant;
use crate::ingress::IngressPorts;
use crate::k8s_utils::{WatchScope, scoped_api};
use crate::merged_store::MergedStore;
use crate::reference_grants::{
    GrantSet, flatten_basic_auth_secret_grants, flatten_ca_grants, flatten_grants,
    flatten_ls_cert_grants, flatten_tcp_backend_grants, flatten_udp_backend_grants,
};
use crate::status::{
    GatewayListenerStatus, ListenerSource, SharedBackendTlsPolicyStatus,
    SharedClientTrafficPolicyStatus, SharedCoxswainBackendPolicyStatus,
    SharedCoxswainExternalAuthStatus, SharedGatewayListenerStatus, SharedRouteStatus,
};
use crate::status_queue::{StatusKey, StatusKind, StatusWorkqueue};
use async_trait::async_trait;
use coxswain_core::cluster::{PARAMETERS_REF_GROUP, PARAMETERS_REF_KIND, SharedClusterSummary};
use coxswain_core::crd::client_traffic_policy::ClientTrafficPolicy;
use coxswain_core::crd::coxswain_backend_policy::CoxswainBackendPolicy;
use coxswain_core::crd::{
    BasicAuth, Compression, CoxswainExternalAuth, CoxswainGatewayParameters,
    CoxswainIngressClassParameters, CoxswainRelayPolicy, IpAccessControl, JwtAuth,
    PathRewriteRegex, RateLimit, RequestSizeLimit, RetryPolicy,
};
use coxswain_core::dedicated_registry::{
    DedicatedRegistryData, DedicatedRoutingRegistry, DedicatedRoutingSnapshot,
};
use coxswain_core::fleet::{self, SharedFleet};
use coxswain_core::health::LivenessGate;
use coxswain_core::health::SubsystemHandle;
use coxswain_core::ownership::{ObjectKey, OwnedGateways};
use coxswain_core::publish_index::SharedGatewayPublishIndex;
use coxswain_core::routing::{
    BackendClientCert, SharedGatewayRoutingTable, SharedIngressRoutingTable, SharedTcpRouteTable,
    SharedTlsPassthroughTable, SharedUdpRouteTable,
};
use coxswain_core::tls::{SharedClientCertStore, SharedListenerHostnames, SharedPortTlsStore};
use futures::StreamExt;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Node, Pod, Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use kube::{
    Client,
    api::Api,
    runtime::{WatchStreamExt, reflector, watcher},
};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinSet;

/// Error returned when parsing `--ingress-default-backend`.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum IngressDefaultBackendParseError {
    /// No `:` separator found; expected `<namespace>/<service>:<port>`.
    #[error("missing port; expected <namespace>/<service>:<port>")]
    MissingPort,
    /// No `/` separator found before the port; expected `<namespace>/<service>:<port>`.
    #[error("missing namespace; expected <namespace>/<service>:<port>")]
    MissingNamespace,
    /// Port substring is not a valid integer.
    #[error("invalid port '{0}'; expected an integer")]
    InvalidPort(String),
    /// Namespace or service name is empty after parsing.
    #[error("namespace and service name must not be empty")]
    EmptyComponent,
}

/// A parsed reference to the controller-wide ingress default backend service.
///
/// Set via `--ingress-default-backend=<namespace>/<service>:<port>`.
/// Implements [`std::str::FromStr`]; parsing errors are reported as
/// [`IngressDefaultBackendParseError`].
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct IngressDefaultBackend {
    /// Kubernetes namespace of the backend service.
    pub namespace: String,
    /// Name of the backend service.
    pub name: String,
    /// Service port number.
    pub port: i32,
}

impl std::str::FromStr for IngressDefaultBackend {
    type Err = IngressDefaultBackendParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ns_name, port_str) = s
            .rsplit_once(':')
            .ok_or(IngressDefaultBackendParseError::MissingPort)?;
        let (namespace, name) = ns_name
            .split_once('/')
            .ok_or(IngressDefaultBackendParseError::MissingNamespace)?;
        let port: i32 = port_str
            .parse()
            .map_err(|_| IngressDefaultBackendParseError::InvalidPort(port_str.to_owned()))?;
        if namespace.is_empty() || name.is_empty() {
            return Err(IngressDefaultBackendParseError::EmptyComponent);
        }
        Ok(IngressDefaultBackend {
            namespace: namespace.to_string(),
            name: name.to_string(),
            port,
        })
    }
}

/// Diagnostic events emitted from the Ingress-rebuild path and forwarded to
/// the controller's event recorder task.
///
/// The channel sender is wired only in the controller role (via
/// [`ReconcilerOptions::ingress_event_tx`]). The proxy role passes `None`,
/// so no events are emitted and no `events` RBAC is required on the proxy
/// `ServiceAccount`.
#[non_exhaustive]
pub enum IngressEvent {
    /// Two Ingresses claimed the same `(port, host, path)` slot; the loser is
    /// silently ignored. The controller emits a `Warning` Event on the losing
    /// Ingress naming the winner.
    Conflict {
        /// Namespace of the losing (shadowed) Ingress.
        namespace: String,
        /// Name of the losing (shadowed) Ingress.
        name: String,
        /// Source identity `"{ns}/{name}"` of the winning Ingress.
        winner_route_id: String,
        /// Host on which the conflict occurred.
        host: String,
        /// Path on which the conflict occurred.
        path: String,
    },
    /// An `ingress.coxswain-labs.dev/*` annotation carried an invalid value;
    /// the feature is disabled and a `Warning` Event is emitted on the Ingress.
    InvalidAnnotation {
        /// Namespace of the affected Ingress.
        namespace: String,
        /// Name of the affected Ingress.
        name: String,
        /// Annotation key that failed to parse (e.g. `"ingress.coxswain-labs.dev/circuit-breaker-threshold"`).
        annotation: &'static str,
        /// Human-readable diagnostic (same text as the `tracing::warn!` that already fired).
        message: String,
    },
}

/// Optional configuration for a [`SharedProxyReconciler`].
#[non_exhaustive]
pub struct ReconcilerOptions {
    /// Which namespaces the namespaced watches are scoped to (multi-namespace
    /// watch, #59). [`WatchScope::ClusterWide`] watches every namespace
    /// (`Api::all`); [`WatchScope::Namespaces`] spawns one namespaced watch per
    /// listed namespace, merged into a single logical store. Built once at the
    /// argument boundary via [`WatchScope::parse`].
    pub watch_scope: WatchScope,
    /// The controller's own namespace (its pod's namespace). Namespaced infra
    /// resources that can live in the install namespace as well as the watched
    /// tenant namespaces — the fleet `Pod` watch and the
    /// `CoxswainGatewayParameters` / `CoxswainIngressClassParameters` `parametersRef`
    /// sources — are scoped to `watch_scope ∪ {pod_namespace}` via
    /// [`WatchScope::with_namespace`] rather than cluster-wide, so the least-privilege
    /// lockdown needs no cluster-wide read on them (#59). Empty by default (an
    /// unset value widens nothing when the scope is [`WatchScope::ClusterWide`]).
    pub pod_namespace: String,
    /// Controller-wide default backend for Ingress traffic with no matching rule.
    pub ingress_default_backend: Option<IngressDefaultBackend>,
    /// Ports on which Ingress routes are served.
    pub ingress_ports: IngressPorts,
    /// Pod role driving the metric-prefix selection (`coxswain_proxy_*` vs
    /// `coxswain_controller_*`). Default [`crate::MetricsPrefix::Proxy`].
    pub metrics_prefix: crate::MetricsPrefix,
    /// When `true`, spawn a 12th reflector that watches `Pod` objects labelled
    /// `app.kubernetes.io/name=coxswain` and publishes a [`SharedFleet`] snapshot
    /// on every change. Must only be set to `true` for the controller role — the
    /// shared-proxy ServiceAccount does not hold pod-read RBAC.
    pub watch_fleet: bool,
    /// When `true`, back the status-relevant stores (`Gateway`, `GatewayClass`,
    /// route kinds, `Ingress`, policies, …) with pre-created reflector stores
    /// and expose their read handles via [`StatusStores`] so the controller's
    /// unified status worker reconciles off the reflector's authoritative stores
    /// without duplicating watches (#347, #574). Controller role only — the
    /// proxy role never writes status and leaves this `false`.
    pub status_stores: bool,
    /// When `Some`, the reflector's rebuild pass enqueues every status-relevant
    /// object into this shared work queue after each rebuild, so the controller's
    /// single leader-gated worker reconciles it (#574). This replaces the lossy
    /// `Subscription` fan-out that fed the old per-kind `Controller` work-queues.
    /// Controller role only; the proxy role leaves this `None`.
    pub status_queue: Option<StatusWorkqueue>,
    /// When `Some`, the reconciler forwards Ingress diagnostic events
    /// (route conflicts, annotation parse failures) to the controller's event
    /// recorder task via this sender. Set only for the controller role; the
    /// proxy role leaves this `None` so no `events` RBAC is needed on the
    /// proxy `ServiceAccount`.
    pub ingress_event_tx: Option<tokio::sync::mpsc::Sender<IngressEvent>>,
    /// When `true` (default), spawn Gateway API reflectors (`Gateway`,
    /// `GatewayClass`, `HTTPRoute`, `GRPCRoute`, `TLSRoute`, `ListenerSet`,
    /// `ReferenceGrant`, `BackendTLSPolicy`, `ConfigMap`) and register the
    /// `gateway_api_crds` readiness check. When `false`, all Gateway API
    /// watches are skipped entirely.
    ///
    /// If `true` but the CRDs are absent at startup, readiness fails under
    /// the `gateway_api_crds` check and a background re-probe loop
    /// self-heals once the CRDs appear (no pod restart required).
    pub enable_gateway_api: bool,
    /// When `true` (default), spawn Ingress reflectors (`Ingress`,
    /// `IngressClass`, `CoxswainIngressClassParameters`) and register their
    /// readiness checks. When `false`, all Ingress watches are skipped.
    pub enable_ingress: bool,
    /// When `true`, spawn the background task that fetches and refreshes
    /// remote JWKS endpoints named by `JwtAuth` CRs (#441). Must only be set
    /// to `true` for the controller role — the read-only data plane must never
    /// egress to an identity provider (the Istio model, not Envoy's default
    /// proxy-side fetch); see [`crate::jwks`].
    pub fetch_remote_jwks: bool,
    /// Bounds for the adaptive rebuild debounce (#512). Replaces the
    /// reconciler's original fixed 500 ms coalescing timer — see
    /// `super::debounce::settle`.
    pub debounce: crate::DebounceSettings,
    /// When `Some`, spawn the relist liveness backstop (#573): a monitor that
    /// trips this gate — failing `/healthz` so kubelet restarts the pod — if any
    /// reflector's watch relist stays incomplete past
    /// [`crate::metrics::RELIST_STUCK_WINDOW`]. Controller role only; the proxy
    /// role leaves this `None` (its reflectors don't gate cluster status).
    pub liveness_gate: Option<LivenessGate>,
}

impl Default for ReconcilerOptions {
    fn default() -> Self {
        Self {
            watch_scope: WatchScope::ClusterWide,
            pod_namespace: String::new(),
            ingress_default_backend: None,
            ingress_ports: IngressPorts::default(),
            metrics_prefix: crate::MetricsPrefix::Proxy,
            watch_fleet: false,
            status_stores: false,
            status_queue: None,
            ingress_event_tx: None,
            enable_gateway_api: true,
            fetch_remote_jwks: false,
            enable_ingress: true,
            debounce: crate::DebounceSettings::default(),
            liveness_gate: None,
        }
    }
}

/// Idle-timeout (seconds) for the small, status-gating control-plane watches
/// (Gateway API objects, CRs, Namespace, Ingress) — the #574 watch-stall
/// backstop.
///
/// In kube-runtime 4.0 [`watcher::Config::timeout`] is *both* the server-side
/// `timeoutSeconds` and a client-side idle deadline: a watch that delivers
/// nothing for `timeout + 5s` is treated as dead and reconnected (a full
/// relist). A silently-stalled watch — HTTP/2 head-of-line collateral on the
/// shared client connection, the residual #575 failure — therefore self-heals
/// within this window instead of serving a stale view for minutes. Set well
/// below kube's 290s default so a control-plane stall is bounded to ~this long;
/// these resources are low-cardinality, so the periodic relist a quiet watch
/// incurs is cheap. Bulk caches keep the 290s default — see
/// [`bulk_watch_config`].
const CONTROL_WATCH_IDLE_TIMEOUT_SECS: u32 = 45;

/// Periodic resync cadence for the rebuild loop — the #574 watch-stall backstop.
///
/// The rebuild trigger is a lossless `watch` channel (see [`ReflectorEffects`]),
/// so a *delivered* watch event can no longer be dropped before the rebuild
/// loop observes it — this tick is NOT the recovery path for a raced wake. It
/// exists for the one gap the trigger can't cover: a watch stream that goes
/// silent *without* delivering an event (so nothing bumps the trigger) while its
/// store still holds a now-stale snapshot. The periodic tick re-derives from the
/// authoritative stores unconditionally, so such a gap costs at most this long.
/// Idempotent: a resync with no drift republishes identical snapshots. Works
/// alongside [`CONTROL_WATCH_IDLE_TIMEOUT_SECS`], which forces a stalled watch to
/// relist; this tick additionally re-derives even before that relist lands.
const REBUILD_RESYNC_PERIOD: Duration = Duration::from_secs(30);

/// Watch config for the small control-plane resources — kube defaults plus the
/// tightened [`CONTROL_WATCH_IDLE_TIMEOUT_SECS`] idle timeout.
fn control_watch_config() -> watcher::Config {
    watcher::Config::default().timeout(CONTROL_WATCH_IDLE_TIMEOUT_SECS)
}

/// Watch config for the high-cardinality bulk caches (EndpointSlice, TLS
/// Secrets, Service, ConfigMap). Kube's default 290s idle timeout is retained
/// deliberately: a full relist of these on every idle window would be far more
/// expensive than for the control-plane resources, and their stalls are covered
/// by the relist-liveness `LivenessGate` (pod restart) rather than a tight
/// per-watch relist.
fn bulk_watch_config() -> watcher::Config {
    watcher::Config::default()
}

/// Build a dedicated kube [`Client`] — its own HTTP/2 connection — for one watch,
/// from the shared inferred [`kube::Config`] (#574).
///
/// All watches sharing one client means one HTTP/2 connection, where a single
/// stalled/slow stream head-of-line-blocks every sibling watch on that
/// connection — the collateral that made the #573 wedge and its #575 residual
/// stall span unrelated kinds. Giving each watch its own connection removes that
/// coupling ("no shared-connection collateral"): a stall is contained to the one
/// watch that owns the connection, and the idle-timeout/relist backstops recover
/// it without freezing the rest of the control plane. Falls back to sharing the
/// primary connection only if a fresh client cannot be built (the config already
/// produced one, so this is unreachable outside a transient TLS/config fault).
fn watch_client(kube_config: &kube::Config, fallback: &Client) -> Client {
    Client::try_from(kube_config.clone()).unwrap_or_else(|e| {
        tracing::warn!(
            error = %e,
            "failed to build a dedicated watch client; sharing the primary connection"
        );
        fallback.clone()
    })
}

/// The inputs [`watch_client`] needs to mint a fresh per-watch connection —
/// bundled so [`add_gateway_api_reflectors`] stays within the 7-argument
/// threshold.
#[derive(Clone, Copy)]
struct WatchClientSource<'a> {
    /// Inferred config used to build each fresh per-watch client.
    config: &'a kube::Config,
    /// Primary client, used only as the fallback if a fresh build fails.
    fallback: &'a Client,
}

impl WatchClientSource<'_> {
    /// A dedicated client (own connection) for one watch.
    fn client(&self) -> Client {
        watch_client(self.config, self.fallback)
    }
}

/// Health-registry handles consumed by the [`SharedProxyReconciler`].
///
/// Each reflector flips a per-source check on `controller` to `Ready` once it
/// has emitted its first `InitDone` (the authoritative "initial sync complete"
/// signal). After the first successful routing-table publish, the reconciler
/// also flips `controller.routing_table_built` and `proxy.routing_table_loaded`.
#[non_exhaustive]
pub struct ReconcilerHealth {
    /// Handle for the `controller` subsystem (per-reflector + `routing_table_built`).
    pub controller: SubsystemHandle,
    /// Handle for the `proxy` subsystem (`routing_table_loaded`).
    pub proxy: SubsystemHandle,
}

impl ReconcilerHealth {
    /// Construct a `ReconcilerHealth` from the two subsystem handles.
    #[must_use]
    pub fn new(controller: SubsystemHandle, proxy: SubsystemHandle) -> Self {
        Self { controller, proxy }
    }
}

/// Pingora background service that maintains reflector-backed stores for
/// `HTTPRoute`, `Ingress`, `IngressClass`, `Gateway`, `GatewayClass`,
/// `BackendTLSPolicy`, `ConfigMap`, and `EndpointSlice`, and rebuilds the routing
/// table whenever any of them change — with a 500 ms trailing-edge debounce to
/// coalesce burst updates (e.g. rolling deploys).
///
/// When [`ReconcilerOptions::watch_fleet`] is `true` (controller role only), a
/// 12th reflector watches `Pod` objects and publishes a [`SharedFleet`] snapshot
/// immediately on every change.
#[non_exhaustive]
pub struct SharedProxyReconciler {
    ingress_routes: SharedIngressRoutingTable,
    gateway_routes: SharedGatewayRoutingTable,
    tls: SharedPortTlsStore,
    /// Per-Ingress client-certificate mTLS config (#267). Keyed by SNI host, parallel to `tls`.
    client_certs: SharedClientCertStore,
    /// Per-port HTTPS Gateway-listener hostname snapshot (GEP-3567, #96).
    listener_hostnames: SharedListenerHostnames,
    listener_status: SharedGatewayListenerStatus,
    cluster_summary: SharedClusterSummary,
    /// SNI-keyed TLS passthrough routing table for TLSRoute / GEP-2643 (#70).
    passthrough_routes: SharedTlsPassthroughTable,
    /// SNI-keyed TLS terminate routing table for TLSRouteModeTerminate (#481).
    terminate_routes: SharedTlsPassthroughTable,
    /// Port-keyed TCP routing table for TCPRoute / GEP-1901 (#505).
    tcp_routes: SharedTcpRouteTable,
    /// Port-keyed UDP routing table for UDPRoute / GEP-2645 (#506).
    udp_routes: SharedUdpRouteTable,
    /// Per-cut-over-Gateway routing snapshots. Written by this reconciler on
    /// every rebuild; read by the discovery server to serve `Scope::Gateway` subscribers.
    dedicated_registry: DedicatedRoutingRegistry,
    route_status: SharedRouteStatus,
    /// Per-(GRPCRoute, parent) health — a dedicated instance separate from `route_status`
    /// because `RouteParentKey` is kind-neutral and an HTTPRoute and GRPCRoute with the
    /// same name+ns+gateway would collide in one map.
    grpc_route_status: SharedRouteStatus,
    /// Per-(TLSRoute, parent) health — separate from `route_status` and `grpc_route_status`
    /// for the same kind-neutrality reason.
    tls_route_status: SharedRouteStatus,
    /// Per-(TCPRoute, parent) health — separate from the other route-kind status
    /// maps for the same kind-neutrality reason.
    tcp_route_status: SharedRouteStatus,
    /// Per-(UDPRoute, parent) health — separate from the other route-kind status
    /// maps for the same kind-neutrality reason.
    udp_route_status: SharedRouteStatus,
    policy_status: SharedBackendTlsPolicyStatus,
    ctp_status: SharedClientTrafficPolicyStatus,
    /// Per-`CoxswainBackendPolicy` ancestor health (#354).
    cbp_status: SharedCoxswainBackendPolicyStatus,
    /// Per-`CoxswainExternalAuth` ancestor health (#23).
    external_auth_status: SharedCoxswainExternalAuthStatus,
    /// Per-Gateway publish-sequence stamps for the #531 `Programmed` ack
    /// gate. Stamped at the end of every rebuild, after all cells above.
    publish_index: SharedGatewayPublishIndex,
    fleet: SharedFleet,
    owned_gateways: OwnedGateways,
    leader: Arc<AtomicBool>,
    health: ReconcilerHealth,
    controller_name: String,
    opts: ReconcilerOptions,
    /// Reflector-store writers (status-relevant types) pre-created in `new` when
    /// `opts.status_stores` is set; taken by `start` and moved into
    /// `spawn_tasks`. `None` when status stores are disabled (proxy role).
    status_store_writers: parking_lot::Mutex<Option<StatusStoreWriters>>,
    /// The read handles matching `status_store_writers`, taken once by
    /// [`SharedProxyReconciler::status_stores`].
    status_stores: parking_lot::Mutex<Option<StatusStores>>,
    /// Operator-specific store writers (`params`, `Node`, and the shared
    /// `namespaces`/`services`/`pods`) pre-created in `new` when `opts.status_stores`
    /// is set; taken by `start` and moved into `spawn_tasks` (#574 operator fold).
    operator_store_writers: parking_lot::Mutex<Option<OperatorStoreWriters>>,
    /// The read handles matching `operator_store_writers`, taken once by
    /// [`SharedProxyReconciler::operator_stores`].
    operator_stores: parking_lot::Mutex<Option<OperatorStores>>,
}

/// The `Shared<T>` outputs the [`SharedProxyReconciler`] writes into on each rebuild.
///
/// Bundling them lets [`SharedProxyReconciler::new`] stay under the workspace
/// `clippy::too_many_arguments` threshold; callers pass one
/// `ReconcilerOutputs` struct instead of several positional handles.
// intentionally open: field-literal constructed in coxswain-controller/status_writer.rs and coxswain-bin/lib.rs.
pub struct ReconcilerOutputs {
    /// Ingress-flavored routing table snapshot, updated on every successful Ingress build.
    pub ingress_routes: SharedIngressRoutingTable,
    /// Gateway-API-flavored routing table snapshot, updated on every successful Gateway build.
    pub gateway_routes: SharedGatewayRoutingTable,
    /// TLS certificate store snapshot, updated whenever a `kubernetes.io/tls` Secret changes.
    pub tls: SharedPortTlsStore,
    /// Per-Ingress client-certificate mTLS config snapshot, updated whenever an
    /// `auth-tls`-labelled Secret changes (#267). Keyed by SNI host, parallel to `tls`.
    pub client_certs: SharedClientCertStore,
    /// Per-port HTTPS Gateway-listener hostname snapshot (GEP-3567, #96).
    pub listener_hostnames: SharedListenerHostnames,
    /// Per-listener Gateway health used by status writes and the hot-reloader.
    pub listener_status: SharedGatewayListenerStatus,
    /// Cluster aggregate (per-Gateway / per-Ingress summary) consumed by the
    /// controller's `/cluster` admin endpoint. Updated on every rebuild.
    pub cluster_summary: SharedClusterSummary,
    /// Per-cut-over-Gateway routing snapshots, keyed by [`ObjectKey`].  Updated
    /// on every rebuild by the shared reconciler; read by the discovery server
    /// when serving `coxswain_discovery::Scope::Gateway` subscribers (#426).
    pub dedicated_registry: DedicatedRoutingRegistry,
    /// SNI-keyed TLS passthrough routing table for TLSRoute / GEP-2643 (#70).
    pub passthrough_routes: SharedTlsPassthroughTable,
    /// SNI-keyed TLS terminate routing table for TLSRouteModeTerminate (#481).
    ///
    /// The proxy terminates TLS on accept, then L4-splices the decrypted stream to
    /// the backend over plain TCP. Isolated from the passthrough table so Mixed-mode
    /// listeners on the same port cannot cross-leak routes.
    pub terminate_routes: SharedTlsPassthroughTable,
    /// Port-keyed TCP routing table for TCPRoute / GEP-1901 (#505).
    ///
    /// No SNI dimension — a TCP listener has exactly one mode, so this table is a
    /// plain `port → BackendGroup` map, isolated from the TLS-flavored tables.
    pub tcp_routes: SharedTcpRouteTable,
    /// Port-keyed UDP routing table for UDPRoute / GEP-2645 (#506).
    ///
    /// No SNI dimension — a UDP listener has exactly one mode, so this table is a
    /// plain `port → BackendGroup` map, isolated from the TCP/TLS-flavored tables.
    pub udp_routes: SharedUdpRouteTable,
}

/// Read handles onto the reflector's authoritative status-relevant stores,
/// consumed by the controller's unified status worker (#574).
///
/// The worker resolves each drained [`StatusKey`] to its live object through the
/// matching reader here, then reconciles `*/status`. These are the *same* synced
/// stores the reflector's rebuild pass reads and enqueues from — one authoritative
/// cache, no duplicate watch. Cheap to [`Clone`] (each field is an `Arc`-backed
/// store handle). Obtained once from [`SharedProxyReconciler::status_stores`].
#[non_exhaustive]
#[derive(Clone)]
pub struct StatusStores {
    /// `Gateway` store reader.
    pub gateways: MergedStore<Gateway>,
    /// `GatewayClass` store reader.
    pub gateway_classes: MergedStore<GatewayClass>,
    /// `HTTPRoute` store reader.
    pub routes: MergedStore<HttpRoute>,
    /// `GRPCRoute` store reader.
    pub grpc_routes: MergedStore<GrpcRoute>,
    /// `Ingress` store reader.
    pub ingresses: MergedStore<Ingress>,
    /// `IngressClass` store reader.
    pub ingress_classes: MergedStore<IngressClass>,
    /// `BackendTLSPolicy` store reader.
    pub policies: MergedStore<BackendTlsPolicy>,
    /// `TLSRoute` store reader.
    pub tls_routes: MergedStore<TlsRoute>,
    /// `TCPRoute` store reader.
    pub tcp_routes: MergedStore<TcpRoute>,
    /// `UDPRoute` store reader.
    pub udp_routes: MergedStore<UdpRoute>,
    /// `XListenerSet` store reader (GEP-1713).
    pub listener_sets: MergedStore<ListenerSet>,
    /// `ClientTrafficPolicy` store reader (#327).
    pub client_traffic_policies: MergedStore<ClientTrafficPolicy>,
    /// `CoxswainBackendPolicy` store reader (#354).
    pub coxswain_backend_policies: MergedStore<CoxswainBackendPolicy>,
    /// `CoxswainExternalAuth` store reader (#23).
    pub coxswain_external_auths: MergedStore<CoxswainExternalAuth>,
}

/// Pre-created reflector-store writers for the status-relevant types.
///
/// Built in [`SharedProxyReconciler::new`] (so the matching [`StatusStores`]
/// readers exist at wiring time, before `start`), stashed behind a `Mutex`, and
/// moved into [`spawn_tasks`] on `start` to drive the reflectors — the worker
/// reads the very stores these writers fill.
struct StatusStoreWriters {
    // Namespaced types carry one writer per watched namespace (#59); the
    // cluster-scoped `gateway_classes` / `ingress_classes` carry a single writer.
    gateways: Vec<reflector::store::Writer<Gateway>>,
    gateway_classes: reflector::store::Writer<GatewayClass>,
    routes: Vec<reflector::store::Writer<HttpRoute>>,
    grpc_routes: Vec<reflector::store::Writer<GrpcRoute>>,
    ingresses: Vec<reflector::store::Writer<Ingress>>,
    ingress_classes: reflector::store::Writer<IngressClass>,
    policies: Vec<reflector::store::Writer<BackendTlsPolicy>>,
    tls_routes: Vec<reflector::store::Writer<TlsRoute>>,
    tcp_routes: Vec<reflector::store::Writer<TcpRoute>>,
    udp_routes: Vec<reflector::store::Writer<UdpRoute>>,
    listener_sets: Vec<reflector::store::Writer<ListenerSet>>,
    client_traffic_policies: Vec<reflector::store::Writer<ClientTrafficPolicy>>,
    coxswain_backend_policies: Vec<reflector::store::Writer<CoxswainBackendPolicy>>,
    coxswain_external_auths: Vec<reflector::store::Writer<CoxswainExternalAuth>>,
}

/// `Option`-wrapped form of [`StatusStoreWriters`] produced by
/// [`StatusStoreWriters::into_option_writers`].
///
/// Named to avoid a `clippy::type_complexity` violation on the method's return type.
struct StatusStoreOptionWriters {
    routes: Option<Vec<reflector::store::Writer<HttpRoute>>>,
    grpc_routes: Option<Vec<reflector::store::Writer<GrpcRoute>>>,
    ingresses: Option<Vec<reflector::store::Writer<Ingress>>>,
    ingress_classes: Option<reflector::store::Writer<IngressClass>>,
    gateways: Option<Vec<reflector::store::Writer<Gateway>>>,
    gateway_classes: Option<reflector::store::Writer<GatewayClass>>,
    policies: Option<Vec<reflector::store::Writer<BackendTlsPolicy>>>,
    tls_routes: Option<Vec<reflector::store::Writer<TlsRoute>>>,
    tcp_routes: Option<Vec<reflector::store::Writer<TcpRoute>>>,
    udp_routes: Option<Vec<reflector::store::Writer<UdpRoute>>>,
    listener_sets: Option<Vec<reflector::store::Writer<ListenerSet>>>,
    client_traffic_policies: Option<Vec<reflector::store::Writer<ClientTrafficPolicy>>>,
    coxswain_backend_policies: Option<Vec<reflector::store::Writer<CoxswainBackendPolicy>>>,
    coxswain_external_auths: Option<Vec<reflector::store::Writer<CoxswainExternalAuth>>>,
}

impl StatusStoreWriters {
    /// Unwrap an `Option<Self>` into a [`StatusStoreOptionWriters`].
    ///
    /// `None` maps every field to `None`; `Some(w)` wraps each field in `Some`.
    /// Used in [`spawn_tasks`] to feed the optional pre-created writers into
    /// [`scoped_reader_writers`] / [`cluster_reader_writer`] without repeating the
    /// `None` arm at every site.
    fn into_option_writers(opt: Option<Self>) -> StatusStoreOptionWriters {
        match opt {
            Some(w) => StatusStoreOptionWriters {
                routes: Some(w.routes),
                grpc_routes: Some(w.grpc_routes),
                ingresses: Some(w.ingresses),
                ingress_classes: Some(w.ingress_classes),
                gateways: Some(w.gateways),
                gateway_classes: Some(w.gateway_classes),
                policies: Some(w.policies),
                tls_routes: Some(w.tls_routes),
                tcp_routes: Some(w.tcp_routes),
                udp_routes: Some(w.udp_routes),
                listener_sets: Some(w.listener_sets),
                client_traffic_policies: Some(w.client_traffic_policies),
                coxswain_backend_policies: Some(w.coxswain_backend_policies),
                coxswain_external_auths: Some(w.coxswain_external_auths),
            },
            None => StatusStoreOptionWriters {
                routes: None,
                grpc_routes: None,
                ingresses: None,
                ingress_classes: None,
                gateways: None,
                gateway_classes: None,
                policies: None,
                tls_routes: None,
                tcp_routes: None,
                udp_routes: None,
                listener_sets: None,
                client_traffic_policies: None,
                coxswain_backend_policies: None,
                coxswain_external_auths: None,
            },
        }
    }
}

/// Read handles onto the stores the dedicated-provisioning operator reconciles
/// against (#574). Handed to the controller so the operator runs off the *same*
/// authoritative watch fabric as the status worker — no duplicate Gateway /
/// GatewayClass / ListenerSet / Namespace / Service watches. `CoxswainGatewayParameters`
/// and `Node` are watched only for the operator; the rest are shared with routing
/// and status. The operator filters the (superset) fleet-Pod and bulk-Service
/// stores in memory to its dedicated-proxy Pods / VIP Services.
#[non_exhaustive]
#[derive(Clone)]
pub struct OperatorStores {
    /// `GatewayClass` reader (shared with [`StatusStores`]).
    pub gateway_classes: MergedStore<GatewayClass>,
    /// `CoxswainGatewayParameters` reader (operator-only watch).
    pub params: MergedStore<CoxswainGatewayParameters>,
    /// `CoxswainRelayPolicy` reader (operator-only watch, #589): per-namespace relay
    /// tuning overlaid onto the #584 global relay defaults.
    pub relay_policies: MergedStore<CoxswainRelayPolicy>,
    /// Fleet `Pod` reader (`app.kubernetes.io/name=coxswain`); the operator
    /// filters to dedicated-proxy Pods.
    pub pods: MergedStore<Pod>,
    /// `Node` reader (operator-only watch; consulted for NodePort Services).
    pub nodes: MergedStore<Node>,
    /// `Gateway` reader (shared with [`StatusStores`]).
    pub gateways: MergedStore<Gateway>,
    /// Bulk `Service` reader; the operator filters to the per-Gateway VIP Services.
    pub services: MergedStore<Service>,
    /// `XListenerSet` reader (shared with [`StatusStores`], GEP-1713).
    pub listener_sets: MergedStore<ListenerSet>,
    /// `Namespace` reader (shared with routing's `allowedListeners` gate).
    pub namespaces: MergedStore<Namespace>,
}

/// Pre-created writers for the operator-specific stores (`params`, `nodes`) and
/// the stores the operator shares with routing (`namespaces`, `services`,
/// `pods`) — created in [`SharedProxyReconciler::new`] so the matching
/// [`OperatorStores`] readers exist at wiring time, then driven by `spawn_tasks`.
struct OperatorStoreWriters {
    // `nodes` and `namespaces` are genuinely cluster-scoped resources, watched
    // cluster-wide (single writer). The namespaced watches fan out one writer per
    // scope namespace (#59): `relay_policies` over the tenant `watch_scope` (a relay
    // policy governs its own tenant namespace); `params`, `services`, and the fleet
    // `pods` over the wider infra scope (`watch_scope ∪ {pod_namespace}`) so they
    // also see the install namespace (VIP Services, params defaults, fleet pods).
    params: Vec<reflector::store::Writer<CoxswainGatewayParameters>>,
    relay_policies: Vec<reflector::store::Writer<CoxswainRelayPolicy>>,
    nodes: reflector::store::Writer<Node>,
    namespaces: reflector::store::Writer<Namespace>,
    services: Vec<reflector::store::Writer<Service>>,
    pods: Vec<reflector::store::Writer<Pod>>,
}

impl SharedProxyReconciler {
    /// Construct a new reconciler (does not start the watch loop).
    ///
    /// `leader` is the shared leader-election flag the controller pod owns; the
    /// proxy pod passes a fresh `Arc::new(AtomicBool::new(false))` since it never
    /// holds a lease. The reconciler reads it once per rebuild to populate
    /// [`coxswain_core::cluster::ControllerSummary::leader`].
    pub fn new(
        outputs: ReconcilerOutputs,
        owned_gateways: OwnedGateways,
        leader: Arc<AtomicBool>,
        health: ReconcilerHealth,
        controller_name: String,
        opts: ReconcilerOptions,
    ) -> Self {
        let ReconcilerOutputs {
            ingress_routes,
            gateway_routes,
            tls,
            client_certs,
            listener_hostnames,
            listener_status,
            cluster_summary,
            dedicated_registry,
            passthrough_routes,
            terminate_routes,
            tcp_routes,
            udp_routes,
        } = outputs;
        // When the controller role asks for status stores, pre-create the
        // status-relevant reflector stores now (sync) so their read handles
        // (`StatusStores`) exist before `start` runs and can be handed to the
        // controller's unified status worker at wiring time. Plain reflector
        // stores: the worker reads them, the rebuild pass enqueues from them, and
        // nothing fans out to back-pressure the root reflector (#574).
        let (status_store_writers, status_stores, operator_store_writers, operator_stores) = if opts
            .status_stores
        {
            // Pre-create one reflector store per watched namespace for namespaced
            // types (#59); cluster-scoped types (and those deliberately watched
            // cluster-wide) get a single store wrapped in a one-element
            // `MergedStore`. The readers stay a uniform `MergedStore<K>` either
            // way; the writers are `Vec` (namespaced) or single (cluster).
            let scope = &opts.watch_scope;
            // Infra scope for namespaced resources that also live in the install
            // namespace (fleet `Pod`, `CoxswainGatewayParameters`): the tenant
            // watch set widened with the controller's own namespace (#59). Under
            // `ClusterWide` this is unchanged (still `Api::all`).
            let infra_scope = opts.watch_scope.with_namespace(&opts.pod_namespace);
            let (gateways_r, gateways_w) = scoped_reader_writers::<Gateway>(None, scope);
            let (gateway_classes_r, gateway_classes_w) =
                cluster_reader_writer::<GatewayClass>(None);
            let (routes_r, routes_w) = scoped_reader_writers::<HttpRoute>(None, scope);
            let (grpc_routes_r, grpc_routes_w) = scoped_reader_writers::<GrpcRoute>(None, scope);
            let (ingresses_r, ingresses_w) = scoped_reader_writers::<Ingress>(None, scope);
            let (ingress_classes_r, ingress_classes_w) =
                cluster_reader_writer::<IngressClass>(None);
            let (policies_r, policies_w) = scoped_reader_writers::<BackendTlsPolicy>(None, scope);
            let (tls_routes_r, tls_routes_w) = scoped_reader_writers::<TlsRoute>(None, scope);
            let (tcp_routes_r, tcp_routes_w) = scoped_reader_writers::<TcpRoute>(None, scope);
            let (udp_routes_r, udp_routes_w) = scoped_reader_writers::<UdpRoute>(None, scope);
            let (listener_sets_r, listener_sets_w) =
                scoped_reader_writers::<ListenerSet>(None, scope);
            let (client_traffic_policies_r, client_traffic_policies_w) =
                scoped_reader_writers::<ClientTrafficPolicy>(None, scope);
            let (coxswain_backend_policies_r, coxswain_backend_policies_w) =
                scoped_reader_writers::<CoxswainBackendPolicy>(None, scope);
            let (coxswain_external_auths_r, coxswain_external_auths_w) =
                scoped_reader_writers::<CoxswainExternalAuth>(None, scope);
            // Operator-specific + shared stores (#574 operator fold). `params` and
            // `nodes` are watched only for the operator; `namespaces`/`services`/
            // `pods` are shared with routing/fleet. `gateways`/`gateway_classes`/
            // `listener_sets` reuse the status readers above (same watch, cloned
            // handle). `Node` / `Namespace` are genuinely cluster-scoped, so those stay
            // cluster-wide. The namespaced watches fan out per scope (#59):
            // `CoxswainRelayPolicy` over the tenant `scope` (governs its own tenant
            // namespace); `params`, `services`, and fleet `pods` over `infra_scope`
            // (tenant ∪ install namespace) so the lockdown needs no cluster-wide read.
            let (params_r, params_w) =
                scoped_reader_writers::<CoxswainGatewayParameters>(None, &infra_scope);
            let (relay_policies_r, relay_policies_w) =
                scoped_reader_writers::<CoxswainRelayPolicy>(None, scope);
            let (nodes_r, nodes_w) = cluster_reader_writer::<Node>(None);
            let (namespaces_r, namespaces_w) = cluster_reader_writer::<Namespace>(None);
            // `Service` fans over `infra_scope` (tenant ∪ install namespace), NOT
            // the plain tenant scope: besides tenant backend Services, the rebuild
            // reads the per-Gateway shared-VIP Services (#472) — which the operator
            // provisions in the controller's own namespace — to resolve each
            // Gateway listener's internal bind port. Scoping Services to tenants
            // only would leave that `(gateway, port) → internal_port` map empty, so
            // the proxy would bind the listener port instead of the VIP-mapped
            // internal port and the Gateway VIP would be unreachable.
            let (services_r, services_w) = scoped_reader_writers::<Service>(None, &infra_scope);
            let (pods_r, pods_w) = scoped_reader_writers::<Pod>(None, &infra_scope);
            let op_stores = OperatorStores {
                gateway_classes: gateway_classes_r.clone(),
                params: params_r,
                relay_policies: relay_policies_r,
                pods: pods_r,
                nodes: nodes_r,
                gateways: gateways_r.clone(),
                services: services_r,
                listener_sets: listener_sets_r.clone(),
                namespaces: namespaces_r,
            };
            let op_writers = OperatorStoreWriters {
                params: params_w,
                relay_policies: relay_policies_w,
                nodes: nodes_w,
                namespaces: namespaces_w,
                services: services_w,
                pods: pods_w,
            };
            let stores = StatusStores {
                gateways: gateways_r,
                gateway_classes: gateway_classes_r,
                routes: routes_r,
                grpc_routes: grpc_routes_r,
                ingresses: ingresses_r,
                ingress_classes: ingress_classes_r,
                policies: policies_r,
                tls_routes: tls_routes_r,
                tcp_routes: tcp_routes_r,
                udp_routes: udp_routes_r,
                listener_sets: listener_sets_r,
                client_traffic_policies: client_traffic_policies_r,
                coxswain_backend_policies: coxswain_backend_policies_r,
                coxswain_external_auths: coxswain_external_auths_r,
            };
            let writers = StatusStoreWriters {
                gateways: gateways_w,
                gateway_classes: gateway_classes_w,
                routes: routes_w,
                grpc_routes: grpc_routes_w,
                ingresses: ingresses_w,
                ingress_classes: ingress_classes_w,
                policies: policies_w,
                tls_routes: tls_routes_w,
                tcp_routes: tcp_routes_w,
                udp_routes: udp_routes_w,
                listener_sets: listener_sets_w,
                client_traffic_policies: client_traffic_policies_w,
                coxswain_backend_policies: coxswain_backend_policies_w,
                coxswain_external_auths: coxswain_external_auths_w,
            };
            (
                Some(writers),
                Some(stores),
                Some(op_writers),
                Some(op_stores),
            )
        } else {
            (None, None, None, None)
        };
        Self {
            ingress_routes,
            gateway_routes,
            tls,
            client_certs,
            listener_hostnames,
            listener_status,
            cluster_summary,
            dedicated_registry,
            passthrough_routes,
            terminate_routes,
            tcp_routes,
            udp_routes,
            route_status: SharedRouteStatus::new(),
            grpc_route_status: SharedRouteStatus::new(),
            tls_route_status: SharedRouteStatus::new(),
            tcp_route_status: SharedRouteStatus::new(),
            udp_route_status: SharedRouteStatus::new(),
            policy_status: SharedBackendTlsPolicyStatus::new(),
            ctp_status: SharedClientTrafficPolicyStatus::new(),
            cbp_status: SharedCoxswainBackendPolicyStatus::new(),
            external_auth_status: SharedCoxswainExternalAuthStatus::new(),
            publish_index: SharedGatewayPublishIndex::new(),
            fleet: SharedFleet::new(),
            owned_gateways,
            leader,
            health,
            controller_name,
            opts,
            status_store_writers: parking_lot::Mutex::new(status_store_writers),
            status_stores: parking_lot::Mutex::new(status_stores),
            operator_store_writers: parking_lot::Mutex::new(operator_store_writers),
            operator_stores: parking_lot::Mutex::new(operator_stores),
        }
    }

    /// Take the status-store read handles, if this reconciler was built with
    /// [`ReconcilerOptions::status_stores`]. Returns `Some` exactly once (the
    /// controller's status worker owns them thereafter); a second call — or any
    /// call on a proxy-role reconciler — returns `None`.
    pub fn status_stores(&self) -> Option<StatusStores> {
        self.status_stores.lock().take()
    }

    /// Take the operator store read handles (#574 operator fold), if built with
    /// [`ReconcilerOptions::status_stores`]. Returns `Some` exactly once — the
    /// controller's dedicated-provisioning worker branch owns them thereafter.
    pub fn operator_stores(&self) -> Option<OperatorStores> {
        self.operator_stores.lock().take()
    }

    /// Returns the shared route status handle so other services (e.g. the Controller)
    /// can subscribe to updates published by this reconciler.
    pub fn route_status(&self) -> SharedRouteStatus {
        self.route_status.clone()
    }

    /// Returns the per-Gateway publish-sequence index handle (#531): the
    /// discovery server captures its counter before each snapshot build, and
    /// both `Programmed` status writers look up stamps from it.
    #[must_use]
    pub fn publish_index(&self) -> SharedGatewayPublishIndex {
        self.publish_index.clone()
    }

    /// Returns the shared GRPCRoute status handle so the Controller can subscribe to
    /// updates published by this reconciler.
    ///
    /// Separate from [`Self::route_status`] — `RouteParentKey` is kind-neutral, so
    /// HTTPRoute and GRPCRoute status maps must never be merged.
    pub fn grpc_route_status(&self) -> SharedRouteStatus {
        self.grpc_route_status.clone()
    }

    /// Returns the shared TLSRoute status handle so the Controller can subscribe to
    /// updates published by this reconciler.
    ///
    /// Separate from [`Self::route_status`] and [`Self::grpc_route_status`] —
    /// `RouteParentKey` is kind-neutral, so TLSRoute status must live in its own map.
    pub fn tls_route_status(&self) -> SharedRouteStatus {
        self.tls_route_status.clone()
    }

    /// Returns the shared TCPRoute status handle so the Controller can subscribe to
    /// updates published by this reconciler.
    ///
    /// Separate from the other route-kind status handles — `RouteParentKey` is
    /// kind-neutral, so TCPRoute status must live in its own map.
    pub fn tcp_route_status(&self) -> SharedRouteStatus {
        self.tcp_route_status.clone()
    }

    /// Returns the shared UDPRoute status handle so the Controller can subscribe to
    /// updates published by this reconciler.
    ///
    /// Separate from the other route-kind status handles — `RouteParentKey` is
    /// kind-neutral, so UDPRoute status must live in its own map.
    pub fn udp_route_status(&self) -> SharedRouteStatus {
        self.udp_route_status.clone()
    }

    /// Returns the shared `BackendTLSPolicy` status handle so the Controller can
    /// write `status.ancestors[]` when leader.
    pub fn policy_status(&self) -> SharedBackendTlsPolicyStatus {
        self.policy_status.clone()
    }

    /// Returns the shared `ClientTrafficPolicy` status handle so the Controller can
    /// write `status.ancestors[]` when leader (#327).
    pub fn ctp_status(&self) -> SharedClientTrafficPolicyStatus {
        self.ctp_status.clone()
    }

    /// Returns the shared `CoxswainBackendPolicy` status handle so the Controller
    /// can write `status.ancestors[]` when leader (#354).
    pub fn cbp_status(&self) -> SharedCoxswainBackendPolicyStatus {
        self.cbp_status.clone()
    }

    /// Returns the shared `CoxswainExternalAuth` status handle so the Controller
    /// can write `status.ancestors[]` when leader (#23).
    pub fn external_auth_status(&self) -> SharedCoxswainExternalAuthStatus {
        self.external_auth_status.clone()
    }

    /// Returns the SNI-keyed TLS passthrough routing table (GEP-2643, #70).
    ///
    /// The proxy reads this on each accepted TCP connection on the passthrough port
    /// to pick a backend by SNI without terminating TLS.
    pub fn passthrough_routes(&self) -> SharedTlsPassthroughTable {
        self.passthrough_routes.clone()
    }

    /// Returns the SNI-keyed TLS terminate routing table (TLSRouteModeTerminate, #481).
    ///
    /// The proxy terminates TLS on accept and L4-splices the decrypted stream to the
    /// backend. Isolated from the passthrough table for Mixed-mode correctness.
    pub fn terminate_routes(&self) -> SharedTlsPassthroughTable {
        self.terminate_routes.clone()
    }

    /// Returns the port-keyed TCP routing table (GEP-1901, #505).
    ///
    /// The proxy reads this on each accepted TCP connection on a `TCP`-protocol
    /// listener port to pick a backend purely by port — no SNI peek is involved.
    pub fn tcp_routes(&self) -> SharedTcpRouteTable {
        self.tcp_routes.clone()
    }

    /// Returns the port-keyed UDP routing table (GEP-2645, #506).
    ///
    /// The proxy reads this on each inbound datagram on a `UDP`-protocol
    /// listener port to pick a backend purely by port — no SNI peek is involved.
    pub fn udp_routes(&self) -> SharedUdpRouteTable {
        self.udp_routes.clone()
    }

    /// Returns the fleet snapshot handle so the admin API can read the current
    /// set of coxswain pods. Only populated when [`ReconcilerOptions::watch_fleet`]
    /// is `true` (controller role); returns an empty snapshot otherwise.
    pub fn fleet(&self) -> SharedFleet {
        self.fleet.clone()
    }
}

struct ReconcilerConfig {
    controller_name: String,
    watch_scope: WatchScope,
    /// See [`ReconcilerOptions::pod_namespace`].
    pod_namespace: String,
    ingress_default_backend: Option<IngressDefaultBackend>,
    ingress_ports: IngressPorts,
    metrics: crate::ReflectorMetrics,
    /// See [`ReconcilerOptions::watch_fleet`].
    watch_fleet: bool,
    /// See [`ReconcilerOptions::ingress_event_tx`].
    ingress_event_tx: Option<tokio::sync::mpsc::Sender<IngressEvent>>,
    /// See [`ReconcilerOptions::enable_gateway_api`].
    enable_gateway_api: bool,
    /// See [`ReconcilerOptions::enable_ingress`].
    enable_ingress: bool,
    /// See [`ReconcilerOptions::fetch_remote_jwks`].
    fetch_remote_jwks: bool,
    /// See [`ReconcilerOptions::debounce`].
    debounce: crate::DebounceSettings,
    /// See [`ReconcilerOptions::liveness_gate`].
    liveness_gate: Option<LivenessGate>,
    /// See [`ReconcilerOptions::status_queue`].
    status_queue: Option<StatusWorkqueue>,
}

pub(super) struct ReflectorStores<'a> {
    pub(super) routes: &'a MergedStore<HttpRoute>,
    pub(super) grpc_routes: &'a MergedStore<GrpcRoute>,
    pub(super) tls_routes: &'a MergedStore<TlsRoute>,
    pub(super) tcp_routes: &'a MergedStore<TcpRoute>,
    pub(super) udp_routes: &'a MergedStore<UdpRoute>,
    pub(super) ingresses: &'a MergedStore<Ingress>,
    pub(super) ingress_classes: &'a MergedStore<IngressClass>,
    /// `CoxswainIngressClassParameters` CRs in scope — the per-class annotation
    /// default sources resolved from `IngressClass.spec.parameters` (#190).
    pub(super) ingress_class_parameters: &'a MergedStore<CoxswainIngressClassParameters>,
    pub(super) gateways: &'a MergedStore<Gateway>,
    pub(super) gateway_classes: &'a MergedStore<GatewayClass>,
    /// `ListenerSet` resources in scope (GEP-1713). Merged into each parent
    /// Gateway's effective listener set during rebuild, gated by the parent's
    /// `spec.allowedListeners`.
    pub(super) listener_sets: &'a MergedStore<ListenerSet>,
    /// All `Namespace` objects (cluster-wide). Read only to evaluate a Gateway's
    /// `allowedListeners.namespaces.from: Selector` against the ListenerSet's
    /// namespace labels; nothing else consumes it.
    pub(super) namespaces: &'a MergedStore<Namespace>,
    pub(super) services: &'a MergedStore<Service>,
    /// Incrementally-maintained `(namespace, service, port)` endpoint-resolution
    /// cache (#511) — every route builder reads through this instead of
    /// scanning the `EndpointSlice` store directly. `refresh()`'d once per
    /// rebuild from the `EndpointSlice` store before this struct is
    /// constructed; see [`super::cache::ReflectorCaches`].
    pub(super) endpoint_cache: &'a crate::endpoints::pool::EndpointCache,
    /// `(Gateway, listenerPort) → internalPort` map (#472), read ONCE per rebuild
    /// from the VIP Services so the routing/TLS/passthrough/listener-bind keyings
    /// all agree on one Service snapshot. A per-builder re-read could observe a
    /// mid-rebuild Service mutation and disagree (bound on port X, routed under Y).
    pub(super) vip_internal: &'a super::route_builder::VipInternalPorts,
    pub(super) grants: &'a MergedStore<ReferenceGrant>,
    pub(super) secrets: &'a MergedStore<Secret>,
    /// Label-scoped htpasswd Secrets (`ingress.coxswain-labs.dev/auth-basic=true`) used
    /// by the `auth-basic-secret` Ingress annotation (#24).  Separate from `secrets`
    /// (which watches TLS secrets) to bound memory — Opaque Secrets are not filtered
    /// by type, only by label.  Fail-closed: absent/unlabeled → 503 on the route.
    pub(super) auth_secrets: &'a MergedStore<Secret>,
    /// Label-scoped CA Secrets (`ingress.coxswain-labs.dev/auth-tls=true`) used by the
    /// `auth-tls-secret` Ingress annotation (#267).  Separate from `secrets` (TLS certs)
    /// and `auth_secrets` (htpasswd) to bound memory.  Fail-closed: absent/unlabeled →
    /// handshake abort for that host.
    pub(super) auth_tls_secrets: &'a MergedStore<Secret>,
    /// `BackendTLSPolicy` resources in scope (namespaced per `watch_scope`).
    pub(super) policies: &'a MergedStore<BackendTlsPolicy>,
    /// All ConfigMaps in scope — used to resolve `caCertificateRefs`.
    /// Unlike the `Secret` reflector (which uses a type= field selector), ConfigMaps
    /// have no equivalent filter; all CMs in scope are watched. A follow-up will
    /// switch to per-policy informers to bound memory use in large clusters.
    pub(super) configmaps: &'a MergedStore<ConfigMap>,
    /// `RateLimit` CRs in scope — resolved from `HTTPRouteRule` `ExtensionRef`
    /// filters during Gateway API reconciliation.
    pub(super) rate_limits: &'a MergedStore<RateLimit>,
    /// `RetryPolicy` CRs in scope — resolved from `HTTPRouteRule`/`GRPCRouteRule`
    /// `ExtensionRef` filters into the per-route retry policy (#445).
    pub(super) retry_policies: &'a MergedStore<RetryPolicy>,
    /// `PathRewriteRegex` CRs in scope — resolved from `HTTPRouteRule` `ExtensionRef`
    /// filters during Gateway API reconciliation.
    pub(super) path_rewrites: &'a MergedStore<PathRewriteRegex>,
    /// `IpAccessControl` CRs in scope — resolved from `HTTPRouteRule` `ExtensionRef`
    /// filters into per-route source-IP allow/deny CIDR sets (#479).
    pub(super) ip_access: &'a MergedStore<IpAccessControl>,
    /// `BasicAuth` CRs in scope — resolved from `HTTPRouteRule` `ExtensionRef`
    /// filters, HTTPRoute-only (#442).
    pub(super) basic_auths: &'a MergedStore<BasicAuth>,
    /// `CoxswainExternalAuth` CRs in scope — resolved from `HTTPRouteRule`
    /// `ExternalAuth` `ExtensionRef` filters (and, later, Gateway policies) into
    /// per-route ext_authz config, HTTPRoute-only (#23).
    pub(super) external_auths: &'a MergedStore<CoxswainExternalAuth>,
    /// `JwtAuth` CRs in scope — resolved from `HTTPRouteRule` `ExtensionRef`
    /// filters into per-route JWT (JWKS bearer-token) validation config (#441).
    /// No status subresource (unlike `CoxswainExternalAuth`) — `JwtAuth` has no
    /// `targetRefs`/Gateway-attachment surface, so a plain (non-status-relevant)
    /// store is enough; diagnosability is WARN logs + the route's fail-closed 503.
    pub(super) jwt_auths: &'a MergedStore<JwtAuth>,
    /// Controller-fetched remote-JWKS cache (#441), read synchronously when
    /// resolving a `JwtAuth` CR that names a `jwks.remote`. Grouped alongside
    /// `jwt_auths` here (rather than `Ownership`) so `rebuild()` stays within
    /// the workspace `clippy::too_many_arguments` threshold. See [`crate::jwks`].
    pub(super) jwks_cache: &'a crate::jwks::SharedJwksCache,
    /// `RequestSizeLimit` CRs in scope — resolved from `HTTPRouteRule`/`GRPCRouteRule`
    /// `ExtensionRef` filters into a per-route body-size cap (#443).
    pub(super) request_size_limits: &'a MergedStore<RequestSizeLimit>,
    /// `Compression` CRs in scope — resolved from `HTTPRouteRule` `ExtensionRef`
    /// filters (HTTPRoute-only, #446) and the Ingress `compression` annotation
    /// (#550); both surfaces resolve the same store through
    /// [`crate::gateway_api::compression::resolve_spec`].
    pub(super) compressions: &'a MergedStore<Compression>,
    /// `ClientTrafficPolicy` CRs in scope — resolved per Gateway/listener to set
    /// `ListenerInfo.proxy_protocol` during rebuild (#327).
    pub(super) client_traffic_policies: &'a MergedStore<ClientTrafficPolicy>,
    /// `CoxswainBackendPolicy` CRs in scope — resolved per target Service to set
    /// per-backend connect/idle timeouts during route building (#354).
    pub(super) coxswain_backend_policies: &'a MergedStore<CoxswainBackendPolicy>,
}

pub(super) struct SharedOutputs<'a> {
    pub(super) ingress_routes: &'a SharedIngressRoutingTable,
    pub(super) gateway_routes: &'a SharedGatewayRoutingTable,
    pub(super) tls: &'a SharedPortTlsStore,
    pub(super) client_certs: &'a SharedClientCertStore,
    pub(super) listener_hostnames: &'a SharedListenerHostnames,
    pub(super) listener_status: &'a SharedGatewayListenerStatus,
    pub(super) cluster_summary: &'a SharedClusterSummary,
    pub(super) dedicated_registry: &'a DedicatedRoutingRegistry,
    pub(super) route_status: &'a SharedRouteStatus,
    pub(super) grpc_route_status: &'a SharedRouteStatus,
    pub(super) tls_route_status: &'a SharedRouteStatus,
    pub(super) tcp_route_status: &'a SharedRouteStatus,
    pub(super) udp_route_status: &'a SharedRouteStatus,
    pub(super) policy_status: &'a SharedBackendTlsPolicyStatus,
    pub(super) ctp_status: &'a SharedClientTrafficPolicyStatus,
    pub(super) cbp_status: &'a SharedCoxswainBackendPolicyStatus,
    pub(super) external_auth_status: &'a SharedCoxswainExternalAuthStatus,
    pub(super) passthrough_routes: &'a SharedTlsPassthroughTable,
    pub(super) terminate_routes: &'a SharedTlsPassthroughTable,
    pub(super) tcp_routes: &'a SharedTcpRouteTable,
    pub(super) udp_routes: &'a SharedUdpRouteTable,
    pub(super) publish_index: &'a SharedGatewayPublishIndex,
    pub(super) ingress_event_tx: Option<&'a tokio::sync::mpsc::Sender<IngressEvent>>,
}

pub(super) struct Ownership<'a> {
    pub(super) ingress_classes: &'a HashSet<String>,
    pub(super) default_ingress_class: Option<&'a str>,
    pub(super) gateways: &'a HashSet<ObjectKey>,
    pub(super) gateway_classes: &'a HashSet<String>,
    pub(super) backend_grants: &'a GrantSet,
    pub(super) cert_grants: &'a GrantSet,
    /// `ListenerSet → Secret` grants for GEP-1713 ListenerSet HTTPS listeners whose
    /// `certificateRefs` point at a Secret in another namespace (#93). Distinct from
    /// `cert_grants` because the grant's `from.kind` is `ListenerSet`, not `Gateway`.
    pub(super) ls_cert_grants: &'a GrantSet,
    /// `Gateway → ConfigMap` grants for GEP-91 frontend client-cert validation
    /// CA refs that point at a ConfigMap in another namespace (#86).
    pub(super) ca_grants: &'a GrantSet,
    /// `BasicAuth → Secret` grants authorizing a `BasicAuth` CR to reference its
    /// htpasswd `secretRef` in another namespace (#520). Distinct from `cert_grants`
    /// because the grant's `from.kind`/`from.group` is `BasicAuth`/coxswain, not
    /// `Gateway`/gateway-api. A missing grant fails the cross-namespace ref closed.
    pub(super) basic_auth_secret_grants: &'a GrantSet,
    /// Per-(Service, port) `BackendTLSPolicy` lookup table, built before this
    /// `Ownership` is constructed. Carried alongside ownership data because
    /// `build_routes` and the per-route `reconcile` both need it on the same
    /// borrow pass — folding it in here keeps the function arities clippy-clean.
    pub(super) policy_index: &'a BackendTlsIndex,
    /// Per-`Service` connect/idle timeout index from `CoxswainBackendPolicy` (#354).
    /// Consulted during Gateway API route building to set per-backend timeouts.
    /// Folded into `Ownership` for the same arity reason as `policy_index`.
    pub(super) backend_policy_index: &'a BackendPolicyIndex,
    /// Per-Gateway ext-auth mandate from `CoxswainExternalAuth` `targetRefs`
    /// policies (#23). Prepended to every bound route's auth chain during Gateway
    /// API route building. Folded into `Ownership` for the same arity reason.
    pub(super) external_auth_gateway_index: &'a crate::gateway_api::ExternalAuthGatewayIndex,
    /// Resolved GEP-3155 backend client certs, keyed by `ObjectKey(ns, gw_name)`.
    /// Populated from `resolve_backend_client_certs` before the route build. Folded
    /// into `Ownership` (same rationale as `policy_index`) to keep arities clean.
    pub(super) backend_client_certs: &'a HashMap<ObjectKey, Arc<BackendClientCert>>,
    /// Gateways whose `spec.tls.backend.clientCertificateRef` is configured but
    /// failed to resolve (missing Secret / wrong type / RefNotPermitted), keyed by
    /// `ObjectKey(ns, gw_name)`. Routes inheriting from such a Gateway fail closed
    /// (502) on BackendTLSPolicy-driven upstreams rather than connecting without the
    /// proxy's configured identity (GEP-3155, matching the project's fail-closed
    /// posture for every other cert path).
    pub(super) backend_client_cert_failures: &'a HashSet<ObjectKey>,
    /// Per-Gateway effective listener sets (own listeners + those merged from
    /// attached ListenerSets, GEP-1713), computed once per rebuild. Folded into
    /// `Ownership` (same rationale as `policy_index`) so the route/TLS builders
    /// read one consistent merged view without an extra arg.
    pub(super) effective_gateways: &'a HashMap<ObjectKey, super::listener_merge::EffectiveGateway>,
}

/// Per-reflector side-effect channels: rebuild trigger, readiness flip,
/// and metric observation.
///
/// Grouped so [`spawn_reflector`] stays under `clippy::too_many_arguments`.
/// Since #574 removed the lossy fan-out, this no longer carries a per-kind
/// sender — every watch event just bumps the shared rebuild trigger, and the
/// rebuild pass enqueues the derived status keys — so it is no longer generic
/// over the watched kind.
///
/// The trigger is a `watch::Sender<u64>` generation counter, NOT a
/// `tokio::sync::Notify`. A `watch` channel never loses the latest value:
/// `changed()`/`borrow_and_update()` on the rebuild-loop receiver observe every
/// bump regardless of whether the loop was parked in its `select!` at the
/// instant of the send. `Notify::notify_one` in a `select!` against the resync
/// tick could drop an already-delivered wake if the tick branch won the same
/// poll, leaving convergence to wait on the coarse 30 s backstop
/// ([`REBUILD_RESYNC_PERIOD`]) — the class of stall #574 exists to remove. This
/// also matches the reflector's *output* signals (the status cells), which are
/// already `watch::Sender<u64>`.
pub(super) struct ReflectorEffects {
    trigger: watch::Sender<u64>,
    controller_health: SubsystemHandle,
    /// Health-check name to flip Ready once every watched namespace of the check
    /// has completed its first `Event::InitDone`. Also the `kind` metric label
    /// for `watch_events_total` / `watch_errors_total`.
    check: &'static str,
    /// Watched namespace for this reflector, or `""` for a cluster-wide /
    /// cluster-scoped watch. Labels the per-`(kind, ns)` relist accounting so
    /// the #573 liveness backstop tracks each namespace's relist independently
    /// under a shared `check` (multi-namespace watch, #59).
    ns: String,
    /// Shared per-check readiness barrier: the count of the check's watched
    /// namespaces whose *first* relist has not yet completed. Every reflector of
    /// the check holds a clone; the one that drops it to 0 flips the check Ready,
    /// so a multi-namespace check reports Ready only once *all* its namespaces
    /// have synced. A single-store check starts at 1 — identical to the
    /// pre-#59 single-`InitDone` behaviour.
    readiness: Arc<AtomicUsize>,
    metrics: crate::ReflectorMetrics,
}

impl ReflectorEffects {
    pub(super) fn new(
        trigger: &watch::Sender<u64>,
        health: &SubsystemHandle,
        check: &'static str,
        metrics: crate::ReflectorMetrics,
        ns: String,
        readiness: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            trigger: trigger.clone(),
            controller_health: health.clone(),
            check,
            ns,
            readiness,
            metrics,
        }
    }
}

/// Bump the rebuild-trigger generation counter, waking the rebuild loop.
///
/// `send_modify` always marks the value changed and notifies every receiver, so
/// the wake is lossless even if the rebuild loop is mid-rebuild (not currently
/// awaiting `changed()`) at the instant of the bump — the next `changed()` still
/// observes the new generation. The counter value itself is unused; only the
/// change signal matters (it wraps to avoid an unbounded increment).
#[inline]
fn bump_rebuild(trigger: &watch::Sender<u64>) {
    trigger.send_modify(|g| *g = g.wrapping_add(1));
}

pub(super) fn spawn_reflector<T>(
    set: &mut JoinSet<()>,
    writer: reflector::store::Writer<T>,
    api: Api<T>,
    config: watcher::Config,
    effects: ReflectorEffects,
    label: &'static str,
) where
    T: kube::Resource
        + serde::de::DeserializeOwned
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
    T::DynamicType: Default + Clone + std::hash::Hash + Eq + Send + Sync + 'static,
{
    let ReflectorEffects {
        trigger,
        controller_health,
        check,
        ns,
        readiness,
        metrics,
    } = effects;
    set.spawn(async move {
        // Guards the shared readiness barrier so only this reflector's *first*
        // relist decrements it; later re-lists (further `InitDone`s) must not.
        let mut first_relist_done = false;
        let stream = reflector::reflector(writer, watcher(api, config).default_backoff());
        tokio::pin!(stream);
        while let Some(event) = stream.next().await {
            match event {
                Ok(watcher::Event::InitDone) => {
                    // `reflector()` swapped the relist buffer into the store
                    // before yielding this event, so waking the rebuild loop now
                    // re-derives (routing + status) from the fresh post-relist
                    // world; the rebuild pass enqueues the status keys.
                    bump_rebuild(&trigger);
                    // Flip the check Ready only once every watched namespace of
                    // the check has completed its first relist (barrier → 0).
                    if !first_relist_done {
                        first_relist_done = true;
                        if readiness.fetch_sub(1, Ordering::AcqRel) == 1 {
                            controller_health.ready(check);
                        }
                    }
                    metrics.observe_watch_event(check, "init_done");
                    metrics.observe_relist_completed(check, &ns);
                }
                Ok(watcher::Event::Init) => {
                    // A relist began: mark it in flight and (re)start its stall
                    // clock.
                    bump_rebuild(&trigger);
                    metrics.observe_watch_event(check, "restart");
                    metrics.observe_relist_progress(check, &ns);
                }
                Ok(watcher::Event::InitApply(_)) => {
                    // An object streamed in during the list phase: relist
                    // progress. Buffered by `reflector()` into the pending
                    // snapshot. Refreshing the stall clock here keeps a
                    // large-but-streaming relist from ever looking frozen to the
                    // liveness backstop.
                    bump_rebuild(&trigger);
                    metrics.observe_watch_event(check, "restart");
                    metrics.observe_relist_progress(check, &ns);
                }
                Ok(watcher::Event::Apply(_)) => {
                    // The store already holds the object (applied before this
                    // yield); waking the rebuild loop re-derives and enqueues.
                    bump_rebuild(&trigger);
                    metrics.observe_watch_event(check, "apply");
                }
                Ok(watcher::Event::Delete(_)) => {
                    bump_rebuild(&trigger);
                    metrics.observe_watch_event(check, "delete");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "{label} reflector error");
                    metrics.observe_watch_error(check);
                }
            }
        }
    });
}

#[async_trait]
impl BackgroundService for SharedProxyReconciler {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        // Infer the config once, then build a primary client from it. #574: each
        // watch gets its OWN client (a fresh HTTP/2 connection) built from this
        // same config, so a stalled stream on one connection cannot head-of-line-
        // block sibling watches — the "no shared-connection collateral" invariant
        // the single-fabric design requires (a shared connection is why the #573
        // wedge's collateral persisted). See `watch_client`.
        let kube_config = match kube::Config::infer().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "failed to infer Kubernetes config; reconciler will not run");
                return;
            }
        };
        let client = match Client::try_from(kube_config.clone()) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "failed to initialise Kubernetes client; reconciler will not run");
                return;
            }
        };
        let config = ReconcilerConfig {
            controller_name: self.controller_name.clone(),
            watch_scope: self.opts.watch_scope.clone(),
            pod_namespace: self.opts.pod_namespace.clone(),
            ingress_default_backend: self.opts.ingress_default_backend.clone(),
            ingress_ports: self.opts.ingress_ports,
            metrics: crate::ReflectorMetrics::new(self.opts.metrics_prefix),
            watch_fleet: self.opts.watch_fleet,
            ingress_event_tx: self.opts.ingress_event_tx.clone(),
            enable_gateway_api: self.opts.enable_gateway_api,
            enable_ingress: self.opts.enable_ingress,
            fetch_remote_jwks: self.opts.fetch_remote_jwks,
            debounce: self.opts.debounce,
            liveness_gate: self.opts.liveness_gate.clone(),
            status_queue: self.opts.status_queue.clone(),
        };
        let handles = SharedHandles {
            ingress_routes: self.ingress_routes.clone(),
            gateway_routes: self.gateway_routes.clone(),
            tls: self.tls.clone(),
            client_certs: self.client_certs.clone(),
            listener_hostnames: self.listener_hostnames.clone(),
            listener_status: self.listener_status.clone(),
            cluster_summary: self.cluster_summary.clone(),
            dedicated_registry: self.dedicated_registry.clone(),
            route_status: self.route_status.clone(),
            grpc_route_status: self.grpc_route_status.clone(),
            tls_route_status: self.tls_route_status.clone(),
            tcp_route_status: self.tcp_route_status.clone(),
            udp_route_status: self.udp_route_status.clone(),
            policy_status: self.policy_status.clone(),
            ctp_status: self.ctp_status.clone(),
            cbp_status: self.cbp_status.clone(),
            external_auth_status: self.external_auth_status.clone(),
            publish_index: self.publish_index.clone(),
            passthrough_routes: self.passthrough_routes.clone(),
            terminate_routes: self.terminate_routes.clone(),
            tcp_routes: self.tcp_routes.clone(),
            udp_routes: self.udp_routes.clone(),
            fleet: self.fleet.clone(),
            owned_gateways: self.owned_gateways.clone(),
            leader: Arc::clone(&self.leader),
            controller_health: self.health.controller.clone(),
            proxy_health: self.health.proxy.clone(),
        };
        // Hand the pre-created shared-store writers (if any) to the watch
        // tasks. Taken here so `spawn_tasks` drives the same stores the
        // status-writer subscribed to in `new`.
        let status_writers = self.status_store_writers.lock().take();
        let operator_writers = self.operator_store_writers.lock().take();
        let mut set = spawn_tasks(
            client,
            kube_config,
            handles,
            config,
            status_writers,
            operator_writers,
        )
        .await;
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                res = set.join_next() => match res {
                    Some(Ok(())) => tracing::warn!("SharedProxyReconciler task exited unexpectedly"),
                    Some(Err(e)) => tracing::error!(error = %e, "SharedProxyReconciler task panicked"),
                    None => break,
                },
            }
        }
    }
}

/// Owned bundle of shared state handles consumed by [`spawn_tasks`].
///
/// Groups every cross-task handle the reconciler clones into its background work
/// so the function stays under the `clippy::too_many_arguments` threshold.
struct SharedHandles {
    ingress_routes: SharedIngressRoutingTable,
    gateway_routes: SharedGatewayRoutingTable,
    tls: SharedPortTlsStore,
    client_certs: SharedClientCertStore,
    listener_hostnames: SharedListenerHostnames,
    listener_status: SharedGatewayListenerStatus,
    cluster_summary: SharedClusterSummary,
    dedicated_registry: DedicatedRoutingRegistry,
    route_status: SharedRouteStatus,
    grpc_route_status: SharedRouteStatus,
    tls_route_status: SharedRouteStatus,
    tcp_route_status: SharedRouteStatus,
    udp_route_status: SharedRouteStatus,
    policy_status: SharedBackendTlsPolicyStatus,
    ctp_status: SharedClientTrafficPolicyStatus,
    cbp_status: SharedCoxswainBackendPolicyStatus,
    external_auth_status: SharedCoxswainExternalAuthStatus,
    /// Per-Gateway publish-sequence stamps for the #531 ack gate.
    publish_index: SharedGatewayPublishIndex,
    /// SNI-keyed TLS passthrough routing table for TLSRoute / GEP-2643 (#70).
    passthrough_routes: SharedTlsPassthroughTable,
    /// SNI-keyed TLS terminate routing table for TLSRouteModeTerminate (#481).
    terminate_routes: SharedTlsPassthroughTable,
    /// Port-keyed TCP routing table for TCPRoute / GEP-1901 (#505).
    tcp_routes: SharedTcpRouteTable,
    /// Port-keyed UDP routing table for UDPRoute / GEP-2645 (#506).
    udp_routes: SharedUdpRouteTable,
    /// Populated by the fleet task when `watch_fleet` is enabled; carried here
    /// so the fleet-rebuild task can publish into the same cell that callers
    /// obtain via [`SharedProxyReconciler::fleet`].
    fleet: SharedFleet,
    owned_gateways: OwnedGateways,
    leader: Arc<AtomicBool>,
    controller_health: SubsystemHandle,
    proxy_health: SubsystemHandle,
}

/// Resolve a `(reader, writer)` pair for a reflector store: reuse a pre-created
/// [`reflector::store::Writer`] from [`SharedProxyReconciler::new`] (its reader
/// is the same synced store the controller's status worker reads), or create a
/// fresh store when status stores are disabled (the proxy role).
/// Create (or adopt) one reflector store **per watched namespace** for a
/// namespaced resource, returning the merged reader and the per-namespace
/// writers, index-aligned with [`WatchScope::api_scopes`] (multi-namespace
/// watch, #59).
///
/// `pre` adopts a status-relevant type's pre-created writers (from
/// [`SharedProxyReconciler::new`]) so the controller's status worker and the
/// reflector's rebuild pass read the *same* stores; those writers were made from
/// the same `scope`, so they realign with `api_scopes` here. `None` mints fresh
/// stores. Cluster-scoped resources use [`cluster_reader_writer`] instead.
fn scoped_reader_writers<K>(
    pre: Option<Vec<reflector::store::Writer<K>>>,
    scope: &WatchScope,
) -> (MergedStore<K>, Vec<reflector::store::Writer<K>>)
where
    K: kube::Resource + Clone + 'static,
    K::DynamicType: Eq + std::hash::Hash + Clone + Default,
{
    let namespaces = scope.api_scopes();
    let writers = pre.unwrap_or_else(|| {
        namespaces
            .iter()
            .map(|_| reflector::store::<K>().1)
            .collect()
    });
    // Re-pair each writer's reader handle with the namespace it watches, so the
    // merged store can route `get` by namespace.
    let readers = writers
        .iter()
        .zip(namespaces)
        .map(|(writer, ns)| (ns.map(str::to_string), writer.as_reader()))
        .collect();
    (MergedStore::new(readers), writers)
}

/// Create (or adopt) a single cluster-wide reflector store for a cluster-scoped
/// resource (e.g. `GatewayClass`, `Namespace`) — or one deliberately watched
/// cluster-wide regardless of `--watch-namespace` (e.g. `IngressClass`).
///
/// Returns a single-element [`MergedStore`] so reader fields stay a uniform
/// `MergedStore<K>` whether the resource is namespaced or cluster-scoped.
fn cluster_reader_writer<K>(
    pre: Option<reflector::store::Writer<K>>,
) -> (MergedStore<K>, reflector::store::Writer<K>)
where
    K: kube::Resource + Clone + 'static,
    K::DynamicType: Eq + std::hash::Hash + Clone + Default,
{
    let (reader, writer) = match pre {
        Some(writer) => (writer.as_reader(), writer),
        None => reflector::store::<K>(),
    };
    (MergedStore::single(reader), writer)
}

/// Shared context for spawning per-namespace reflector fans (#59). Groups the
/// values every spawn needs so the fan-out — a shared readiness barrier plus one
/// reflector per watched namespace — lives in one place instead of at ~30 call
/// sites, and the per-type methods stay under the argument ceiling.
struct ScopedSpawn<'a> {
    set: &'a mut JoinSet<()>,
    clients: WatchClientSource<'a>,
    scope: &'a WatchScope,
    trigger: &'a watch::Sender<u64>,
    health: &'a SubsystemHandle,
    metrics: crate::ReflectorMetrics,
}

impl ScopedSpawn<'_> {
    /// Spawn one reflector per watched namespace for a **namespaced** resource,
    /// each on its own client (own connection), sharing a readiness barrier so
    /// `check` flips Ready only once every namespace has synced. `writers` must
    /// align by index with [`WatchScope::api_scopes`] — both come from
    /// [`scoped_reader_writers`] over the same scope.
    fn namespaced<K>(
        &mut self,
        writers: Vec<reflector::store::Writer<K>>,
        config: watcher::Config,
        check: &'static str,
        label: &'static str,
    ) where
        K: kube::Resource<Scope = kube::core::NamespaceResourceScope>
            + serde::de::DeserializeOwned
            + Clone
            + std::fmt::Debug
            + Send
            + Sync
            + 'static,
        K::DynamicType: Default + Clone + std::hash::Hash + Eq + Send + Sync + 'static,
    {
        // Copy the `&WatchScope` out first: `namespaced_in` takes `&mut self`, so
        // the scope arg must not alias a live borrow of `self`.
        let scope = self.scope;
        self.namespaced_in(scope, writers, config, check, label);
    }

    /// Like [`Self::namespaced`], but fans over the **passed** `scope` rather than
    /// `self.scope` — for namespaced resources watched on a *widened* scope (the
    /// tenant set plus the controller's own namespace, [`WatchScope::with_namespace`]):
    /// the fleet `Pod` watch and the `CoxswainGatewayParameters` /
    /// `CoxswainIngressClassParameters` `parametersRef` sources (#59). `writers`
    /// must align by index with `scope.api_scopes()` — both derive from the same
    /// scope via [`scoped_reader_writers`].
    fn namespaced_in<K>(
        &mut self,
        scope: &WatchScope,
        writers: Vec<reflector::store::Writer<K>>,
        config: watcher::Config,
        check: &'static str,
        label: &'static str,
    ) where
        K: kube::Resource<Scope = kube::core::NamespaceResourceScope>
            + serde::de::DeserializeOwned
            + Clone
            + std::fmt::Debug
            + Send
            + Sync
            + 'static,
        K::DynamicType: Default + Clone + std::hash::Hash + Eq + Send + Sync + 'static,
    {
        let readiness = Arc::new(AtomicUsize::new(writers.len().max(1)));
        for (writer, ns) in writers.into_iter().zip(scope.api_scopes()) {
            let effects = ReflectorEffects::new(
                self.trigger,
                self.health,
                check,
                self.metrics,
                ns.unwrap_or("").to_string(),
                Arc::clone(&readiness),
            );
            spawn_reflector(
                self.set,
                writer,
                scoped_api::<K>(self.clients.client(), ns),
                config.clone(),
                effects,
                label,
            );
        }
    }

    /// Spawn a single cluster-wide reflector for a **cluster-scoped** resource
    /// (or one deliberately watched cluster-wide). The caller supplies the
    /// `Api::all` handle since cluster-scoped types cannot use [`scoped_api`].
    fn cluster<K>(
        &mut self,
        writer: reflector::store::Writer<K>,
        api: Api<K>,
        config: watcher::Config,
        check: &'static str,
        label: &'static str,
    ) where
        K: kube::Resource
            + serde::de::DeserializeOwned
            + Clone
            + std::fmt::Debug
            + Send
            + Sync
            + 'static,
        K::DynamicType: Default + Clone + std::hash::Hash + Eq + Send + Sync + 'static,
    {
        let effects = ReflectorEffects::new(
            self.trigger,
            self.health,
            check,
            self.metrics,
            String::new(),
            Arc::new(AtomicUsize::new(1)),
        );
        spawn_reflector(self.set, writer, api, config, effects, label);
    }
}

/// Writer bundle for all Gateway API stores, passed as a unit to
/// [`add_gateway_api_reflectors`]. Gathered here so the callers
/// don't exceed the 7-argument function threshold.
struct GatewayApiStoreWriters {
    // Namespaced types carry one writer per watched namespace (#59); the
    // cluster-scoped `gateway_classes` and cluster-wide `namespaces` are single.
    routes: Vec<reflector::store::Writer<HttpRoute>>,
    grpc_routes: Vec<reflector::store::Writer<GrpcRoute>>,
    tls_routes: Vec<reflector::store::Writer<TlsRoute>>,
    tcp_routes: Vec<reflector::store::Writer<TcpRoute>>,
    udp_routes: Vec<reflector::store::Writer<UdpRoute>>,
    gateways: Vec<reflector::store::Writer<Gateway>>,
    gateway_classes: reflector::store::Writer<GatewayClass>,
    grants: Vec<reflector::store::Writer<ReferenceGrant>>,
    policies: Vec<reflector::store::Writer<BackendTlsPolicy>>,
    configmaps: Vec<reflector::store::Writer<ConfigMap>>,
    path_rewrites: Vec<reflector::store::Writer<PathRewriteRegex>>,
    basic_auths: Vec<reflector::store::Writer<BasicAuth>>,
    request_size_limits: Vec<reflector::store::Writer<RequestSizeLimit>>,
    listener_sets: Vec<reflector::store::Writer<ListenerSet>>,
    namespaces: reflector::store::Writer<Namespace>,
    client_traffic_policies: Vec<reflector::store::Writer<ClientTrafficPolicy>>,
    coxswain_backend_policies: Vec<reflector::store::Writer<CoxswainBackendPolicy>>,
}

/// Spawn all Gateway API reflectors through `scoped` — one reflector per watched
/// namespace for namespaced types, a single cluster-wide watch for the
/// cluster-scoped `GatewayClass` / `Namespace` (#59).
///
/// Called either immediately at startup (CRDs present) or from the self-heal
/// probe task once the CRDs appear. Consumes the writer bundle so each
/// underlying `reflector::store::Writer` is owned by exactly one task.
fn add_gateway_api_reflectors(scoped: &mut ScopedSpawn<'_>, writers: GatewayApiStoreWriters) {
    let GatewayApiStoreWriters {
        routes,
        grpc_routes,
        tls_routes,
        tcp_routes,
        udp_routes,
        gateways,
        gateway_classes,
        grants,
        policies,
        configmaps,
        path_rewrites,
        basic_auths,
        request_size_limits,
        listener_sets,
        namespaces,
        client_traffic_policies,
        coxswain_backend_policies,
    } = writers;
    // Cluster-scoped `Api::all` handles built up front (Copy `clients` snapshot),
    // so the `&mut scoped` spawns below don't alias an immutable `scoped` borrow.
    let clients = scoped.clients;

    scoped.namespaced::<HttpRoute>(routes, control_watch_config(), "httproute", "HttpRoute");
    scoped.namespaced::<GrpcRoute>(
        grpc_routes,
        control_watch_config(),
        "grpcroute",
        "GrpcRoute",
    );
    scoped.namespaced::<TlsRoute>(tls_routes, control_watch_config(), "tls_route", "TlsRoute");
    scoped.namespaced::<TcpRoute>(tcp_routes, control_watch_config(), "tcp_route", "TcpRoute");
    scoped.namespaced::<UdpRoute>(udp_routes, control_watch_config(), "udp_route", "UdpRoute");
    scoped.namespaced::<Gateway>(gateways, control_watch_config(), "gateway", "Gateway");
    // GatewayClass is cluster-scoped: always one cluster-wide watch.
    scoped.cluster::<GatewayClass>(
        gateway_classes,
        Api::<GatewayClass>::all(clients.client()),
        control_watch_config(),
        "gateway_class",
        "GatewayClass",
    );
    scoped.namespaced::<ReferenceGrant>(
        grants,
        control_watch_config(),
        "reference_grant",
        "ReferenceGrant",
    );
    scoped.namespaced::<BackendTlsPolicy>(
        policies,
        control_watch_config(),
        "backend_tls_policy",
        "BackendTlsPolicy",
    );
    // ConfigMaps have no type= field selector equivalent; all CMs in scope are
    // watched so BackendTLSPolicy caCertificateRefs can be resolved.
    scoped.namespaced::<ConfigMap>(configmaps, bulk_watch_config(), "config_map", "ConfigMap");
    scoped.namespaced::<PathRewriteRegex>(
        path_rewrites,
        control_watch_config(),
        "path_rewrite_regex",
        "PathRewriteRegex",
    );
    scoped.namespaced::<BasicAuth>(
        basic_auths,
        control_watch_config(),
        "basic_auth",
        "BasicAuth",
    );
    scoped.namespaced::<RequestSizeLimit>(
        request_size_limits,
        control_watch_config(),
        "request_size_limit",
        "RequestSizeLimit",
    );
    // GEP-1713: ListenerSets are namespaced and merged into their parent Gateway's
    // effective listener set during rebuild.
    scoped.namespaced::<ListenerSet>(
        listener_sets,
        control_watch_config(),
        "listener_set",
        "ListenerSet",
    );
    // Namespaces are cluster-scoped and watched only so a Gateway's
    // `allowedListeners.namespaces.from: Selector` can be matched against the
    // ListenerSet's namespace labels (GEP-1713). Must be cluster-wide — a
    // `--watch-namespace` scope can't observe label changes on a ListenerSet's
    // namespace object. Read-only; the proxy SA holds no write verb.
    scoped.cluster::<Namespace>(
        namespaces,
        Api::<Namespace>::all(clients.client()),
        control_watch_config(),
        "namespace",
        "Namespace",
    );
    // `ClientTrafficPolicy` CRs — per-listener PROXY-protocol opt-in (#327).
    // Namespaced and watched alongside other Gateway API policy resources.
    scoped.namespaced::<ClientTrafficPolicy>(
        client_traffic_policies,
        control_watch_config(),
        "client_traffic_policy",
        "ClientTrafficPolicy",
    );
    // `CoxswainBackendPolicy` CRs — per-backend connect/idle timeouts (#354).
    scoped.namespaced::<CoxswainBackendPolicy>(
        coxswain_backend_policies,
        control_watch_config(),
        "coxswain_backend_policy",
        "CoxswainBackendPolicy",
    );
}

async fn spawn_tasks(
    client: Client,
    kube_config: kube::Config,
    handles: SharedHandles,
    config: ReconcilerConfig,
    status_writers: Option<StatusStoreWriters>,
    operator_writers: Option<OperatorStoreWriters>,
) -> JoinSet<()> {
    let SharedHandles {
        ingress_routes,
        gateway_routes,
        tls,
        client_certs,
        listener_hostnames,
        listener_status,
        cluster_summary,
        dedicated_registry,
        route_status,
        grpc_route_status,
        tls_route_status,
        tcp_route_status,
        udp_route_status,
        policy_status,
        ctp_status,
        cbp_status,
        external_auth_status,
        publish_index,
        passthrough_routes,
        terminate_routes,
        tcp_routes,
        udp_routes,
        fleet,
        owned_gateways,
        leader,
        controller_health,
        proxy_health,
    } = handles;
    let ReconcilerConfig {
        controller_name,
        watch_scope,
        pod_namespace,
        ingress_default_backend,
        ingress_ports,
        metrics,
        watch_fleet,
        ingress_event_tx,
        enable_gateway_api,
        enable_ingress,
        fetch_remote_jwks,
        debounce,
        liveness_gate,
        status_queue,
    } = config;
    // Status-relevant stores reuse the writers pre-created in `new` (so the
    // controller's status worker reads the same synced stores the rebuild pass
    // enqueues from); the rest are always fresh non-shared stores.
    let pre = StatusStoreWriters::into_option_writers(status_writers);
    // Operator-fold (#574): pre-created writers for the shared namespaces /
    // services / pods stores and the operator-only params / Node watches, or all
    // `None` in the proxy role (no operator there).
    let (op_params_w, op_relay_policies_w, op_nodes_w, op_namespaces_w, op_services_w, op_pods_w) =
        match operator_writers {
            Some(w) => (
                Some(w.params),
                Some(w.relay_policies),
                Some(w.nodes),
                Some(w.namespaces),
                Some(w.services),
                Some(w.pods),
            ),
            None => (None, None, None, None, None, None),
        };
    // Per-namespace stores for namespaced types (#59): the reader is a
    // `MergedStore` folding every watched namespace; the writers are one per
    // namespace, fed to `ScopedSpawn::namespaced` below. Status-relevant types
    // adopt their pre-created writers so the controller's status worker reads the
    // same synced stores. Cluster-scoped types (`IngressClass`,
    // `CoxswainIngressClassParameters`, `Namespace`) use `cluster_reader_writer`.
    let scope = &watch_scope;
    // Widened scope for namespaced infra resources that also live in the install
    // namespace — the fleet `Pod`, `CoxswainGatewayParameters`, and
    // `CoxswainIngressClassParameters` watches (#59). Derived identically to the
    // `infra_scope` in `new()` (same `watch_scope` + `pod_namespace`), so the
    // pre-created writers realign here index-for-index with `api_scopes()`.
    let infra_scope = watch_scope.with_namespace(&pod_namespace);
    let (route_reader, route_writers) = scoped_reader_writers::<HttpRoute>(pre.routes, scope);
    let (grpc_route_reader, grpc_route_writers) =
        scoped_reader_writers::<GrpcRoute>(pre.grpc_routes, scope);
    let (ingress_reader, ingress_writers) = scoped_reader_writers::<Ingress>(pre.ingresses, scope);
    let (class_reader, class_writer) = cluster_reader_writer::<IngressClass>(pre.ingress_classes);
    // Scoped to `infra_scope` (tenant ∪ install namespace): an IngressClass's
    // `spec.parameters.namespace` must now resolve within the watch set or the
    // controller's own namespace, so the lockdown needs no cluster-wide read (#59).
    let (class_params_reader, class_params_writers) =
        scoped_reader_writers::<CoxswainIngressClassParameters>(None, &infra_scope);
    let (gateway_reader, gateway_writers) = scoped_reader_writers::<Gateway>(pre.gateways, scope);
    let (gateway_class_reader, gateway_class_writer) =
        cluster_reader_writer::<GatewayClass>(pre.gateway_classes);
    let (slice_reader, slice_writers) = scoped_reader_writers::<EndpointSlice>(None, scope);
    let (grant_reader, grant_writers) = scoped_reader_writers::<ReferenceGrant>(None, scope);
    let (secret_reader, secret_writers) = scoped_reader_writers::<Secret>(None, scope);
    let (auth_secret_reader, auth_secret_writers) = scoped_reader_writers::<Secret>(None, scope);
    let (auth_tls_secret_reader, auth_tls_secret_writers) =
        scoped_reader_writers::<Secret>(None, scope);
    // See `new()`: Services fan over `infra_scope` so the rebuild sees the
    // per-Gateway shared-VIP Services in the install namespace (#472/#59).
    let (service_reader, service_writers) =
        scoped_reader_writers::<Service>(op_services_w, &infra_scope);
    let (policy_reader, policy_writers) =
        scoped_reader_writers::<BackendTlsPolicy>(pre.policies, scope);
    let (configmap_reader, configmap_writers) = scoped_reader_writers::<ConfigMap>(None, scope);
    let (rate_limit_reader, rate_limit_writers) = scoped_reader_writers::<RateLimit>(None, scope);
    let (retry_policy_reader, retry_policy_writers) =
        scoped_reader_writers::<RetryPolicy>(None, scope);
    let (path_rewrite_reader, path_rewrite_writers) =
        scoped_reader_writers::<PathRewriteRegex>(None, scope);
    let (ip_access_reader, ip_access_writers) =
        scoped_reader_writers::<IpAccessControl>(None, scope);
    let (basic_auth_reader, basic_auth_writers) = scoped_reader_writers::<BasicAuth>(None, scope);
    // JwtAuth has no status subresource (#441) — a plain, non-shared store is
    // enough; unlike CoxswainExternalAuth it has no targetRefs/Gateway-attachment
    // surface for the controller's status-writer to react to.
    let (jwt_auth_reader, jwt_auth_writers) = scoped_reader_writers::<JwtAuth>(None, scope);
    // CoxswainExternalAuth is a status-relevant store: the controller role
    // subscribes to it via `StatusSubscriptions.coxswain_external_auths` (#23) to
    // write `status.ancestors[]`, and the data-plane reader resolves both the
    // route-level ExtensionRef filter and the Gateway-attached policy index.
    let (external_auth_reader, external_auth_writers) =
        scoped_reader_writers::<CoxswainExternalAuth>(pre.coxswain_external_auths, scope);
    let (request_size_limit_reader, request_size_limit_writers) =
        scoped_reader_writers::<RequestSizeLimit>(None, scope);
    let (compression_reader, compression_writers) =
        scoped_reader_writers::<Compression>(None, scope);
    let (tls_route_reader, tls_route_writers) =
        scoped_reader_writers::<TlsRoute>(pre.tls_routes, scope);
    let (tcp_route_reader, tcp_route_writers) =
        scoped_reader_writers::<TcpRoute>(pre.tcp_routes, scope);
    let (udp_route_reader, udp_route_writers) =
        scoped_reader_writers::<UdpRoute>(pre.udp_routes, scope);
    // ListenerSet is a status-relevant store: in the controller role its writer is
    // the shared one pre-created in `new`, so the status-writer's subscription and
    // the data-plane reader observe the same synced store (GEP-1713).
    let (listener_set_reader, listener_set_writers) =
        scoped_reader_writers::<ListenerSet>(pre.listener_sets, scope);
    // ClientTrafficPolicy is a status-relevant store: the controller role subscribes
    // to it via `StatusSubscriptions.client_traffic_policies` (#327).
    let (ctp_reader, ctp_writers) =
        scoped_reader_writers::<ClientTrafficPolicy>(pre.client_traffic_policies, scope);
    // CoxswainBackendPolicy is a status-relevant store: the controller role
    // subscribes to it via `StatusSubscriptions.coxswain_backend_policies` (#354).
    let (cbp_reader, cbp_writers) =
        scoped_reader_writers::<CoxswainBackendPolicy>(pre.coxswain_backend_policies, scope);
    let (namespace_reader, namespace_writer) = cluster_reader_writer::<Namespace>(op_namespaces_w);
    // Lossless rebuild trigger (#574): a `watch::Sender<u64>` generation counter,
    // not a `Notify`. Every watch event bumps it via `bump_rebuild`; the rebuild
    // loop reads it with `changed()`/`borrow_and_update()`, which never miss a
    // bump — see [`ReflectorEffects`]. `rebuild_rx` is the single consumer.
    let (rebuild_tx, mut rebuild_rx) = watch::channel(0u64);
    let mut set = JoinSet::new();

    // Relist liveness backstop (#573), controller role only: trips the gate
    // (failing `/healthz`) if any reflector's watch relist stays incomplete past
    // the window, so kubelet restarts a wedged pod. Spawned before the
    // reflectors so it is already ticking when the first relists begin.
    if let Some(gate) = liveness_gate {
        set.spawn(crate::metrics::run_relist_liveness_monitor(gate));
    }
    // Shared context for the per-namespace reflector fans (#59): each namespaced
    // watch spawns one reflector per watched namespace via `scoped.namespaced`
    // (sharing a readiness barrier so the check flips Ready only once every
    // namespace has synced), and each cluster-scoped watch a single reflector via
    // `scoped.cluster`. `clients` is a Copy handle reused for the cluster-scoped
    // `Api::all` sites. `scoped` borrows `set` mutably; its last use is the
    // operator block below, after which the raw `set` is free again for the
    // JWKS/rebuild tasks (which move `controller_health` and cannot coexist with
    // `scoped`'s immutable borrow of it).
    let clients = WatchClientSource {
        config: &kube_config,
        fallback: &client,
    };
    let mut scoped = ScopedSpawn {
        set: &mut set,
        clients,
        scope: &watch_scope,
        trigger: &rebuild_tx,
        health: &controller_health,
        metrics,
    };

    // --- Always-on reflectors (both surfaces) ---
    //
    // EndpointSlice, Secret (TLS), and Service are needed whether Gateway API,
    // Ingress, or both are enabled: backends require port resolution (Service +
    // EndpointSlice) and TLS certs are shared across surfaces.
    scoped.namespaced::<EndpointSlice>(
        slice_writers,
        bulk_watch_config(),
        "endpoint_slice",
        "EndpointSlice",
    );
    // Field-selector scoped to `type=kubernetes.io/tls` to avoid pulling every Secret into memory.
    scoped.namespaced::<Secret>(
        secret_writers,
        bulk_watch_config().fields("type=kubernetes.io/tls"),
        "secret",
        "Secret",
    );
    // Used to resolve targetPort for backends where servicePort ≠ targetPort.
    scoped.namespaced_in::<Service>(
        &infra_scope,
        service_writers,
        bulk_watch_config(),
        "service",
        "Service",
    );
    // Label-scoped to `ingress.coxswain-labs.dev/auth-basic=true` — only opt-in
    // htpasswd Secrets are cached.  Keeps the data-plane proxy's memory footprint
    // bounded: Opaque Secrets without this label are never loaded (#24). Always-on
    // (not gated by `enable_ingress`): the Gateway-API `BasicAuth` ExtensionRef
    // (#442) consumes the same label-scoped store — no duplicate watcher.
    scoped.namespaced::<Secret>(
        auth_secret_writers,
        control_watch_config().labels("ingress.coxswain-labs.dev/auth-basic=true"),
        "auth_secret",
        "AuthSecret",
    );
    // Always-on (not gated by `enable_gateway_api`): the Ingress `auth-jwt`
    // annotation (#441) consumes the same `JwtAuth` CR store as the
    // Gateway-API `JwtAuth` ExtensionRef — gating this behind
    // `enable_gateway_api` would leave `auth-jwt` permanently unresolvable
    // (fail-open, no auth enforced) on an Ingress-only install. Mirrors the
    // `auth_secret` fix above for the identical cross-surface-store mistake.
    scoped.namespaced::<JwtAuth>(
        jwt_auth_writers,
        control_watch_config(),
        "jwt_auth",
        "JwtAuth",
    );
    // Always-on (not gated by `enable_gateway_api`): the Ingress `ext-auth`
    // annotation (#549) consumes the same `CoxswainExternalAuth` CR store as
    // the Gateway-API `ExternalAuth` ExtensionRef and `targetRefs` policy
    // surfaces. `CoxswainExternalAuth` is coxswain's own CRD (not upstream
    // Gateway API), so unlike HTTPRoute/Gateway/etc it needs no CRD-presence
    // probe — gating this behind `enable_gateway_api` would leave `ext-auth`
    // permanently unresolvable (fail-closed 503 on every route) on an
    // Ingress-only install. Mirrors the `jwt_auth` fix above for the
    // identical cross-surface-store mistake.
    scoped.namespaced::<CoxswainExternalAuth>(
        external_auth_writers,
        control_watch_config(),
        "coxswain_external_auth",
        "CoxswainExternalAuth",
    );
    // Always-on (not gated by `enable_gateway_api`): the Ingress `compression`
    // annotation (#550) consumes the same `Compression` CR store as the
    // Gateway-API `Compression` ExtensionRef. `Compression` is coxswain's own
    // CRD (not upstream Gateway API), so unlike HTTPRoute/Gateway/etc it needs
    // no CRD-presence probe — gating this behind `enable_gateway_api` would
    // leave `compression` permanently fail-open (silently no compression) on
    // an Ingress-only install. Mirrors the `jwt_auth`/`external_auth` fixes
    // above for the identical cross-surface-store mistake.
    scoped.namespaced::<Compression>(
        compression_writers,
        control_watch_config(),
        "compression",
        "Compression",
    );
    // Always-on (not gated by `enable_gateway_api`): same fix, same rationale,
    // for the Ingress `retry` annotation (#551) and the `RetryPolicy` CR store.
    scoped.namespaced::<RetryPolicy>(
        retry_policy_writers,
        control_watch_config(),
        "retry_policy",
        "RetryPolicy",
    );
    // Always-on (not gated by `enable_gateway_api`): same fix, same rationale,
    // for the Ingress `rate-limit` annotation (#552) and the `RateLimit` CR store.
    scoped.namespaced::<RateLimit>(
        rate_limit_writers,
        control_watch_config(),
        "rate_limit",
        "RateLimit",
    );
    // Always-on (not gated by `enable_gateway_api`): same fix, same rationale,
    // for the Ingress `ip-access-control` annotation (#553) and the
    // `IpAccessControl` CR store.
    scoped.namespaced::<IpAccessControl>(
        ip_access_writers,
        control_watch_config(),
        "ip_access_control",
        "IpAccessControl",
    );

    // --- Ingress reflectors (gated by --disable-ingress) ---
    //
    // The mTLS auth-tls Secret watch is Ingress-specific; the basic-auth Secret
    // watch moved to the always-on block above since Gateway API's `BasicAuth`
    // ExtensionRef (#442) consumes it too.
    if enable_ingress {
        scoped.namespaced::<Ingress>(
            ingress_writers,
            control_watch_config(),
            "ingress",
            "Ingress",
        );
        scoped.cluster::<IngressClass>(
            class_writer,
            Api::<IngressClass>::all(clients.client()),
            control_watch_config(),
            "ingress_class",
            "IngressClass",
        );
        // Watched over `infra_scope` (tenant namespaces ∪ the controller's own
        // namespace): an IngressClass is cluster-scoped but its params CR is a
        // namespaced object, and scoping the watch to the widened infra set lets
        // the lockdown grant a namespaced `Role` instead of cluster-wide read
        // (#59). A params CR outside that set is not observed — the operator must
        // place it in a watched namespace or the install namespace.
        scoped.namespaced_in(
            &infra_scope,
            class_params_writers,
            control_watch_config(),
            "ingress_class_parameters",
            "CoxswainIngressClassParameters",
        );
        // Label-scoped to `ingress.coxswain-labs.dev/auth-tls=true` — only opt-in CA
        // Secrets for per-Ingress client-certificate mTLS are cached (#267).  Separate
        // watch from `secrets` (server-TLS) and `auth_secrets` (htpasswd) to bound
        // memory: only operator-tagged CA Secrets are loaded.
        scoped.namespaced::<Secret>(
            auth_tls_secret_writers,
            control_watch_config().labels("ingress.coxswain-labs.dev/auth-tls=true"),
            "auth_tls_secret",
            "AuthTlsSecret",
        );
    }

    // --- Gateway API reflectors (gated by --disable-gateway-api + CRD probe) ---
    //
    // When the surface is enabled (default), probe for Gateway API CRDs. If
    // present, spawn all reflectors immediately. If absent, readiness fails
    // under the `gateway_api_crds` check and a background re-probe loop starts
    // the reflectors once the CRDs appear (self-healing — no pod restart needed).
    if enable_gateway_api {
        let gw_writers = GatewayApiStoreWriters {
            routes: route_writers,
            grpc_routes: grpc_route_writers,
            tls_routes: tls_route_writers,
            tcp_routes: tcp_route_writers,
            udp_routes: udp_route_writers,
            gateways: gateway_writers,
            gateway_classes: gateway_class_writer,
            grants: grant_writers,
            policies: policy_writers,
            configmaps: configmap_writers,
            path_rewrites: path_rewrite_writers,
            basic_auths: basic_auth_writers,
            request_size_limits: request_size_limit_writers,
            listener_sets: listener_set_writers,
            namespaces: namespace_writer,
            client_traffic_policies: ctp_writers,
            coxswain_backend_policies: cbp_writers,
        };
        if crate::crds::gateway_api_crds_present(&client).await {
            add_gateway_api_reflectors(&mut scoped, gw_writers);
            controller_health.ready("gateway_api_crds");
        } else {
            tracing::warn!(
                "Gateway API CRDs not found; readiness will wait until they appear \
                 (self-healing re-probe every 30 s — no pod restart required)"
            );
            // Self-heal probe task: polls until CRDs appear, then spawns the
            // Gateway API reflectors and clears the `gateway_api_crds` check.
            //
            // The writers slot is consumed exactly once (on first CRD detection)
            // and then the inner supervise-loop runs forever, so the outer loop
            // body never reaches the take() a second time.
            let probe_client = watch_client(&kube_config, &client);
            let probe_kube_config = kube_config.clone();
            let probe_trigger = rebuild_tx.clone();
            let probe_health = controller_health.clone();
            let probe_watch_scope = watch_scope.clone();
            let mut writers_slot = Some(gw_writers);
            scoped.set.spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    if crate::crds::gateway_api_crds_present(&probe_client).await {
                        let Some(writers) = writers_slot.take() else {
                            // The inner supervise loop exited — this is a bug
                            // since join_next() should run forever. Return to
                            // let the JoinSet clean up.
                            return;
                        };
                        let mut gw_set = JoinSet::new();
                        let mut probe_scoped = ScopedSpawn {
                            set: &mut gw_set,
                            clients: WatchClientSource {
                                config: &probe_kube_config,
                                fallback: &probe_client,
                            },
                            scope: &probe_watch_scope,
                            trigger: &probe_trigger,
                            health: &probe_health,
                            metrics,
                        };
                        add_gateway_api_reflectors(&mut probe_scoped, writers);
                        probe_health.ready("gateway_api_crds");
                        bump_rebuild(&probe_trigger);
                        tracing::info!(
                            "Gateway API CRDs detected; reflectors started and readiness cleared"
                        );
                        // Supervise the dynamically spawned reflectors for the
                        // lifetime of the probe task.
                        loop {
                            match gw_set.join_next().await {
                                Some(Ok(())) => {
                                    tracing::warn!("gateway-api reflector exited unexpectedly");
                                }
                                Some(Err(e)) => {
                                    tracing::error!(
                                        error = %e,
                                        "gateway-api reflector panicked"
                                    );
                                }
                                None => return,
                            }
                        }
                    }
                }
            });
        }
    }

    // --- Fleet / operator pod watch (controller role only) ---
    //
    // One `app.kubernetes.io/name=coxswain` Pod watch feeds two independent
    // consumers off the same shared store (#574): the `SharedFleet` snapshot
    // (operator tooling) and the operator fold's dedicated-proxy-readiness
    // reads. The watch fires whenever *either* consumer is wired, so the two
    // are structurally decoupled — the fleet snapshot task alone is gated on
    // `watch_fleet`, the store population is not. The shared-proxy pod (which
    // lacks pod-read RBAC and has neither consumer) never reaches this branch.
    if watch_fleet || op_pods_w.is_some() {
        // Scoped to `infra_scope` (tenant namespaces ∪ the install namespace):
        // coxswain's own pods live in the install namespace, and dedicated-proxy
        // pods in the tenant namespaces, so the widened set covers both without a
        // cluster-wide read (#59). The reader is a `MergedStore` folding every
        // scope namespace; `pod_writers` aligns index-for-index with
        // `infra_scope.api_scopes()`.
        let (pod_reader, pod_writers) = scoped_reader_writers::<Pod>(op_pods_w, &infra_scope);
        // Own `watch` trigger for the fleet snapshot (same lossless rationale as
        // the rebuild trigger): a pod event during a `build_snapshot` must not be
        // dropped. Distinct channel because the fleet snapshot is a separate,
        // undebounced consumer of the pod watch, not part of the routing rebuild.
        let (fleet_trigger, fleet_rx) = watch::channel(0u64);
        // Direct spawn per scope namespace (not `ScopedSpawn::namespaced_in`, which
        // is hard-wired to the rebuild trigger) because this watch drives the
        // distinct `fleet_trigger`. One shared readiness barrier across the fan so
        // the `pod` check flips Ready only once every namespace has synced.
        let pod_readiness = Arc::new(AtomicUsize::new(pod_writers.len().max(1)));
        for (writer, ns) in pod_writers.into_iter().zip(infra_scope.api_scopes()) {
            spawn_reflector(
                &mut *scoped.set,
                writer,
                scoped_api::<Pod>(clients.client(), ns),
                control_watch_config().labels("app.kubernetes.io/name=coxswain"),
                ReflectorEffects::new(
                    &fleet_trigger,
                    &controller_health,
                    "pod",
                    metrics,
                    ns.unwrap_or("").to_string(),
                    Arc::clone(&pod_readiness),
                ),
                "Pod",
            );
        }
        if watch_fleet {
            // Publishes a `SharedFleet` snapshot immediately on every pod watch
            // event — no debounce, because pod IP / annotation changes are
            // infrequent and low-latency matters for operator tooling.
            let mut fleet_rx = fleet_rx;
            scoped.set.spawn(async move {
                while fleet_rx.changed().await.is_ok() {
                    let pods = pod_reader.state();
                    fleet.store(Arc::new(fleet::build_snapshot(
                        pods.iter().map(Arc::as_ref),
                    )));
                }
            });
        }
    }

    // --- Operator-fold watches (#574), controller + Gateway API only ---
    //
    // CoxswainGatewayParameters (dedicated-proxy spec source), CoxswainRelayPolicy
    // (per-namespace relay tuning, #589), and Node (NodePort address resolution) back
    // OperatorStores. The reflector drives them here so the dedicated-provisioning
    // operator no longer runs its own client/watches. Gated by Gateway API (dedicated
    // Gateways require it) and by the presence of the pre-created operator writers
    // (controller role).
    if enable_gateway_api
        && let (Some(params_writers), Some(relay_policies_writers), Some(nodes_writer)) =
            (op_params_w, op_relay_policies_w, op_nodes_w)
    {
        // CoxswainGatewayParameters is a namespaced CRD, watched over `infra_scope`
        // (tenant namespaces ∪ the install namespace) so the lockdown grants a
        // namespaced `Role` instead of cluster-wide read (#59). `params_writers`
        // was pre-created in `new()` from the same `infra_scope`, so it aligns
        // index-for-index with `api_scopes()` here. A dedicated Gateway's
        // `parametersRef` must therefore resolve within the watch set or the
        // install namespace; a params CR outside that set is not observed.
        scoped.namespaced_in(
            &infra_scope,
            params_writers,
            control_watch_config(),
            "coxswain_gateway_parameters",
            "CoxswainGatewayParameters",
        );
        // CoxswainRelayPolicy is a namespaced CRD (#59): the policy in a namespace governs
        // that namespace's relay, so it is watched over the tenant `watch_scope` (NOT
        // widened by the install namespace — a relay policy governs a tenant namespace, not
        // `coxswain-system`). A policy change re-enqueues owned Gateways via `rebuild_tx` so
        // per-namespace relay convergence recomputes. `relay_policies_writers` was
        // pre-created in `new()` from the same `watch_scope`, so it aligns index-for-index.
        scoped.namespaced::<CoxswainRelayPolicy>(
            relay_policies_writers,
            control_watch_config(),
            "coxswain_relay_policy",
            "CoxswainRelayPolicy",
        );
        scoped.cluster::<Node>(
            nodes_writer,
            Api::<Node>::all(clients.client()),
            bulk_watch_config(),
            "node",
            "Node",
        );
    }

    // --- JWKS fetch/refresh (controller role only, #441) ---
    //
    // Fetches and refreshes remote JWKS endpoints named by `JwtAuth` CRs,
    // publishing resolved keys into `jwks_cache`. Gated by `fetch_remote_jwks`
    // so the read-only proxy role never egresses to an identity provider (the
    // Istio model, not Envoy's default proxy-side fetch) — see [`crate::jwks`].
    let jwks_cache = crate::jwks::SharedJwksCache::new();
    if fetch_remote_jwks {
        let cache = jwks_cache.clone();
        let jwt_auths_for_fetch = jwt_auth_reader.clone();
        // Single connection-pooling client for JWKS fetches — mirrors the
        // ext_authz sub-request client (bin/lib.rs); rustls backend, no
        // native-tls dep. `run()` installs the crypto provider before any
        // reconciler role starts, so this construction succeeds in practice; a
        // rustls-init failure is environmental, not a logic bug, so degrade
        // (skip the fetcher — JWT validation fails closed on absent keys) rather
        // than crashing the controller.
        match reqwest::Client::builder().use_rustls_tls().build() {
            Ok(jwks_client) => {
                set.spawn(async move {
                    crate::jwks::run(cache, jwt_auths_for_fetch, jwks_client).await;
                });
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "JWKS fetch client could not be built; remote JWKS refresh disabled \
                     (JWT validation fails closed until the controller restarts)"
                );
            }
        }
        // Forward cache-change notifications into the shared rebuild trigger so a
        // JWKS resolving, rotating, or starting to fail re-drives the debounced
        // rebuild below — the same mechanism every watched CR uses. Bumping the
        // `watch` generation is lossless even if the rebuild loop is mid-rebuild
        // (the old `notify_waiters()` here woke only currently-parked waiters, so
        // a JWKS change during a rebuild was dropped until the next resync tick).
        let mut jwks_changed = jwks_cache.subscribe();
        let jwks_trigger = rebuild_tx.clone();
        set.spawn(async move {
            while jwks_changed.changed().await.is_ok() {
                bump_rebuild(&jwks_trigger);
            }
        });
    }

    // --- Adaptive trailing-edge debounce + rebuild (#512) ---
    //
    // Waits for the first notification, then settles via `debounce::settle`:
    // a short quiet window (`debounce.min()`) fires fast for an isolated
    // event, widening only up to a hard ceiling (`debounce.max()`) under
    // sustained churn. When it settles, the full routing table is rebuilt
    // from the current store snapshots — never from the API server.
    set.spawn(async move {
        let mut routing_table_published = false;
        // Cross-rebuild reuse state (#511) — owned by this task, outliving any
        // single `rebuild()` call, since `rebuild()` itself has no handle to
        // what it published last cycle. See `reconciler::cache` module docs.
        let mut caches = super::cache::ReflectorCaches::default();
        // #574 backstop: a periodic resync re-runs the rebuild even when no watch
        // event fires, so a *silently stalled watch connection* (a stream that
        // never delivers, distinct from the store) can't leave the routing table
        // and derived status cells stale indefinitely (see [`REBUILD_RESYNC_PERIOD`]).
        // The trigger itself is now a lossless `watch` channel, so — unlike the
        // former `Notify` — a *delivered* event is never dropped in favor of this
        // tick; the resync is a true backstop, not the recovery path for a raced
        // wake. `biased;` makes that explicit: the trigger is polled before the
        // tick, so a pending bump is always taken first.
        let mut resync = tokio::time::interval(REBUILD_RESYNC_PERIOD);
        resync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Consume the immediate first tick so the loop still blocks on the first
        // real watch event before its first rebuild — a resync-triggered rebuild
        // against empty startup stores would flip the first-publish readiness
        // checks prematurely.
        resync.tick().await;
        loop {
            tokio::select! {
                biased;
                changed = rebuild_rx.changed() => {
                    // Err only when every reflector trigger has been dropped —
                    // the reconciler is shutting down; exit the rebuild task.
                    if changed.is_err() {
                        return;
                    }
                    rebuild_rx.borrow_and_update();
                }
                _ = resync.tick() => {}
            }
            // #513: the debounce-wait stage starts the instant the first watch
            // event of this cycle is observed (here, not before — the loop was
            // idle waiting for it) and ends when `settle` returns. This is the
            // "trigger → debounce fire" leg of the convergence pipeline,
            // measured independently of rebuild() cost — #512 shrinks this
            // stage for isolated edits without changing the churn ceiling.
            let debounce_start = std::time::Instant::now();
            super::debounce::settle(&mut rebuild_rx, debounce).await;
            let debounce_wait = debounce_start.elapsed();
            metrics.observe_debounce_wait(debounce_wait);
            // One VIP-Service read per rebuild (#472), shared by every builder.
            let vip_internal = crate::port_alloc::read_vip_internal_ports(&service_reader.state());
            // Regroup the EndpointSlice store by (namespace, service) before any
            // builder runs (#511) — resolve_from_group / EndpointCache::get reads
            // this rebuild's grouping, never re-scanning the full store per
            // backend reference.
            caches.endpoints.refresh(&slice_reader);
            let stores = ReflectorStores {
                routes: &route_reader,
                grpc_routes: &grpc_route_reader,
                tls_routes: &tls_route_reader,
                tcp_routes: &tcp_route_reader,
                udp_routes: &udp_route_reader,
                ingresses: &ingress_reader,
                ingress_classes: &class_reader,
                ingress_class_parameters: &class_params_reader,
                gateways: &gateway_reader,
                gateway_classes: &gateway_class_reader,
                listener_sets: &listener_set_reader,
                namespaces: &namespace_reader,
                services: &service_reader,
                endpoint_cache: &caches.endpoints,
                vip_internal: &vip_internal,
                grants: &grant_reader,
                secrets: &secret_reader,
                auth_secrets: &auth_secret_reader,
                auth_tls_secrets: &auth_tls_secret_reader,
                policies: &policy_reader,
                configmaps: &configmap_reader,
                rate_limits: &rate_limit_reader,
                retry_policies: &retry_policy_reader,
                path_rewrites: &path_rewrite_reader,
                ip_access: &ip_access_reader,
                basic_auths: &basic_auth_reader,
                external_auths: &external_auth_reader,
                jwt_auths: &jwt_auth_reader,
                jwks_cache: &jwks_cache,
                request_size_limits: &request_size_limit_reader,
                compressions: &compression_reader,
                client_traffic_policies: &ctp_reader,
                coxswain_backend_policies: &cbp_reader,
            };
            let outputs = SharedOutputs {
                ingress_routes: &ingress_routes,
                gateway_routes: &gateway_routes,
                tls: &tls,
                client_certs: &client_certs,
                listener_hostnames: &listener_hostnames,
                listener_status: &listener_status,
                cluster_summary: &cluster_summary,
                dedicated_registry: &dedicated_registry,
                route_status: &route_status,
                grpc_route_status: &grpc_route_status,
                tls_route_status: &tls_route_status,
                tcp_route_status: &tcp_route_status,
                udp_route_status: &udp_route_status,
                policy_status: &policy_status,
                ctp_status: &ctp_status,
                cbp_status: &cbp_status,
                external_auth_status: &external_auth_status,
                publish_index: &publish_index,
                passthrough_routes: &passthrough_routes,
                terminate_routes: &terminate_routes,
                tcp_routes: &tcp_routes,
                udp_routes: &udp_routes,
                ingress_event_tx: ingress_event_tx.as_ref(),
            };
            let rebuild_start = std::time::Instant::now();
            let published = rebuild(
                &stores,
                &controller_name,
                &owned_gateways,
                ingress_default_backend.as_ref(),
                ingress_ports,
                leader.load(Ordering::Acquire),
                RebuildIo {
                    outputs: &outputs,
                    gateway_partitions: &mut caches.gateway_partitions,
                    dedicated_partitions: &mut caches.dedicated_partitions,
                },
            );
            let rebuild_duration = rebuild_start.elapsed();
            // Mirror routing-table size gauges and TLS cert counters from published snapshots.
            record_rebuild_metrics(&metrics, &outputs, rebuild_duration, published);
            // #513: correlate this convergence across the reflector/discovery/proxy
            // tiers by the rebuild sequence — `rebuild()` unconditionally stamps
            // `publish_index` (proxy.rs `stamp_rebuild` call), so `current_seq()`
            // here is exactly this rebuild's sequence. The discovery server logs
            // the same seq (captured before its snapshot build) alongside the
            // snapshot's content-hash `version`, letting an operator join a
            // reflector log line to a discovery push by `seq` and a discovery
            // push to a proxy apply by `version`.
            tracing::debug!(
                seq = outputs.publish_index.current_seq(),
                published,
                debounce_ms = debounce_wait.as_millis() as u64,
                rebuild_ms = rebuild_duration.as_millis() as u64,
                "convergence: routing table rebuilt"
            );
            // First successful publish: flip the readiness checks that gate
            // `/readyz` on having an honest routing table. Subsequent rebuilds
            // do not re-touch the checks — `Ready` is idempotent and there is
            // no transient state we want to flag here.
            if published && !routing_table_published {
                controller_health.ready("routing_table_built");
                proxy_health.ready("routing_table_loaded");
                routing_table_published = true;
            }
            // #574: with the fresh routing + derived status cells published,
            // enqueue every status-relevant object so the controller's unified
            // worker reconciles its `*/status`. This is the single trigger that
            // replaces the deleted per-kind fan-out — one pass over the
            // authoritative stores, deduped by the queue, with cross-object drift
            // (a ReferenceGrant / Secret / Service change flipping a route's
            // `ResolvedRefs`) picked up because the rebuild ran first. `None` in
            // the proxy role (no status is written there).
            if let Some(queue) = &status_queue {
                enqueue_status_keys(queue, &stores);
            }
        }
    });

    set
}

/// Enqueue every status-relevant object from the authoritative stores into the
/// controller's work queue (#574). Bounded work: the queue de-duplicates and the
/// worker's reconcilers short-circuit when no `*/status` patch is needed, so
/// re-enqueuing the full set after each rebuild converges cross-object status
/// drift without a per-object diff.
fn enqueue_status_keys(queue: &StatusWorkqueue, stores: &ReflectorStores<'_>) {
    fn enq<K>(queue: &StatusWorkqueue, kind: StatusKind, store: &MergedStore<K>)
    where
        K: kube::Resource + Clone + 'static,
        K::DynamicType: Eq + std::hash::Hash + Clone + Default,
    {
        for obj in store.state() {
            // Cluster-scoped kinds (GatewayClass) have no namespace — key them
            // with an empty namespace rather than dropping them (which
            // `ObjectKey::from_meta` would do), or their status never converges.
            if let Some(name) = obj.meta().name.clone() {
                let ns = obj.meta().namespace.clone().unwrap_or_default();
                queue.add(StatusKey::new(kind, ObjectKey::new(ns, name)));
            }
        }
    }
    enq(queue, StatusKind::Gateway, stores.gateways);
    enq(queue, StatusKind::GatewayClass, stores.gateway_classes);
    enq(queue, StatusKind::HttpRoute, stores.routes);
    enq(queue, StatusKind::GrpcRoute, stores.grpc_routes);
    enq(queue, StatusKind::TlsRoute, stores.tls_routes);
    enq(queue, StatusKind::TcpRoute, stores.tcp_routes);
    enq(queue, StatusKind::UdpRoute, stores.udp_routes);
    enq(queue, StatusKind::Ingress, stores.ingresses);
    enq(queue, StatusKind::BackendTlsPolicy, stores.policies);
    enq(queue, StatusKind::ListenerSet, stores.listener_sets);
    enq(
        queue,
        StatusKind::ClientTrafficPolicy,
        stores.client_traffic_policies,
    );
    enq(
        queue,
        StatusKind::CoxswainBackendPolicy,
        stores.coxswain_backend_policies,
    );
    enq(
        queue,
        StatusKind::CoxswainExternalAuth,
        stores.external_auths,
    );
}

/// Publish outputs plus the cross-rebuild partition-reuse caches (#511) a
/// rebuild pass writes into — grouped so `rebuild()` stays under the
/// workspace's 7-argument threshold. Carries the two partition-cache fields
/// directly (not `&mut ReflectorCaches` as a whole): `stores.endpoint_cache`
/// is a separate borrow of `ReflectorCaches::endpoints` alive for this same
/// call, and borrowing the whole struct here would conflict with it — these
/// are disjoint fields, so the caller passes each by its own `&mut`.
pub(super) struct RebuildIo<'a> {
    pub(super) outputs: &'a SharedOutputs<'a>,
    pub(super) gateway_partitions: &'a mut super::cache::PartitionCache,
    pub(super) dedicated_partitions: &'a mut HashMap<ObjectKey, super::cache::PartitionCache>,
}

/// Returns `true` if a new routing table was published (the rebuild succeeded).
/// Used by the debounce loop to flip the first-publish readiness checks once.
fn rebuild(
    stores: &ReflectorStores<'_>,
    controller_name: &str,
    owned_gateways_handle: &OwnedGateways,
    ingress_default_backend: Option<&IngressDefaultBackend>,
    ingress_ports: IngressPorts,
    leader: bool,
    io: RebuildIo<'_>,
) -> bool {
    let RebuildIo {
        outputs,
        gateway_partitions,
        dedicated_partitions,
    } = io;
    // #531: the generations stamped into the publish index at the END of this
    // rebuild MUST come from a store snapshot taken BEFORE any routing cell is
    // built. The live watcher store keeps updating while the cells build; a
    // generation read afterwards can be newer than the config the cells
    // actually carry, and stamping it would let the ack gate certify a
    // generation no proxy has received (the stamp is sticky per generation,
    // so the over-claim would never self-repair). A start-of-rebuild snapshot
    // can only under-claim — fail closed — and the store change that caused
    // the skew triggers the next debounced rebuild, which re-stamps.
    let stamp_gateways = stores.gateways.state();
    let routes = stores.routes.state();
    let grpc_routes = stores.grpc_routes.state();
    let ingresses = stores.ingresses.state();

    let OwnedResources {
        ingress_classes: owned_ingress_classes,
        default_ingress_class: owned_default_ingress_class,
        gateway_classes: owned_gateway_classes,
        gateways: owned_gateways,
    } = compute_ownership(
        stores.ingress_classes,
        stores.gateway_classes,
        stores.gateways,
        controller_name,
        owned_gateways_handle,
    );

    let grants_snapshot = stores.grants.state();
    let (backend_grants, cert_grants) = flatten_grants(&grants_snapshot);
    let ca_grants = flatten_ca_grants(&grants_snapshot);
    let ls_cert_grants = flatten_ls_cert_grants(&grants_snapshot);
    let basic_auth_secret_grants = flatten_basic_auth_secret_grants(&grants_snapshot);
    let tcp_backend_grants = flatten_tcp_backend_grants(&grants_snapshot);
    let udp_backend_grants = flatten_udp_backend_grants(&grants_snapshot);

    tracing::debug!(
        http_routes = routes.len(),
        ingresses = ingresses.len(),
        owned_ingress_classes = owned_ingress_classes.len(),
        owned_gateways = owned_gateways.len(),
        "Rebuilding routing table"
    );

    // Resolve `ClientTrafficPolicy` configs per (gateway, optional listener) before
    // the rebuild so `gateway_listener_status` can be annotated with proxy_protocol.
    let (ctp_index, ctp_status_map) =
        resolve_client_traffic_policies(stores.client_traffic_policies, &owned_gateways);

    // `policy_index` is built first because `Ownership` now carries a borrow of it.
    let (policy_index, mut policy_status_map) =
        build_backend_tls_index(stores.policies, stores.configmaps, stores.services);

    // Per-Service connect/idle timeout index from `CoxswainBackendPolicy` (#354).
    // Carried in `Ownership` alongside `policy_index` and applied to each
    // Gateway API `BackendGroup` during route building.
    let (backend_policy_index, cbp_status_map) =
        build_backend_policy_index(stores.coxswain_backend_policies);

    // Per-Gateway ext-auth mandate from `CoxswainExternalAuth` `targetRefs`
    // policies (#23). The index is prepended to every bound route's auth chain
    // during Gateway API route building; the status map feeds the controller's
    // `status.ancestors[]` writer (published at the end of the rebuild).
    let (external_auth_gateway_index, external_auth_status_map) =
        crate::gateway_api::resolve_gateway_policies(
            stores.external_auths,
            &owned_gateways,
            stores.services,
            stores.endpoint_cache,
            &backend_grants,
        );

    // GEP-3155: resolve each Gateway's backend client cert once. `certs` is attached
    // to UpstreamTls during the route build; `health` feeds the gateway-level
    // ResolvedRefs condition merged into `gateway_listener_status` below.
    let backend_client_certs =
        resolve_backend_client_certs(stores, &owned_gateway_classes, &cert_grants, true);

    // GEP-1713: compute every owned Gateway's effective listener set (its own plus
    // the listeners merged from attached ListenerSets, gated by each Gateway's
    // `allowedListeners`) ONCE, before both the shared and dedicated build paths,
    // so they consume one consistent source of truth.
    let effective = super::listener_merge::merge_effective_gateways(
        &stores.gateways.state(),
        &stores.listener_sets.state(),
        &owned_gateway_classes,
        stores.namespaces,
    );

    let ownership = Ownership {
        ingress_classes: &owned_ingress_classes,
        default_ingress_class: owned_default_ingress_class.as_deref(),
        gateways: &owned_gateways,
        gateway_classes: &owned_gateway_classes,
        backend_grants: &backend_grants,
        cert_grants: &cert_grants,
        ls_cert_grants: &ls_cert_grants,
        ca_grants: &ca_grants,
        basic_auth_secret_grants: &basic_auth_secret_grants,
        policy_index: &policy_index,
        backend_policy_index: &backend_policy_index,
        external_auth_gateway_index: &external_auth_gateway_index,
        backend_client_certs: &backend_client_certs.certs,
        backend_client_cert_failures: &backend_client_certs.failures,
        effective_gateways: &effective,
    };
    // Computed ONCE per rebuild and shared by the shared-pool build below and
    // every dedicated-Gateway build (#511): the epoch reads only rebuild-wide
    // stores and grant sets identical across all of them, and recomputing it
    // per build would repay a full hash pass over every Secret/ConfigMap/
    // policy/Gateway once per dedicated Gateway.
    let global_epoch = super::route_builder::compute_global_epoch(stores, &ownership);

    let routes_published = build_routes(
        stores,
        &routes,
        &grpc_routes,
        &ingresses,
        &ownership,
        IngressBuildConfig {
            default_backend: ingress_default_backend,
            ports: ingress_ports,
        },
        RouteBuildIo {
            outputs,
            gateway_partitions,
            global_epoch,
        },
    );

    let mut gateway_listener_status = build_tls(
        stores,
        &ingresses,
        &ownership,
        outputs.tls,
        outputs.listener_hostnames,
        true,
        ingress_ports.https,
    );
    build_client_certs(
        stores,
        &ingresses,
        &ownership,
        outputs.client_certs,
        &mut gateway_listener_status,
        true,
        ingress_ports.https,
    );
    merge_backend_client_cert_health(&mut gateway_listener_status, &backend_client_certs.health);

    let tls_routes = stores.tls_routes.state();
    let tcp_routes_crs = stores.tcp_routes.state();
    let udp_routes_crs = stores.udp_routes.state();
    // GEP-1713: ListenerSet → parent Gateway map so a `parentRef.kind: ListenerSet`
    // route counts against the listener on its parent Gateway's health entry.
    let ls_parent: HashMap<ObjectKey, ObjectKey> = effective
        .iter()
        .flat_map(|(gw_key, eff)| {
            eff.listeners.iter().filter_map(move |l| match &l.source {
                ListenerSource::ListenerSet(ls_key) => Some((ls_key.clone(), gw_key.clone())),
                ListenerSource::Gateway => None,
            })
        })
        .collect();
    count_attached_routes(
        &routes,
        &owned_gateways,
        &ls_parent,
        &mut gateway_listener_status,
        RouteAttachKind::Http,
    );
    count_attached_routes(
        &grpc_routes,
        &owned_gateways,
        &ls_parent,
        &mut gateway_listener_status,
        RouteAttachKind::Http,
    );
    count_attached_routes(
        &tls_routes,
        &owned_gateways,
        &ls_parent,
        &mut gateway_listener_status,
        RouteAttachKind::TlsL4,
    );
    count_attached_routes(
        &tcp_routes_crs,
        &owned_gateways,
        &ls_parent,
        &mut gateway_listener_status,
        RouteAttachKind::Tcp,
    );
    count_attached_routes(
        &udp_routes_crs,
        &owned_gateways,
        &ls_parent,
        &mut gateway_listener_status,
        RouteAttachKind::Udp,
    );

    // Wire CTP-resolved proxy_protocol config into each listener's `ListenerInfo`
    // (#327). Section-scoped policies take precedence via `effective_proxy_config`.
    for (gw_key, gw_status) in &mut gateway_listener_status {
        for (listener_key, listener_info) in &mut gw_status.listeners {
            if let Some(config) = effective_proxy_config(&ctp_index, gw_key, &listener_key.name) {
                listener_info.proxy_protocol = Some(config.clone());
            }
        }
    }

    let gateways = stores.gateways.state();

    // GatewayClass names that have a CoxswainGatewayParameters parametersRef —
    // used to classify Gateways whose dedicated-mode opt-in comes via the class
    // rather than a per-Gateway infrastructure.parametersRef (#229).
    let dedicated_gateway_class_names: HashSet<String> = stores
        .gateway_classes
        .state()
        .into_iter()
        .filter(|gc| {
            gc.spec.parameters_ref.as_ref().is_some_and(|pr| {
                pr.group == PARAMETERS_REF_GROUP && pr.kind == PARAMETERS_REF_KIND
            })
        })
        .filter_map(|gc| gc.metadata.name.clone())
        .collect();

    // `owned_gateways` deliberately drops Gateways cut over to a dedicated proxy
    // (#210) so the shared pool stops *routing* them. The cluster summary is an
    // observability surface, not a routing input: it must still LIST those
    // Gateways (a dedicated Gateway is just as real as a shared one), so build a
    // superset keyed on owned GatewayClass — independent of cut-over state.
    // `build_gateways` then classifies each as shared/dedicated on its own.
    let summary_gateways: HashSet<ObjectKey> = gateways
        .iter()
        .filter(|g| owned_gateway_classes.contains(&g.spec.gateway_class_name))
        .filter_map(|g| ObjectKey::from_meta(&g.metadata))
        .collect();

    // Per-(route, parent) health feeds both the route-status writer and the
    // cluster summary's traffic-served HTTPRoute status, so compute it before
    // publishing the summary.
    let route_status_map = GatewayApiReconciler::compute_route_health(
        &routes,
        &gateways,
        &owned_gateways,
        &effective,
        &backend_grants,
        stores.services,
    );

    // GRPCRoute health uses a separate map and channel — RouteParentKey is kind-neutral
    // and an HTTPRoute + GRPCRoute with the same name/ns/gateway would collide.
    let grpc_route_status_map = GrpcRouteReconciler::compute_route_health(
        &grpc_routes,
        &gateways,
        &owned_gateways,
        &effective,
        &backend_grants,
        stores.services,
    );

    // Publish the cluster summary while we still have access to gateway_listener_status
    // (it's moved into `listener_status.store_and_notify` next). Reads from already-
    // materialised state: nothing kube-side, no allocations beyond the summary.
    // Routing-table conflicts/dead-routes are overlaid in the UI from the
    // cross-proxy `/api/v1/problems` aggregate (the controller's table excludes
    // cut-over dedicated gateways, so it can't see all of them, #301).
    outputs
        .cluster_summary
        .store(Arc::new(build_cluster_summary(&ClusterSummaryInputs {
            gateways: &gateways,
            ingresses: &ingresses,
            owned_gateways: &summary_gateways,
            dedicated_gateway_class_names: &dedicated_gateway_class_names,
            owned_ingress_classes: &owned_ingress_classes,
            default_ingress_class: owned_default_ingress_class.as_deref(),
            gateway_listener_status: &gateway_listener_status,
            routes: &routes,
            route_status: &route_status_map,
            leader,
        })));

    // Merge the shared pool's (non-cut-over) listener status into the cell
    // without clobbering the cut-over Gateways' entries, which the dedicated
    // reconcilers own. A full replace here would transiently drop a dedicated
    // Gateway's listener under concurrent reconciles, making its proxy unbind
    // the listener (#423 dedicated bind→remove).
    let cut_over_keys: HashSet<ObjectKey> = gateways
        .iter()
        .filter(|g| gateway_is_cut_over(g))
        .filter_map(|g| ObjectKey::from_meta(&g.metadata))
        .collect();
    outputs
        .listener_status
        .update_scoped(gateway_listener_status, |k| !cut_over_keys.contains(k));
    outputs.route_status.store_and_notify(route_status_map);
    outputs
        .grpc_route_status
        .store_and_notify(grpc_route_status_map);

    // Compute per-policy ancestor lists and merge with the validity health from index build.
    let ancestor_health = GatewayApiReconciler::compute_policy_health(
        &policy_index,
        stores.policies,
        &routes,
        &owned_gateways,
    );
    for (key, ah) in ancestor_health {
        let entry = policy_status_map.entry(key).or_default();
        entry.ancestors = ah.ancestors;
    }
    outputs.policy_status.store_and_notify(policy_status_map);
    outputs.ctp_status.store_and_notify(ctp_status_map);
    outputs.cbp_status.store_and_notify(cbp_status_map);
    outputs
        .external_auth_status
        .store_and_notify(external_auth_status_map);

    // Build per-cut-over-Gateway snapshots for the dedicated registry (#426).
    //
    // This is the single-writer pass: only the shared reconciler writes to
    // `DedicatedRoutingRegistry`, so concurrent dedicated-proxy subscribes cannot
    // clobber each other's routing cells.  A Gateway that is no longer cut-over
    // simply does not appear in the new map — automatic teardown with no explicit
    // delete path.
    // GEP-3155: resolve backend client certs for the dedicated path once, outside
    // the per-Gateway loop. `skip_cut_over=false` — cut-over Gateways are included
    // (each IS the target Gateway for its dedicated proxy).
    let dedicated_backend_client_certs =
        resolve_backend_client_certs(stores, &owned_gateway_classes, &cert_grants, false);
    let empty_ingress_classes: HashSet<String> = HashSet::new();
    let dedicated_inputs = DedicatedBuildInputs {
        routes: &routes,
        grpc_routes: &grpc_routes,
        ingresses: &ingresses,
        base_ownership: &ownership,
        dedicated_certs: &dedicated_backend_client_certs,
        empty_ingress_classes: &empty_ingress_classes,
        global_epoch,
    };
    let registry_map: HashMap<ObjectKey, Arc<DedicatedRoutingSnapshot>> = stores
        .gateways
        .state()
        .iter()
        .filter_map(|gw| {
            build_dedicated_gateway_snapshot(gw, stores, &dedicated_inputs, dedicated_partitions)
        })
        .collect();
    let dedicated_keys: HashSet<ObjectKey> = registry_map.keys().cloned().collect();
    // Drop partition caches for Gateways that produced no dedicated snapshot
    // this rebuild (deleted, or reverted from cut-over) — without this the
    // per-Gateway `PartitionCache`s (each holding compiled `Arc<HostRouter>`s)
    // accumulate for the controller's lifetime under Gateway churn (#511).
    // Reappearance is safe: planning re-checks fingerprints from scratch, so
    // an evicted Gateway simply recompiles fresh on its next cut-over.
    dedicated_partitions.retain(|key, _| dedicated_keys.contains(key));
    // Fold each dedicated snapshot's listener health into the controller-side
    // cell too (#570). The snapshot copy only travels the discovery wire to
    // the dedicated proxy; without this fold the controller cell keeps a
    // cut-over Gateway's entry frozen at its LAST pre-cut-over shared-path
    // value — `VipPending`, because the shared path keys internal ports off
    // VIP Services a dedicated Gateway never gets — so the operator status
    // writer never sees the real per-listener readiness (a malformed cert
    // reads as eternally-pending instead of settling `InvalidCertificateRef`).
    // Scoped to `dedicated_keys`: the shared writer's own `update_scoped`
    // below owns every non-cut-over entry. Ordered BEFORE the publish-index
    // stamp so the stamped health fingerprints cover these entries.
    let dedicated_health: HashMap<ObjectKey, GatewayListenerStatus> = registry_map
        .values()
        .flat_map(|snap| {
            snap.listener_status
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
        })
        .collect();
    outputs
        .listener_status
        .update_scoped(dedicated_health, |k| dedicated_keys.contains(k));
    outputs
        .dedicated_registry
        .store(Arc::new(DedicatedRegistryData::from_map(registry_map)));

    // Build the SNI-keyed TLS passthrough table from TLSRoutes bound to
    // TLS/Passthrough listeners on owned Gateways and their attached ListenerSets
    // (GEP-2643 #70, GEP-1713 #93).
    let passthrough_status_map = build_passthrough_routes(
        stores,
        &owned_gateways,
        &effective,
        &backend_grants,
        outputs.passthrough_routes,
    );
    // Build the SNI-keyed TLS terminate table from TLSRoutes bound to
    // TLS/Terminate listeners (TLSRouteModeTerminate, #481). The two tables are
    // isolated so Mixed-mode ports can carry both listener types without cross-leak.
    // Route health is merged: a TLSRoute may bind to both a passthrough and a
    // terminate listener (different parentRef.sectionName) so the union is the full
    // health picture.
    let terminate_status_map = build_terminate_routes(
        stores,
        &owned_gateways,
        &effective,
        &backend_grants,
        outputs.terminate_routes,
    );
    // Merge both status maps (passthrough wins on key collision — same route,
    // same parent can't bind to both modes simultaneously per GW-API invariant).
    let mut tls_route_status_map = passthrough_status_map;
    tls_route_status_map.extend(terminate_status_map);
    outputs
        .tls_route_status
        .store_and_notify(tls_route_status_map);

    // Build the port-keyed TCP routing table from TCPRoutes bound to
    // `protocol: TCP` listeners (GEP-1901, #505). No SNI/hostname dimension —
    // isolated from both TLS L4 tables.
    let tcp_route_status_map = build_tcp_routes(
        stores,
        &owned_gateways,
        &effective,
        &tcp_backend_grants,
        outputs.tcp_routes,
    );
    outputs
        .tcp_route_status
        .store_and_notify(tcp_route_status_map);

    // Build the port-keyed UDP routing table from UDPRoutes bound to
    // `protocol: UDP` listeners (GEP-2645, #506). No SNI/hostname dimension —
    // isolated from both TCP and TLS L4 tables.
    let udp_route_status_map = build_udp_routes(
        stores,
        &owned_gateways,
        &effective,
        &udp_backend_grants,
        outputs.udp_routes,
    );
    outputs
        .udp_route_status
        .store_and_notify(udp_route_status_map);

    // #531 ack gate: stamp the publish index LAST, after every routing cell
    // above has been stored — the sequence bump is the publication fence the
    // discovery server's pre-build capture relies on. Covers both worlds:
    // shared-pool Gateways (config in the shared cells) and cut-over Gateways
    // (config in the dedicated registry), each at its current generation plus
    // a fingerprint of its own published listener-status entry: a
    // same-generation content change (a frontendValidation CA resolving one
    // rebuild after the spec was first processed, a cert ref flipping, a
    // route attaching) re-arms the stamp so proxies must apply THAT content
    // before Programmed flips. Then re-tick the rebuild watch so
    // subscription loops that woke on the mid-rebuild `store_and_notify`
    // re-capture a post-stamp sequence — without it a quiet cluster strands
    // the gate until the next content change.
    let published_listener_status = outputs.listener_status.load();
    let stamped = stamp_gateways.iter().filter_map(|g| {
        let key = ObjectKey::from_meta(&g.metadata)?;
        (owned_gateways.contains(&key) || dedicated_keys.contains(&key)).then(|| {
            let fingerprint = {
                use std::hash::{Hash as _, Hasher as _};
                let mut h = std::collections::hash_map::DefaultHasher::new();
                // Debug-format hashing: the entry's types carry no Hash impl,
                // but their derived Debug output is a pure function of the
                // state (readiness enums, resolution outcomes, counts —
                // no timestamps), which is exactly what the stamp needs.
                if let Some(entry) = published_listener_status.get(&key) {
                    format!("{entry:?}").hash(&mut h);
                }
                h.finish()
            };
            (key, g.metadata.generation.unwrap_or(0), fingerprint)
        })
    });
    outputs.publish_index.stamp_rebuild(stamped);
    outputs.route_status.notify_rebuilt();

    routes_published
}

/// Emit routing-table and TLS size/timing metrics after each rebuild.
///
/// Separated from [`rebuild`] so that the debounce loop stays readable and the
/// metric paths are independently testable.
fn record_rebuild_metrics(
    metrics: &crate::ReflectorMetrics,
    outputs: &SharedOutputs<'_>,
    elapsed: std::time::Duration,
    published: bool,
) {
    metrics.observe_rebuild(elapsed, if published { "ok" } else { "error" });
    let ing_snapshot = outputs.ingress_routes.load();
    let gw_snapshot = outputs.gateway_routes.load();
    metrics.set_routing_table(
        ing_snapshot.host_count() + gw_snapshot.host_count(),
        ing_snapshot.host_count(),
        gw_snapshot.host_count(),
    );
    let tls_snapshot = outputs.tls.load();
    let (exact, wildcard, default) = tls_snapshot.cert_counts();
    let expiries = tls_snapshot.expiries();
    metrics.set_tls(exact, wildcard, default, &expiries);
}

#[cfg(test)]
mod tests {
    use super::gateway_is_cut_over;
    use crate::MergedStore;
    use crate::gw_types::v::gateways::{Gateway, GatewayStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
    use kube::api::ObjectMeta;

    fn cond(type_: &str, status: &str, observed_gen: i64) -> Condition {
        Condition {
            type_: type_.into(),
            status: status.into(),
            reason: "x".into(),
            message: String::new(),
            observed_generation: Some(observed_gen),
            last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
        }
    }

    fn gw(generation: i64, conditions: Vec<Condition>) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some("gw".into()),
                namespace: Some("ns".into()),
                generation: Some(generation),
                ..Default::default()
            },
            spec: Default::default(),
            status: Some(GatewayStatus {
                conditions: Some(conditions),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn no_status_means_not_cut_over() {
        let gw = Gateway {
            metadata: ObjectMeta {
                name: Some("gw".into()),
                namespace: Some("ns".into()),
                generation: Some(1),
                ..Default::default()
            },
            spec: Default::default(),
            status: None,
        };
        assert!(!gateway_is_cut_over(&gw));
    }

    #[test]
    fn no_dedicated_proxy_ready_condition_means_not_cut_over() {
        let gw = gw(1, vec![cond("Accepted", "True", 1)]);
        assert!(!gateway_is_cut_over(&gw));
    }

    #[test]
    fn dedicated_proxy_ready_false_means_not_cut_over() {
        let gw = gw(
            1,
            vec![cond(
                "gateway.coxswain-labs.dev/DedicatedProxyReady",
                "False",
                1,
            )],
        );
        assert!(!gateway_is_cut_over(&gw));
    }

    #[test]
    fn dedicated_proxy_ready_true_with_current_gen_means_cut_over() {
        let gw = gw(
            2,
            vec![cond(
                "gateway.coxswain-labs.dev/DedicatedProxyReady",
                "True",
                2,
            )],
        );
        assert!(gateway_is_cut_over(&gw));
    }

    #[test]
    fn stale_true_condition_does_not_cut_over() {
        // metadata.generation=2 but condition observed gen=1 → the condition
        // reflects an older spec; do not filter the Gateway out until the
        // operator has re-published the condition against the new spec.
        let gw = gw(
            2,
            vec![cond(
                "gateway.coxswain-labs.dev/DedicatedProxyReady",
                "True",
                1,
            )],
        );
        assert!(!gateway_is_cut_over(&gw));
    }

    use crate::reconciler::{IngressDefaultBackend, IngressDefaultBackendParseError};

    #[test]
    fn happy_path() {
        let b: IngressDefaultBackend = "default/echo:80".parse().unwrap();
        assert_eq!(b.namespace, "default");
        assert_eq!(b.name, "echo");
        assert_eq!(b.port, 80);
    }

    #[test]
    fn missing_colon_returns_missing_port() {
        let err = "default/echo".parse::<IngressDefaultBackend>().unwrap_err();
        assert!(matches!(err, IngressDefaultBackendParseError::MissingPort));
    }

    #[test]
    fn missing_slash_returns_missing_namespace() {
        let err = "defaultecho:80"
            .parse::<IngressDefaultBackend>()
            .unwrap_err();
        assert!(matches!(
            err,
            IngressDefaultBackendParseError::MissingNamespace
        ));
    }

    #[test]
    fn empty_namespace_returns_empty_component() {
        let err = "/echo:80".parse::<IngressDefaultBackend>().unwrap_err();
        assert!(matches!(
            err,
            IngressDefaultBackendParseError::EmptyComponent
        ));
    }

    #[test]
    fn empty_name_returns_empty_component() {
        let err = "default/:80".parse::<IngressDefaultBackend>().unwrap_err();
        assert!(matches!(
            err,
            IngressDefaultBackendParseError::EmptyComponent
        ));
    }

    #[test]
    fn non_numeric_port_returns_invalid_port() {
        let err = "default/echo:abc"
            .parse::<IngressDefaultBackend>()
            .unwrap_err();
        assert!(matches!(
            err,
            IngressDefaultBackendParseError::InvalidPort(s) if s == "abc"
        ));
    }

    #[test]
    fn port_overflow_returns_invalid_port() {
        let err = "default/echo:2147483648"
            .parse::<IngressDefaultBackend>()
            .unwrap_err();
        assert!(matches!(
            err,
            IngressDefaultBackendParseError::InvalidPort(_)
        ));
    }

    #[test]
    fn colon_in_service_name_uses_last_colon_as_port_separator() {
        // rsplit_once(':') splits on the last colon; "ns/svc:extra:80" → ns_name="ns/svc:extra", port=80
        let b: IngressDefaultBackend = "ns/svc:extra:80".parse().unwrap();
        assert_eq!(b.namespace, "ns");
        assert_eq!(b.name, "svc:extra");
        assert_eq!(b.port, 80);
    }

    // ── compute_ownership ─────────────────────────────────────────────────────
    // These tests verify both the OwnedResources return value AND the side effect
    // on OwnedGateways, since higher-level reconcile tests only check routing output.

    use super::compute_ownership;
    use crate::gw_types::v::gatewayclasses::{GatewayClass, GatewayClassSpec};
    use crate::gw_types::v::gateways::GatewaySpec;
    use coxswain_core::ownership::OwnedGateways;
    use k8s_openapi::api::networking::v1::{IngressClass, IngressClassSpec};
    use kube::runtime::{reflector, watcher};
    use std::collections::BTreeMap;

    fn ic_store(classes: Vec<IngressClass>) -> MergedStore<IngressClass> {
        let mut w = reflector::store::Writer::<IngressClass>::default();
        for ic in classes {
            w.apply_watcher_event(&watcher::Event::Apply(ic));
        }
        MergedStore::single(w.as_reader())
    }

    fn gc_store(classes: Vec<GatewayClass>) -> MergedStore<GatewayClass> {
        let mut w = reflector::store::Writer::<GatewayClass>::default();
        for gc in classes {
            w.apply_watcher_event(&watcher::Event::Apply(gc));
        }
        MergedStore::single(w.as_reader())
    }

    fn gw_store_co(gateways: Vec<Gateway>) -> MergedStore<Gateway> {
        let mut w = reflector::store::Writer::<Gateway>::default();
        for gw in gateways {
            w.apply_watcher_event(&watcher::Event::Apply(gw));
        }
        MergedStore::single(w.as_reader())
    }

    fn make_ic(name: &str, controller: &str, default: bool) -> IngressClass {
        let mut anns: Option<BTreeMap<String, String>> = None;
        if default {
            let mut m = BTreeMap::new();
            m.insert(
                "ingressclass.kubernetes.io/is-default-class".to_string(),
                "true".to_string(),
            );
            anns = Some(m);
        }
        IngressClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                annotations: anns,
                ..Default::default()
            },
            spec: Some(IngressClassSpec {
                controller: Some(controller.to_string()),
                ..Default::default()
            }),
        }
    }

    fn make_gc(name: &str, controller: &str) -> GatewayClass {
        GatewayClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: controller.to_string(),
                ..Default::default()
            },
            status: None,
        }
    }

    fn make_gw(ns: &str, name: &str, class: &str) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: class.to_string(),
                ..Default::default()
            },
            status: None,
        }
    }

    #[test]
    fn empty_stores_return_empty_owned_resources() {
        let handle = OwnedGateways::new();
        let r = compute_ownership(
            &ic_store(vec![]),
            &gc_store(vec![]),
            &gw_store_co(vec![]),
            "cox",
            &handle,
        );
        assert!(r.ingress_classes.is_empty());
        assert!(r.default_ingress_class.is_none());
        assert!(r.gateway_classes.is_empty());
        assert!(r.gateways.is_empty());
        assert!(
            handle.load().is_empty(),
            "side-effect: owned gateways handle must be empty"
        );
    }

    #[test]
    fn owned_ingress_class_appears_in_ingress_classes_field() {
        let handle = OwnedGateways::new();
        let r = compute_ownership(
            &ic_store(vec![make_ic("nginx", "cox", false)]),
            &gc_store(vec![]),
            &gw_store_co(vec![]),
            "cox",
            &handle,
        );
        assert!(
            r.ingress_classes.contains("nginx"),
            "owned IC must appear in ingress_classes"
        );
        assert!(r.default_ingress_class.is_none());
        assert!(r.gateway_classes.is_empty(), "no GatewayClasses in store");
    }

    #[test]
    fn foreign_controller_ingress_class_excluded() {
        let handle = OwnedGateways::new();
        let r = compute_ownership(
            &ic_store(vec![make_ic("nginx", "other-controller", false)]),
            &gc_store(vec![]),
            &gw_store_co(vec![]),
            "cox",
            &handle,
        );
        assert!(
            r.ingress_classes.is_empty(),
            "IC from foreign controller must be excluded"
        );
    }

    #[test]
    fn default_annotation_sets_default_ingress_class() {
        let handle = OwnedGateways::new();
        let r = compute_ownership(
            &ic_store(vec![make_ic("nginx", "cox", true)]),
            &gc_store(vec![]),
            &gw_store_co(vec![]),
            "cox",
            &handle,
        );
        assert_eq!(r.default_ingress_class.as_deref(), Some("nginx"));
    }

    #[test]
    fn multiple_defaults_picks_lexicographically_lowest() {
        let handle = OwnedGateways::new();
        let r = compute_ownership(
            &ic_store(vec![
                make_ic("beta", "cox", true),
                make_ic("alpha", "cox", true),
            ]),
            &gc_store(vec![]),
            &gw_store_co(vec![]),
            "cox",
            &handle,
        );
        assert_eq!(
            r.default_ingress_class.as_deref(),
            Some("alpha"),
            "lexicographically lowest name must win when multiple defaults exist"
        );
    }

    #[test]
    fn owned_gateway_class_and_gateway_appear_in_their_fields() {
        let handle = OwnedGateways::new();
        let r = compute_ownership(
            &ic_store(vec![]),
            &gc_store(vec![make_gc("cox-class", "cox")]),
            &gw_store_co(vec![make_gw("default", "my-gw", "cox-class")]),
            "cox",
            &handle,
        );
        assert!(
            r.gateway_classes.contains("cox-class"),
            "gateway_classes must contain owned class"
        );
        assert!(
            r.gateways
                .contains(&coxswain_core::ownership::ObjectKey::new(
                    "default", "my-gw"
                )),
            "gateways must contain the owned gateway"
        );
        assert!(r.ingress_classes.is_empty(), "no IngressClasses in store");
    }

    #[test]
    fn cut_over_gateway_excluded_from_gateways_field() {
        // A Gateway with DedicatedProxyReady=True is cut over to a dedicated proxy
        // and must be excluded from the shared-pool `gateways` set.
        let handle = OwnedGateways::new();
        let cut_over = Gateway {
            metadata: ObjectMeta {
                name: Some("gw".to_string()),
                namespace: Some("default".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "cox-class".to_string(),
                ..Default::default()
            },
            status: Some(GatewayStatus {
                conditions: Some(vec![cond(
                    "gateway.coxswain-labs.dev/DedicatedProxyReady",
                    "True",
                    1,
                )]),
                ..Default::default()
            }),
        };
        let r = compute_ownership(
            &ic_store(vec![]),
            &gc_store(vec![make_gc("cox-class", "cox")]),
            &gw_store_co(vec![cut_over]),
            "cox",
            &handle,
        );
        assert!(
            r.gateways.is_empty(),
            "cut-over gateway must be excluded from the shared-pool gateways set"
        );
    }

    #[test]
    fn side_effect_publishes_owned_gateways_to_handle() {
        let handle = OwnedGateways::new();
        let r = compute_ownership(
            &ic_store(vec![]),
            &gc_store(vec![make_gc("cox-class", "cox")]),
            &gw_store_co(vec![
                make_gw("ns-a", "gw1", "cox-class"),
                make_gw("ns-b", "gw2", "cox-class"),
            ]),
            "cox",
            &handle,
        );
        let published = handle.load();
        assert_eq!(
            *published, r.gateways,
            "owned_gateways_handle must reflect the same set as the returned OwnedResources"
        );
    }
}
