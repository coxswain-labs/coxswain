//! `kube_runtime::Controller`-based reconcile loop for the dedicated-mode
//! provisioning operator.
//!
//! Primary resource: [`Gateway`]. Cross-watches: [`GatewayClass`] (changes to
//! a class trigger reconcile for every Gateway in that class) and
//! [`CoxswainGatewayParameters`] (any params change triggers reconcile for
//! every Gateway — the population is small enough by design that re-checking
//! all is cheaper than tracking which Gateways resolve to which params).
//!
//! ## Step 9 scope: server-side-apply
//!
//! Every reconcile renders the desired Deployment/Service/ServiceAccount and
//! server-side-applies all three under field manager `"coxswain-controller"`
//! with `force=true` — the controller is the authoritative owner of the
//! generated resources (see [`super::apply`] for the source-of-truth
//! contract). The hash check from Step 8 is preserved but only suppresses
//! the INFO log on no-change reconciles; SSA still fires every time so any
//! out-of-band `kubectl edit` is reverted on the next reconcile.
//!
//! ## Leader gating
//!
//! Every reconcile checks the shared leader [`AtomicBool`] (owned by the
//! existing [`crate::Controller`]'s leader-election machinery). Non-leader
//! pods short-circuit and re-queue; only the elected leader applies.
//!
//! ## Status writing (Step 12, #211)
//!
//! Every reconcile that completes its SSA provisioning stage also calls
//! [`super::status::patch_dedicated_gateway_status`] with the latest snapshot
//! of provisioned Service, Node fleet, listener TLS health, and Ready Pod
//! count. The `NotFound` branch writes `Accepted=False,
//! reason=InvalidParameters` directly via the same entry point — no shared
//! `AcceptedOverrides` map is needed because the operator is now the sole
//! writer of `Gateway.status` on dedicated-mode Gateways (the shared-pool
//! writer skips them via a `parametersRef` group/kind check). Health-channel
//! retriggers wire [`SharedGatewayListenerStatus`] and
//! [`SharedRouteStatus`] into [`Controller::reconcile_all_on`] so a
//! cert-ref or route-resolution flip kicks every owned Gateway through the
//! patch path within watch latency.

use super::{apply, params, render, render_shared, status, vip};
use async_trait::async_trait;
use coxswain_core::Shared;
use coxswain_core::crd::{CoxswainGatewayParameters, ServiceType};
use coxswain_core::ownership::ObjectKey;
use coxswain_reflector::gw_types::ListenerSet;
use coxswain_reflector::gw_types::v::gatewayclasses::GatewayClass;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use coxswain_reflector::ingress::IngressPorts;
use coxswain_reflector::status::{
    GatewayListenerStatus, SharedGatewayListenerStatus, SharedRouteStatus,
};
use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Node, Pod, Service, ServiceAccount};
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use kube::{
    Api, Client, Resource as _,
    api::{DeleteParams, ObjectMeta, Patch, PatchParams},
    runtime::{
        WatchStreamExt,
        controller::{Action, Controller},
        reflector::{self, ObjectRef, Store},
        watcher,
    },
};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{DefaultHasher, Hash as _, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use std::time::Duration;
use thiserror::Error;
use tokio::task::JoinSet;

/// Re-queue interval when the operator's pod isn't the leader. Long enough to
/// avoid hot-spinning the reconcile loop, short enough that promotion to
/// leader translates into action quickly (the existing status writer's lease
/// TTL defaults to 15 s).
const NON_LEADER_REQUEUE: Duration = Duration::from_secs(20);

/// Re-queue interval while a dedicated Gateway's `Programmed` is held on the
/// proxy bind gate (#531). Mirrors the shared writer's
/// `DEFERRED_PROGRAMMED_REQUEUE`: the node-registry forwarder is the prompt
/// signal; this is the backstop, and the sampling cadence for the ack half
/// of the gate (snapshot acks don't re-drive the queue). Keep at 2 s — see
/// the shared writer's constant for why shorter cadences backfire.
const BIND_GATE_REQUEUE: Duration = Duration::from_secs(2);

/// Default re-queue after a reconcile error. Short backoff is fine — most
/// errors here are transient (apiserver hiccup, missing object that's about
/// to be created).
const ERROR_REQUEUE: Duration = Duration::from_secs(15);

/// Re-queue interval while a dedicated→shared hand-off is in flight: we have
/// cleared our dedicated-mode status and are waiting for the shared pool to
/// re-adopt and program the Gateway before tearing the dedicated proxy down.
/// Short enough to make the teardown prompt once the shared pool is serving
/// (rebind lands in ~1 s), long enough not to hot-spin the apiserver. The
/// dedicated proxy keeps bridging traffic across every one of these ticks.
const MIGRATION_HANDOFF_REQUEUE: Duration = Duration::from_secs(1);

/// Errors that can be returned from [`reconcile`]. They are observed only by
/// the controller framework's error policy (which converts them into a
/// re-queue) and the operator's own logs — the K8s API does not see them.
#[non_exhaustive]
#[derive(Debug, Error)]
pub(super) enum ReconcileError {
    /// Kubernetes API error encountered outside the SSA path (e.g. by future
    /// pre-flight reads of provisioned resources, or by the status patch).
    #[error("kube error: {0}")]
    Kube(#[from] kube::Error),
    /// SSA of one of the three rendered resources failed.
    #[error("apply: {0}")]
    Apply(#[from] apply::ApplyError),
}

/// Bundle of inputs the operator's [`BackgroundService::start`] needs from
/// the bin layer. Carries the leader flag so the operator shares one
/// truth-source with the [`crate::Controller`] status writer.
///
/// Not `#[non_exhaustive]` — same rationale as
/// [`crate::StatusWriterConfig`]: it's an internal wiring struct that only
/// `coxswain-bin` instantiates.
// intentionally open: field-literal constructed in crates/coxswain-bin/src/main.rs from CLI args.
pub struct OperatorConfig {
    /// `GatewayClass.spec.controllerName` claim — same string the status
    /// writer uses; we only reconcile Gateways whose class matches.
    pub controller_name: String,
    /// Image for the rendered proxy container when
    /// `CoxswainGatewayParameters.spec.image` is unset. Typically the
    /// controller's own image so dedicated proxies stay version-pinned to
    /// the controller without operator-level coordination.
    pub controller_image: String,
    /// Shared leader-election flag the status writer flips on `Acquire`.
    /// Reconcile is a no-op (re-queue) when this is `false`.
    pub leader: Arc<AtomicBool>,
    /// Per-listener health channel for every listener of every owned Gateway —
    /// HTTP, HTTPS, and TLS alike, each carrying its TLS-resolution outcome,
    /// attached-route count, and advertised/internal port mapping (#472). Named
    /// for listeners, not TLS: HTTP listeners are present too (with a
    /// `NotApplicable` TLS outcome). Read on every reconcile (the patch builder
    /// maps each listener to its `(readiness, attached_routes)` snapshot) and
    /// subscribed via [`SharedGatewayListenerStatus::subscribe`] so any health
    /// flip (e.g. a TLS-cert resolution change) kicks every owned Gateway through
    /// [`Controller::reconcile_all_on`].
    pub listener_status: SharedGatewayListenerStatus,
    /// Per-route ResolvedRefs/Accepted health channel. Subscribed for the
    /// same retrigger reason as [`Self::listener_status`]; the patch builder does
    /// not consume the snapshot directly (per-listener `ResolvedRefs`
    /// derives from TLS health alone — see the issue-211 grilling notes),
    /// but a route-health flip still warrants re-checking listener
    /// `attached_routes` counts.
    pub route_status: SharedRouteStatus,
    /// Ports reserved for the Ingress data plane via `--proxy-http-port` /
    /// `--proxy-https-port`. Forwarded to the listener-status helper so a
    /// dedicated-mode listener whose port collides with the Ingress
    /// reservation surfaces `Programmed=False, reason=PortUnavailable` —
    /// same semantics as the shared-pool writer (#201).
    pub ingress_ports: IngressPorts,
    /// Admin server port rendered into the `gateway.coxswain-labs.dev/admin-port`
    /// annotation on every dedicated-proxy pod. Propagated from the
    /// `--admin-port` / `COXSWAIN_ADMIN_PORT` CLI argument.
    pub admin_port: u16,
    /// gRPC discovery endpoint the dedicated proxy connects to for routing
    /// snapshots. Rendered as `--discovery-endpoint=<endpoint>`. Since #423 the
    /// Stream listener is mTLS-only, so this is an `https://` URL.
    pub discovery_endpoint: String,
    /// Server-auth-only bootstrap endpoint rendered as
    /// `--discovery-bootstrap-endpoint=<endpoint>` so the dedicated proxy can
    /// obtain its SVID (projected token + trust mount, #423).
    pub discovery_bootstrap_endpoint: String,
    /// Projected SA-token path rendered as `--discovery-sa-token-path`.
    pub discovery_sa_token_path: String,
    /// CA trust-bundle path rendered as `--discovery-ca-bundle-path`.
    pub discovery_ca_bundle_path: String,
    /// SPIFFE trust domain rendered as `--discovery-trust-domain`.
    pub discovery_trust_domain: String,
    /// Namespace the controller (and its trust-bundle publisher) runs in. The
    /// operator copies the published `coxswain-discovery-trust` ConfigMap from
    /// here into each dedicated proxy's namespace; when a Gateway lives in the
    /// controller namespace the publisher's own ConfigMap is reused and no copy
    /// is made (the publisher is its sole writer).
    pub controller_namespace: String,
    /// Label selector targeting the one shared proxy pod, used as the `selector`
    /// of every per-Gateway shared-mode VIP Service (#472). Supplied by the
    /// chart via `--shared-proxy-selector` because the controller cannot derive
    /// the install's `app.kubernetes.io/instance` (release name) itself.
    /// Empty disables shared-mode per-Gateway addressing (Ingress-only / tests).
    pub shared_proxy_selector: BTreeMap<String, String>,
    /// Service type for the per-Gateway shared-mode VIP Services (#472).
    /// `LoadBalancer` by default so each Gateway gets its own external address.
    pub shared_vip_service_type: ServiceType,
    /// Shared handle for publishing definitively-failed static-address VIP
    /// provisioning to the status writer (#531/#533). Constructed in
    /// `coxswain-bin` and cloned into the `Controller` too, so the single
    /// serialized VIP reconciler is the writer and the status writer the reader.
    pub vip_failures: Shared<HashSet<ObjectKey>>,
    /// Leadership watch (#531): a rising edge (standby → leader) immediately
    /// re-drives every owned Gateway and the VIP reconciler, collapsing the
    /// 15–20 s post-failover provisioning lag that the `NON_LEADER_REQUEUE` /
    /// `VIP_RESYNC_INTERVAL` backstops would otherwise impose. The status
    /// writer's lease loop is the sender. `None` in tests.
    pub leadership_rx: Option<tokio::sync::watch::Receiver<bool>>,
    /// Connected-proxy registry with per-node bound-port reports (#531). Read
    /// to gate a dedicated Gateway's `Programmed=True` on its own proxy having
    /// actually bound the effective listener ports — pod readiness alone flips
    /// before a listener *added by a spec change* is bound. `None` disables
    /// the gate (tests).
    pub node_registry: Option<coxswain_core::node_registry::SharedNodeRegistry>,
    /// Per-Gateway publish-sequence index (#531): the ack half of the
    /// dedicated `Programmed` gate — the Gateway's own proxy must have Ack'd
    /// a snapshot containing the current generation, not merely hold its
    /// (possibly stale) port binds. `None` disables it (tests).
    pub publish_index: Option<coxswain_core::publish_index::SharedGatewayPublishIndex>,
}

/// Provisioning operator. Registered as a Pingora `BackgroundService` next
/// to the [`crate::Controller`] in `serve controller`; shares the controller
/// pod's process and leader-election truth-source but owns its own kube-rs
/// `Controller` and reflector stores.
#[non_exhaustive]
pub struct Operator {
    config: OperatorConfig,
}

impl Operator {
    /// Construct a new operator instance (does not start the watch loop).
    #[must_use]
    pub fn new(config: OperatorConfig) -> Self {
        Self { config }
    }
}

/// Reconcile context shared across all per-Gateway reconcile invocations.
/// `parking_lot::Mutex` (not `tokio::sync::Mutex`) because the lock is held
/// only briefly inside the reconcile body and never across `.await` — the
/// async one would make the reconcile future `!Unpin` for no benefit, and the
/// `parking_lot` guard's `!Send` bound makes an accidental hold-across-await a
/// compile error.
pub(super) struct ReconcileContext {
    pub(super) controller_name: String,
    controller_image: String,
    pub(super) leader: Arc<AtomicBool>,
    pub(super) client: Client,
    pub(super) class_store: Store<GatewayClass>,
    pub(super) params_store: Store<CoxswainGatewayParameters>,
    /// Pods carrying the dedicated-proxy labels. Reads off this store drive
    /// the `gateway.coxswain-labs.dev/DedicatedProxyReady` condition (#210)
    /// and gate `Programmed=True` on having ≥1 Ready Pod (#211).
    /// Cluster-wide watch narrowed by `PROXY_POD_LABEL_SELECTOR`.
    pods_store: Store<Pod>,
    /// Cluster `Node` snapshot. Only consulted when a dedicated Gateway's
    /// Service is `NodePort`-typed; otherwise unused. Unscoped watch
    /// (Nodes are cluster-wide and low-cardinality).
    nodes_store: Store<Node>,
    /// Shared per-listener TLS-health channel — read-only snapshot at each
    /// reconcile.
    listener_status: SharedGatewayListenerStatus,
    /// Ports reserved for the Ingress data plane via the controller's CLI.
    /// Forwarded to [`super::status::build_dedicated_gateway_status_patch`]
    /// for the listener `PortUnavailable` precedence check.
    ingress_ports: IngressPorts,
    /// Admin server port injected as `gateway.coxswain-labs.dev/admin-port` on
    /// every rendered dedicated-proxy pod.
    admin_port: u16,
    /// gRPC discovery endpoint rendered as `--discovery-endpoint=<endpoint>`
    /// in every dedicated-proxy Deployment.
    discovery_endpoint: String,
    /// Bootstrap endpoint + token/bundle paths + trust domain rendered into the
    /// dedicated-proxy Deployment so it can obtain an SVID (#423).
    discovery_bootstrap_endpoint: String,
    discovery_sa_token_path: String,
    discovery_ca_bundle_path: String,
    discovery_trust_domain: String,
    /// Controller namespace; source of the trust-bundle ConfigMap copied into
    /// out-of-namespace dedicated proxies.
    pub(super) controller_namespace: String,
    /// All Gateways, cluster-wide. Enumerated on a shared-mode reconcile to
    /// compute the *global* internal-port allocation (#472) so concurrent
    /// per-Gateway reconciles agree on the same deterministic map.
    pub(super) gateways_store: Store<Gateway>,
    /// The per-Gateway shared-mode VIP Services we provision, label-scoped to
    /// the shared-VIP component. Their `targetPort`s are the durable source of
    /// truth for the internal-port allocation across reconciles/restarts (#472).
    pub(super) services_store: Store<Service>,
    /// All ListenerSets, cluster-wide (GEP-1713, #93). Merged into each owned
    /// Gateway's effective listener set so the VIP/dedicated Service and
    /// internal-port allocation cover ListenerSet listener ports.
    pub(super) listener_sets_store: Store<ListenerSet>,
    /// All Namespaces, cluster-wide. Backs the parent Gateway's
    /// `allowedListeners.namespaces.from: Selector` gate during the merge (#93).
    pub(super) namespaces_store: Store<Namespace>,
    /// Shared proxy pod selector + VIP service type for shared-mode Service
    /// provisioning (#472). See [`OperatorConfig::shared_proxy_selector`].
    pub(super) shared_proxy_selector: BTreeMap<String, String>,
    pub(super) shared_vip_service_type: ServiceType,
    /// Signals the serialized [`run_vip_reconciler`] task to run a whole-VIP
    /// pass (#472). Per-Gateway reconciles only *signal* here — they never
    /// provision VIP Services themselves, so the allocation stays single-writer.
    pub(super) vip_trigger: Arc<tokio::sync::Notify>,
    /// Shared-mode Gateways whose static-address VIP provisioning has
    /// definitively failed (all requested clusterIPs rejected). Written by
    /// [`run_vip_reconciler`] each pass, read by the shared-pool status writer so
    /// it settles their `AddressNotUsable` while holding still-provisioning
    /// Gateways at `Pending` (#531/#533).
    pub(super) vip_failures: Shared<HashSet<ObjectKey>>,
    /// Connected-proxy registry (#531): gates dedicated `Programmed=True` on
    /// the Gateway's own proxy reporting its listener ports bound.
    node_registry: Option<coxswain_core::node_registry::SharedNodeRegistry>,
    /// Per-Gateway publish-sequence index (#531): ack half of the gate.
    publish_index: Option<coxswain_core::publish_index::SharedGatewayPublishIndex>,
    last_hashes: Mutex<HashMap<ObjectKey, u64>>,
}

/// Finalizer key the operator places on every dedicated-mode Gateway. It keeps
/// the Gateway alive across a dedicated→shared migration so the operator can
/// hand status ownership back to the shared pool and tear the dedicated proxy
/// resources down in order before the object is deleted; provisioned same-ns
/// resources (Deployment/Service/SA) GC via owner-ref on a plain delete.
const CLEANUP_FINALIZER: &str = "gateway.coxswain-labs.dev/dedicated-cleanup";

/// Label selector matching every Pod the operator provisions for a
/// dedicated-mode Gateway. The selector is the intersection of the reserved
/// labels rendered onto each Pod (see `RESERVED_LABEL_KEYS` in
/// [`super::render`]) — `managed-by=coxswain` alone is too narrow (some
/// charts use it for unrelated objects), the `app.kubernetes.io/name=coxswain`
/// pin closes that gap.
const PROXY_POD_LABEL_SELECTOR: &str =
    "app.kubernetes.io/managed-by=coxswain,app.kubernetes.io/name=coxswain";

/// Label key identifying the owning Gateway's name on every rendered Pod.
/// Set by `super::render::standard_labels` to match the Gateway-API
/// GEP-1762 convention.
const POD_GATEWAY_NAME_LABEL: &str = "gateway.networking.k8s.io/gateway-name";

/// Short re-queue used after adding the finalizer on a fresh dedicated
/// Gateway. The follow-up reconcile sees the patched object (with the
/// finalizer in place) and proceeds to apply + bind in one body.
const POST_FINALIZER_REQUEUE: Duration = Duration::from_millis(50);

pub(super) fn gateway_key(gw: &Gateway) -> ObjectKey {
    ObjectKey::new(
        gw.metadata.namespace.clone().unwrap_or_default(),
        gw.metadata.name.clone().unwrap_or_default(),
    )
}

#[async_trait]
impl BackgroundService for Operator {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let client = match Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "operator: failed to initialise Kubernetes client; will not run");
                return;
            }
        };

        // Spawn the cross-watched reflector stores in parallel with the
        // Controller. Their `Store`s are shared into the reconcile Context.
        let mut tasks = JoinSet::new();
        let (class_reader, class_writer) = reflector::store::<GatewayClass>();
        tasks.spawn({
            let api = Api::<GatewayClass>::all(client.clone());
            async move {
                let stream = reflector::reflector(
                    class_writer,
                    watcher(api, watcher::Config::default()).default_backoff(),
                );
                tokio::pin!(stream);
                while stream.next().await.is_some() {}
            }
        });
        let (params_reader, params_writer) = reflector::store::<CoxswainGatewayParameters>();
        tasks.spawn({
            let api = Api::<CoxswainGatewayParameters>::all(client.clone());
            async move {
                let stream = reflector::reflector(
                    params_writer,
                    watcher(api, watcher::Config::default()).default_backoff(),
                );
                tokio::pin!(stream);
                while stream.next().await.is_some() {}
            }
        });
        // Pod reflector for dedicated-proxy readiness (#210). Cluster-wide
        // scope (dedicated-proxy Pods live in each Gateway's own namespace)
        // narrowed to our own Pods via label selector — the watch streams
        // only the small fleet we provision, not every Pod in the cluster.
        let (pods_reader, pods_writer) = reflector::store::<Pod>();
        tasks.spawn({
            let api = Api::<Pod>::all(client.clone());
            let config = watcher::Config::default().labels(PROXY_POD_LABEL_SELECTOR);
            async move {
                let stream =
                    reflector::reflector(pods_writer, watcher(api, config).default_backoff());
                tokio::pin!(stream);
                while stream.next().await.is_some() {}
            }
        });
        // Node reflector — cluster-wide, no label scoping. Only consulted for
        // `NodePort`-typed dedicated Services; one snapshot per reconcile.
        // Low cardinality at the cluster sizes Coxswain targets (tens of
        // Nodes) so an unfiltered watch is fine.
        let (nodes_reader, nodes_writer) = reflector::store::<Node>();
        tasks.spawn({
            let api = Api::<Node>::all(client.clone());
            async move {
                let stream = reflector::reflector(
                    nodes_writer,
                    watcher(api, watcher::Config::default()).default_backoff(),
                );
                tokio::pin!(stream);
                while stream.next().await.is_some() {}
            }
        });
        // Gateway reflector — cluster-wide. Enumerated on each shared-mode
        // reconcile to compute the global internal-port allocation (#472).
        let (gateways_reader, gateways_writer) = reflector::store::<Gateway>();
        tasks.spawn({
            let api = Api::<Gateway>::all(client.clone());
            async move {
                let stream = reflector::reflector(
                    gateways_writer,
                    watcher(api, watcher::Config::default()).default_backoff(),
                );
                tokio::pin!(stream);
                while stream.next().await.is_some() {}
            }
        });
        // Service reflector — cluster-wide, narrowed to the per-Gateway
        // shared-mode VIP Services we provision (#472). Their `targetPort`s are
        // the durable source of truth for the internal-port allocation.
        let (services_reader, services_writer) = reflector::store::<Service>();
        tasks.spawn({
            let api = Api::<Service>::all(client.clone());
            let config = watcher::Config::default().labels(&format!(
                "app.kubernetes.io/component={}",
                render::SHARED_GATEWAY_VIP_COMPONENT
            ));
            async move {
                let stream =
                    reflector::reflector(services_writer, watcher(api, config).default_backoff());
                tokio::pin!(stream);
                while stream.next().await.is_some() {}
            }
        });
        // ListenerSet + Namespace reflectors (GEP-1713, #93). The VIP/dedicated
        // Service and internal-port allocation must cover a Gateway's attached
        // ListenerSets' listeners, not just `spec.listeners`, or a ListenerSet
        // listener on a new port is never exposed. The Namespace store backs the
        // parent Gateway's `allowedListeners.namespaces.from: Selector` gate.
        let (listener_sets_reader, listener_sets_writer) = reflector::store::<ListenerSet>();
        tasks.spawn({
            let api = Api::<ListenerSet>::all(client.clone());
            async move {
                let stream = reflector::reflector(
                    listener_sets_writer,
                    watcher(api, watcher::Config::default()).default_backoff(),
                );
                tokio::pin!(stream);
                while stream.next().await.is_some() {}
            }
        });
        let (namespaces_reader, namespaces_writer) = reflector::store::<Namespace>();
        tasks.spawn({
            let api = Api::<Namespace>::all(client.clone());
            async move {
                let stream = reflector::reflector(
                    namespaces_writer,
                    watcher(api, watcher::Config::default()).default_backoff(),
                );
                tokio::pin!(stream);
                while stream.next().await.is_some() {}
            }
        });

        // Wait for every dependency reflector to complete its initial sync
        // before exposing the stores to the reconcile loop, so the first
        // reconcile after pod start (or controller restart) sees populated
        // GatewayClass/params/Pod/Node state rather than racing an empty
        // store and producing a transient render that SSA must immediately
        // re-apply (an unnecessary Deployment resourceVersion bump).
        //
        // The wait is bounded at 30 s so a misconfigured watch (e.g. one that
        // 403s forever) doesn't hang the operator indefinitely; the controller
        // logs and proceeds, so partial observability is preferable to a stuck
        // reconcile loop.
        let sync_timeout = Duration::from_secs(30);
        let deadline = tokio::time::Instant::now() + sync_timeout;
        async fn wait_or_name<F: std::future::Future>(
            name: &'static str,
            fut: F,
            deadline: tokio::time::Instant,
        ) -> Option<&'static str> {
            if tokio::time::timeout_at(deadline, fut).await.is_err() {
                Some(name)
            } else {
                None
            }
        }
        // Errors from `wait_until_ready` mean the writer was dropped — the
        // operator is shutting down. We treat those as "synced" because there
        // is nothing left for this reader to deliver; the controller will
        // exit on the next iteration anyway.
        let (a, b, c, d, e, f, g, h) = tokio::join!(
            wait_or_name("GatewayClass", class_reader.wait_until_ready(), deadline),
            wait_or_name(
                "CoxswainGatewayParameters",
                params_reader.wait_until_ready(),
                deadline,
            ),
            wait_or_name("Pod", pods_reader.wait_until_ready(), deadline),
            wait_or_name("Node", nodes_reader.wait_until_ready(), deadline),
            wait_or_name("Gateway", gateways_reader.wait_until_ready(), deadline),
            wait_or_name("Service", services_reader.wait_until_ready(), deadline),
            wait_or_name(
                "ListenerSet",
                listener_sets_reader.wait_until_ready(),
                deadline
            ),
            wait_or_name("Namespace", namespaces_reader.wait_until_ready(), deadline),
        );
        let unsynced: Vec<&'static str> = [a, b, c, d, e, f, g, h].into_iter().flatten().collect();
        if !unsynced.is_empty() {
            tracing::warn!(
                timeout = ?sync_timeout,
                unsynced = ?unsynced,
                "operator: dependency reflectors did not complete initial sync within timeout; \
                 proceeding with partial state — first reconciles may bump resourceVersion until \
                 watches catch up. Check RBAC if the unsynced list is non-empty."
            );
        }

        let ctx = Arc::new(ReconcileContext {
            controller_name: self.config.controller_name.clone(),
            controller_image: self.config.controller_image.clone(),
            leader: Arc::clone(&self.config.leader),
            client: client.clone(),
            class_store: class_reader,
            params_store: params_reader,
            pods_store: pods_reader,
            nodes_store: nodes_reader,
            listener_status: self.config.listener_status.clone(),
            ingress_ports: self.config.ingress_ports,
            admin_port: self.config.admin_port,
            discovery_endpoint: self.config.discovery_endpoint.clone(),
            discovery_bootstrap_endpoint: self.config.discovery_bootstrap_endpoint.clone(),
            discovery_sa_token_path: self.config.discovery_sa_token_path.clone(),
            discovery_ca_bundle_path: self.config.discovery_ca_bundle_path.clone(),
            discovery_trust_domain: self.config.discovery_trust_domain.clone(),
            controller_namespace: self.config.controller_namespace.clone(),
            gateways_store: gateways_reader,
            services_store: services_reader,
            listener_sets_store: listener_sets_reader,
            namespaces_store: namespaces_reader,
            shared_proxy_selector: self.config.shared_proxy_selector.clone(),
            shared_vip_service_type: self.config.shared_vip_service_type,
            vip_trigger: Arc::new(tokio::sync::Notify::new()),
            vip_failures: self.config.vip_failures.clone(),
            node_registry: self.config.node_registry.clone(),
            publish_index: self.config.publish_index.clone(),
            last_hashes: Mutex::new(HashMap::new()),
        });

        // Single serialized VIP reconciler (#472): the sole writer of shared-mode
        // per-Gateway VIP Services. Per-Gateway reconciles signal it via
        // `ctx.vip_trigger`; it never runs on the concurrent work-queue.
        tasks.spawn(vip::run_vip_reconciler(Arc::clone(&ctx), shutdown.clone()));

        // Build the kube-rs Controller. We don't `.owns(Deployment)` yet —
        // Step 8 writes nothing, so there are no owned Deployments to
        // observe. Step 9 (#208) adds `.owns(api_deployments, ...)`.
        let api_gateways: Api<Gateway> = Api::all(client.clone());
        let api_classes: Api<GatewayClass> = Api::all(client.clone());
        let api_params: Api<CoxswainGatewayParameters> = Api::all(client.clone());
        let api_pods: Api<Pod> = Api::all(client.clone());
        let api_services: Api<Service> = Api::all(client);
        let class_store_for_watches = ctx.class_store.clone();

        // Build the health-channel retrigger stream (#211). We bridge two
        // `tokio::sync::watch::Receiver<u64>`s (which are `Send` but not
        // `Sync`) onto a single `futures::channel::mpsc::UnboundedReceiver`
        // (which is `Send + Sync`, the bound `Controller::reconcile_all_on`
        // requires). Each forwarder task drops the initial value via
        // `borrow_and_update` so operator startup doesn't spuriously fire a
        // reconcile-all before any health flip has actually occurred.
        let (trigger_tx, trigger_rx) = futures::channel::mpsc::unbounded::<()>();
        {
            let mut tls_rx = self.config.listener_status.subscribe();
            let tx = trigger_tx.clone();
            tasks.spawn(async move {
                let _ = tls_rx.borrow_and_update();
                while tls_rx.changed().await.is_ok() {
                    if tx.unbounded_send(()).is_err() {
                        break;
                    }
                }
            });
        }
        {
            let mut route_rx = self.config.route_status.subscribe();
            let tx = trigger_tx.clone();
            tasks.spawn(async move {
                let _ = route_rx.borrow_and_update();
                while route_rx.changed().await.is_ok() {
                    if tx.unbounded_send(()).is_err() {
                        break;
                    }
                }
            });
        }
        // Bind-report re-drive (#531): a proxy's NodeStatus landing in the
        // node registry must re-reconcile owned Gateways promptly — the
        // dedicated Programmed bind gate waits on exactly that report, and
        // no k8s watch event fires for it.
        if let Some(registry) = &self.config.node_registry {
            let mut reg_rx = registry.subscribe();
            let tx = trigger_tx.clone();
            tasks.spawn(async move {
                let _ = reg_rx.borrow_and_update();
                while reg_rx.changed().await.is_ok() {
                    if tx.unbounded_send(()).is_err() {
                        break;
                    }
                }
            });
        }

        // Promotion re-drive (#531): a standby ingests Gateways with all writes
        // gated off; on promotion it must act on them NOW, not at the next
        // watch event or periodic backstop. Rising edge → re-drive the Gateway
        // work-queue and kick the VIP reconciler.
        if let Some(mut leader_rx) = self.config.leadership_rx.clone() {
            let tx = trigger_tx.clone();
            let vip_trigger = Arc::clone(&ctx.vip_trigger);
            tasks.spawn(async move {
                let mut was_leader = *leader_rx.borrow_and_update();
                while leader_rx.changed().await.is_ok() {
                    let now_leader = *leader_rx.borrow_and_update();
                    if now_leader && !was_leader {
                        tracing::info!(
                            "operator: promoted to leader; re-driving Gateway and VIP reconciliation"
                        );
                        if tx.unbounded_send(()).is_err() {
                            break;
                        }
                        vip_trigger.notify_one();
                    }
                    was_leader = now_leader;
                }
            });
        }

        // Drop the construction-site sender so the receiver closes if both
        // forwarder tasks exit. Without this, the receiver would stay alive
        // forever and `Controller::reconcile_all_on` would hold a permanent
        // task slot.
        drop(trigger_tx);

        let controller = Controller::new(api_gateways, watcher::Config::default());
        let gateway_store = controller.store();

        let controller = controller
            .watches(api_classes, watcher::Config::default(), {
                let gateway_store = gateway_store.clone();
                move |class: GatewayClass| -> Vec<ObjectRef<Gateway>> {
                    let Some(class_name) = class.meta().name.clone() else {
                        return vec![];
                    };
                    gateway_store
                        .state()
                        .into_iter()
                        .filter(|gw| gw.spec.gateway_class_name == class_name)
                        .map(|gw| ObjectRef::from_obj(gw.as_ref()))
                        .collect()
                }
            })
            .watches(api_params, watcher::Config::default(), {
                // Any params change triggers reconcile for every owned
                // Gateway. With per-Gateway tracking we could narrow this to
                // the affected Gateways only, but the population is small by
                // design (#218 / architecture plan: tens of dedicated
                // Gateways at most), so re-checking all is cheaper than
                // maintaining the cross-index.
                let gateway_store = gateway_store.clone();
                let class_store = class_store_for_watches.clone();
                move |_p: CoxswainGatewayParameters| -> Vec<ObjectRef<Gateway>> {
                    let owned_class_names: std::collections::HashSet<String> = class_store
                        .state()
                        .into_iter()
                        .filter_map(|gc| gc.meta().name.clone())
                        .collect();
                    gateway_store
                        .state()
                        .into_iter()
                        .filter(|gw| owned_class_names.contains(&gw.spec.gateway_class_name))
                        .map(|gw| ObjectRef::from_obj(gw.as_ref()))
                        .collect()
                }
            })
            // Pod → Gateway: dedicated-proxy Pods live in the Gateway's own
            // namespace, so the mapping is `pod.metadata.namespace` +
            // `pod.metadata.labels[gateway.networking.k8s.io/gateway-name]`.
            // Drives the `DedicatedProxyReady` condition: every Ready ↔
            // NotReady flip reconciles the owning Gateway within watch
            // latency, no polling required.
            .watches(
                api_pods,
                watcher::Config::default().labels(PROXY_POD_LABEL_SELECTOR),
                |pod: Pod| -> Vec<ObjectRef<Gateway>> {
                    let Some(ns) = pod.metadata.namespace.as_deref() else {
                        return vec![];
                    };
                    let Some(labels) = pod.metadata.labels.as_ref() else {
                        return vec![];
                    };
                    let Some(name) = labels.get(POD_GATEWAY_NAME_LABEL) else {
                        return vec![];
                    };
                    vec![ObjectRef::new(name).within(ns)]
                },
            )
            // Service → Gateway: dedicated-proxy Services live in the
            // Gateway's own namespace and carry the GEP-1762 gateway-name
            // label. Drives `Programmed=False, reason=AddressNotAssigned`
            // → `True` transitions the instant the apiserver populates
            // `clusterIP` (ClusterIP type) or an LB controller writes
            // `status.loadBalancer.ingress` — without this watch the status
            // would only refresh on the next natural Gateway reconcile (#211).
            .watches(
                api_services,
                watcher::Config::default().labels(PROXY_POD_LABEL_SELECTOR),
                |svc: Service| -> Vec<ObjectRef<Gateway>> {
                    let Some(ns) = svc.metadata.namespace.as_deref() else {
                        return vec![];
                    };
                    let Some(labels) = svc.metadata.labels.as_ref() else {
                        return vec![];
                    };
                    let Some(name) = labels.get(POD_GATEWAY_NAME_LABEL) else {
                        return vec![];
                    };
                    vec![ObjectRef::new(name).within(ns)]
                },
            )
            // Bulk retrigger on listener-TLS / route-health flips. Each tick
            // reconciles every Gateway in the controller's store; the
            // `dedicated_gateway_needs_status_patch` idempotence check
            // absorbs duplicates so this is cheap even under chatty health
            // channels.
            .reconcile_all_on(trigger_rx);

        let stream = controller.run(reconcile, error_policy, ctx);
        // The controller stream contains `!Unpin` futures internally
        // (kube-runtime's `applier`); pinning to the stack here lets
        // `tokio::select!` poll it across iterations.
        tokio::pin!(stream);

        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                next = stream.next() => match next {
                    Some(Ok(_)) => {}
                    Some(Err(e)) => tracing::debug!(error = %e, "operator: controller stream error"),
                    None => {
                        tracing::warn!("operator: controller stream ended; tearing down");
                        break;
                    }
                },
            }
        }
        tasks.shutdown().await;
    }
}

async fn reconcile(gw: Arc<Gateway>, ctx: Arc<ReconcileContext>) -> Result<Action, ReconcileError> {
    let started = std::time::Instant::now();
    let res = reconcile_inner(gw, ctx).await;
    crate::metrics::observe_reconcile("operator", started, &res);
    res
}

async fn reconcile_inner(
    gw: Arc<Gateway>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, ReconcileError> {
    if !ctx.leader.load(Ordering::Acquire) {
        // Non-leader pods don't apply. Re-queue rather than `await_change()`
        // so the operator catches up promptly on leader promotion.
        return Ok(Action::requeue(NON_LEADER_REQUEUE));
    }

    // Any Gateway change (create/spec edit/mode switch/delete) may shift the
    // shared-mode VIP map — signal the single serialized reconciler to recompute
    // it. Cheap and coalesced; the actual provisioning never runs here (#472).
    // Skipped when the feature is off (no VIP task is consuming the signal).
    if !ctx.shared_proxy_selector.is_empty() {
        ctx.vip_trigger.notify_one();
    }

    let key = gateway_key(&gw);
    let gw_namespace = gw.metadata.namespace.as_deref().unwrap_or("");
    let gw_name = gw.metadata.name.as_deref().unwrap_or("");

    // ----- Finalizer / deletion path ------------------------------------
    //
    // A Gateway with `deletionTimestamp` set is being deleted; if it carries
    // our finalizer we just drop it — provisioned resources
    // (Deployment/Service/SA) in the Gateway's own namespace GC via owner-refs.
    // The finalizer exists for the dedicated→shared migration hand-off below,
    // not for cleanup on a plain delete.
    if gw.metadata.deletion_timestamp.is_some() {
        if has_our_finalizer(&gw) {
            tracing::info!(
                gateway = %gateway_id(&gw),
                "operator: finalizing terminating dedicated-mode Gateway"
            );
            remove_finalizer(&ctx.client, &gw).await?;
            // GC of in-namespace resources (Deployment/Service/SA) is
            // owner-ref driven; nothing else to do here.
            ctx.last_hashes.lock().remove(&key);
        }
        return Ok(Action::await_change());
    }

    let class_name = &gw.spec.gateway_class_name;
    let Some(class) = ctx
        .class_store
        .state()
        .into_iter()
        .find(|gc| gc.meta().name.as_deref() == Some(class_name.as_str()))
    else {
        // Class not yet observed — wait for its reflector to sync; the
        // GatewayClass cross-watch will re-queue this Gateway when the class
        // appears.
        return Ok(Action::await_change());
    };
    if class.spec.controller_name != ctx.controller_name {
        // Different controller's Gateway; not ours to provision.
        return Ok(Action::await_change());
    }

    // Resolve effective parameters. The lookup closure reads the snapshot of
    // the params reflector store; the store's interior `ArcSwap` makes this
    // a cheap atomic load per call.
    let effective = match params::resolve(&gw, &class, |r: &params::ParamsRef| {
        ctx.params_store
            .state()
            .iter()
            .find(|p| {
                p.meta().namespace.as_deref() == Some(r.namespace.as_str())
                    && p.meta().name.as_deref() == Some(r.name.as_str())
            })
            .map(|p| p.spec.clone())
    }) {
        Ok(Some(e)) => e,
        Ok(None) => {
            // Shared-mode Gateway. Provision its per-Gateway identity
            // ServiceAccount in the Gateway's OWN namespace (#482, GEP-1867).
            // In shared mode the proxy pod and VIP Service both live in the
            // controller's namespace, so this SA is the only per-Gateway artifact
            // in the Gateway's namespace — the carrier for the propagated
            // `spec.infrastructure.{labels,annotations}` and a stable identity
            // object. SSA force-apply makes add/update/remove of those fields
            // reconcile for free. Runs for every owned shared Gateway, including
            // one mid dedicated→shared migration (the dedicated teardown below).
            let sa = render_shared::render_shared_gateway_service_account(&gw);
            apply::apply_shared_gateway_service_account(&ctx.client, gw_namespace, &sa).await?;

            // The Gateway is no longer in dedicated mode. If we never placed our
            // finalizer there is nothing to undo — it was always shared-pool.
            //
            // The finalizer is what tells us we ever owned this Gateway: it is
            // the DURABLE record that a dedicated→shared hand-off is still
            // pending. It lives on the Gateway object, not in controller memory,
            // so a controller that loses leadership (or crashes) mid-hand-off
            // leaves it in place, and whichever pod next holds leadership
            // re-enters this branch and resumes from the current cluster state.
            // Every step below is driven off observable state (conditions,
            // resource existence), never in-memory bookkeeping, so the resume is
            // exact. Without the finalizer the clear path would also delete
            // conditions written by the shared-pool writer on every reconcile of
            // every non-dedicated Gateway, producing an unbounded patch loop.
            if has_our_finalizer(&gw) {
                // Step 1 — hand status ownership back to the shared pool, ONCE.
                // We are the sole writer of `DedicatedProxyReady`; its presence
                // means we have not yet handed off. Clearing our dedicated-mode
                // conditions (plus the generation bump from the spec edit) is
                // what un-gates the shared pool's re-adoption. We must clear only
                // while we still own that condition — once it is gone the
                // shared-pool writer owns `Accepted`/`Programmed` and re-clearing
                // would stomp them in an unbounded fight.
                if has_dedicated_proxy_ready_condition(&gw) {
                    tracing::info!(
                        gateway = %gateway_id(&gw),
                        "operator: Gateway left dedicated mode; clearing status and handing back to shared pool"
                    );
                    status::clear_dedicated_gateway_status(&ctx.client, &gw).await?;
                    return Ok(Action::requeue(MIGRATION_HANDOFF_REQUEUE));
                }

                // Step 2 — wait for the shared pool to actually be serving the
                // migrated routes before we tear the dedicated proxy down. The
                // dedicated Deployment/Service keep bridging traffic across this
                // window; deleting them earlier would blackhole the host during
                // the shared pool's ~1 s listener rebind. This is the symmetric
                // counterpart to shared→dedicated cut-over, which waits for the
                // dedicated Pod to be Ready before flipping the signal.
                if !shared_pool_is_serving(&gw) {
                    return Ok(Action::requeue(MIGRATION_HANDOFF_REQUEUE));
                }

                // Step 3 — shared pool is serving: tear down the dedicated proxy.
                // Owner-ref GC cannot reclaim these on a migration (the owning
                // Gateway survives), so we delete them explicitly. We delete the
                // resources STRICTLY BEFORE removing the finalizer: a crash
                // between the two leaves the finalizer in place, so the next
                // leader re-runs the idempotent delete and only then drops it —
                // never re-leaking the proxy.
                let resource_name = render::resource_name(&gw, class_name);
                tracing::info!(
                    gateway = %gateway_id(&gw),
                    resource = %resource_name,
                    "operator: shared pool serving migrated Gateway; deleting dedicated proxy resources"
                );
                delete_dedicated_resources(&ctx.client, gw_namespace, &resource_name).await?;
                remove_finalizer(&ctx.client, &gw).await?;
                ctx.last_hashes.lock().remove(&key);
            }
            // Shared-mode Gateway (no parametersRef): its VIP Service is owned by
            // the serialized `run_vip_reconciler` task (signalled at the top of
            // this fn), not provisioned here — see #472. Nothing per-Gateway to do.
            return Ok(Action::await_change());
        }
        Err(params::ParamsError::NotFound(ns, name)) => {
            tracing::warn!(
                gateway = %gateway_id(&gw),
                missing = %format!("{ns}/{name}"),
                "operator: parametersRef target not found; writing \
                 Accepted=False, reason=InvalidParameters and re-queuing"
            );
            // The operator is the sole writer of Gateway.status for
            // dedicated-mode Gateways — InvalidParameters is emitted
            // directly here, no shared cross-task signal involved.
            let inputs = status::DedicatedGatewayStatusInputs {
                gw: &gw,
                service: None,
                nodes: &[],
                listener_status: &GatewayListenerStatus::default(),
                ingress_ports: ctx.ingress_ports,
                accepted: status::AcceptedOutcome::InvalidParameters,
                ready_pod_count: 0,
                // Unreached: InvalidParameters outranks the bind gate.
                proxy_bound: false,
            };
            status::patch_dedicated_gateway_status(&ctx.client, &inputs).await?;
            return Ok(Action::requeue(ERROR_REQUEUE));
        }
    };

    // Dedicated-mode Gateway. Ensure the finalizer is in place before doing
    // any provisioning — if anything goes wrong before the finalizer is
    // patched, a delete can race past us. Add → requeue → continue.
    if !has_our_finalizer(&gw) {
        add_finalizer(&ctx.client, &gw).await?;
        return Ok(Action::requeue(POST_FINALIZER_REQUEUE));
    }

    // Effective listener ports for THIS dedicated Gateway: its own listeners plus
    // those merged from attached ListenerSets (GEP-1713, #93), so the dedicated
    // proxy's Service and container expose ListenerSet listener ports too.
    let dedicated_listener_sets = ctx.listener_sets_store.state();
    let dedicated_owned_classes: std::collections::HashSet<String> = ctx
        .class_store
        .state()
        .iter()
        .filter(|gc| gc.spec.controller_name == ctx.controller_name)
        .filter_map(|gc| gc.meta().name.clone())
        .collect();
    let dedicated_effective = coxswain_reflector::effective_listener_ports(
        std::slice::from_ref(&gw),
        &dedicated_listener_sets,
        &dedicated_owned_classes,
        &ctx.namespaces_store,
    );
    let empty_effective_ports = Vec::new();
    let dedicated_ports = dedicated_effective
        .get(&gateway_key(&gw))
        .unwrap_or(&empty_effective_ports);

    let rendered = render::render(&render::RenderInputs {
        gateway: &gw,
        params: &effective,
        controller_image: &ctx.controller_image,
        gateway_class_name: class_name,
        discovery_endpoint: &ctx.discovery_endpoint,
        discovery_bootstrap_endpoint: &ctx.discovery_bootstrap_endpoint,
        discovery_sa_token_path: &ctx.discovery_sa_token_path,
        discovery_ca_bundle_path: &ctx.discovery_ca_bundle_path,
        discovery_trust_domain: &ctx.discovery_trust_domain,
        admin_port: ctx.admin_port,
        effective_ports: dedicated_ports,
    });

    // Stage 1a — make the controller's CA trust bundle reachable from the
    // dedicated proxy's namespace so its `trust-bundle` volume has content and
    // it can verify the controller during SVID bootstrap (#423). No-op when the
    // Gateway shares the controller namespace (the publisher already owns the
    // ConfigMap there).
    //
    // Ordered BEFORE the Deployment: the trust volume is `optional`, so a pod
    // that starts before the ConfigMap exists boots with an empty mount and
    // only sees the bundle after kubelet's next ConfigMap sync (up to ~1 min) —
    // long enough to blow a 60 s route-liveness budget. Creating the ConfigMap
    // first means the pod mounts it populated from the start.
    copy_trust_bundle(&ctx.client, &gw, &ctx.controller_namespace).await?;

    // GatewayStaticAddresses (#260): when the rendered Service pins a requested
    // clusterIP that diverges from a live one, delete first — clusterIP is
    // immutable so SSA cannot mutate it. No-op for Gateways without a static IP.
    vip::repin_dedicated_clusterip_if_diverged(&ctx.client, &gw, &rendered.service).await;

    // Stage 1b — provisioning (Deployment/Service/SA). SSA with force=true
    // re-asserts ownership on every reconcile; the apply order is SA →
    // Service → Deployment. The dedicated proxy is a pure discovery client
    // (post-#424) with zero Kubernetes API access, so the rendered SA carries
    // no RoleBindings — it exists only as the pod identity.
    apply::apply_rendered(&ctx.client, &gw, &rendered).await?;

    // A Gateway that migrated shared→dedicated still carries the shared-mode
    // identity ServiceAccount (#482) in its namespace; owner-ref GC cannot
    // reclaim it (the owning Gateway survives the migration), so prune it
    // explicitly. Idempotent NotFound no-op for a Gateway that was always
    // dedicated. The dedicated trio's own SA (a distinct GEP-1762 name) is
    // unaffected.
    let shared_sa_name = render_shared::shared_gateway_service_account_name(gw_namespace, gw_name);
    delete_shared_gateway_service_account(&ctx.client, gw_namespace, &shared_sa_name).await?;

    // Stage 2 — write Gateway.status (#211). One JSON merge patch carries
    // Accepted/Programmed/per-listener/addresses + the
    // `gateway.coxswain-labs.dev/DedicatedProxyReady` cut-over signal the
    // shared-proxy reflector consumes (#210). All gated on observed Pod
    // readiness + resolved Service-address presence + TLS-health.
    //
    // The Service is fetched directly from the apiserver — NOT read from a
    // reflector store — because the Service cross-watch that triggers this
    // reconcile is an independent subscription from any reflector: the
    // cross-watch can deliver a MODIFIED event before a reflector finishes
    // applying it, leaving the store one resourceVersion behind for the
    // duration of this reconcile. A status-only LoadBalancer patch has no
    // other trigger to re-reconcile against, so reading stale state here
    // would silently strand `Programmed=False, reason=AddressNotAssigned`
    // indefinitely.
    let ready_pod_count = count_ready_proxy_pods(&ctx.pods_store, gw_namespace, gw_name);
    let services_api: Api<Service> = Api::namespaced(ctx.client.clone(), gw_namespace);
    let resource_name = status::resource_name(gw_name, class_name);
    let service = match services_api.get(&resource_name).await {
        Ok(svc) => Some(svc),
        Err(kube::Error::Api(api_err)) if api_err.code == 404 => None,
        Err(e) => return Err(ReconcileError::Kube(e)),
    };
    let nodes: Vec<Arc<Node>> = ctx.nodes_store.state();
    let listener_status_map = ctx.listener_status.load();
    let gateway_health = listener_status_map.get(&key).cloned().unwrap_or_default();
    // Proxy readiness gate (#531), two halves — same shape as the shared
    // writer's:
    //  * Bind: this Gateway's own connected proxy must report the effective
    //    listener ports bound (pod readiness alone flips before a listener
    //    added by a spec change is bound).
    //  * Ack: the proxy must have Ack'd a snapshot containing the current
    //    generation — a config-only spec change (no new port) leaves the bind
    //    set unchanged, so bind alone would open the gate while the new
    //    config is still propagating.
    // The anti-flap latch keeps an already-Programmed generation immune to
    // pod-replacement churn.
    let proxy_bound = match &ctx.node_registry {
        Some(registry) => {
            crate::status_common::gateway_programmed_at_current_gen(&gw) || {
                let snapshot_acked = match &ctx.publish_index {
                    Some(index) => index.get(&key).is_some_and(|stamp| {
                        stamp.generation >= gw.metadata.generation.unwrap_or(0)
                            && registry.gateway_node_acked(gw_namespace, gw_name, stamp.seq)
                    }),
                    None => true,
                };
                snapshot_acked
                    && registry.load().gateway_node_bound(
                        gw_namespace,
                        gw_name,
                        &dedicated_ports.iter().map(|p| p.port).collect(),
                    )
            }
        }
        None => true,
    };
    let inputs = status::DedicatedGatewayStatusInputs {
        gw: &gw,
        service: service.as_ref(),
        nodes: &nodes,
        listener_status: &gateway_health,
        ingress_ports: ctx.ingress_ports,
        accepted: status::AcceptedOutcome::Accepted,
        ready_pod_count,
        proxy_bound,
    };
    status::patch_dedicated_gateway_status(&ctx.client, &inputs).await?;

    let new_hash = hash_rendered(&rendered);
    let changed = {
        let mut hashes = ctx.last_hashes.lock();
        let prior = hashes.get(&key).copied();
        let changed = prior != Some(new_hash);
        if changed {
            hashes.insert(key, new_hash);
        }
        changed
        // Lock guard drops at the closing brace — well before any further
        // .await point.
    };
    if changed {
        log_rendered_change(&gw, &rendered);
    } else {
        tracing::debug!(
            gateway = %gateway_id(&gw),
            "operator: re-render produced identical specs; SSA was a no-op server-side"
        );
    }

    // Bind-gate backstop (#531): while this Gateway's Programmed is held on
    // the proxy's bound-port report, requeue shortly instead of parking on
    // await_change — the registry forwarder re-drives on the report landing,
    // and this backstop covers a forwarder/event race the same way the shared
    // writer's DEFERRED_PROGRAMMED_REQUEUE does.
    if !proxy_bound {
        return Ok(Action::requeue(BIND_GATE_REQUEUE));
    }

    Ok(Action::await_change())
}

/// Returns true iff the Gateway carries our cleanup finalizer.
fn has_our_finalizer(gw: &Gateway) -> bool {
    gw.metadata
        .finalizers
        .as_ref()
        .is_some_and(|f| f.iter().any(|s| s == CLEANUP_FINALIZER))
}

/// Patch the Gateway to add our finalizer to `metadata.finalizers`.
/// Idempotent server-side: if the finalizer is already present, the patched
/// state matches and the apiserver accepts the no-op.
/// Copy the controller-published trust-bundle ConfigMap into a dedicated
/// proxy's namespace so its `trust-bundle` volume has content for SVID
/// bootstrap.
///
/// A ConfigMap is namespace-scoped — a proxy can only mount one from its own
/// namespace. The publisher writes the bundle to the controller namespace; this
/// mirrors it into any *other* namespace hosting a dedicated proxy. The copy is
/// owned by the Gateway so it garbage-collects with it. No-op when the Gateway
/// shares the controller namespace: the publisher is the sole writer there and
/// a copy would fight it for SSA field ownership.
///
/// # Errors
///
/// Returns the [`kube::Error`] from the source read or destination SSA patch. A
/// missing source ConfigMap (publisher hasn't published yet) is not an error —
/// the proxy's trust volume is `optional` and its bootstrap loop retries until
/// a later reconcile lands the copy.
async fn copy_trust_bundle(
    client: &Client,
    gw: &Gateway,
    controller_namespace: &str,
) -> Result<(), kube::Error> {
    let gw_namespace = gw.metadata.namespace.as_deref().unwrap_or_else(|| {
        panic!("invariant: Gateway has no namespace; the API server requires it")
    });
    if gw_namespace == controller_namespace {
        return Ok(());
    }
    let cm_name = crate::identity::publisher::TRUST_BUNDLE_CM_NAME;
    let src: Api<ConfigMap> = Api::namespaced(client.clone(), controller_namespace);
    let Some(source) = src.get_opt(cm_name).await? else {
        tracing::warn!(
            namespace = %gw_namespace,
            "trust bundle ConfigMap not yet published; dedicated proxy bootstraps once it lands"
        );
        return Ok(());
    };
    let copy = ConfigMap {
        metadata: ObjectMeta {
            name: Some(cm_name.to_string()),
            namespace: Some(gw_namespace.to_string()),
            owner_references: Some(vec![render::gateway_owner_reference(gw)]),
            ..Default::default()
        },
        data: source.data.clone(),
        binary_data: source.binary_data.clone(),
        ..Default::default()
    };
    let dst: Api<ConfigMap> = Api::namespaced(client.clone(), gw_namespace);
    let params = PatchParams::apply(apply::FIELD_MANAGER).force();
    dst.patch(cm_name, &params, &Patch::Apply(&copy)).await?;
    Ok(())
}

async fn add_finalizer(client: &Client, gw: &Gateway) -> Result<(), kube::Error> {
    let namespace = gw.metadata.namespace.as_deref().unwrap_or_else(|| {
        panic!("invariant: Gateway has no namespace; the API server requires it")
    });
    let name =
        gw.metadata.name.as_deref().unwrap_or_else(|| {
            panic!("invariant: Gateway has no name; the API server requires it")
        });
    // Construct the desired finalizer set: existing + ours. SSA's strategic
    // merge handles deduplication when we list our finalizer alongside
    // pre-existing ones.
    let mut finalizers: Vec<String> = gw.metadata.finalizers.clone().unwrap_or_default();
    if !finalizers.iter().any(|s| s == CLEANUP_FINALIZER) {
        finalizers.push(CLEANUP_FINALIZER.to_string());
    }
    let patch = serde_json::json!({
        "metadata": {
            "finalizers": finalizers,
        }
    });
    let api: Api<Gateway> = Api::namespaced(client.clone(), namespace);
    let params = PatchParams::default();
    api.patch(name, &params, &Patch::Merge(&patch)).await?;
    Ok(())
}

/// Patch the Gateway to remove our finalizer. Idempotent — if the finalizer
/// isn't present, we still write the resulting list back; the apiserver
/// accepts the no-op.
async fn remove_finalizer(client: &Client, gw: &Gateway) -> Result<(), kube::Error> {
    let namespace = gw.metadata.namespace.as_deref().unwrap_or_else(|| {
        panic!("invariant: Gateway has no namespace; the API server requires it")
    });
    let name =
        gw.metadata.name.as_deref().unwrap_or_else(|| {
            panic!("invariant: Gateway has no name; the API server requires it")
        });
    let finalizers: Vec<String> = gw
        .metadata
        .finalizers
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s != CLEANUP_FINALIZER)
        .collect();
    let patch = serde_json::json!({
        "metadata": {
            "finalizers": finalizers,
        }
    });
    let api: Api<Gateway> = Api::namespaced(client.clone(), namespace);
    let params = PatchParams::default();
    api.patch(name, &params, &Patch::Merge(&patch)).await?;
    Ok(())
}

/// True while the Gateway still carries a `DedicatedProxyReady` condition.
///
/// The operator is the sole writer of that condition (the shared-pool status
/// writer never touches it), so its presence is a durable signal that we have
/// not yet handed this Gateway back to the shared pool. The migration path uses
/// it to clear our dedicated-mode status exactly once — re-clearing after the
/// shared-pool writer has taken over `Accepted`/`Programmed` would stomp those
/// conditions in an unbounded patch fight.
fn has_dedicated_proxy_ready_condition(gw: &Gateway) -> bool {
    gw.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .is_some_and(|cs| {
            cs.iter()
                .any(|c| c.type_ == status::DEDICATED_PROXY_READY_CONDITION_TYPE)
        })
}

/// True once the shared pool is demonstrably serving the Gateway at its current
/// generation: a `Programmed=True` condition whose `observedGeneration` is at
/// least the Gateway's `metadata.generation`.
///
/// The shared-pool status writer is the only writer of `Programmed` for a
/// non-dedicated Gateway (the operator clears its own copy on hand-off), and it
/// writes `Programmed=True` at the current generation only once the Gateway is
/// adopted and its listeners are programmed. So this is the deterministic
/// "routes have migrated to the shared proxy" signal — the safe point to tear
/// the dedicated proxy down. The generation check (mirroring the shared pool's
/// own `gateway_is_cut_over` gate) rejects a stale `Programmed` left over from
/// before the spec edit that triggered the migration.
/// Whether `gw` is owned by this controller AND served by the shared pool
/// (no `parametersRef` → not dedicated mode). Mirrors the per-Gateway
/// classification in [`reconcile_inner`], applied across the whole Gateway set
/// so the shared-mode allocation sees every owned shared Gateway.
pub(super) fn is_owned_shared_mode(
    gw: &Gateway,
    classes: &[Arc<GatewayClass>],
    params_store: &Store<CoxswainGatewayParameters>,
    controller_name: &str,
) -> bool {
    if gw.metadata.deletion_timestamp.is_some() {
        return false;
    }
    let Some(class) = classes
        .iter()
        .find(|gc| gc.meta().name.as_deref() == Some(gw.spec.gateway_class_name.as_str()))
    else {
        return false;
    };
    if class.spec.controller_name != controller_name {
        return false;
    }
    matches!(
        params::resolve(gw, class, |r: &params::ParamsRef| {
            params_store
                .state()
                .iter()
                .find(|p| {
                    p.meta().namespace.as_deref() == Some(r.namespace.as_str())
                        && p.meta().name.as_deref() == Some(r.name.as_str())
                })
                .map(|p| p.spec.clone())
        }),
        Ok(None)
    )
}

fn shared_pool_is_serving(gw: &Gateway) -> bool {
    let expected_gen = gw.metadata.generation.unwrap_or(0);
    gw.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == "Programmed"))
        .is_some_and(|c| c.status == "True" && c.observed_generation.unwrap_or(0) >= expected_gen)
}

/// Delete the provisioned dedicated-proxy `Deployment`, `Service`, and
/// `ServiceAccount` for a Gateway that has migrated out of dedicated mode.
///
/// Owner-ref GC cannot reclaim these on a *migration* — the owning Gateway
/// survives, so the cluster garbage collector never fires — so they are deleted
/// explicitly. Idempotent: a `NotFound` (already deleted, partially deleted, or
/// never provisioned) is treated as success, so the cleanup converges across
/// re-queues and across a controller that resumes the hand-off after a crash or
/// a change of leadership.
///
/// # Errors
///
/// Returns the underlying [`kube::Error`] for any delete that fails for a reason
/// other than `NotFound`.
async fn delete_dedicated_resources(
    client: &Client,
    namespace: &str,
    name: &str,
) -> Result<(), kube::Error> {
    let dp = DeleteParams::default();
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let services: Api<Service> = Api::namespaced(client.clone(), namespace);
    let service_accounts: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
    // HPA and PDB carry the same GEP-1762 name as the Deployment/Service/SA.
    // They survive a plain Gateway delete (owner-ref GC handles that), but the
    // dedicated→shared migration path deletes the Gateway resources explicitly
    // because the Gateway itself survives and owner-ref GC doesn't run.
    let hpas: Api<HorizontalPodAutoscaler> = Api::namespaced(client.clone(), namespace);
    let pdbs: Api<PodDisruptionBudget> = Api::namespaced(client.clone(), namespace);
    ignore_not_found(deployments.delete(name, &dp).await)?;
    ignore_not_found(services.delete(name, &dp).await)?;
    ignore_not_found(service_accounts.delete(name, &dp).await)?;
    ignore_not_found(hpas.delete(name, &dp).await)?;
    ignore_not_found(pdbs.delete(name, &dp).await)?;
    Ok(())
}

/// Delete the per-Gateway shared-mode identity `ServiceAccount` (#482) for a
/// Gateway that has migrated shared→dedicated.
///
/// Owner-ref GC cannot reclaim it on a migration — the owning Gateway survives
/// — so it is deleted explicitly. Idempotent: a `NotFound` (already gone, or a
/// Gateway that was always dedicated) is treated as success.
///
/// # Errors
///
/// Returns the underlying [`kube::Error`] for any delete that fails for a reason
/// other than `NotFound`.
async fn delete_shared_gateway_service_account(
    client: &Client,
    namespace: &str,
    name: &str,
) -> Result<(), kube::Error> {
    let service_accounts: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
    ignore_not_found(
        service_accounts
            .delete(name, &DeleteParams::default())
            .await,
    )
}

/// Collapse a `404 NotFound` delete result to success; propagate every other
/// error. Lets [`delete_dedicated_resources`] be safely re-run on every
/// hand-off re-queue.
pub(super) fn ignore_not_found<T>(result: Result<T, kube::Error>) -> Result<(), kube::Error> {
    match result {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(e),
    }
}

/// Returns true iff any HTTPRoute attached to the given Gateway has a
/// `backendRef` whose target namespace equals `target_ns`. Used by the
/// Count the dedicated-proxy Pods that are Ready for the given Gateway.
///
/// "Ready" means the Pod is in `gw_namespace`, carries the
/// `gateway.networking.k8s.io/gateway-name` label matching `gw_name`, has
/// no `deletionTimestamp` (a terminating Pod is not serving traffic), and
/// carries a `Ready=True` condition in its `status.conditions`.
fn count_ready_proxy_pods(pods_store: &Store<Pod>, gw_namespace: &str, gw_name: &str) -> usize {
    pods_store
        .state()
        .iter()
        .filter(|pod| {
            pod.metadata.namespace.as_deref() == Some(gw_namespace)
                && pod.metadata.deletion_timestamp.is_none()
                && pod
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get(POD_GATEWAY_NAME_LABEL))
                    .is_some_and(|n| n == gw_name)
                && pod_is_ready(pod)
        })
        .count()
}

/// Returns true iff the Pod's `status.conditions` carries a `Ready=True`
/// entry. Kubelet flips this based on the Pod's readiness probe — for
/// dedicated-proxy Pods that means `/readyz` is passing.
fn pod_is_ready(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .is_some_and(|cs| cs.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
}

fn error_policy(obj: Arc<Gateway>, err: &ReconcileError, _ctx: Arc<ReconcileContext>) -> Action {
    tracing::warn!(
        gateway = %gateway_id(&obj),
        error = %err,
        "operator: reconcile error; backing off"
    );
    Action::requeue(ERROR_REQUEUE)
}

pub(super) fn gateway_id(gw: &Gateway) -> String {
    format!(
        "{}/{}",
        gw.metadata.namespace.as_deref().unwrap_or(""),
        gw.metadata.name.as_deref().unwrap_or("")
    )
}

fn hash_rendered(rendered: &render::RenderedSpecs) -> u64 {
    let mut hasher = DefaultHasher::new();
    // Hash via JSON round-trip: structural equivalence we care about
    // (`Deployment` field set, container args, label values, etc.) is
    // exactly what `serde_json::to_value` exposes. Bypasses the lack of
    // `Hash` impls on k8s-openapi types.
    let payload = serde_json::json!({
        "deployment": serde_json::to_value(&rendered.deployment).unwrap_or_default(),
        "service": serde_json::to_value(&rendered.service).unwrap_or_default(),
        "service_account": serde_json::to_value(&rendered.service_account).unwrap_or_default(),
    });
    payload.to_string().hash(&mut hasher);
    hasher.finish()
}

fn log_rendered_change(gw: &Gateway, rendered: &render::RenderedSpecs) {
    let deployment_yaml = serde_yaml::to_string(&rendered.deployment)
        .unwrap_or_else(|e| format!("# yaml serialise failed: {e}"));
    let service_yaml = serde_yaml::to_string(&rendered.service)
        .unwrap_or_else(|e| format!("# yaml serialise failed: {e}"));
    let service_account_yaml = serde_yaml::to_string(&rendered.service_account)
        .unwrap_or_else(|e| format!("# yaml serialise failed: {e}"));
    tracing::info!(
        gateway = %gateway_id(gw),
        deployment = %deployment_yaml,
        service = %service_yaml,
        service_account = %service_account_yaml,
        "operator: dedicated-proxy specs changed; SSA succeeded"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_key_uses_namespace_and_name() {
        let gw = Gateway {
            metadata: kube::api::ObjectMeta {
                namespace: Some("tenant-a".into()),
                name: Some("my-gw".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let k = gateway_key(&gw);
        assert_eq!(k.ns, "tenant-a");
        assert_eq!(k.name, "my-gw");
    }

    fn condition(
        type_: &str,
        status_: &str,
        observed_gen: i64,
    ) -> k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
        k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
            type_: type_.to_string(),
            status: status_.to_string(),
            reason: type_.to_string(),
            message: String::new(),
            observed_generation: Some(observed_gen),
            last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::UNIX_EPOCH,
            ),
        }
    }

    fn gateway_with(
        generation: i64,
        conditions: Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition>,
    ) -> Gateway {
        use coxswain_reflector::gw_types::v::gateways::GatewayStatus;
        Gateway {
            metadata: kube::api::ObjectMeta {
                namespace: Some("default".into()),
                name: Some("gw".into()),
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
    fn dedicated_proxy_ready_condition_detected_regardless_of_status() {
        // Presence is the signal — True or False both mean we still own it and
        // have not yet handed off.
        let gw_true = gateway_with(
            2,
            vec![condition(
                status::DEDICATED_PROXY_READY_CONDITION_TYPE,
                "True",
                2,
            )],
        );
        assert!(has_dedicated_proxy_ready_condition(&gw_true));
        let gw_false = gateway_with(
            2,
            vec![condition(
                status::DEDICATED_PROXY_READY_CONDITION_TYPE,
                "False",
                2,
            )],
        );
        assert!(has_dedicated_proxy_ready_condition(&gw_false));
    }

    #[test]
    fn no_dedicated_proxy_ready_condition_means_handed_off() {
        // Cleared status (only shared-pool conditions remain) → handed off.
        let gw = gateway_with(2, vec![condition("Programmed", "True", 2)]);
        assert!(!has_dedicated_proxy_ready_condition(&gw));
        // No status at all → nothing owned.
        let bare = Gateway {
            metadata: kube::api::ObjectMeta {
                name: Some("gw".into()),
                ..Default::default()
            },
            spec: Default::default(),
            status: None,
        };
        assert!(!has_dedicated_proxy_ready_condition(&bare));
    }

    #[test]
    fn shared_pool_serving_requires_programmed_true_at_current_generation() {
        // Programmed=True at the current generation → shared pool is serving.
        let serving = gateway_with(3, vec![condition("Programmed", "True", 3)]);
        assert!(shared_pool_is_serving(&serving));
        // A newer observedGeneration also counts (>=).
        let ahead = gateway_with(3, vec![condition("Programmed", "True", 4)]);
        assert!(shared_pool_is_serving(&ahead));
    }

    #[test]
    fn shared_pool_not_serving_on_stale_or_false_or_missing_programmed() {
        // Stale Programmed left over from before the migration's generation bump.
        let stale = gateway_with(3, vec![condition("Programmed", "True", 2)]);
        assert!(!shared_pool_is_serving(&stale));
        // Programmed=False (e.g. shared pool adopted but not yet programmed).
        let not_ready = gateway_with(3, vec![condition("Programmed", "False", 3)]);
        assert!(!shared_pool_is_serving(&not_ready));
        // Accepted present but no Programmed yet → not serving.
        let accepted_only = gateway_with(3, vec![condition("Accepted", "True", 3)]);
        assert!(!shared_pool_is_serving(&accepted_only));
    }

    #[test]
    fn ignore_not_found_collapses_404_only() {
        fn api_err(code: u16) -> kube::Error {
            kube::Error::Api(Box::new(kube::core::Status {
                code,
                ..Default::default()
            }))
        }
        assert!(ignore_not_found::<()>(Ok(())).is_ok());
        assert!(ignore_not_found::<()>(Err(api_err(404))).is_ok());
        assert!(ignore_not_found::<()>(Err(api_err(409))).is_err());
    }

    #[test]
    fn hash_changes_on_replica_change() {
        use crate::operator::params::EffectiveParams;
        use crate::operator::render;
        use coxswain_reflector::gw_types::v::gateways::{GatewayListeners, GatewaySpec};

        let gw = Gateway {
            metadata: kube::api::ObjectMeta {
                namespace: Some("default".into()),
                name: Some("my-gw".into()),
                uid: Some("uid-my-gw".into()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "coxswain".into(),
                listeners: vec![GatewayListeners {
                    name: "http".into(),
                    port: 80,
                    protocol: "HTTP".into(),
                    hostname: None,
                    tls: None,
                    allowed_routes: None,
                }],
                ..Default::default()
            },
            status: None,
        };
        let params_a = EffectiveParams {
            replicas: Some(1),
            ..Default::default()
        };
        let params_b = EffectiveParams {
            replicas: Some(3),
            ..Default::default()
        };
        let r_a = render::render(&render::RenderInputs {
            gateway: &gw,
            params: &params_a,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.default.svc:50051",
            discovery_bootstrap_endpoint: "http://coxswain-controller-discovery.default.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
        });
        let r_b = render::render(&render::RenderInputs {
            gateway: &gw,
            params: &params_b,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.default.svc:50051",
            discovery_bootstrap_endpoint: "http://coxswain-controller-discovery.default.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
        });
        assert_ne!(
            hash_rendered(&r_a),
            hash_rendered(&r_b),
            "replica count is part of the rendered Deployment; hashes must differ"
        );
    }

    #[test]
    fn hash_stable_across_identical_renders() {
        use crate::operator::params::EffectiveParams;
        use crate::operator::render;
        use coxswain_reflector::gw_types::v::gateways::GatewaySpec;

        let gw = Gateway {
            metadata: kube::api::ObjectMeta {
                namespace: Some("default".into()),
                name: Some("my-gw".into()),
                uid: Some("uid-my-gw".into()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "coxswain".into(),
                listeners: vec![],
                ..Default::default()
            },
            status: None,
        };
        let params = EffectiveParams::default();
        let inputs = render::RenderInputs {
            gateway: &gw,
            params: &params,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.default.svc:50051",
            discovery_bootstrap_endpoint: "http://coxswain-controller-discovery.default.svc:50052",
            discovery_sa_token_path: "/var/run/secrets/coxswain/discovery-token/token",
            discovery_ca_bundle_path: "/var/run/secrets/coxswain/trust-bundle/ca.crt",
            discovery_trust_domain: "cluster.local",
            admin_port: 8082,
            effective_ports: &[],
        };
        let r1 = render::render(&inputs);
        let r2 = render::render(&inputs);
        assert_eq!(hash_rendered(&r1), hash_rendered(&r2));
    }
}
