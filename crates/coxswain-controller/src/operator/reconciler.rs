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
//! Every reconcile that completes its SSA + RBAC stages also calls
//! [`super::status::patch_dedicated_gateway_status`] with the latest snapshot
//! of provisioned Service, Node fleet, listener TLS health, and Ready Pod
//! count. The `NotFound` branch writes `Accepted=False,
//! reason=InvalidParameters` directly via the same entry point — no shared
//! `AcceptedOverrides` map is needed because the operator is now the sole
//! writer of `Gateway.status` on dedicated-mode Gateways (the shared-pool
//! writer skips them via a `parametersRef` group/kind check). Health-channel
//! retriggers wire [`SharedGatewayListenerHealth`] and
//! [`SharedHttpRouteHealth`] into [`Controller::reconcile_all_on`] so a
//! cert-ref or route-resolution flip kicks every owned Gateway through the
//! patch path within watch latency.

use super::{apply, params, rbac, render, status};
use async_trait::async_trait;
use coxswain_core::crd::CoxswainGatewayParameters;
use coxswain_core::ownership::ObjectKey;
use coxswain_reflector::gw_types::HttpRoute;
use coxswain_reflector::gw_types::v::gatewayclasses::GatewayClass;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use coxswain_reflector::gw_types::v::referencegrants::ReferenceGrant;
use coxswain_reflector::ingress::IngressPorts;
use coxswain_reflector::tls::{
    GatewayListenerHealth, SharedGatewayListenerHealth, SharedHttpRouteHealth,
};
use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Node, Pod, Service, ServiceAccount};
use k8s_openapi::api::rbac::v1::RoleBinding;
use kube::{
    Api, Client, Resource as _,
    api::{DeleteParams, Patch, PatchParams},
    runtime::{
        WatchStreamExt,
        controller::{Action, Controller},
        reflector::{self, ObjectRef, Store},
        watcher,
    },
};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash as _, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::task::JoinSet;

/// Re-queue interval when the operator's pod isn't the leader. Long enough to
/// avoid hot-spinning the reconcile loop, short enough that promotion to
/// leader translates into action quickly (the existing status writer's lease
/// TTL defaults to 15 s).
const NON_LEADER_REQUEUE: Duration = Duration::from_secs(20);

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
    /// Per-namespace `RoleBinding` reconcile or cleanup failed (#209).
    #[error("rbac: {0}")]
    Rbac(#[from] rbac::RbacError),
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
    /// Per-listener TLS-resolution health channel. Read on every reconcile
    /// (the patch builder maps each listener to its `(tls_outcome,
    /// attached_routes)` snapshot) and subscribed via
    /// [`SharedGatewayListenerHealth::subscribe`] so a TLS-cert resolution
    /// flip kicks every owned Gateway through
    /// [`Controller::reconcile_all_on`].
    pub tls_health: SharedGatewayListenerHealth,
    /// Per-route ResolvedRefs/Accepted health channel. Subscribed for the
    /// same retrigger reason as [`Self::tls_health`]; the patch builder does
    /// not consume the snapshot directly (per-listener `ResolvedRefs`
    /// derives from TLS health alone — see the issue-211 grilling notes),
    /// but a route-health flip still warrants re-checking listener
    /// `attached_routes` counts.
    pub route_health: SharedHttpRouteHealth,
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
    /// Stream listener is mTLS-only, so this is an `https://` URL. Dedicated-proxy
    /// SVID bootstrap (projected token + per-namespace trust mount) is a
    /// follow-up (#381); the shared proxy is the fully-wired path today.
    pub discovery_endpoint: String,
}

/// Provisioning operator. Registered as a Pingora `BackgroundService` next
/// to the [`crate::Controller`] in `serve controller` and `serve dev`;
/// shares the controller pod's process and leader-election truth-source but
/// owns its own kube-rs `Controller` and reflector stores.
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
/// `std::sync::Mutex` (not `tokio::sync::Mutex`) because the lock is held
/// only briefly inside the reconcile body and never across `.await` — the
/// async one would make the reconcile future `!Unpin` for no benefit.
struct ReconcileContext {
    controller_name: String,
    controller_image: String,
    leader: Arc<AtomicBool>,
    client: Client,
    class_store: Store<GatewayClass>,
    params_store: Store<CoxswainGatewayParameters>,
    routes_store: Store<HttpRoute>,
    grants_store: Store<ReferenceGrant>,
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
    tls_health: SharedGatewayListenerHealth,
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
    last_hashes: Mutex<HashMap<ObjectKey, u64>>,
}

/// Finalizer key the operator places on every dedicated-mode Gateway. The
/// reconcile clears cross-namespace `RoleBinding`s (and provisioned same-ns
/// resources will GC via owner-ref) before removing this finalizer; without
/// it K8s would delete the Gateway before we can clean up the bindings,
/// leaving stale RBAC across the cluster.
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

fn gateway_key(gw: &Gateway) -> ObjectKey {
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
        let (routes_reader, routes_writer) = reflector::store::<HttpRoute>();
        tasks.spawn({
            let api = Api::<HttpRoute>::all(client.clone());
            async move {
                let stream = reflector::reflector(
                    routes_writer,
                    watcher(api, watcher::Config::default()).default_backoff(),
                );
                tokio::pin!(stream);
                while stream.next().await.is_some() {}
            }
        });
        let (grants_reader, grants_writer) = reflector::store::<ReferenceGrant>();
        tasks.spawn({
            let api = Api::<ReferenceGrant>::all(client.clone());
            async move {
                let stream = reflector::reflector(
                    grants_writer,
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

        // Wait for every dependency reflector to complete its initial sync
        // before exposing the stores to the reconcile loop. Without this,
        // the first reconcile after pod start (or controller restart) can
        // fire while `routes_store` / `grants_store` are still empty —
        // producing a transient render whose `--proxy-watch-namespaces`
        // arg list is missing every cross-namespace backend ns. SSA with
        // `force=true` accepts the transient render, then a second reconcile
        // with the full stores SSAs again — net effect: every controller
        // restart bumps the proxy Deployment's `resourceVersion` twice
        // (and triggers an unnecessary rolling update).
        //
        // The wait is bounded at 30 s so a misconfigured RBAC (which would
        // cause the watches to 403 forever) doesn't hang the operator
        // indefinitely; the controller logs and proceeds, so partial
        // observability is preferable to a stuck reconcile loop.
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
        let (a, b, c, d, e, f) = tokio::join!(
            wait_or_name("GatewayClass", class_reader.wait_until_ready(), deadline),
            wait_or_name(
                "CoxswainGatewayParameters",
                params_reader.wait_until_ready(),
                deadline,
            ),
            wait_or_name("HTTPRoute", routes_reader.wait_until_ready(), deadline),
            wait_or_name("ReferenceGrant", grants_reader.wait_until_ready(), deadline),
            wait_or_name("Pod", pods_reader.wait_until_ready(), deadline),
            wait_or_name("Node", nodes_reader.wait_until_ready(), deadline),
        );
        let unsynced: Vec<&'static str> = [a, b, c, d, e, f].into_iter().flatten().collect();
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
            routes_store: routes_reader,
            grants_store: grants_reader,
            pods_store: pods_reader,
            nodes_store: nodes_reader,
            tls_health: self.config.tls_health.clone(),
            ingress_ports: self.config.ingress_ports,
            admin_port: self.config.admin_port,
            discovery_endpoint: self.config.discovery_endpoint.clone(),
            last_hashes: Mutex::new(HashMap::new()),
        });

        // Build the kube-rs Controller. We don't `.owns(Deployment)` yet —
        // Step 8 writes nothing, so there are no owned Deployments to
        // observe. Step 9 (#208) adds `.owns(api_deployments, ...)`.
        let api_gateways: Api<Gateway> = Api::all(client.clone());
        let api_classes: Api<GatewayClass> = Api::all(client.clone());
        let api_params: Api<CoxswainGatewayParameters> = Api::all(client.clone());
        let api_routes: Api<HttpRoute> = Api::all(client.clone());
        let api_grants: Api<ReferenceGrant> = Api::all(client.clone());
        let api_bindings: Api<RoleBinding> = Api::all(client.clone());
        let api_pods: Api<Pod> = Api::all(client.clone());
        let api_services: Api<Service> = Api::all(client);
        let class_store_for_watches = ctx.class_store.clone();
        let routes_store_for_watches = ctx.routes_store.clone();

        // Build the health-channel retrigger stream (#211). We bridge two
        // `tokio::sync::watch::Receiver<u64>`s (which are `Send` but not
        // `Sync`) onto a single `futures::channel::mpsc::UnboundedReceiver`
        // (which is `Send + Sync`, the bound `Controller::reconcile_all_on`
        // requires). Each forwarder task drops the initial value via
        // `borrow_and_update` so operator startup doesn't spuriously fire a
        // reconcile-all before any health flip has actually occurred.
        let (trigger_tx, trigger_rx) = futures::channel::mpsc::unbounded::<()>();
        {
            let mut tls_rx = self.config.tls_health.subscribe();
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
            let mut route_rx = self.config.route_health.subscribe();
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
            // HTTPRoute → Gateway: every parentRef pointing at a Gateway
            // we manage triggers a reconcile for that Gateway. Precise
            // mapping — no fan-out.
            .watches(api_routes, watcher::Config::default(), {
                move |route: HttpRoute| -> Vec<ObjectRef<Gateway>> {
                    let route_ns = route
                        .metadata
                        .namespace
                        .as_deref()
                        .unwrap_or("")
                        .to_string();
                    let Some(parents) = route.spec.parent_refs.as_deref() else {
                        return vec![];
                    };
                    parents
                        .iter()
                        .filter(|p| {
                            let group = p.group.as_deref().unwrap_or("gateway.networking.k8s.io");
                            let kind = p.kind.as_deref().unwrap_or("Gateway");
                            group == "gateway.networking.k8s.io" && kind == "Gateway"
                        })
                        .map(|p| {
                            let ns = p.namespace.clone().unwrap_or_else(|| route_ns.clone());
                            ObjectRef::new(&p.name).within(&ns)
                        })
                        .collect()
                }
            })
            // ReferenceGrant → Gateway: filter to those whose routes have a
            // backendRef into the grant's namespace. Engineering-correct
            // precise mapping; we deliberately do not broad fan-out — the
            // cost of maintaining the index closure is bounded
            // (dedicated_gateways × routes × backend_refs) and the precise
            // mapping scales naturally past today's "tens of Gateways" cap.
            .watches(api_grants, watcher::Config::default(), {
                let gateway_store = gateway_store.clone();
                let routes_store = routes_store_for_watches.clone();
                move |grant: ReferenceGrant| -> Vec<ObjectRef<Gateway>> {
                    let Some(target_ns) = grant.metadata.namespace.clone() else {
                        return vec![];
                    };
                    let routes: Vec<Arc<HttpRoute>> = routes_store.state();
                    gateway_store
                        .state()
                        .into_iter()
                        .filter(|gw| {
                            let gw_ns = gw.metadata.namespace.as_deref().unwrap_or("");
                            let gw_name = gw.metadata.name.as_deref().unwrap_or("");
                            gateway_routes_into(&routes, gw_ns, gw_name, &target_ns)
                        })
                        .map(|gw| ObjectRef::from_obj(gw.as_ref()))
                        .collect()
                }
            })
            // RoleBinding → Gateway: managed-by label filter; mapper reads
            // the gateway-namespace/gateway-name labels to identify the
            // owning Gateway. Drives drift detection — an out-of-band delete
            // re-creates within watch latency rather than waiting for the
            // next natural reconcile trigger.
            .watches(
                api_bindings,
                watcher::Config::default().labels("app.kubernetes.io/managed-by=coxswain"),
                |rb: RoleBinding| -> Vec<ObjectRef<Gateway>> {
                    let Some(labels) = rb.metadata.labels.as_ref() else {
                        return vec![];
                    };
                    let Some(name) = labels.get("gateway.networking.k8s.io/gateway-name") else {
                        return vec![];
                    };
                    let Some(ns) = labels.get("gateway.coxswain-labs.dev/gateway-namespace") else {
                        return vec![];
                    };
                    vec![ObjectRef::new(name).within(ns)]
                },
            )
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

    let key = gateway_key(&gw);
    let gw_namespace = gw.metadata.namespace.as_deref().unwrap_or("");
    let gw_name = gw.metadata.name.as_deref().unwrap_or("");

    // ----- Finalizer / deletion path ------------------------------------
    //
    // A Gateway with `deletionTimestamp` set is being deleted; if it carries
    // our finalizer, we own the synchronous cleanup of cross-namespace
    // `RoleBinding`s before K8s can finalize the delete. Provisioned
    // resources (Deployment/Service/SA) in the Gateway's own namespace
    // GC via owner-refs — independent of this finalizer.
    if gw.metadata.deletion_timestamp.is_some() {
        if has_our_finalizer(&gw) {
            tracing::info!(
                gateway = %gateway_id(&gw),
                "operator: cleaning up dedicated-mode bindings for terminating Gateway"
            );
            rbac::delete_all_for_gateway(&ctx.client, gw_namespace, gw_name).await?;
            rbac::delete_all_cluster_bindings_for_gateway(&ctx.client, gw_namespace, gw_name)
                .await?;
            remove_finalizer(&ctx.client, &gw).await?;
            // GC of in-namespace resources is owner-ref driven; nothing else
            // to do here.
            ctx.last_hashes
                .lock()
                .unwrap_or_else(|e| panic!("invariant: hash-tracking mutex poisoned: {e}"))
                .remove(&key);
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
                // Cross-namespace RBAC is safe to reconcile every pass — the
                // deletes are NotFound-tolerant (idempotent).
                rbac::delete_all_for_gateway(&ctx.client, gw_namespace, gw_name).await?;
                rbac::delete_all_cluster_bindings_for_gateway(&ctx.client, gw_namespace, gw_name)
                    .await?;

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
                ctx.last_hashes
                    .lock()
                    .unwrap_or_else(|e| panic!("invariant: hash-tracking mutex poisoned: {e}"))
                    .remove(&key);
            }
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
                tls_health: &GatewayListenerHealth::default(),
                ingress_ports: ctx.ingress_ports,
                accepted: status::AcceptedOutcome::InvalidParameters,
                ready_pod_count: 0,
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

    // Derive RBAC scope from the Gateway's listener specs. Pure, no I/O.
    let derived = rbac::derive_proxy_rbac(&gw);

    // Compute the desired namespace set for per-namespace RoleBindings (#209).
    // Cross-namespace routes contribute their backend namespaces when any
    // listener has from: All or from: Selector.
    let allow_cross_ns = derived.allow_cluster_wide_route_read;
    let desired = rbac::desired_namespaces_for_gateway(
        &gw,
        &ctx.routes_store,
        &ctx.grants_store,
        allow_cross_ns,
    );

    let rendered = render::render(&render::RenderInputs {
        gateway: &gw,
        params: &effective,
        controller_image: &ctx.controller_image,
        gateway_class_name: class_name,
        discovery_endpoint: &ctx.discovery_endpoint,
        admin_port: ctx.admin_port,
    });

    // Stage 1 — provisioning (Deployment/Service/SA). SSA with force=true
    // re-asserts ownership on every reconcile; the apply order is SA →
    // Service → Deployment so the ServiceAccount exists before any
    // RoleBinding references it.
    apply::apply_rendered(&ctx.client, &gw, &rendered).await?;

    // Stage 2 — per-namespace RoleBindings. The proxy SA name matches the
    // rendered SA's name (GEP-1762 `<NAME>-<GATEWAY CLASS>`); we pass it in
    // explicitly so reconciler.rs stays the single source of truth for
    // resource naming.
    let proxy_sa_name = rendered
        .service_account
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| panic!("invariant: rendered ServiceAccount has no name"));
    rbac::reconcile_rbac(&ctx.client, &gw, proxy_sa_name, &desired).await?;

    // Stage 2b — cluster-wide ClusterRoleBindings for from: All / Selector
    // listeners (#229). Idempotent: creates/deletes based on derived flags.
    rbac::reconcile_cluster_rbac(&ctx.client, &gw, proxy_sa_name, derived).await?;

    // Stage 3 — write Gateway.status (#211). One JSON merge patch carries
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
    let tls_health_map = ctx.tls_health.load();
    let gateway_health = tls_health_map.get(&key).cloned().unwrap_or_default();
    let inputs = status::DedicatedGatewayStatusInputs {
        gw: &gw,
        service: service.as_ref(),
        nodes: &nodes,
        tls_health: &gateway_health,
        ingress_ports: ctx.ingress_ports,
        accepted: status::AcceptedOutcome::Accepted,
        ready_pod_count,
    };
    status::patch_dedicated_gateway_status(&ctx.client, &inputs).await?;

    let new_hash = hash_rendered(&rendered);
    let changed = {
        let mut hashes = ctx
            .last_hashes
            .lock()
            .unwrap_or_else(|e| panic!("invariant: hash-tracking mutex must not be poisoned: {e}"));
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
    ignore_not_found(deployments.delete(name, &dp).await)?;
    ignore_not_found(services.delete(name, &dp).await)?;
    ignore_not_found(service_accounts.delete(name, &dp).await)?;
    Ok(())
}

/// Collapse a `404 NotFound` delete result to success; propagate every other
/// error. Lets [`delete_dedicated_resources`] be safely re-run on every
/// hand-off re-queue.
fn ignore_not_found<T>(result: Result<T, kube::Error>) -> Result<(), kube::Error> {
    match result {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(e),
    }
}

/// Returns true iff any HTTPRoute attached to the given Gateway has a
/// `backendRef` whose target namespace equals `target_ns`. Used by the
/// ReferenceGrant cross-watch mapper to filter affected Gateways precisely.
fn gateway_routes_into(
    routes: &[Arc<HttpRoute>],
    gw_namespace: &str,
    gw_name: &str,
    target_ns: &str,
) -> bool {
    for route in routes {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("");
        let Some(parents) = route.spec.parent_refs.as_deref() else {
            continue;
        };
        let attaches = parents.iter().any(|p| {
            let group = p.group.as_deref().unwrap_or("gateway.networking.k8s.io");
            let kind = p.kind.as_deref().unwrap_or("Gateway");
            let ns = p.namespace.as_deref().unwrap_or(route_ns);
            group == "gateway.networking.k8s.io"
                && kind == "Gateway"
                && p.name == gw_name
                && ns == gw_namespace
        });
        if !attaches {
            continue;
        }
        let Some(rules) = route.spec.rules.as_deref() else {
            continue;
        };
        for rule in rules {
            let Some(brefs) = rule.backend_refs.as_deref() else {
                continue;
            };
            for b in brefs {
                let ns = b.namespace.as_deref().unwrap_or(route_ns);
                if ns == target_ns {
                    return true;
                }
            }
        }
    }
    false
}

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

fn gateway_id(gw: &Gateway) -> String {
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
            admin_port: 8082,
        });
        let r_b = render::render(&render::RenderInputs {
            gateway: &gw,
            params: &params_b,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            discovery_endpoint: "http://coxswain-controller-discovery.default.svc:50051",
            admin_port: 8082,
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
            admin_port: 8082,
        };
        let r1 = render::render(&inputs);
        let r2 = render::render(&inputs);
        assert_eq!(hash_rendered(&r1), hash_rendered(&r2));
    }
}
