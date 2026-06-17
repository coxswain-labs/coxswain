//! Leader-elected status writer: a set of kube `Controller` work-queues that
//! patch Gateway API status conditions back to the API server.
//!
//! One reconcile path per primary resource (`Gateway`, `GatewayClass`,
//! `HTTPRoute`, `Ingress`, `BackendTLSPolicy`), each driven by the reflector's
//! **shared** informers (`StatusSubscriptions`) rather than its own duplicate
//! watches (#347). Every reconcile reads ownership/state from the synced
//! reflector stores at reconcile time, so there is no cross-stream ordering
//! race: a Gateway observed before its `GatewayClass` simply reconciles to
//! `await_change` and is re-driven by the `GatewayClass → Gateway` secondary
//! watch once the class lands. "Not leader" / "data plane not yet synced"
//! become native `Action::requeue`s, not dropped events.
//!
//! Leader election (the `Lease` renewal loop) lives in this same background
//! service; the shared `leader` flag gates every reconcile and is the one
//! truth-source the dedicated-mode operator also reads.

use async_trait::async_trait;
use coxswain_core::health::HealthRegistry;
use coxswain_core::ownership::{ObjectKey, OwnedGateways};
use coxswain_reflector::StatusSubscriptions;
use coxswain_reflector::gw_types::v::gatewayclasses::GatewayClass;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use coxswain_reflector::gw_types::{BackendTlsPolicy, HttpRoute};
use coxswain_reflector::tls::{
    GatewayListenerHealth, SharedBackendTlsPolicyHealth, SharedGatewayListenerHealth,
    SharedHttpRouteHealth,
};
use futures::StreamExt;
use futures::channel::mpsc::{self, UnboundedSender};
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use kube::{
    Client, Resource as _,
    runtime::{
        controller::{Action, Controller as KubeController},
        reflector::ObjectRef,
    },
};
use kube_leader_election::{LeaseLock, LeaseLockParams, LeaseLockResult};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::task::JoinSet;

mod backend_tls_events;
mod conditions;
mod config;
mod gateway_class_events;
mod gateway_class_status;
mod gateway_events;
mod gateway_status;
mod ingress_events;
mod ingress_status;
mod route_events;

pub use config::{ControllerConfig, ControllerConfigError, LeaseSettings, StatusAddress};

use conditions::gateway_accepted;
use gateway_class_status::gateway_class_needs_status_patch;
use gateway_status::gateway_needs_status_patch;
use ingress_status::ingress_lb_already_matches;

const LEASE_NAME: &str = "coxswain-leader-lock";

/// Re-queue interval for a reconcile that ran on a non-leader pod. Long enough
/// not to hot-spin, short enough that leader promotion translates into action
/// promptly (the lease TTL defaults to 15 s).
const NON_LEADER_REQUEUE: Duration = Duration::from_secs(20);

/// Re-queue interval after a reconcile error (none of the status helpers
/// currently surface one, so this is a backstop for the framework's error
/// policy).
const ERROR_REQUEUE: Duration = Duration::from_secs(15);

/// Re-queue interval while a Gateway's `Programmed` condition is deferred
/// because the `controller` subsystem has not finished its first data-plane
/// rebuild. Replaces the old `STATUS_RESYNC_INTERVAL` backstop: instead of a
/// process-wide periodic scan, only the Gateways actually waiting on readiness
/// requeue, and only until the subsystem flips ready (then the `tls_health`
/// re-drive and normal events take over).
const DEFERRED_PROGRAMMED_REQUEUE: Duration = Duration::from_secs(2);

/// The three reflector-published health channels the status reconcilers read
/// (a `.load()` snapshot per reconcile) and subscribe to (to re-drive the
/// affected work-queue when a TLS-resolution / route-health / policy-health
/// outcome flips).
// intentionally open: field-literal constructed in crate::spawn_status_writer.
pub struct StatusHealthChannels {
    /// Per-listener Gateway TLS health.
    pub tls: SharedGatewayListenerHealth,
    /// Per-route Accepted/ResolvedRefs health.
    pub route: SharedHttpRouteHealth,
    /// Per-`BackendTLSPolicy` ancestor health.
    pub policy: SharedBackendTlsPolicyHealth,
}

/// Leader-elected status writer. Registered as a Pingora `BackgroundService`
/// next to the reflector (whose shared informers it consumes) in `serve
/// controller` and `serve dev`.
#[non_exhaustive]
pub struct Controller {
    health: HealthRegistry,
    leader: Arc<AtomicBool>,
    owned_gateways: OwnedGateways,
    channels: StatusHealthChannels,
    config: ControllerConfig,
    /// Shared-informer subscriptions handed over by the reflector; taken once
    /// in `start` (the handles are independent broadcast subscribers and must
    /// not be left undrained, which would back-pressure the stores).
    subscriptions: std::sync::Mutex<Option<StatusSubscriptions>>,
}

impl Controller {
    /// Construct a new status writer (does not start the work-queues).
    pub fn new(
        health: HealthRegistry,
        leader: Arc<AtomicBool>,
        owned_gateways: OwnedGateways,
        channels: StatusHealthChannels,
        subscriptions: StatusSubscriptions,
        config: ControllerConfig,
    ) -> Self {
        Self {
            health,
            leader,
            owned_gateways,
            channels,
            config,
            subscriptions: std::sync::Mutex::new(Some(subscriptions)),
        }
    }

    async fn run_controllers(&self, mut shutdown: ShutdownWatch) {
        let client = match Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "failed to initialise Kubernetes client; controller will not run");
                return;
            }
        };

        let lease_lock = LeaseLock::new(
            client.clone(),
            &self.config.pod_namespace,
            LeaseLockParams {
                holder_id: self.config.pod_name.clone(),
                lease_name: LEASE_NAME.to_string(),
                lease_ttl: self.config.lease.ttl,
            },
        );

        // Acquire leadership before building the work-queues so the initial
        // reconcile burst (driven by the shared informers' InitApply) runs with
        // the correct leader state.
        let mut is_leader = Self::try_renew(&lease_lock, &self.config.pod_name).await;
        self.leader.store(is_leader, Ordering::Release);
        crate::metrics::leader().set(i64::from(is_leader));

        let subs = self
            .subscriptions
            .lock()
            .unwrap_or_else(|e| panic!("invariant: subscriptions mutex poisoned: {e}"))
            .take()
            .unwrap_or_else(|| panic!("invariant: status subscriptions taken twice"));
        let StatusSubscriptions {
            gateways,
            gateway_classes,
            routes,
            ingresses,
            ingress_classes,
            policies,
            ..
        } = subs;

        // Readers for ownership lookups + secondary mappers. Captured before the
        // handles are consumed as work-queue triggers; an independent secondary
        // subscriber for the Gateway controller's GatewayClass watch is cloned
        // off the GatewayClass handle.
        let gateways_reader = gateways.reader();
        let gateway_classes_reader = gateway_classes.reader();
        let routes_reader = routes.reader();
        let ingresses_reader = ingresses.reader();
        let ingress_classes_reader = ingress_classes.reader();
        let policies_reader = policies.reader();
        let gateway_classes_for_gateways = gateway_classes.clone();

        let ctx = Arc::new(ReconcileContext {
            client,
            leader: Arc::clone(&self.leader),
            health: self.health.clone(),
            controller_name: self.config.controller_name.clone(),
            status_address: self.config.status_address.clone(),
            ingress_ports: self.config.ingress_ports,
            owned_gateways: self.owned_gateways.clone(),
            tls_health: self.channels.tls.clone(),
            route_health: self.channels.route.clone(),
            policy_health: self.channels.policy.clone(),
            gateway_classes: gateway_classes_reader,
            ingress_classes: ingress_classes_reader,
        });

        // One re-drive channel per work-queue. Each is fed by the relevant
        // health forwarder (TLS → Gateway, route → HTTPRoute, policy →
        // BackendTLSPolicy) and by leader-promotion (all five). `reconcile_all_on`
        // re-reconciles every object currently in that controller's store; the
        // per-resource idempotency gates absorb the duplicates.
        let (gw_tx, gw_rx) = mpsc::unbounded::<()>();
        let (gc_tx, gc_rx) = mpsc::unbounded::<()>();
        let (route_tx, route_rx) = mpsc::unbounded::<()>();
        let (ing_tx, ing_rx) = mpsc::unbounded::<()>();
        let (pol_tx, pol_rx) = mpsc::unbounded::<()>();
        let leadership_txs = vec![
            gw_tx.clone(),
            gc_tx.clone(),
            route_tx.clone(),
            ing_tx.clone(),
            pol_tx.clone(),
        ];

        let mut tasks = JoinSet::new();

        // Health → work-queue forwarders. Each bridges a `watch::Receiver<u64>`
        // (Send, !Sync) onto the `mpsc::Unbounded` stream `reconcile_all_on`
        // wants, dropping the initial value so a fresh subscription does not
        // spuriously re-drive before any health flip occurs.
        spawn_health_forwarder(&mut tasks, self.channels.tls.subscribe(), gw_tx);
        spawn_health_forwarder(&mut tasks, self.channels.route.subscribe(), route_tx);
        spawn_health_forwarder(&mut tasks, self.channels.policy.subscribe(), pol_tx);

        // --- Gateway: primary Gateway, secondary GatewayClass → Gateways in
        // that class, re-driven on TLS-health flips + promotion. ---
        let gateway_ctrl = KubeController::for_shared_stream(gateways, gateways_reader.clone())
            .watches_shared_stream(gateway_classes_for_gateways, {
                let gw_store = gateways_reader.clone();
                move |gc: Arc<GatewayClass>| -> Vec<ObjectRef<Gateway>> {
                    let Some(class_name) = gc.meta().name.clone() else {
                        return Vec::new();
                    };
                    gw_store
                        .state()
                        .into_iter()
                        .filter(|gw| gw.spec.gateway_class_name == class_name)
                        .map(|gw| ObjectRef::from_obj(gw.as_ref()))
                        .collect()
                }
            })
            .reconcile_all_on(gw_rx)
            .run(reconcile_gateway, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, gateway_ctrl, "Gateway");

        // --- GatewayClass: primary only; re-driven on promotion. ---
        let gateway_class_ctrl =
            KubeController::for_shared_stream(gateway_classes, ctx.gateway_classes.clone())
                .reconcile_all_on(gc_rx)
                .run(reconcile_gateway_class, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, gateway_class_ctrl, "GatewayClass");

        // --- HTTPRoute: primary only; re-driven on route-health flips +
        // promotion. ---
        let route_ctrl = KubeController::for_shared_stream(routes, routes_reader)
            .reconcile_all_on(route_rx)
            .run(reconcile_route, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, route_ctrl, "HTTPRoute");

        // --- Ingress: primary Ingress, secondary IngressClass → all Ingresses
        // (ownership re-checked per reconcile); re-driven on promotion. ---
        let ingress_ctrl = KubeController::for_shared_stream(ingresses, ingresses_reader.clone())
            .watches_shared_stream(ingress_classes, {
                let ing_store = ingresses_reader.clone();
                move |_ic: Arc<IngressClass>| -> Vec<ObjectRef<Ingress>> {
                    ing_store
                        .state()
                        .into_iter()
                        .map(|ing| ObjectRef::from_obj(ing.as_ref()))
                        .collect()
                }
            })
            .reconcile_all_on(ing_rx)
            .run(reconcile_ingress, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, ingress_ctrl, "Ingress");

        // --- BackendTLSPolicy: primary only; re-driven on policy-health flips +
        // promotion. ---
        let policy_ctrl = KubeController::for_shared_stream(policies, policies_reader)
            .reconcile_all_on(pol_rx)
            .run(reconcile_policy, error_policy, ctx.clone());
        spawn_controller_stream(&mut tasks, policy_ctrl, "BackendTLSPolicy");

        tracing::info!(pod = %self.config.pod_name, is_leader, "Status-writer work-queues active");

        let mut renewal_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + self.config.lease.renew_interval,
            self.config.lease.renew_interval,
        );

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if is_leader {
                        match lease_lock.step_down().await {
                            Ok(()) => tracing::info!(pod = %self.config.pod_name, "Stepped down from leadership"),
                            Err(kube_leader_election::Error::ReleaseLockWhenNotLeading { .. }) => {}
                            Err(e) => tracing::warn!(error = %e, "Failed to step down from leadership"),
                        }
                    }
                    break;
                }
                _ = renewal_interval.tick() => {
                    let leading = Self::try_renew(&lease_lock, &self.config.pod_name).await;
                    if leading != is_leader {
                        if leading {
                            tracing::info!(pod = %self.config.pod_name, "Acquired leadership");
                        } else {
                            tracing::info!(pod = %self.config.pod_name, "Lost leadership");
                        }
                        is_leader = leading;
                        self.leader.store(is_leader, Ordering::Release);
                        crate::metrics::leader().set(i64::from(is_leader));
                        crate::metrics::leader_transitions_total().inc();
                        if is_leader {
                            // Promotion: re-drive every work-queue so Gateways /
                            // routes / policies observed while we were standby
                            // (their status writes gated off) are reconciled now,
                            // not at the next watch event.
                            for tx in &leadership_txs {
                                let _ = tx.unbounded_send(());
                            }
                        }
                    }
                }
                res = tasks.join_next() => {
                    match res {
                        Some(Ok(())) => tracing::warn!("status-writer: a background task exited unexpectedly"),
                        Some(Err(e)) => tracing::error!(error = %e, "status-writer: a background task panicked"),
                        None => break,
                    }
                }
            }
        }
        tasks.shutdown().await;
    }

    async fn try_renew(lease_lock: &LeaseLock, pod_name: &str) -> bool {
        match lease_lock.try_acquire_or_renew().await {
            Ok(LeaseLockResult::Acquired(_)) => true,
            Ok(LeaseLockResult::NotAcquired(_)) => false,
            Err(e) => {
                tracing::warn!(pod = %pod_name, error = %e, "Lease operation failed, assuming standby");
                false
            }
        }
    }
}

#[async_trait]
impl BackgroundService for Controller {
    async fn start(&self, shutdown: ShutdownWatch) {
        self.run_controllers(shutdown).await;
    }
}

/// Bridge a health `watch::Receiver<u64>` onto an `mpsc` `()` stream feeding a
/// work-queue's `reconcile_all_on`. The initial value is dropped via
/// `borrow_and_update` so a fresh subscription does not fire a spurious
/// re-drive before any health flip.
fn spawn_health_forwarder(
    tasks: &mut JoinSet<()>,
    mut rx: tokio::sync::watch::Receiver<u64>,
    tx: UnboundedSender<()>,
) {
    tasks.spawn(async move {
        let _ = rx.borrow_and_update();
        while rx.changed().await.is_ok() {
            if tx.unbounded_send(()).is_err() {
                break;
            }
        }
    });
}

/// Drain a kube `Controller::run` stream, logging reconcile errors. The stream
/// owns the work-queue; dropping it would stop reconciliation, so it is kept
/// running until the service shuts down (which aborts the `JoinSet`).
fn spawn_controller_stream<K>(
    tasks: &mut JoinSet<()>,
    stream: impl futures::Stream<
        Item = Result<
            (ObjectRef<K>, Action),
            kube::runtime::controller::Error<Infallible, kube::runtime::watcher::Error>,
        >,
    > + Send
    + 'static,
    label: &'static str,
) where
    K: kube::Resource + 'static,
{
    tasks.spawn(async move {
        tokio::pin!(stream);
        while let Some(res) = stream.next().await {
            if let Err(e) = res {
                tracing::debug!(controller = label, error = %e, "status-writer: controller stream error");
            }
        }
        tracing::warn!(controller = label, "status-writer: controller stream ended");
    });
}

/// State shared across every reconcile invocation of all five work-queues.
struct ReconcileContext {
    client: Client,
    leader: Arc<AtomicBool>,
    health: HealthRegistry,
    controller_name: String,
    status_address: Option<StatusAddress>,
    ingress_ports: coxswain_reflector::ingress::IngressPorts,
    owned_gateways: OwnedGateways,
    tls_health: SharedGatewayListenerHealth,
    route_health: SharedHttpRouteHealth,
    policy_health: SharedBackendTlsPolicyHealth,
    /// Synced GatewayClass store, read for Gateway ownership at reconcile time.
    gateway_classes: kube::runtime::reflector::Store<GatewayClass>,
    /// Synced IngressClass store, read for Ingress ownership at reconcile time.
    ingress_classes: kube::runtime::reflector::Store<IngressClass>,
}

/// Error policy shared by every work-queue. The status reconcilers are
/// infallible ([`Infallible`]) — every fallible patch is a fire-and-forget log
/// inside the `*_events` helpers — so this is never invoked; it exists only to
/// satisfy `Controller::run`.
fn error_policy<K>(_obj: Arc<K>, _err: &Infallible, _ctx: Arc<ReconcileContext>) -> Action {
    Action::requeue(ERROR_REQUEUE)
}

async fn reconcile_gateway(
    gw: Arc<Gateway>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_gateway_inner(&gw, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_gateway_inner(gw: &Gateway, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }

    // Ownership is read from the synced GatewayClass store at reconcile time —
    // never from a sibling handler's cache — so the cold-start ordering race
    // cannot recur. An un-owned (or not-yet-observed) class yields
    // `await_change`; the GatewayClass → Gateway secondary watch re-drives this
    // Gateway once its class lands.
    let classes = ctx.gateway_classes.state();
    let (owned, owned_dedicated) = classify_gateway_classes(&classes, &ctx.controller_name);
    let class_name = gw.spec.gateway_class_name.as_str();
    if !owned.contains(class_name) {
        return Action::await_change();
    }
    // Dedicated-mode Gateways are the operator's to write (#211); skipping here
    // keeps the two writers from racing on `status.conditions`.
    if is_dedicated_mode(gw, &owned_dedicated) {
        return Action::await_change();
    }

    let key = ObjectKey::new(
        gw.metadata.namespace.clone().unwrap_or_default(),
        gw.metadata.name.clone().unwrap_or_default(),
    );
    if ctx.health.is_subsystem_ready("controller") {
        let health_map = ctx.tls_health.load();
        let health = health_map.get(&key).cloned().unwrap_or_default();
        if gateway_needs_status_patch(gw, &health) {
            gateway_events::patch_gateway_status(
                &ctx.client,
                gw,
                &health,
                ctx.status_address.as_ref(),
                ctx.ingress_ports,
            )
            .await;
        }
        Action::await_change()
    } else if !gateway_accepted(gw) {
        // Before the data plane is synced, write the minimal Accepted-oriented
        // status and requeue to revisit `Programmed` once ready. This requeue
        // replaces the old process-wide resync backstop.
        let empty_health = GatewayListenerHealth::default();
        if gateway_needs_status_patch(gw, &empty_health) {
            gateway_events::patch_gateway_status(
                &ctx.client,
                gw,
                &empty_health,
                ctx.status_address.as_ref(),
                ctx.ingress_ports,
            )
            .await;
        }
        Action::requeue(DEFERRED_PROGRAMMED_REQUEUE)
    } else {
        // Accepted already set, but the subsystem is not ready yet: revisit
        // shortly so `Programmed` lands without waiting for the next event.
        Action::requeue(DEFERRED_PROGRAMMED_REQUEUE)
    }
}

async fn reconcile_gateway_class(
    gc: Arc<GatewayClass>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_gateway_class_inner(&gc, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_gateway_class_inner(gc: &GatewayClass, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }
    if gc.spec.controller_name != ctx.controller_name {
        return Action::await_change();
    }
    if gateway_class_needs_status_patch(gc) {
        let Some(generation) = gc.metadata.generation else {
            tracing::warn!(
                name = gc.metadata.name.as_deref().unwrap_or(""),
                "Skipping GatewayClass status patch: metadata.generation is unset"
            );
            return Action::await_change();
        };
        let name = gc.metadata.name.as_deref().unwrap_or_default();
        gateway_class_events::patch_gateway_class_status(&ctx.client, name, generation).await;
    }
    Action::await_change()
}

async fn reconcile_route(
    route: Arc<HttpRoute>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_route_inner(&route, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_route_inner(route: &HttpRoute, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }
    // `mark_http_route_programmed` is idempotent (skips the patch when the
    // route already carries the conditions we would write), so it is safe to
    // call on both spec-change events and route-health re-drives without
    // churning `lastTransitionTime`.
    let owned = ctx.owned_gateways.load();
    let rh = ctx.route_health.load();
    route_events::mark_http_route_programmed(&ctx.client, route, &ctx.controller_name, &owned, &rh)
        .await;
    Action::await_change()
}

async fn reconcile_ingress(
    ing: Arc<Ingress>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_ingress_inner(&ing, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_ingress_inner(ing: &Ingress, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }
    let Some(addr) = ctx.status_address.as_ref() else {
        return Action::await_change();
    };
    let classes = ctx.ingress_classes.state();
    let (owned_classes, default_classes) = classify_ingress_classes(&classes, &ctx.controller_name);
    let owned = match coxswain_reflector::ingress::claimed_ingress_class(ing) {
        Some(c) => owned_classes.contains(c),
        None => !default_classes.is_empty(),
    };
    if owned && !ingress_lb_already_matches(ing, addr, ctx.ingress_ports) {
        ingress_events::patch_ingress_status(&ctx.client, ing, addr, ctx.ingress_ports).await;
    }
    Action::await_change()
}

async fn reconcile_policy(
    policy: Arc<BackendTlsPolicy>,
    ctx: Arc<ReconcileContext>,
) -> Result<Action, Infallible> {
    let started = std::time::Instant::now();
    let res: Result<Action, Infallible> = Ok(reconcile_policy_inner(&policy, &ctx).await);
    crate::metrics::observe_reconcile("status_writer", started, &res);
    res
}

async fn reconcile_policy_inner(policy: &BackendTlsPolicy, ctx: &ReconcileContext) -> Action {
    if !ctx.leader.load(Ordering::Acquire) {
        return Action::requeue(NON_LEADER_REQUEUE);
    }
    let ph = ctx.policy_health.load();
    backend_tls_events::patch_backend_tls_policy_status(
        &ctx.client,
        policy,
        &ctx.controller_name,
        &ph,
    )
    .await;
    Action::await_change()
}

/// Classify GatewayClasses from a synced store snapshot into `(owned,
/// owned_dedicated)` ownership sets. Mirrors the per-event classification the
/// old watcher applied; pure, so it is unit-testable.
fn classify_gateway_classes(
    classes: &[Arc<GatewayClass>],
    controller_name: &str,
) -> (HashSet<String>, HashSet<String>) {
    let mut owned = HashSet::new();
    let mut dedicated = HashSet::new();
    for gc in classes {
        if gc.spec.controller_name != controller_name {
            continue;
        }
        let Some(name) = gc.metadata.name.clone() else {
            continue;
        };
        if class_has_coxswain_params_ref(gc) {
            dedicated.insert(name.clone());
        }
        owned.insert(name);
    }
    (owned, dedicated)
}

/// Classify IngressClasses from a synced store snapshot into `(owned,
/// owned_default)` ownership sets. Pure, so it is unit-testable.
fn classify_ingress_classes(
    classes: &[Arc<IngressClass>],
    controller_name: &str,
) -> (HashSet<String>, HashSet<String>) {
    let mut owned = HashSet::new();
    let mut default = HashSet::new();
    for ic in classes {
        let is_owned =
            ic.spec.as_ref().and_then(|s| s.controller.as_deref()) == Some(controller_name);
        if !is_owned {
            continue;
        }
        let Some(name) = ic.metadata.name.clone() else {
            continue;
        };
        if coxswain_reflector::ingress::is_default_ingress_class(ic) {
            default.insert(name.clone());
        }
        owned.insert(name);
    }
    (owned, default)
}

/// CRD group hosting [`coxswain_core::crd::CoxswainGatewayParameters`]. A
/// `parametersRef` with this group + matching kind marks a Gateway (or its
/// GatewayClass) as dedicated-mode, which the shared-pool status writer
/// must skip (#211).
const COXSWAIN_PARAMS_GROUP: &str = "gateway.coxswain-labs.dev";
/// CRD kind for the dedicated-mode parameters CRD.
const COXSWAIN_PARAMS_KIND: &str = "CoxswainGatewayParameters";

/// Returns true iff the GatewayClass's `parametersRef` targets
/// `CoxswainGatewayParameters`. The presence of the reference is the
/// dedicated-mode opt-in signal — we do not resolve the target here, because
/// even an unresolvable reference is the operator's case (the
/// `InvalidParameters` Gateway condition).
fn class_has_coxswain_params_ref(gc: &GatewayClass) -> bool {
    gc.spec
        .parameters_ref
        .as_ref()
        .is_some_and(|r| r.group == COXSWAIN_PARAMS_GROUP && r.kind == COXSWAIN_PARAMS_KIND)
}

/// Same predicate, applied to the Gateway's own
/// `spec.infrastructure.parametersRef`. Either reference triggers
/// dedicated mode.
fn gateway_has_coxswain_params_ref(gw: &Gateway) -> bool {
    gw.spec
        .infrastructure
        .as_ref()
        .and_then(|i| i.parameters_ref.as_ref())
        .is_some_and(|r| r.group == COXSWAIN_PARAMS_GROUP && r.kind == COXSWAIN_PARAMS_KIND)
}

/// Returns true iff the Gateway is in dedicated mode and therefore must NOT
/// have its `status` patched by the shared-pool writer. The check is purely
/// derived from already-watched specs (no resolve, no shared state) so the
/// dispatch is race-free with respect to the operator.
fn is_dedicated_mode(gw: &Gateway, owned_dedicated_classes: &HashSet<String>) -> bool {
    gateway_has_coxswain_params_ref(gw)
        || owned_dedicated_classes.contains(gw.spec.gateway_class_name.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_reflector::gw_types::v::gatewayclasses::{GatewayClass, GatewayClassSpec};
    use k8s_openapi::api::networking::v1::{IngressClass, IngressClassSpec};
    use kube::api::ObjectMeta;

    fn gateway_class(name: &str, controller: &str, dedicated: bool) -> Arc<GatewayClass> {
        use coxswain_reflector::gw_types::v::gatewayclasses::GatewayClassParametersRef;
        Arc::new(GatewayClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: controller.to_string(),
                parameters_ref: dedicated.then(|| GatewayClassParametersRef {
                    group: COXSWAIN_PARAMS_GROUP.to_string(),
                    kind: COXSWAIN_PARAMS_KIND.to_string(),
                    name: "params".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            status: None,
        })
    }

    fn ingress_class(name: &str, controller: Option<&str>, default: bool) -> Arc<IngressClass> {
        let annotations = default.then(|| {
            [(
                "ingressclass.kubernetes.io/is-default-class".to_string(),
                "true".to_string(),
            )]
            .into_iter()
            .collect()
        });
        Arc::new(IngressClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                annotations,
                ..Default::default()
            },
            spec: Some(IngressClassSpec {
                controller: controller.map(str::to_string),
                ..Default::default()
            }),
        })
    }

    #[test]
    fn classify_gateway_classes_partitions_owned_and_dedicated() {
        let classes = [
            gateway_class("ours-shared", "coxswain", false),
            gateway_class("ours-dedicated", "coxswain", true),
            gateway_class("theirs", "other", false),
        ];
        let (owned, dedicated) = classify_gateway_classes(&classes, "coxswain");
        assert!(owned.contains("ours-shared"));
        assert!(owned.contains("ours-dedicated"));
        assert!(!owned.contains("theirs"));
        assert!(dedicated.contains("ours-dedicated"));
        assert!(!dedicated.contains("ours-shared"));
    }

    #[test]
    fn classify_ingress_classes_partitions_owned_and_default() {
        let classes = [
            ingress_class("ours", Some("coxswain"), false),
            ingress_class("ours-default", Some("coxswain"), true),
            ingress_class("theirs", Some("other"), true),
        ];
        let (owned, default) = classify_ingress_classes(&classes, "coxswain");
        assert!(owned.contains("ours"));
        assert!(owned.contains("ours-default"));
        assert!(!owned.contains("theirs"));
        assert!(default.contains("ours-default"));
        assert!(!default.contains("ours"));
        // `theirs` is default-annotated but not ours, so it must not appear.
        assert!(!default.contains("theirs"));
    }

    #[test]
    fn is_dedicated_mode_detects_class_membership() {
        let gw = Arc::new(Gateway {
            metadata: ObjectMeta::default(),
            spec: coxswain_reflector::gw_types::v::gateways::GatewaySpec {
                gateway_class_name: "ours-dedicated".to_string(),
                ..Default::default()
            },
            status: None,
        });
        let dedicated: HashSet<String> = ["ours-dedicated".to_string()].into_iter().collect();
        assert!(is_dedicated_mode(&gw, &dedicated));
        let empty = HashSet::new();
        assert!(!is_dedicated_mode(&gw, &empty));
    }
}
