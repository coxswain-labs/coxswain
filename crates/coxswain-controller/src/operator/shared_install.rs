//! Config-keyed **install reconcile** for the controller-owned shared proxy pool
//! (#604).
//!
//! Unlike the dedicated-proxy and namespace-relay convergences — keyed off a
//! Gateway or a namespace's dedicated demand — the shared pool is the install's
//! base data plane and must exist from install with **zero Gateways**. So a
//! single serialized task, modelled on [`super::run_vip_reconciler`], provisions
//! the pool off config alone. It is **event-driven with a resync backstop**: the
//! leadership edge provisions the pool the moment the controller wins the lease
//! (no waiting for a poll tick — the base data plane must come up promptly), the
//! [`super::ReconcileContext::shared_install_trigger`] nudges it on Gateway
//! changes, and a 15s resync backstops any missed signal. Leader-gated (only the
//! lease holder applies); best-effort per pass (a failed apply logs and the next
//! signal retries from cluster state).

use super::reconciler::ReconcileContext;
use super::relay_autoscaler::{RelayInputs, RelayRecord, RelayTuning};
use super::relay_converge::{self, Converge, RelayCell};
use super::relay_params::EffectiveRelayPolicy;
use super::relay_reconcile::{
    clamp_u32_to_i32, clamp_usize_to_u32, delete_relay_resources, leadership_changed,
    registry_changed,
};
use super::render_relay::{self, RelayRenderInputs, RelayVariant};
use super::render_shared_proxy::{SharedProxyRenderInputs, render_shared_proxy};
use coxswain_core::crd::RelayAutoscaling;
use k8s_openapi::api::apps::v1::Deployment;
use kube::Api;
use pingora_core::server::ShutdownWatch;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Resync backstop cadence. The leadership edge + the trigger are the real
/// drivers; this bounds staleness if a signal is ever missed.
const SHARED_INSTALL_RESYNC_INTERVAL: Duration = Duration::from_secs(15);

/// The single serialized task that owns the controller-provisioned shared proxy
/// pool (#604).
///
/// Returns immediately only when the pool is unnamed (nothing to manage — a bare
/// test context). Otherwise it loops, and each leader-gated pass **apply-or-
/// deletes**: it provisions the pool when enabled with a selector, and reclaims it
/// (idempotent, 404-tolerant delete) when disabled or unaddressable — so toggling
/// `proxy.shared.enabled=false` removes the pool instead of orphaning it.
///
/// `leadership` is the controller's leadership watch (`None` in tests): the
/// false→true edge provisions the pool immediately on promotion, so a fresh
/// leader (e.g. after a `helm upgrade` rolls the controller) brings the data
/// plane up without waiting for the resync tick. Shutdown wins (biased).
pub(crate) async fn run_shared_install_reconciler(
    ctx: Arc<ReconcileContext>,
    mut shutdown: ShutdownWatch,
    mut leadership: Option<watch::Receiver<bool>>,
) {
    if ctx.shared_proxy.name.is_empty() {
        return;
    }
    // The node registry is the prompt driver for the shared-relay control loop
    // (#605): a shared proxy connect/disconnect shifts the ready/subscriber gates.
    // `None` in unit contexts, so the arm parks forever there.
    let mut registry = ctx.node_registry.as_ref().map(|r| r.subscribe());
    let mut interval = tokio::time::interval(SHARED_INSTALL_RESYNC_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        // `became_leader` is read straight off the watch value (not the leader
        // AtomicBool) so the promotion edge acts without racing whichever writer
        // updates first.
        let mut became_leader = false;
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = leadership_changed(&mut leadership) => {
                became_leader = leadership.as_ref().is_some_and(|rx| *rx.borrow());
            }
            _ = ctx.shared_install_trigger.notified() => {}
            _ = registry_changed(&mut registry) => {}
            _ = interval.tick() => {}
        }
        // Only the leader writes; followers idle until promotion. Both apply and
        // delete are idempotent against current cluster state, so a fresh leader
        // (or a leadership flap) needs no seeding — the next pass re-converges.
        if became_leader || ctx.leader.load(Ordering::Acquire) {
            reconcile_shared_pool(&ctx).await;
            // Advance the demand-driven shared-relay control loop after the pool
            // pass, so its provision/GC decision sees the pool's current state.
            converge_shared_pool(&ctx, Instant::now()).await;
        }
    }
}

/// One install-reconcile pass. Provisions the pool when it is enabled with a
/// selector (the chart couples the two); otherwise reclaims any previously
/// provisioned pool. Best-effort — a failure logs and the next tick retries.
async fn reconcile_shared_pool(ctx: &ReconcileContext) {
    if !ctx.shared_proxy.enabled || ctx.shared_proxy_selector.is_empty() {
        if let Err(e) = super::apply::delete_shared_proxy(
            &ctx.client,
            &ctx.controller_namespace,
            &ctx.shared_proxy.name,
        )
        .await
        {
            tracing::warn!(
                error = %e,
                "shared-install: failed to reclaim the disabled shared proxy pool; retrying on the next resync tick"
            );
        }
        return;
    }
    let inputs = SharedProxyRenderInputs {
        config: &ctx.shared_proxy,
        selector: &ctx.shared_proxy_selector,
        namespace: &ctx.controller_namespace,
        controller_image: &ctx.controller_image,
        discovery_bootstrap_endpoint: &ctx.discovery_bootstrap_endpoint,
        discovery_sa_token_path: &ctx.discovery_sa_token_path,
        discovery_ca_bundle_path: &ctx.discovery_ca_bundle_path,
        discovery_trust_domain: &ctx.discovery_trust_domain,
        ingress_http_port: ctx.ingress_ports.http,
        ingress_https_port: ctx.ingress_ports.https,
        health_port: ctx.health_port,
        admin_port: ctx.admin_port,
        enable_ingress: ctx.enable_ingress,
        enable_gateway_api: ctx.enable_gateway_api,
    };
    let rendered = render_shared_proxy(&inputs);
    if let Err(e) =
        super::apply::apply_shared_proxy(&ctx.client, &ctx.controller_namespace, &rendered).await
    {
        tracing::warn!(
            error = %e,
            "shared-install: failed to apply the shared proxy pool; retrying on the next resync tick"
        );
    }
}

/// Advance the single-cell **shared-pool relay** control loop one pass (#605), the
/// shared-tier analogue of [`super::relay_reconcile`]'s per-namespace pass.
///
/// The demand **signal** is the shared pool's replica count
/// ([`shared_pool_replica_signal`]) — stable across proxies repointing behind the
/// relay, unlike a live subscriber count. The break-even + cooldown + autoscaling
/// decision reuses the #602 [`super::relay_autoscaler`] verbatim; the shared relay
/// has no `CoxswainRelayPolicy`, so its tuning is synthesized from the `--relay-*`
/// flags (autoscaled between `--relay-replicas` and `--relay-max-replicas`). Make-
/// before-break is enforced by [`RelayInputs::ready`] (the shared relay caches
/// before the pool repoints) and [`RelayInputs::subscribers`] (the pool drains
/// before delete), both read off the node registry. Best-effort — a failed
/// apply/delete logs and the next pass retries.
async fn converge_shared_pool(ctx: &ReconcileContext, now: Instant) {
    // The shared relay exists only when tiering is on AND the pool exists. When the
    // pool is gone the relay tears down at once (bypassing the cooldown), exactly as
    // a genuinely-drained namespace does via `demand_present`.
    let pool_present = ctx.shared_proxy.enabled && !ctx.shared_proxy_selector.is_empty();
    let tuning = shared_relay_tuning(ctx);

    let signal = shared_pool_replica_signal(ctx).await;
    let (ready, subscribers) = match &ctx.node_registry {
        Some(reg) => {
            let snap = reg.load();
            (
                snap.shared_pool_relay_ready(),
                clamp_usize_to_u32(snap.shared_pool_relay_subscriber_count()),
            )
        }
        None => (false, 0),
    };
    let inputs = RelayInputs {
        signal,
        ready,
        subscribers,
        demand_present: pool_present,
    };

    // Publish the repoint gate once per pass — but only when the pass settled. A
    // failed apply/delete (`Converge::Retry`) changed nothing on the cluster, so the
    // pool must not be repointed off a half-applied state; the next pass retries.
    // (Bumps the discovery watch only on a real Active transition, so the pool is
    // repointed exactly then.)
    if relay_converge::advance(&SharedCell { ctx }, inputs, &tuning, now).await == Converge::Done {
        ctx.publish_shared_relay();
    }
}

/// The shared-pool [`RelayCell`]: a single record in
/// [`ReconcileContext::shared_relay_state`]; resources rendered from the `--relay-*`
/// flags (no namespaced policy) into the install namespace and named
/// [`render_relay::SHARED_RELAY_NAME`].
struct SharedCell<'a> {
    ctx: &'a ReconcileContext,
}

#[async_trait::async_trait]
impl RelayCell for SharedCell<'_> {
    fn load(&self) -> Option<RelayRecord> {
        self.ctx.shared_relay_state.lock().clone()
    }

    fn store(&self, record: RelayRecord) {
        *self.ctx.shared_relay_state.lock() = Some(record);
    }

    fn clear(&self) {
        *self.ctx.shared_relay_state.lock() = None;
    }

    async fn apply(&self, replicas: u32, pdb_ceiling: u32) -> Result<(), super::apply::ApplyError> {
        apply_shared_relay_at(self.ctx, replicas, pdb_ceiling).await
    }

    async fn delete(&self) -> Result<(), super::apply::ApplyError> {
        delete_relay_resources(
            &self.ctx.client,
            &self.ctx.controller_namespace,
            render_relay::SHARED_RELAY_NAME,
        )
        .await
    }

    fn metric_labels(&self) -> (&'static str, &str) {
        ("shared", "")
    }

    fn is_leader(&self) -> bool {
        self.ctx.leader.load(Ordering::Acquire)
    }

    fn log_provision_failed(&self, error: &super::apply::ApplyError) {
        tracing::warn!(error = %error, "shared relay: provision apply failed; retrying next pass");
    }

    fn log_provisioned(&self, replicas: u32) {
        tracing::info!(replicas, "shared relay: provisioned (awaiting Ready)");
    }

    fn log_activate(&self) {
        tracing::info!("shared relay: Ready — repointing the pool onto it");
    }

    fn log_resize_failed(&self, error: &super::apply::ApplyError) {
        tracing::warn!(error = %error, "shared relay: resize apply failed; retrying next pass");
    }

    fn log_resized(&self, replicas: u32) {
        tracing::info!(replicas, "shared relay: resized to live pool demand");
    }

    fn log_start_drain(&self) {
        tracing::info!(
            "shared relay: below break-even past cooldown — repointing the pool back to the controller, then draining"
        );
    }

    fn log_delete_failed(&self, error: &super::apply::ApplyError) {
        tracing::warn!(error = %error, "shared relay: teardown delete failed; retrying next pass");
    }

    fn log_deleted(&self) {
        tracing::info!("shared relay: drained (0 subscribers) — deleted");
    }
}

/// Synthesize the shared relay's [`RelayTuning`] from the `--relay-*` flags (#605).
///
/// The shared relay has no namespaced `CoxswainRelayPolicy`, so it autoscales
/// directly off the flags: floor `--relay-replicas`, cap `--relay-max-replicas`,
/// capacity `--relay-target-proxies-per-replica`; cooldown / stabilization /
/// tolerance fall back to their flag defaults. `enabled: Some(false)` when tiering
/// is off force-tears-down any running shared relay (the KEDA force-off path).
fn shared_relay_tuning(ctx: &ReconcileContext) -> RelayTuning {
    let floor = ctx.relay.replicas.max(1);
    let policy = EffectiveRelayPolicy {
        enabled: (!ctx.relay.enabled).then_some(false),
        replicas: None,
        resources: None,
        pod_template: None,
        autoscaling: Some(RelayAutoscaling::capped(
            floor,
            ctx.relay.max_replicas.max(floor),
            ctx.relay.target_proxies_per_replica.max(1),
        )),
    };
    RelayTuning::resolve(&policy, ctx.relay_tuning_defaults())
}

/// The shared-relay demand signal (#605): the shared pool's replica count.
///
/// An HPA-autoscaled pool has the HPA own `spec.replicas`, so the live count is
/// read from the Deployment; a statically-sized pool uses its config replica count
/// (no I/O). A disabled/unaddressable pool signals 0 (no relay). The pool's *size*
/// — not a live subscriber count — is the signal: it stays stable when proxies
/// repoint behind the relay, so the break-even/cooldown decision does not thrash on
/// its own make-before-break cutover.
async fn shared_pool_replica_signal(ctx: &ReconcileContext) -> u32 {
    if !ctx.shared_proxy.enabled || ctx.shared_proxy_selector.is_empty() {
        return 0;
    }
    if !ctx.shared_proxy.autoscaling_enabled {
        return ctx.shared_proxy.replicas;
    }
    let deployments: Api<Deployment> =
        Api::namespaced(ctx.client.clone(), &ctx.controller_namespace);
    match deployments.get_opt(&ctx.shared_proxy.name).await {
        Ok(dep) => dep
            .and_then(|d| d.spec)
            .and_then(|s| s.replicas)
            .and_then(|r| u32::try_from(r).ok())
            .unwrap_or(ctx.shared_proxy.autoscaling_min_replicas),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "shared relay: failed to read pool replicas; using the autoscaling floor as the signal"
            );
            ctx.shared_proxy.autoscaling_min_replicas
        }
    }
}

/// Render and server-side-apply the shared-pool relay at `replicas`/`pdb_ceiling`
/// into the install namespace (#605). Resources come straight from the `--relay-*`
/// flags (no namespaced policy overlay).
async fn apply_shared_relay_at(
    ctx: &ReconcileContext,
    replicas: u32,
    pdb_ceiling: u32,
) -> Result<(), super::apply::ApplyError> {
    let resources = render_relay::relay_resources(
        &ctx.relay.cpu_request,
        &ctx.relay.memory_request,
        &ctx.relay.memory_limit,
    );
    let rendered = render_relay::render_relay(&RelayRenderInputs {
        variant: RelayVariant::Shared {
            install_namespace: &ctx.controller_namespace,
        },
        replicas: clamp_u32_to_i32(replicas),
        controller_image: &ctx.controller_image,
        discovery_bootstrap_endpoint: &ctx.discovery_bootstrap_endpoint,
        discovery_sa_token_path: &ctx.discovery_sa_token_path,
        discovery_ca_bundle_path: &ctx.discovery_ca_bundle_path,
        discovery_trust_domain: &ctx.discovery_trust_domain,
        resources,
        pod_template: None,
        pdb_replica_ceiling: clamp_u32_to_i32(pdb_ceiling),
    });
    super::apply::apply_relay(&ctx.client, &ctx.controller_namespace, &rendered).await
}
