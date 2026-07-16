//! Config-keyed **install reconcile** for the controller-owned shared proxy pool
//! (#604).
//!
//! Unlike the dedicated-proxy and namespace-relay convergences — keyed off a
//! Gateway or a namespace's dedicated demand — the shared pool is the install's
//! base data plane and must exist from install with **zero Gateways**. So a
//! single serialized task, modelled on [`super::run_vip_reconciler`], provisions
//! the pool off config alone: the immediate first interval tick brings it up at
//! boot, a 15s resync backstops watch lag, and per-Gateway reconciles nudge the
//! [`super::ReconcileContext::shared_install_trigger`] for prompt convergence.
//! Leader-gated (only the lease holder applies); best-effort per pass (a failed
//! apply logs and the next tick retries from cluster state).

use super::reconciler::ReconcileContext;
use super::render_shared_proxy::{SharedProxyRenderInputs, render_shared_proxy};
use pingora_core::server::ShutdownWatch;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// Resync backstop cadence. The trigger + the immediate first tick are the real
/// drivers; this bounds staleness if a signal is ever missed.
const SHARED_INSTALL_RESYNC_INTERVAL: Duration = Duration::from_secs(15);

/// The single serialized task that owns the controller-provisioned shared proxy
/// pool (#604).
///
/// Returns immediately only when the pool is unnamed (nothing to manage — a bare
/// test context). Otherwise it loops, and each leader-gated pass **apply-or-
/// deletes**: it provisions the pool when enabled with a selector, and reclaims it
/// (idempotent, 404-tolerant delete) when disabled or unaddressable — so toggling
/// `proxy.shared.enabled=false` removes the pool instead of orphaning it. Shutdown
/// wins (biased); a trigger or the resync tick drives each pass.
pub(crate) async fn run_shared_install_reconciler(
    ctx: Arc<ReconcileContext>,
    mut shutdown: ShutdownWatch,
) {
    if ctx.shared_proxy.name.is_empty() {
        return;
    }
    let mut interval = tokio::time::interval(SHARED_INSTALL_RESYNC_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = ctx.shared_install_trigger.notified() => {}
            _ = interval.tick() => {}
        }
        // Only the leader writes; followers idle until promotion. Both apply and
        // delete are idempotent against current cluster state, so a fresh leader
        // (or a leadership flap) needs no seeding — the next pass re-converges.
        if ctx.leader.load(Ordering::Acquire) {
            reconcile_shared_pool(&ctx).await;
        }
    }
}

/// One install-reconcile pass. Provisions the pool when it is enabled with a
/// selector (the chart couples the two); otherwise reclaims any previously
/// provisioned pool. Best-effort — a failure logs and the next tick retries.
async fn reconcile_shared_pool(ctx: &ReconcileContext) {
    if !ctx.shared_proxy.enabled || ctx.shared_proxy.selector.is_empty() {
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
