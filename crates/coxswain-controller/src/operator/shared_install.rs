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
use super::render_shared_proxy::{SharedProxyRenderInputs, render_shared_proxy};
use pingora_core::server::ShutdownWatch;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
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
            _ = interval.tick() => {}
        }
        // Only the leader writes; followers idle until promotion. Both apply and
        // delete are idempotent against current cluster state, so a fresh leader
        // (or a leadership flap) needs no seeding — the next pass re-converges.
        if became_leader || ctx.leader.load(Ordering::Acquire) {
            reconcile_shared_pool(&ctx).await;
        }
    }
}

/// Await the next leadership change, or park forever when leadership is unwired
/// (tests) so the `select!` arm never fires.
async fn leadership_changed(leadership: &mut Option<watch::Receiver<bool>>) {
    match leadership {
        Some(rx) => {
            // A closed sender (controller shutting down) ends the wait; the
            // shutdown arm handles teardown, so treat it as a benign no-op.
            let _ = rx.changed().await;
        }
        None => std::future::pending().await,
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
