//! Serialized relay control-loop reconciler (#602).
//!
//! The dedicated relay tier is provisioned by a control loop — HPA-style sizing +
//! KEDA-style activation/cooldown — driven by each namespace's **live
//! dedicated-proxy subscriber count** read off the node registry. That signal
//! jitters and the cooldown/stabilization windows expire on *time*, not on a
//! Kubernetes event, so this cannot ride the per-Gateway reconcile. Instead a
//! single serialized task (the third of the operator's whole-world single-writer
//! passes, next to [`super::run_vip_reconciler`] and
//! [`super::run_shared_install_reconciler`]) advances every candidate namespace's
//! [`RelayNsState`] machine each pass. The pure decision logic lives in
//! [`super::relay_autoscaler`]; this module is the I/O around it.
//!
//! ## Make-before-break
//!
//! A relay is created and authorized to subscribe upstream (via the
//! `provisioned_relays` authz set) *before* leaves repoint onto it (via the
//! `active_relays` repoint set), and leaves repoint *away* before it is deleted.
//! Both sets are derived from [`ReconcileContext::relay_states`] at the end of each
//! pass by [`ReconcileContext::publish_relay_sets`]; a delete never coincides with
//! its repoint-removal in the same pass (teardown is `Active → Draining → delete`
//! across ≥2 passes), so the ordering invariant holds.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Service, ServiceAccount};
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use kube::{Api, Client, Resource as _, api::DeleteParams};
use pingora_core::server::ShutdownWatch;
use tokio::sync::watch;

use coxswain_reflector::gw_types::v::gateways::Gateway;

use super::reconciler::{ReconcileContext, ignore_not_found, namespace_is_terminating};
use super::relay_autoscaler::{
    RelayAction, RelayInputs, RelayNsRecord, RelayNsState, RelayTuning, initial_size,
    should_provision,
};
use super::relay_params::EffectiveRelayPolicy;
use super::render_relay::{self, RelayRenderInputs, RelayVariant};
use super::{apply, params};

/// Resync backstop cadence. The registry watch is the prompt driver (a leaf
/// connect/disconnect shifts the signal); this bounds staleness and, crucially,
/// fires the **time-based** transitions — the deactivation cooldown and the
/// scale-down stabilization window expire with no cluster event to wake the loop.
/// Well below both default windows (300s) so a cooldown boundary is never missed
/// by more than one tick.
const RELAY_RESYNC_INTERVAL: Duration = Duration::from_secs(10);

/// The single serialized task that owns the dedicated relay tier (#602).
///
/// Runs regardless of `--relay-enabled` (#616) — like
/// [`super::run_shared_install_reconciler`], the master switch gates
/// **provisioning**, never **convergence**: a namespace relay left over from before
/// the tier was disabled must still be advanced by this loop, whose force-off
/// teardown (see [`process_namespace`]) then GCs it. Skipping the loop when
/// disabled would strand that Deployment forever (it would never even be tracked —
/// see [`super::reconciler::ReconcileContext::rehydrate_provisioned_relays`]).
///
/// Each leader-gated pass advances every candidate namespace's control-loop state
/// machine off the live registry signal. `registry` (from `node_registry.subscribe()`)
/// is the prompt driver; `leadership` provisions promptly on the promotion edge; the
/// resync interval fires the time-based transitions. Shutdown wins (biased).
pub(crate) async fn run_relay_reconciler(
    ctx: Arc<ReconcileContext>,
    mut shutdown: ShutdownWatch,
    mut leadership: Option<watch::Receiver<bool>>,
) {
    let mut registry = ctx.node_registry.as_ref().map(|r| r.subscribe());
    let mut interval = tokio::time::interval(RELAY_RESYNC_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let mut became_leader = false;
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = leadership_changed(&mut leadership) => {
                became_leader = leadership.as_ref().is_some_and(|rx| *rx.borrow());
            }
            _ = registry_changed(&mut registry) => {}
            _ = interval.tick() => {}
        }
        if became_leader || ctx.leader.load(Ordering::Acquire) {
            relay_pass(&ctx).await;
        }
    }
}

/// Await the next leadership change, or park forever when leadership is unwired
/// (tests) so the `select!` arm never fires.
async fn leadership_changed(leadership: &mut Option<watch::Receiver<bool>>) {
    match leadership {
        Some(rx) => {
            let _ = rx.changed().await;
        }
        None => std::future::pending().await,
    }
}

/// Await the next node-registry membership change, or park forever when the
/// registry is unwired (tests).
async fn registry_changed(registry: &mut Option<watch::Receiver<u64>>) {
    match registry {
        Some(rx) => {
            let _ = rx.changed().await;
        }
        None => std::future::pending().await,
    }
}

/// One control-loop pass: advance every candidate namespace's state machine off the
/// live registry signal, then publish the two derived relay sets once.
async fn relay_pass(ctx: &Arc<ReconcileContext>) {
    // Single timestamp for the whole pass — the cooldown/stabilization windows are
    // O(minutes), so a pass's worth of skew is irrelevant and one clock read keeps
    // the transitions deterministic within the pass.
    let now = Instant::now();
    // Namespaces that currently hold ≥1 owned active dedicated Gateway — a stable
    // spec fact that distinguishes "genuinely drained" (tear down at once) from a
    // transient 0 live subscribers (relay restart / reconnect → hold, cooldown).
    let gateway_namespaces = namespaces_with_dedicated_gateways(ctx);
    // Evaluate the union of Gateway-holding namespaces and already-tracked ones (so a
    // namespace that lost its last Gateway is still driven through teardown).
    let mut namespaces: BTreeSet<String> = gateway_namespaces.clone();
    namespaces.extend(ctx.relay_states.lock().keys().cloned());
    for namespace in namespaces {
        let has_dedicated_gateways = gateway_namespaces.contains(&namespace);
        process_namespace(ctx, &namespace, has_dedicated_gateways, now).await;
    }
    ctx.publish_relay_sets();
}

/// The namespaces holding ≥1 owned, non-terminating, active dedicated Gateway (the
/// relay candidates), by the same class-match + `params::resolve` decision the
/// per-Gateway reconcile makes.
fn namespaces_with_dedicated_gateways(ctx: &ReconcileContext) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for gw in ctx.gateways_store.state().iter() {
        if let Some(namespace) = gw.metadata.namespace.as_deref()
            && is_owned_active_dedicated(ctx, gw)
        {
            set.insert(namespace.to_owned());
        }
    }
    set
}

/// Whether `gw` is an owned, non-terminating, dedicated-mode Gateway — the same
/// class-match + `params::resolve` decision the per-Gateway reconcile makes, read
/// only for candidate enumeration.
fn is_owned_active_dedicated(ctx: &ReconcileContext, gw: &Gateway) -> bool {
    if gw.metadata.deletion_timestamp.is_some() {
        return false;
    }
    let class_name = &gw.spec.gateway_class_name;
    let Some(class) = ctx
        .class_store
        .state()
        .into_iter()
        .find(|gc| gc.meta().name.as_deref() == Some(class_name.as_str()))
    else {
        return false;
    };
    if class.spec.controller_name != ctx.controller_name {
        return false;
    }
    matches!(
        params::resolve(gw, &class, |r: &params::ParamsRef| {
            ctx.params_store
                .state()
                .iter()
                .find(|p| {
                    p.meta().namespace.as_deref() == Some(r.namespace.as_str())
                        && p.meta().name.as_deref() == Some(r.name.as_str())
                })
                .map(|p| p.spec.clone())
        }),
        Ok(Some(_))
    )
}

/// Advance one namespace's relay state machine and perform the decided I/O.
async fn process_namespace(
    ctx: &Arc<ReconcileContext>,
    namespace: &str,
    has_dedicated_gateways: bool,
    now: Instant,
) {
    // An SSA/delete into a terminating namespace is doomed (403) and its relay GCs
    // with the namespace regardless — skip to avoid warn-log churn.
    if namespace_is_terminating(&ctx.namespaces_store, namespace) {
        return;
    }
    let mut policy = ctx.resolve_relay_policy(namespace);
    // The master switch overrides even a per-namespace `enabled: true` policy — a
    // disabled tier force-tears-down everything via the same KEDA force-off path a
    // namespace's own `enabled: false` uses (mirrors `shared_relay_tuning` in
    // `shared_install.rs`). Without this, `enabled_override` stays `None` here
    // (no per-namespace policy) and `should_deactivate` never force-triggers (#616).
    if !ctx.relay_enabled {
        policy.enabled = Some(false);
    }
    let tuning = RelayTuning::resolve(&policy, ctx.relay_tuning_defaults());
    let (signal, ready, subscribers) = registry_signal(ctx, namespace);
    let inputs = RelayInputs {
        signal,
        ready,
        subscribers,
        has_dedicated_gateways,
    };

    let existing = ctx.relay_states.lock().get(namespace).cloned();
    match existing {
        None => {
            if !should_provision(signal, &tuning) {
                return;
            }
            let (replicas, pdb_ceiling) = initial_size(signal, &tuning);
            if let Err(e) = apply_relay_at(ctx, namespace, &policy, replicas, pdb_ceiling).await {
                tracing::warn!(
                    namespace = %namespace,
                    error = %e,
                    "relay: provision apply failed; retrying next pass"
                );
                return;
            }
            let mut record = RelayNsRecord::existing(RelayNsState::Provisioning, replicas);
            record.observe(now, signal, &tuning);
            ctx.relay_states.lock().insert(namespace.to_owned(), record);
            tracing::info!(namespace = %namespace, replicas, "relay: provisioned (awaiting Ready)");
        }
        Some(mut record) => {
            record.observe(now, signal, &tuning);
            let decision = record.decide(now, inputs, &tuning);
            match decision.action {
                RelayAction::None => commit(ctx, namespace, record, decision.next_state, None),
                RelayAction::Activate => {
                    tracing::info!(namespace = %namespace, "relay: Ready — repointing leaves onto it");
                    commit(ctx, namespace, record, decision.next_state, None);
                }
                RelayAction::Resize {
                    replicas,
                    pdb_ceiling,
                } => {
                    if let Err(e) =
                        apply_relay_at(ctx, namespace, &policy, replicas, pdb_ceiling).await
                    {
                        tracing::warn!(
                            namespace = %namespace,
                            error = %e,
                            "relay: resize apply failed; retrying next pass"
                        );
                        return;
                    }
                    tracing::info!(namespace = %namespace, replicas, "relay: resized to live demand");
                    commit(ctx, namespace, record, decision.next_state, Some(replicas));
                }
                RelayAction::StartDrain => {
                    tracing::info!(
                        namespace = %namespace,
                        "relay: below break-even past cooldown — repointing leaves back to the controller, then draining"
                    );
                    commit(ctx, namespace, record, decision.next_state, None);
                }
                RelayAction::Delete => {
                    if let Err(e) =
                        delete_relay_resources(&ctx.client, namespace, render_relay::RELAY_NAME)
                            .await
                    {
                        tracing::warn!(
                            namespace = %namespace,
                            error = %e,
                            "relay: teardown delete failed; retrying next pass"
                        );
                        return;
                    }
                    ctx.relay_states.lock().remove(namespace);
                    tracing::info!(namespace = %namespace, "relay: drained (0 subscribers) — deleted");
                }
            }
        }
    }
}

/// Commit a transitioned record back to the state map: set its state and, when the
/// action resized the Deployment, its sizing baseline.
fn commit(
    ctx: &ReconcileContext,
    namespace: &str,
    mut record: RelayNsRecord,
    next_state: RelayNsState,
    replicas: Option<u32>,
) {
    record.state = next_state;
    if let Some(r) = replicas {
        record.current_replicas = r;
    }
    ctx.relay_states.lock().insert(namespace.to_owned(), record);
}

/// Read the namespace's `(signal, relay_ready, subscriber_count)` off the node
/// registry. Without a registry (unit contexts) the signal is 0, so nothing is
/// ever provisioned.
fn registry_signal(ctx: &ReconcileContext, namespace: &str) -> (u32, bool, u32) {
    let Some(registry) = &ctx.node_registry else {
        return (0, false, 0);
    };
    let snapshot = registry.load();
    (
        clamp_usize(snapshot.namespace_leaf_count(namespace)),
        snapshot.relay_ready(namespace),
        clamp_usize(snapshot.relay_subscriber_count(namespace)),
    )
}

/// Render and server-side-apply the namespace relay at `replicas`/`pdb_ceiling`,
/// applying the `CoxswainRelayPolicy` resource/pod-template overrides.
async fn apply_relay_at(
    ctx: &ReconcileContext,
    namespace: &str,
    policy: &EffectiveRelayPolicy,
    replicas: u32,
    pdb_ceiling: u32,
) -> Result<(), apply::ApplyError> {
    let resources = policy.resources.clone().or_else(|| {
        render_relay::relay_resources(
            &ctx.relay_cpu_request,
            &ctx.relay_memory_request,
            &ctx.relay_memory_limit,
        )
    });
    let rendered = render_relay::render_relay(&RelayRenderInputs {
        variant: RelayVariant::Namespace { namespace },
        replicas: clamp_u32_to_i32(replicas),
        controller_image: &ctx.controller_image,
        discovery_bootstrap_endpoint: &ctx.discovery_bootstrap_endpoint,
        discovery_sa_token_path: &ctx.discovery_sa_token_path,
        discovery_ca_bundle_path: &ctx.discovery_ca_bundle_path,
        discovery_trust_domain: &ctx.discovery_trust_domain,
        resources,
        pod_template: policy.pod_template.as_ref(),
        pdb_replica_ceiling: clamp_u32_to_i32(pdb_ceiling),
    });
    apply::apply_relay(&ctx.client, namespace, &rendered).await
}

/// Idempotently delete a relay's `Deployment` / `Service` / `ServiceAccount` /
/// `PodDisruptionBudget` (all share `name` — [`render_relay::RELAY_NAME`] for the
/// dedicated tier, [`render_relay::SHARED_RELAY_NAME`] for the shared pool). A relay
/// has no owner reference, so GC is this explicit delete; a `NotFound` is success.
/// `pub(super)` so the shared-relay convergence in [`super::shared_install`] reuses
/// the same teardown.
///
/// # Errors
///
/// Returns the underlying [`kube::Error`] for any delete that fails for a reason
/// other than `NotFound`.
pub(super) async fn delete_relay_resources(
    client: &Client,
    namespace: &str,
    name: &str,
) -> Result<(), kube::Error> {
    let dp = DeleteParams::default();
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let services: Api<Service> = Api::namespaced(client.clone(), namespace);
    let service_accounts: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
    // The PDB is optional (rendered only at ceiling ≥2); delete it unconditionally so GC is
    // complete whether or not one was ever provisioned (NotFound is success).
    let pdbs: Api<PodDisruptionBudget> = Api::namespaced(client.clone(), namespace);
    ignore_not_found(deployments.delete(name, &dp).await)?;
    ignore_not_found(services.delete(name, &dp).await)?;
    ignore_not_found(service_accounts.delete(name, &dp).await)?;
    ignore_not_found(pdbs.delete(name, &dp).await)?;
    Ok(())
}

/// Saturating `usize → u32` for a registry count (a count above `u32::MAX` is
/// nonsensical but must never wrap or panic). `pub(super)` so the shared-relay
/// convergence reuses the same saturation.
pub(super) fn clamp_usize(v: usize) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// Saturating `u32 → i32` for a replica count (a count above `i32::MAX` is
/// nonsensical but must never wrap or panic). `pub(super)` for the shared-relay
/// convergence.
pub(super) fn clamp_u32_to_i32(v: u32) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}
