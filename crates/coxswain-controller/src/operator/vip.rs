//! Serialized shared-mode per-Gateway VIP Service reconciler (#472).
//!
//! Owns every shared-mode Gateway's VIP `Service` from ONE serialized task so
//! the global internal-port allocation stays single-writer: each pass computes
//! one collision-free port map and applies it atomically. The allocation's
//! `existing` (reuse) input is read AUTHORITATIVELY from the apiserver — a
//! consistent LIST of the VIP Services, not the watch-lagged reflector store —
//! so the pass has read-your-own-writes semantics with no in-memory ledger:
//! `allocate_internal_ports` keeps every in-range existing assignment, so a
//! pass racing its own previous apply (or a freshly-promoted leader) can never
//! remap a live Gateway's internal port. Per-Gateway reconciles in
//! [`super::reconciler`] only *signal* this task via
//! [`super::ReconcileContext::vip_trigger`]; the periodic tick is a backstop.
//! Also honours GatewayStaticAddresses (#260) by pinning requested
//! `IPAddress`es as the VIP Service `spec.clusterIP`, and orphan-prunes VIP
//! Services whose owning Gateway is gone or has left shared mode.

use super::reconciler::{
    ReconcileContext, gateway_id, gateway_key, ignore_not_found, is_owned_shared_mode,
};
use super::{apply, render_shared};
use coxswain_core::crd::ServiceType;
use coxswain_core::ownership::ObjectKey;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use coxswain_reflector::port_alloc::{
    DEFAULT_INTERNAL_PORT_RANGE, ListenerKey, SHARED_GATEWAY_VIP_COMPONENT,
    allocate_internal_ports, read_vip_internal_ports,
};
use k8s_openapi::api::core::v1::{ObjectReference, Service};
use kube::{Api, Client, Resource as _, api::DeleteParams, api::ListParams};
use pingora_core::server::ShutdownWatch;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// A live Gateway's `listenerPort → internalPort` assignment changed between
/// passes — the allocation stability invariant was violated. With the
/// `existing` input read authoritatively from the apiserver (a consistent LIST,
/// not the watch-lagged store) the allocator keeps every in-range existing
/// assignment, so this is unreachable outside a genuine anomaly (an existing
/// `targetPort` out of range, or a duplicate). It is surfaced (WARN +
/// Kubernetes Event), never panicked — the operator must keep reconciling.
struct RemapViolation {
    /// Owning Gateway.
    gateway: ObjectKey,
    /// Advertised listener port whose internal mapping moved.
    listener_port: u16,
    /// Previously persisted internal port.
    old_internal: u16,
    /// Newly allocated internal port.
    new_internal: u16,
}

/// Backstop resync interval for the serialized VIP reconciler (#472). Events
/// make the common case prompt; this catches a Gateway missed on an
/// event-driven pass because a reflector store had not yet caught up.
const VIP_RESYNC_INTERVAL: Duration = Duration::from_secs(15);

/// The single serialized background task that owns every shared-mode per-Gateway
/// VIP Service (#472).
///
/// Running the whole-map reconcile from ONE task — never the concurrent
/// per-Gateway work-queue — is what makes the internal-port allocation safe:
/// each pass reads one consistent snapshot, computes one collision-free global
/// map, and applies it atomically, so no two reconciles can diverge and
/// double-book a port. Per-Gateway reconciles only *signal* this task via
/// [`ReconcileContext::vip_trigger`]; the periodic tick is a store-lag backstop.
pub(super) async fn run_vip_reconciler(ctx: Arc<ReconcileContext>, mut shutdown: ShutdownWatch) {
    if ctx.shared_proxy_selector.is_empty() {
        // Shared-mode per-Gateway addressing disabled (Ingress-only install).
        return;
    }
    let mut interval = tokio::time::interval(VIP_RESYNC_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = ctx.vip_trigger.notified() => {}
            _ = interval.tick() => {}
        }
        // Only the leader writes; followers idle until promotion. The
        // allocation is stateless across passes and leadership terms: each pass
        // reads the current internal-port assignments authoritatively from the
        // apiserver, so a fresh leader (or a leadership flap) needs no seeding
        // or reset — there is no in-memory state that could go stale.
        if ctx.leader.load(Ordering::Acquire) {
            reconcile_all_vips(&ctx).await;
        }
    }
}

/// One serialized whole-VIP reconcile pass (#472). Computes the global
/// internal-port allocation, SSA-applies every owned shared Gateway's VIP
/// Service, and prunes the VIP Service of any Gateway that has left shared mode.
///
/// Best-effort: a single Service apply/delete failure is logged and the pass
/// continues — the next tick retries from current cluster state. Because
/// `existing` is read authoritatively from the apiserver each pass, a failed
/// apply cannot shift the port landscape for anyone else: the retried pass sees
/// exactly the assignments that actually persisted.
async fn reconcile_all_vips(ctx: &ReconcileContext) {
    let gateways = ctx.gateways_store.state();
    let services = ctx.services_store.state();
    let classes = ctx.class_store.state();

    let is_shared =
        |g: &Gateway| is_owned_shared_mode(g, &classes, &ctx.params_store, &ctx.controller_name);

    // Effective listener ports per owned Gateway: its own listeners plus those
    // merged from attached ListenerSets (GEP-1713, #93). Drives BOTH the
    // internal-port allocation and the VIP Service ports below, so a ListenerSet
    // listener on a new port is allocated an internal port and exposed.
    let owned_classes: std::collections::HashSet<String> = classes
        .iter()
        .filter(|gc| gc.spec.controller_name == ctx.controller_name)
        .filter_map(|gc| gc.meta().name.clone())
        .collect();
    let listener_sets = ctx.listener_sets_store.state();
    let effective_ports = coxswain_reflector::effective_listener_ports(
        &gateways,
        &listener_sets,
        &owned_classes,
        &ctx.namespaces_store,
    );

    let desired =
        super::shared_alloc::desired_listener_keys(&gateways, &effective_ports, is_shared);
    // Read-your-own-writes without any in-memory state: read the current
    // `(Gateway, listenerPort) → internalPort` assignments authoritatively from
    // the apiserver (a consistent LIST of the VIP Services), NOT from the
    // watch-lagged Services store. A pass racing its own previous apply — or a
    // freshly-promoted leader racing a predecessor's writes — sees exactly what
    // persisted, so `allocate_internal_ports` (which keeps every in-range
    // existing assignment) can never force-SSA a new targetPort onto a live
    // Gateway's VIP Service. On a LIST failure we fall back to the store view:
    // a stale existing map degrades to the pre-existing behaviour (possible
    // transient remap) rather than blocking provisioning entirely.
    let existing = match list_persisted_internal_ports(ctx).await {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "operator: authoritative VIP-Service LIST failed; falling back to \
                 the (possibly stale) Services store for this pass"
            );
            super::shared_alloc::existing_internal_ports(&services)
        }
    };
    let allocation = allocate_internal_ports(&desired, &existing, DEFAULT_INTERNAL_PORT_RANGE);
    // Alarm on any live-Gateway remap. Structurally unreachable when `existing`
    // is authoritative (the allocator keeps in-range existing ports), so a
    // firing here means a genuine anomaly — a persisted targetPort outside the
    // range, or a duplicate — worth an operator-visible Event, not a silent
    // reallocation.
    for violation in detect_remaps(&existing, &allocation) {
        emit_remap_violation_event(ctx, &gateways, &violation).await;
    }

    // Apply each owned shared Gateway's VIP Service into the CONTROLLER namespace
    // (alongside the shared proxy pod) so its selector resolves and the cloud LB
    // assigns a real address (#472).
    let ctrl_ns = ctx.controller_namespace.as_str();
    // Gateways whose static-address VIP provisioning definitively failed this
    // pass (all requested clusterIPs rejected) — published so the status writer
    // reports a settled `AddressNotUsable` for them, while a Gateway still
    // mid-provisioning (absent here) is held `Pending` (#531/#533).
    let mut static_vip_failures: std::collections::HashSet<ObjectKey> =
        std::collections::HashSet::new();
    for gw in gateways.iter().filter(|g| is_shared(g)) {
        let key = gateway_key(gw);
        if allocation.is_gateway_exhausted(&key) {
            emit_port_exhaustion_event(&ctx.client, gw, &ctx.controller_name).await;
        }
        let internal_ports = allocation.for_gateway(&key);
        if internal_ports.is_empty() {
            continue;
        }
        let empty_ports = Vec::new();
        let gw_effective_ports = effective_ports.get(&key).unwrap_or(&empty_ports);
        // GatewayStaticAddresses (#260): honor requested static IPAddresses by
        // pinning one as the VIP Service `spec.clusterIP`. With several requested,
        // bind the first the apiserver accepts (see `bind_static_vip_service`) so a
        // usable address that follows an unusable one still binds — the conformance
        // ladder reads `status.addresses` from the multi-address window.
        let candidates = render_shared::requested_static_cluster_ips(gw);
        if !candidates.is_empty() {
            let svc_name = render_shared::shared_gateway_service_name(
                gw.metadata.namespace.as_deref().unwrap_or_default(),
                gw.metadata.name.as_deref().unwrap_or_default(),
            );
            // The keep-or-repin decision MUST read the LIVE Service, never the
            // watch store: the store lags this reconciler's own writes, so a
            // triggered pass arriving within the lag window would see the
            // pre-repin clusterIP, delete the just-correctly-pinned Service,
            // and recreate it — and since every delete/create fires more
            // Service events (→ more passes), the repin becomes a
            // self-sustaining delete/create loop. One GET per static-address
            // Gateway per pass; the dedicated repin has always read live for
            // the same reason.
            let svc_api: Api<Service> = Api::namespaced(ctx.client.clone(), ctrl_ns);
            let live_ip = match svc_api.get_opt(&svc_name).await {
                Ok(svc) => svc
                    .as_ref()
                    .and_then(|s| s.spec.as_ref())
                    .and_then(|sp| sp.cluster_ip.as_deref())
                    .and_then(|s| s.parse::<std::net::IpAddr>().ok()),
                Err(e) => {
                    tracing::warn!(
                        service = %format!("{ctrl_ns}/{svc_name}"),
                        error = %e,
                        "operator: live VIP Service read failed; deferring static bind to next pass"
                    );
                    continue;
                }
            };
            let failed = bind_static_vip_service(StaticVipBinding {
                ctx,
                gw,
                ctrl_ns,
                candidates: &candidates,
                effective_ports: gw_effective_ports,
                internal_ports: &internal_ports,
                live_ip,
            })
            .await;
            if failed {
                static_vip_failures.insert(key.clone());
            }
            continue;
        }
        // Auto-address (legacy/default) path: no static IP requested, so keep the
        // apiserver's auto-allocation and the configured VIP Service type.
        let service =
            render_shared::render_shared_gateway_service(&render_shared::SharedServiceInputs {
                gateway: gw,
                controller_namespace: ctrl_ns,
                shared_proxy_selector: &ctx.shared_proxy_selector,
                effective_ports: gw_effective_ports,
                internal_ports: &internal_ports,
                service_type: ctx.shared_vip_service_type,
                requested_cluster_ip: None,
            });
        if let Err(e) = apply::apply_shared_vip_service(&ctx.client, ctrl_ns, &service).await {
            log_vip_apply_failure(gw, &e, "Service");
        }
    }

    // Publish this pass's definitive static-VIP failures (full replace — a
    // Gateway that has since bound drops out of the set) so the status writer
    // can settle their `AddressNotUsable` while holding still-provisioning
    // Gateways at `Pending` (#531/#533).
    ctx.vip_failures.store(Arc::new(static_vip_failures));

    // Orphan-prune: the VIP Services live in the controller namespace and carry
    // NO owner reference (a cross-namespace owner ref to the Gateway is illegal),
    // so this serialized reconciler — the single writer over the synced Gateway
    // store — deletes any VIP Service whose owning Gateway no longer exists OR has
    // left shared mode (migrated to dedicated). Reading the full *synced* store
    // makes the "Gateway absent" verdict reliable, so there is no store-lag
    // false-positive (the hazard that applied only to the old per-Gateway path).
    let svc_api: Api<Service> = Api::namespaced(ctx.client.clone(), ctrl_ns);
    for svc in &services {
        if !vip_service_should_prune(svc, &gateways, is_shared) {
            continue;
        }
        let Some(name) = svc.metadata.name.as_deref() else {
            continue;
        };
        match ignore_not_found(svc_api.delete(name, &DeleteParams::default()).await) {
            Ok(()) => tracing::info!(
                service = %format!("{ctrl_ns}/{name}"),
                "operator: pruned orphan VIP Service (Gateway gone or no longer shared)"
            ),
            Err(e) => tracing::warn!(
                service = %format!("{ctrl_ns}/{name}"),
                error = %e,
                "operator: failed to prune VIP Service; will retry"
            ),
        }
    }
}

/// The `(Gateway, listenerPort) → internalPort` assignments currently persisted
/// in the VIP Services, read **authoritatively** from the apiserver (a
/// consistent LIST, not the watch-lagged reflector store) so the allocation
/// pass has read-your-own-writes semantics without any in-memory ledger.
///
/// Scoped by the [`SHARED_GATEWAY_VIP_COMPONENT`] label to the controller
/// namespace, so the result set is exactly the VIP Services and stays small.
///
/// # Errors
///
/// Returns the underlying `kube` error if the LIST fails; the caller falls back
/// to the store view for that pass.
async fn list_persisted_internal_ports(
    ctx: &ReconcileContext,
) -> Result<HashMap<ListenerKey, u16>, kube::Error> {
    let ctrl_ns = ctx.controller_namespace.as_str();
    let api: Api<Service> = Api::namespaced(ctx.client.clone(), ctrl_ns);
    let lp = ListParams::default().labels(&format!(
        "app.kubernetes.io/component={SHARED_GATEWAY_VIP_COMPONENT}"
    ));
    let list = api.list(&lp).await?;
    let services: Vec<Arc<Service>> = list.items.into_iter().map(Arc::new).collect();
    Ok(read_vip_internal_ports(&services))
}

/// Detect live-Gateway allocation remaps: a `(Gateway, listenerPort)` whose
/// authoritative `existing` internal port differs from the port just allocated.
/// With an authoritative `existing` this is structurally unreachable
/// (`allocate_internal_ports` keeps every in-range existing assignment), so any
/// result is a genuine anomaly the caller surfaces as a Warning Event.
fn detect_remaps(
    existing: &HashMap<ListenerKey, u16>,
    allocation: &coxswain_reflector::port_alloc::PortAllocation,
) -> Vec<RemapViolation> {
    let mut out = Vec::new();
    for (gw, listener_port, new_internal) in allocation.iter() {
        if let Some(&old_internal) = existing.get(&(gw.clone(), listener_port))
            && old_internal != new_internal
        {
            out.push(RemapViolation {
                gateway: gw.clone(),
                listener_port,
                old_internal,
                new_internal,
            });
        }
    }
    out
}

/// Parameters for [`bind_static_vip_service`], grouped to keep the call within
/// the project's argument-count budget.
struct StaticVipBinding<'a> {
    /// The whole-VIP reconcile context (client, shared-proxy selector, …).
    ctx: &'a ReconcileContext,
    /// The shared-mode Gateway whose VIP is being bound.
    gw: &'a Gateway,
    /// Controller namespace — where the VIP Service lives (#472).
    ctrl_ns: &'a str,
    /// Requested static `IPAddress` candidates, in `spec.addresses` order.
    candidates: &'a [std::net::IpAddr],
    /// Effective listener ports the VIP Service exposes.
    effective_ports: &'a [coxswain_reflector::EffectiveListenerPort],
    /// `listenerPort → internalPort` map for the rendered Service.
    internal_ports: &'a BTreeMap<u16, u16>,
    /// The live VIP Service's `spec.clusterIP`, if one exists.
    live_ip: Option<std::net::IpAddr>,
}

/// Bind a static-address Gateway's VIP Service to the first requested clusterIP
/// the apiserver accepts (GatewayStaticAddresses, #260).
///
/// `clusterIP` is immutable, so:
/// - if the live Service already holds a requested address, keep it (re-pinning
///   would needlessly churn) and SSA the rest idempotently;
/// - otherwise free any live Service whose clusterIP is not requested, then try
///   each candidate in order — an out-of-CIDR candidate's SSA is rejected
///   (creating nothing), so a usable address that follows an unusable one still
///   binds. The live clusterIP then *is* a requested address, which the status
///   writer matches to publish `status.addresses` and decide
///   `AddressNotUsable` vs `Programmed`.
///
/// If no candidate binds, no Service is left and the status writer reports
/// `AddressNotUsable` (out-of-range candidates) or holds `Pending` (transiently
/// unallocatable candidates); the next pass retries.
///
/// Returns `true` only when provisioning **definitively failed** — every
/// requested clusterIP candidate was rejected by the apiserver for a *permanent*
/// reason (out of the Service CIDR), so no VIP Service exists and the address is
/// genuinely unusable. The caller records this so the status writer settles
/// `AddressNotUsable` (#531/#533). A deferred retry — a pending repin delete, or
/// a candidate that is valid but momentarily **already allocated** — returns
/// `false` so the Gateway is held `Pending` and retried, never prematurely
/// settled `AddressNotUsable`.
///
/// clusterIP is immutable, so a repin is a delete + a *later-pass* recreate: the
/// delete and the recreate are split across passes (`return false` after the
/// delete) so the recreate never races the apiserver's ClusterIP allocator
/// releasing the just-deleted IP — the churn that surfaced as the flaky
/// `GatewayStaticAddresses` `AddressNotUsable` (#542).
async fn bind_static_vip_service(b: StaticVipBinding<'_>) -> bool {
    let svc_name = render_shared::shared_gateway_service_name(
        b.gw.metadata.namespace.as_deref().unwrap_or_default(),
        b.gw.metadata.name.as_deref().unwrap_or_default(),
    );

    if let Some(ip) = b.live_ip {
        if b.candidates.contains(&ip) {
            // Already bound to a requested address — keep the immutable clusterIP.
            if let Err(e) = apply_static_vip_candidate(&b, ip).await {
                log_vip_apply_failure(b.gw, &e, "Service");
            }
            return false;
        }
        // Live clusterIP is not requested (auto-assigned, or a stale pin from a
        // prior spec) — free it so a requested candidate can bind. The recreate
        // is DEFERRED to a later pass: recreating in this same pass would race
        // the apiserver releasing the just-deleted clusterIP and be rejected
        // `provided IP is already allocated`, a self-sustaining delete/recreate
        // churn (#542). One Service mutation per pass; the next pass finds no
        // Service and binds a candidate against a settled allocator.
        let svc_api: Api<Service> = Api::namespaced(b.ctx.client.clone(), b.ctrl_ns);
        match ignore_not_found(svc_api.delete(&svc_name, &DeleteParams::default()).await) {
            Ok(()) => tracing::info!(
                service = %format!("{}/{svc_name}", b.ctrl_ns),
                "operator: deleted VIP Service to repin requested clusterIP; recreate deferred to next pass (#260, #542)"
            ),
            Err(e) => tracing::warn!(
                service = %format!("{}/{svc_name}", b.ctrl_ns),
                error = %e,
                "operator: failed to delete VIP Service for clusterIP repin; will retry"
            ),
        }
        // Deferred (not a definitive failure): hold `Pending`, retry next pass.
        return false;
    }

    // No live Service: try each requested candidate. Distinguish a *permanent*
    // rejection (out of the Service CIDR → the address is genuinely unusable)
    // from a *transient* one (`already allocated` → the IP is valid but a prior
    // incarnation's allocation has not been released yet, so retry next pass).
    let mut any_transient = false;
    for &cand in b.candidates {
        match apply_static_vip_candidate(&b, cand).await {
            Ok(()) => return false,
            Err(e) => {
                if apply_error_is_transient(&e) {
                    any_transient = true;
                }
                tracing::debug!(
                    service = %format!("{}/{svc_name}", b.ctrl_ns),
                    candidate = %cand,
                    error = %e,
                    transient = apply_error_is_transient(&e),
                    "operator: requested clusterIP not bound; trying next (#260, #542)"
                );
            }
        }
    }
    // A transient rejection means a candidate is valid but momentarily
    // unallocatable — defer (hold `Pending`, retry) rather than settle
    // `AddressNotUsable`. Only an all-permanent-rejection set is a definitive
    // failure.
    !any_transient
}

/// Whether an SSA apply rejection is a **transient** ClusterIP-allocation
/// conflict. Extracts the apiserver `Status` code + message from the boxed
/// `kube::Error::Api` and delegates to [`is_transient_alloc_rejection`].
fn apply_error_is_transient(e: &apply::ApplyError) -> bool {
    let apply::ApplyError::Service(kube::Error::Api(status)) = e else {
        return false;
    };
    is_transient_alloc_rejection(status.code, &status.message)
}

/// Classify a Service SSA rejection: `true` for the transient ClusterIP-allocator
/// conflict — the apiserver's `provided IP is already allocated` (a prior Service
/// incarnation holds the valid IP but will release it → retry) — and `false` for
/// a permanent rejection like an out-of-CIDR address (`the provided network does
/// not match the current range` → the address is genuinely unusable). Keyed on
/// the `Invalid` (422) status message: the IP-allocator errors carry no dedicated
/// `reason`/cause code, so the message substring is the only available signal;
/// these allocator strings are stable across Kubernetes releases.
fn is_transient_alloc_rejection(code: u16, message: &str) -> bool {
    code == 422 && message.contains("already allocated")
}

/// Render and SSA the static-address Gateway's VIP Service with `cluster_ip`
/// pinned (always ClusterIP-typed so the resolved address IS the requested IP,
/// independent of the global VIP type). Returns the apiserver's verdict so the
/// caller can fall through to the next candidate on rejection (#260).
async fn apply_static_vip_candidate(
    b: &StaticVipBinding<'_>,
    cluster_ip: std::net::IpAddr,
) -> Result<(), apply::ApplyError> {
    let service =
        render_shared::render_shared_gateway_service(&render_shared::SharedServiceInputs {
            gateway: b.gw,
            controller_namespace: b.ctrl_ns,
            shared_proxy_selector: &b.ctx.shared_proxy_selector,
            effective_ports: b.effective_ports,
            internal_ports: b.internal_ports,
            service_type: ServiceType::ClusterIp,
            requested_cluster_ip: Some(cluster_ip),
        });
    apply::apply_shared_vip_service(&b.ctx.client, b.ctrl_ns, &service).await
}

/// Log a VIP Service apply failure. A `NamespaceTerminating` 403 (mid-deletion)
/// is expected and self-heals, so it is logged at debug to avoid a retry-spam of
/// warnings; everything else warns and is retried next pass.
fn log_vip_apply_failure(gw: &Gateway, err: &apply::ApplyError, kind: &str) {
    if err.to_string().contains("being terminated") {
        tracing::debug!(
            gateway = %gateway_id(gw),
            kind,
            "operator: VIP apply skipped — namespace is terminating"
        );
    } else {
        tracing::warn!(
            gateway = %gateway_id(gw),
            error = %err,
            kind,
            "operator: failed to apply shared-mode VIP resource; will retry"
        );
    }
}

/// Delete a dedicated-proxy Service whose live `spec.clusterIP` diverges from the
/// rendered (requested) one (GatewayStaticAddresses, #260). `clusterIP` is
/// immutable, so the subsequent SSA apply would be rejected without this. Pure
/// no-op when the rendered Service pins no clusterIP (the common case) or no live
/// Service exists yet. Best-effort: any API error is logged and retried next
/// reconcile.
pub(super) async fn repin_dedicated_clusterip_if_diverged(
    client: &kube::Client,
    gw: &Gateway,
    rendered_service: &Service,
) {
    let Some(desired) = rendered_service
        .spec
        .as_ref()
        .and_then(|s| s.cluster_ip.as_deref())
    else {
        return;
    };
    let (Some(name), Some(ns)) = (
        rendered_service.metadata.name.as_deref(),
        gw.metadata.namespace.as_deref(),
    ) else {
        return;
    };
    let api: Api<Service> = Api::namespaced(client.clone(), ns);
    let live_ip = match api.get_opt(name).await {
        Ok(Some(live)) => live
            .spec
            .as_ref()
            .and_then(|s| s.cluster_ip.clone())
            .filter(|ip| !ip.is_empty() && ip != "None"),
        Ok(None) => return,
        Err(e) => {
            tracing::debug!(
                gateway = %gateway_id(gw),
                error = %e,
                "operator: dedicated Service clusterIP lookup failed; apply will retry"
            );
            return;
        }
    };
    if live_ip.as_deref() == Some(desired) {
        return;
    }
    match ignore_not_found(api.delete(name, &DeleteParams::default()).await) {
        Ok(()) => tracing::info!(
            service = %format!("{ns}/{name}"),
            desired_cluster_ip = desired,
            "operator: deleting dedicated Service to repin requested clusterIP (#260)"
        ),
        Err(e) => tracing::warn!(
            service = %format!("{ns}/{name}"),
            error = %e,
            "operator: failed to delete dedicated Service for clusterIP repin; will retry"
        ),
    }
}

/// Whether `svc` is an orphan shared-mode VIP Service to delete (#472): one whose
/// owning Gateway (recorded in its `gateway-name`/`gateway-namespace` labels) no
/// longer exists, or exists but has left shared mode (migrated to dedicated).
/// Returns false for non-VIP Services. Safe to prune on "absent" because the
/// caller reads the *synced* Gateway store as the single writer — there is no
/// owner-ref GC for these (the Service lives out-of-namespace), so this is the
/// only path that reclaims them.
fn vip_service_should_prune(
    svc: &Service,
    gateways: &[Arc<Gateway>],
    is_shared: impl Fn(&Gateway) -> bool,
) -> bool {
    let labels = match svc.metadata.labels.as_ref() {
        Some(l) => l,
        None => return false,
    };
    // Only our shared-VIP Services are candidates.
    if labels
        .get("app.kubernetes.io/component")
        .map(String::as_str)
        != Some(coxswain_reflector::port_alloc::SHARED_GATEWAY_VIP_COMPONENT)
    {
        return false;
    }
    let (Some(gw_ns), Some(gw_name)) = (
        labels.get(coxswain_reflector::port_alloc::VIP_GATEWAY_NAMESPACE_LABEL),
        labels.get(coxswain_reflector::port_alloc::VIP_GATEWAY_NAME_LABEL),
    ) else {
        return false;
    };
    match gateways.iter().find(|g| {
        g.metadata.namespace.as_deref() == Some(gw_ns.as_str())
            && g.metadata.name.as_deref() == Some(gw_name.as_str())
    }) {
        Some(gw) => !is_shared(gw), // exists but migrated out of shared mode → prune
        None => true,               // Gateway gone (no GC for an out-of-ns Service) → prune
    }
}

/// Alarm on a violation of the allocation stability invariant (see
/// `vip_ledger`): a live Gateway's `listenerPort → internalPort` mapping moved
/// between passes. With the ledger feeding the allocator this must never fire;
/// if it does, kube-proxy's NAT was remapped while the proxy may still be bound
/// to the old port — connections die before the proxy, so make it loud (WARN +
/// Warning Event) instead of letting it pass as a routine apply. Best-effort:
/// a publish failure is logged, never propagated.
async fn emit_remap_violation_event(
    ctx: &ReconcileContext,
    gateways: &[Arc<Gateway>],
    violation: &RemapViolation,
) {
    use kube::runtime::events::{Event, EventType, Recorder, Reporter};

    tracing::warn!(
        gateway = %violation.gateway,
        listener_port = violation.listener_port,
        old_internal = violation.old_internal,
        new_internal = violation.new_internal,
        "operator: internal-port allocation REMAPPED a live Gateway's listener — \
         stability invariant violated; traffic to the old targetPort will fail \
         until the proxy rebinds"
    );
    let Some(gw) = gateways
        .iter()
        .find(|g| gateway_key(g) == violation.gateway)
    else {
        return;
    };
    let reference = ObjectReference {
        api_version: Some("gateway.networking.k8s.io/v1".into()),
        kind: Some("Gateway".into()),
        name: gw.metadata.name.clone(),
        namespace: gw.metadata.namespace.clone(),
        uid: gw.metadata.uid.clone(),
        ..Default::default()
    };
    let reporter = Reporter {
        controller: ctx.controller_name.to_string(),
        instance: None,
    };
    let recorder = Recorder::new(ctx.client.clone(), reporter);
    if let Err(e) = recorder
        .publish(
            &Event {
                action: "AllocateInternalPort".into(),
                reason: "InternalPortRemapped".into(),
                note: Some(format!(
                    "listener {} internal port moved {} -> {} while the Gateway is live",
                    violation.listener_port, violation.old_internal, violation.new_internal
                )),
                type_: EventType::Warning,
                secondary: None,
            },
            &reference,
        )
        .await
    {
        tracing::warn!(error = %e, "Failed to publish InternalPortRemapped Event");
    }
}

/// Emit a `Warning` Event on the Gateway when the internal target-port range is
/// exhausted (#472). Controller is the sole diagnostic emitter; the unallocated
/// listeners simply get no VIP port. Best-effort — a publish failure is logged,
/// never propagated (it must not block provisioning of the ports that DID fit).
async fn emit_port_exhaustion_event(client: &Client, gw: &Gateway, controller_name: &str) {
    use kube::runtime::events::{Event, EventType, Recorder, Reporter};

    tracing::warn!(
        gateway = %gateway_id(gw),
        "operator: internal target-port range (30000-32767) exhausted; \
         some shared-mode listeners have no VIP port and will not be addressed"
    );
    let reference = ObjectReference {
        api_version: Some("gateway.networking.k8s.io/v1".into()),
        kind: Some("Gateway".into()),
        name: gw.metadata.name.clone(),
        namespace: gw.metadata.namespace.clone(),
        uid: gw.metadata.uid.clone(),
        ..Default::default()
    };
    let reporter = Reporter {
        controller: controller_name.to_string(),
        instance: None,
    };
    let recorder = Recorder::new(client.clone(), reporter);
    if let Err(e) = recorder
        .publish(
            &Event {
                action: "AllocateInternalPort".into(),
                reason: "NoInternalPortAvailable".into(),
                note: Some(
                    "Internal target-port range exhausted; some listeners have no VIP port".into(),
                ),
                type_: EventType::Warning,
                secondary: None,
            },
            &reference,
        )
        .await
    {
        tracing::warn!(error = %e, "Failed to publish NoInternalPortAvailable Event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gw_named(ns: &str, name: &str) -> Arc<Gateway> {
        use coxswain_reflector::gw_types::v::gateways::GatewaySpec;
        Arc::new(Gateway {
            metadata: kube::api::ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "coxswain".into(),
                listeners: vec![],
                ..Default::default()
            },
            status: None,
        })
    }

    /// A VIP Service for Gateway `gw_ns/gw_name` — it lives in the controller
    /// namespace and records the owning Gateway via labels (#472).
    fn vip_svc(gw_ns: &str, gw_name: &str) -> Service {
        use coxswain_reflector::port_alloc::{
            SHARED_GATEWAY_VIP_COMPONENT, VIP_GATEWAY_NAME_LABEL, VIP_GATEWAY_NAMESPACE_LABEL,
        };
        let mut labels = BTreeMap::new();
        labels.insert(
            "app.kubernetes.io/component".into(),
            SHARED_GATEWAY_VIP_COMPONENT.into(),
        );
        labels.insert(VIP_GATEWAY_NAME_LABEL.into(), gw_name.into());
        labels.insert(VIP_GATEWAY_NAMESPACE_LABEL.into(), gw_ns.into());
        Service {
            metadata: kube::api::ObjectMeta {
                namespace: Some("coxswain-system".into()),
                name: Some(format!("{gw_ns}-{gw_name}-shared-gw")),
                labels: Some(labels),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn prune_targets_migrated_and_deleted_gateways() {
        let gateways = vec![gw_named("default", "shared"), gw_named("default", "dedi")];
        let is_shared = |g: &Gateway| g.metadata.name.as_deref() == Some("shared");

        // Exists but migrated out of shared mode → prune.
        assert!(
            vip_service_should_prune(&vip_svc("default", "dedi"), &gateways, is_shared),
            "VIP Service of a Gateway that left shared mode is pruned"
        );
        // Gateway gone entirely → prune (no owner-ref GC for an out-of-ns Service;
        // the single-writer reconciler over the synced store is the only reclaimer).
        assert!(
            vip_service_should_prune(&vip_svc("default", "ghost"), &gateways, is_shared),
            "VIP Service whose Gateway no longer exists is pruned"
        );
        // Still shared → kept.
        assert!(
            !vip_service_should_prune(&vip_svc("default", "shared"), &gateways, is_shared),
            "VIP Service of a still-shared Gateway is kept"
        );
    }

    #[test]
    fn prune_ignores_non_vip_services() {
        let gateways = vec![gw_named("default", "shared")];
        let is_shared = |_: &Gateway| true;
        // A Service without our component label is never our concern.
        let foreign = Service {
            metadata: kube::api::ObjectMeta {
                namespace: Some("coxswain-system".into()),
                name: Some("other".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!vip_service_should_prune(&foreign, &gateways, is_shared));
    }

    #[test]
    fn already_allocated_is_transient_out_of_range_is_definitive() {
        // "provided IP is already allocated" — a prior Service incarnation still
        // holds the (valid) IP; retriable, must NOT settle AddressNotUsable.
        assert!(is_transient_alloc_rejection(
            422,
            "Service \"gw-shared-gw\" is invalid: spec.clusterIPs: Invalid value: \
             [\"10.96.0.42\"]: failed to allocate IP 10.96.0.42: provided IP is already allocated"
        ));
        // Out of the Service CIDR — the address is genuinely unusable; definitive.
        assert!(!is_transient_alloc_rejection(
            422,
            "Service \"gw-shared-gw\" is invalid: spec.clusterIPs: Invalid value: \
             [\"192.0.2.1\"]: failed to allocate IP 192.0.2.1: the provided network \
             does not match the current range"
        ));
        // A non-422 status is never treated as a transient repin.
        assert!(!is_transient_alloc_rejection(409, "already allocated"));
    }
}
