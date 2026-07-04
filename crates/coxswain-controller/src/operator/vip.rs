//! Serialized shared-mode per-Gateway VIP Service reconciler (#472).
//!
//! Owns every shared-mode Gateway's VIP `Service` from ONE serialized task so
//! the global internal-port allocation stays single-writer: each pass reads a
//! consistent snapshot, computes one collision-free port map, and applies it
//! atomically. Per-Gateway reconciles in [`super::reconciler`] only *signal*
//! this task via [`super::ReconcileContext::vip_trigger`]; the periodic tick is
//! a store-lag backstop. Also honours GatewayStaticAddresses (#260) by pinning
//! requested `IPAddress`es as the VIP Service `spec.clusterIP`, and orphan-prunes
//! VIP Services whose owning Gateway is gone or has left shared mode.

use super::reconciler::{
    ReconcileContext, gateway_id, gateway_key, ignore_not_found, is_owned_shared_mode,
};
use super::{apply, render_shared};
use coxswain_core::crd::ServiceType;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use coxswain_reflector::port_alloc::{DEFAULT_INTERNAL_PORT_RANGE, allocate_internal_ports};
use k8s_openapi::api::core::v1::{ObjectReference, Service};
use kube::{Api, Client, Resource as _, api::DeleteParams};
use pingora_core::server::ShutdownWatch;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

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
        // Only the leader writes; followers idle until promotion.
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
/// continues — the next tick retries from current cluster state.
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
    let existing = super::shared_alloc::existing_internal_ports(&services);
    let allocation = allocate_internal_ports(&desired, &existing, DEFAULT_INTERNAL_PORT_RANGE);

    // Apply each owned shared Gateway's VIP Service into the CONTROLLER namespace
    // (alongside the shared proxy pod) so its selector resolves and the cloud LB
    // assigns a real address (#472).
    let ctrl_ns = ctx.controller_namespace.as_str();
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
            let live_ip = services
                .iter()
                .find(|s| s.metadata.name.as_deref() == Some(svc_name.as_str()))
                .and_then(|s| s.spec.as_ref())
                .and_then(|sp| sp.cluster_ip.as_deref())
                .and_then(|s| s.parse::<std::net::IpAddr>().ok());
            bind_static_vip_service(StaticVipBinding {
                ctx,
                gw,
                ctrl_ns,
                candidates: &candidates,
                effective_ports: gw_effective_ports,
                internal_ports: &internal_ports,
                live_ip,
            })
            .await;
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
/// If no candidate binds (all out-of-CIDR), no Service is left and the status
/// writer reports `AddressNotUsable`; the next pass retries.
async fn bind_static_vip_service(b: StaticVipBinding<'_>) {
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
            return;
        }
        // Live clusterIP is not requested (auto-assigned, or a stale pin from a
        // prior spec) — free it so a requested candidate can bind.
        let svc_api: Api<Service> = Api::namespaced(b.ctx.client.clone(), b.ctrl_ns);
        match ignore_not_found(svc_api.delete(&svc_name, &DeleteParams::default()).await) {
            Ok(()) => tracing::info!(
                service = %format!("{}/{svc_name}", b.ctrl_ns),
                "operator: deleting VIP Service to repin requested clusterIP (#260)"
            ),
            Err(e) => {
                tracing::warn!(
                    service = %format!("{}/{svc_name}", b.ctrl_ns),
                    error = %e,
                    "operator: failed to delete VIP Service for clusterIP repin; will retry"
                );
                // Try to bind anyway next pass once the delete lands.
                return;
            }
        }
    }

    for &cand in b.candidates {
        match apply_static_vip_candidate(&b, cand).await {
            Ok(()) => return,
            Err(e) => tracing::debug!(
                service = %format!("{}/{svc_name}", b.ctrl_ns),
                candidate = %cand,
                error = %e,
                "operator: requested clusterIP not usable; trying next (#260)"
            ),
        }
    }
    // No candidate bound: leave no Service so the status writer reports
    // AddressNotUsable. Retried next pass.
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
}
