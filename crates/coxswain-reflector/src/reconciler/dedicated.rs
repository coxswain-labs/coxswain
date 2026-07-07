//! Dedicated-proxy snapshot building + controller ownership computation.
//!
//! Extracted from the shared-proxy reconciler (`proxy.rs`) to keep that file
//! focused on the watch + rebuild pipeline. This module owns two cohesive
//! concerns:
//!
//! - Building the per-Gateway routing snapshot published into the dedicated
//!   registry for each cut-over Gateway ([`build_dedicated_gateway_snapshot`],
//!   [`DedicatedBuildInputs`]).
//! - Computing which IngressClasses, GatewayClasses, and Gateways this
//!   controller owns ([`compute_ownership`], [`OwnedResources`],
//!   [`gateway_is_cut_over`]), plus the Ingress build config grouping
//!   ([`IngressBuildConfig`]).
//!
//! The shared param-structs these functions read (`Ownership`,
//! `ReflectorStores`) are defined in `proxy.rs` and reached via `super::proxy`.

use super::proxy::{IngressDefaultBackend, Ownership, ReflectorStores};
use super::route_builder::{
    BackendClientCertResolution, build_client_certs, build_gateway_routes, build_tls,
    merge_backend_client_cert_health,
};
use crate::gw_types::GrpcRoute;
use crate::gw_types::HttpRoute;
use crate::gw_types::v::gatewayclasses::GatewayClass;
use crate::gw_types::v::gateways::Gateway;
use crate::ingress::IngressPorts;
use crate::status::GatewayListenerStatus;
use coxswain_core::dedicated_registry::DedicatedRoutingSnapshot;
use coxswain_core::naming::gep1762_resource_name;
use coxswain_core::ownership::{ObjectKey, OwnedGateways};
use coxswain_core::routing::SharedGatewayRoutingTable;
use coxswain_core::shared::Shared;
use coxswain_core::tls::{SharedClientCertStore, SharedListenerHostnames, SharedPortTlsStore};
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use kube::runtime::reflector;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Per-rebuild inputs for [`build_dedicated_gateway_snapshot`].
///
/// Grouped to keep that function under the 7-argument project threshold. `stores` is
/// passed separately (it has a longer independent lifetime from the reflector tasks).
pub(super) struct DedicatedBuildInputs<'a> {
    pub(super) routes: &'a [Arc<HttpRoute>],
    pub(super) grpc_routes: &'a [Arc<GrpcRoute>],
    pub(super) ingresses: &'a [Arc<Ingress>],
    pub(super) base_ownership: &'a Ownership<'a>,
    pub(super) dedicated_certs: &'a BackendClientCertResolution,
    pub(super) empty_ingress_classes: &'a HashSet<String>,
}

/// Build the routing snapshot for a single cut-over dedicated-proxy Gateway.
///
/// Returns `None` if `gw` is not owned by a known GatewayClass or has not yet been
/// cut over to a dedicated proxy (so `filter_map` calls naturally skip such gateways).
pub(super) fn build_dedicated_gateway_snapshot(
    gw: &Arc<Gateway>,
    stores: &ReflectorStores<'_>,
    inputs: &DedicatedBuildInputs<'_>,
) -> Option<(ObjectKey, Arc<DedicatedRoutingSnapshot>)> {
    let base = inputs.base_ownership;
    if !base.gateway_classes.contains(&gw.spec.gateway_class_name) {
        return None;
    }
    if !gateway_is_cut_over(gw) {
        return None;
    }
    let ns = gw.metadata.namespace.clone().unwrap_or_default();
    let name = gw.metadata.name.clone().unwrap_or_default();
    let key = ObjectKey::new(ns, name);
    let single_gw = HashSet::from([key.clone()]);

    // Narrow ownership to this one Gateway so the builders produce only its routes and
    // TLS state.  Ingress classes are empty — a dedicated proxy does not serve Ingress.
    // `gateway_classes` is kept at the full set so `build_gateway_routes` can read
    // listener metadata from the Gateway spec; routes are scoped to `single_gw` only.
    let dedicated_ownership = Ownership {
        ingress_classes: inputs.empty_ingress_classes,
        default_ingress_class: None,
        gateways: &single_gw,
        gateway_classes: base.gateway_classes,
        backend_grants: base.backend_grants,
        cert_grants: base.cert_grants,
        ls_cert_grants: base.ls_cert_grants,
        ca_grants: base.ca_grants,
        basic_auth_secret_grants: base.basic_auth_secret_grants,
        policy_index: base.policy_index,
        backend_policy_index: base.backend_policy_index,
        external_auth_gateway_index: base.external_auth_gateway_index,
        backend_client_certs: &inputs.dedicated_certs.certs,
        backend_client_cert_failures: &inputs.dedicated_certs.failures,
        // Same merged map: the dedicated proxy serves its Gateway's effective listeners
        // (own + ListenerSet-merged), consistent with the shared path.
        effective_gateways: base.effective_gateways,
    };

    let gw_routes_cell: SharedGatewayRoutingTable = Shared::new();
    let tls_cell: SharedPortTlsStore = Shared::new();
    let client_certs_cell: SharedClientCertStore = Shared::new();
    // Listener-hostnames for the dedicated proxy are not yet wired into the
    // DedicatedRoutingSnapshot / discovery wire format; the throwaway cell absorbs
    // the build output until that is extended (#96 follow-up).
    let listener_hostnames_cell: SharedListenerHostnames = Shared::new();

    build_gateway_routes(
        stores,
        inputs.routes,
        inputs.grpc_routes,
        &dedicated_ownership,
        &gw_routes_cell,
        false,
    );
    // `build_tls` with `skip_cut_over=false` includes all owned-class gateways in the
    // TLS store; the extra certs are harmless because the dedicated proxy only binds
    // its own listeners.
    let mut dedicated_listener_health = build_tls(
        stores,
        inputs.ingresses,
        &dedicated_ownership,
        &tls_cell,
        &listener_hostnames_cell,
        false,
        // Dedicated proxies never serve Ingress (empty ingress_classes above):
        // there is no Ingress HTTPS bind port, so no Ingress cert is keyed.
        None,
    );
    build_client_certs(
        stores,
        inputs.ingresses,
        &dedicated_ownership,
        &client_certs_cell,
        &mut dedicated_listener_health,
        false,
        // Dedicated proxies never serve Ingress (empty ingress_classes above):
        // there is no Ingress HTTPS bind port, so no Ingress mTLS config is keyed.
        None,
    );
    merge_backend_client_cert_health(
        &mut dedicated_listener_health,
        &inputs.dedicated_certs.health,
    );

    // Retain only the health entry for the owning Gateway.
    let listener_status: HashMap<ObjectKey, GatewayListenerStatus> = dedicated_listener_health
        .into_iter()
        .filter(|(k, _)| k == &key)
        .collect();

    tracing::debug!(?key, "Published dedicated routing snapshot");
    let snap = Arc::new(DedicatedRoutingSnapshot {
        gateway: gw_routes_cell.load(),
        tls: tls_cell.load(),
        client_certs: client_certs_cell.load(),
        listener_status,
        // GEP-1762: the dedicated proxy runs as ServiceAccount `{gw}-{class}`.
        // Stamped here using the same formula the operator uses to provision the
        // ServiceAccount so the discovery binding check can never disagree.
        expected_proxy_sa: gep1762_resource_name(&key.name, &gw.spec.gateway_class_name),
    });
    Some((key, snap))
}

/// Named result of [`compute_ownership`], avoiding positional-tuple ambiguity at call sites.
pub(super) struct OwnedResources {
    /// Names of every `IngressClass` whose controller matches ours.
    pub(super) ingress_classes: HashSet<String>,
    /// The single owned IngressClass annotated as cluster-default, if any.
    pub(super) default_ingress_class: Option<String>,
    /// Names of every `GatewayClass` whose `controllerName` matches ours.
    pub(super) gateway_classes: HashSet<String>,
    /// `ObjectKey`s of every `Gateway` whose class is owned AND is not yet cut
    /// over to a dedicated proxy.
    pub(super) gateways: HashSet<ObjectKey>,
}

/// Compute which IngressClasses, GatewayClasses, and Gateways are owned by this controller.
/// Publishes the owned-gateways snapshot to `owned_gateways_handle` as a side effect.
pub(super) fn compute_ownership(
    class_store: &reflector::Store<IngressClass>,
    gateway_class_store: &reflector::Store<GatewayClass>,
    gateway_store: &reflector::Store<Gateway>,
    controller_name: &str,
    owned_gateways_handle: &OwnedGateways,
) -> OwnedResources {
    let owned_class_objs: Vec<_> = class_store
        .state()
        .into_iter()
        .filter(|ic| {
            ic.spec.as_ref().and_then(|s| s.controller.as_deref()) == Some(controller_name)
        })
        .collect();

    let owned_ingress_classes: HashSet<String> = owned_class_objs
        .iter()
        .filter_map(|ic| ic.metadata.name.clone())
        .collect();

    let mut defaults: Vec<String> = owned_class_objs
        .iter()
        .filter(|ic| crate::ingress::is_default_ingress_class(ic))
        .filter_map(|ic| ic.metadata.name.clone())
        .collect();
    defaults.sort();
    if defaults.len() > 1 {
        tracing::warn!(
            ?defaults,
            "Multiple owned IngressClasses annotated as default; using lexicographically lowest"
        );
    }
    let owned_default_ingress_class = defaults.into_iter().next();

    let owned_gateway_classes: HashSet<String> = gateway_class_store
        .state()
        .into_iter()
        .filter(|gc| gc.spec.controller_name == controller_name)
        .filter_map(|gc| gc.metadata.name.clone())
        .collect();

    let owned_gateways: HashSet<ObjectKey> = gateway_store
        .state()
        .into_iter()
        .filter(|g| owned_gateway_classes.contains(&g.spec.gateway_class_name))
        // Exclude Gateways that have been cut over to a dedicated proxy
        // (#210). The dedicated pool's data plane serves them now; the
        // shared pool must drop them from its routing table.
        .filter(|g| !gateway_is_cut_over(g))
        .filter_map(|g| ObjectKey::from_meta(&g.metadata))
        .collect();

    owned_gateways_handle.store(Arc::new(owned_gateways.clone()));
    OwnedResources {
        ingress_classes: owned_ingress_classes,
        default_ingress_class: owned_default_ingress_class,
        gateway_classes: owned_gateway_classes,
        gateways: owned_gateways,
    }
}

/// Ingress-specific build configuration grouped to keep `build_routes` under the
/// workspace `clippy::too_many_arguments` threshold.
pub(super) struct IngressBuildConfig<'a> {
    pub(super) default_backend: Option<&'a IngressDefaultBackend>,
    pub(super) ports: IngressPorts,
}

/// Returns true iff the Gateway has been cut over to a dedicated proxy and
/// the shared pool should not serve its routes (#210).
///
/// "Cut over" means the controller's provisioning operator (#208 + #210) has
/// published `gateway.coxswain-labs.dev/DedicatedProxyReady=True` with an
/// `observed_generation` that reflects the Gateway's current spec
/// generation. The generation guard prevents a stale True condition (from
/// before a spec change that may have demoted the Gateway out of dedicated
/// mode) from incorrectly filtering the Gateway out — the operator must
/// observe the new generation and re-publish the condition before the
/// shared pool drops it again.
pub(super) fn gateway_is_cut_over(gw: &Gateway) -> bool {
    const CONDITION_TYPE: &str = "gateway.coxswain-labs.dev/DedicatedProxyReady";
    let expected_gen = gw.metadata.generation.unwrap_or(0);
    gw.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == CONDITION_TYPE))
        .is_some_and(|c| c.status == "True" && c.observed_generation.unwrap_or(0) >= expected_gen)
}
