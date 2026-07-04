//! Render the shared-mode per-Gateway `Service` (VIP) and identity
//! `ServiceAccount`.
//!
//! In shared mode the data plane is one proxy pool in the controller's
//! namespace, so the only per-Gateway artifacts are (1) the VIP `Service` that
//! gives each Gateway its own externally-reachable address (#472) and (2) the
//! identity `ServiceAccount` that gives GEP-1867 metadata a per-Gateway home
//! (#482). This module renders both; the dedicated-proxy
//! `Deployment`/`HPA`/`PDB` rendering stays in [`super::render`]. Shared naming
//! is deliberately distinct from the GEP-1762 dedicated resource name so a
//! shared↔dedicated migration never entangles the two lifecycles.

use super::render::{
    SHARED_GATEWAY_VIP_COMPONENT, final_labels, gateway_owner_reference, overlay_infra_annotations,
    service_type_to_k8s_string,
};
use coxswain_core::crd::ServiceType;
use coxswain_reflector::EffectiveListenerPort;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use k8s_openapi::api::core::v1::{Service, ServiceAccount, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;
use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash as _, Hasher as _};

/// `app.kubernetes.io/component` value stamped on the per-Gateway shared-mode
/// identity `ServiceAccount` (#482, GEP-1867) — distinct from `dedicated-proxy`
/// and the VIP's component so the three per-Gateway artifacts are
/// independently identifiable.
pub(super) const SHARED_GATEWAY_SA_COMPONENT: &str = "shared-gateway-sa";

/// Render the per-Gateway identity `ServiceAccount` for a shared-mode Gateway
/// (#482, GEP-1867).
///
/// In shared mode the data plane (one proxy pod) and the VIP Service both live
/// in the controller's namespace, so nothing per-Gateway exists in the
/// Gateway's own namespace. This SA is that per-Gateway artifact: it carries
/// the reserved GEP-1762 labels (incl. `gateway.networking.k8s.io/gateway-name`)
/// plus the overlaid `spec.infrastructure.{labels,annotations}`, giving GEP-1867
/// metadata a home and a stable per-Gateway identity object. It holds zero RBAC
/// — the shared proxy runs as its own ServiceAccount; this one is identity, not
/// a pod-run-as.
///
/// Owner-reffed to the Gateway (same namespace → legal), so a plain Gateway
/// delete reclaims it via GC; a shared→dedicated migration prunes it explicitly
/// (the owning Gateway survives the migration, so GC never fires).
///
/// # Panics
///
/// Panics if the Gateway has no `metadata.name` or `metadata.namespace` —
/// apiserver invariants whose absence indicates a controller bug.
#[must_use]
pub(super) fn render_shared_gateway_service_account(gateway: &Gateway) -> ServiceAccount {
    let gw_name =
        gateway.metadata.name.as_deref().unwrap_or_else(|| {
            panic!("invariant: Gateway has no name; the API server requires it")
        });
    let gw_ns = gateway.metadata.namespace.as_deref().unwrap_or_else(|| {
        panic!("invariant: Gateway has no namespace; the API server requires it")
    });
    let labels = final_labels(gateway, SHARED_GATEWAY_SA_COMPONENT);
    let annotations = overlay_infra_annotations(BTreeMap::new(), gateway);
    ServiceAccount {
        metadata: ObjectMeta {
            name: Some(shared_gateway_service_account_name(gw_ns, gw_name)),
            namespace: Some(gw_ns.to_string()),
            labels: Some(labels),
            annotations: (!annotations.is_empty()).then_some(annotations),
            owner_references: Some(vec![gateway_owner_reference(gateway)]),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Name of the per-Gateway shared-mode VIP Service (#472).
///
/// Deliberately distinct from the GEP-1762 dedicated resource name
/// ([`gep1762_resource_name`]) so the shared Service's lifecycle never entangles
/// with the dedicated `Deployment`/`Service`/`ServiceAccount` during a
/// dedicated↔shared migration. The `-shared-gw` suffix is preserved when the
/// Gateway name is long enough to need truncation to the 63-char DNS limit.
#[must_use]
pub(crate) fn shared_gateway_service_name(gw_ns: &str, gw_name: &str) -> String {
    hashed_shared_name(gw_ns, gw_name, "shared-gw")
}

/// Name of the per-Gateway shared-mode identity `ServiceAccount` (#482),
/// provisioned in the **Gateway's own** namespace.
///
/// Deliberately distinct from both the GEP-1762 dedicated resource name
/// ([`gep1762_resource_name`]) and the VIP Service name
/// ([`shared_gateway_service_name`]) so a shared↔dedicated migration never
/// entangles the three lifecycles. The `-shared-sa` suffix is preserved when
/// the Gateway name is long enough to need truncation to the 63-char DNS limit.
#[must_use]
pub(super) fn shared_gateway_service_account_name(gw_ns: &str, gw_name: &str) -> String {
    hashed_shared_name(gw_ns, gw_name, "shared-sa")
}

/// Build a namespace-qualified, collision-free name for a shared-mode
/// per-Gateway resource: a readable truncated `<ns>-<name>` prefix plus a hash
/// of `<ns>/<name>` and a role `suffix`, kept within the 63-char DNS limit.
/// ns/name are RFC 1123 labels (ASCII), so char-truncation is byte-safe.
fn hashed_shared_name(gw_ns: &str, gw_name: &str, suffix: &str) -> String {
    let mut hasher = DefaultHasher::new();
    format!("{gw_ns}/{gw_name}").hash(&mut hasher);
    let hash = hasher.finish() & 0xffff_ffff;
    let prefix: String = format!("{gw_ns}-{gw_name}").chars().take(40).collect();
    let prefix = prefix.trim_end_matches('-');
    format!("{prefix}-{hash:08x}-{suffix}")
}

/// The caller-requested static `IPAddress` candidates to pin as the VIP Service
/// `spec.clusterIP` (GatewayStaticAddresses, #260), in `spec.addresses` order.
///
/// Returns empty when any requested address carries an unsupported `type` (the
/// Gateway is rejected with `UnsupportedAddress`, so there is nothing to
/// provision). Otherwise every `IPAddress`-typed entry with a non-empty,
/// parseable value is a candidate — `Hostname` and empty (auto-assign) entries
/// are skipped.
///
/// The reconciler tries these in order and binds the first the apiserver
/// accepts: `clusterIP` is immutable and an out-of-CIDR candidate is rejected
/// (creating nothing), so a *usable* address that follows an *unusable* one
/// still binds. That is what makes `status.addresses` reflect the usable
/// address during the transient multi-address window the conformance ladder
/// (`[unusable, usable] → [usable]`) walks through.
#[must_use]
pub(super) fn requested_static_cluster_ips(gw: &Gateway) -> Vec<std::net::IpAddr> {
    let Some(addrs) = gw.spec.addresses.as_deref() else {
        return Vec::new();
    };
    // Don't provision for a Gateway that will be rejected for an unsupported type.
    if addrs.iter().any(|a| {
        a.r#type
            .as_deref()
            .is_some_and(|t| t != "IPAddress" && t != "Hostname")
    }) {
        return Vec::new();
    }
    addrs
        .iter()
        .filter_map(|a| {
            if a.r#type.as_deref() == Some("Hostname") {
                return None;
            }
            a.value
                .as_deref()
                .filter(|v| !v.is_empty())
                .and_then(|v| v.parse::<std::net::IpAddr>().ok())
        })
        .collect()
}

/// The single static `IPAddress` to pin for paths that bind exactly one
/// clusterIP (the dedicated-proxy Service render): the first candidate, or
/// `None` when none is requested. See [`requested_static_cluster_ips`].
#[must_use]
pub(super) fn requested_static_cluster_ip(gw: &Gateway) -> Option<std::net::IpAddr> {
    requested_static_cluster_ips(gw).into_iter().next()
}

/// Inputs to [`render_shared_gateway_service`].
#[non_exhaustive]
pub(super) struct SharedServiceInputs<'a> {
    /// The shared-mode Gateway getting its own VIP.
    pub(super) gateway: &'a Gateway,
    /// Namespace the shared proxy pod lives in — the VIP Service is created here
    /// (#472) so its selector resolves to the proxy pod (a selector only matches
    /// same-namespace pods, and selectorless `LoadBalancer` Services are
    /// unreliable across cloud providers — kubernetes/kubernetes#105937).
    pub(super) controller_namespace: &'a str,
    /// Label selector targeting the shared proxy pod.
    pub(super) shared_proxy_selector: &'a BTreeMap<String, String>,
    /// Effective listener ports (Gateway's own + attached ListenerSets', GEP-1713)
    /// the Service exposes. Deduplicated, collision-free names. A listener port
    /// absent from `internal_ports` (range exhausted) is omitted.
    pub(super) effective_ports: &'a [EffectiveListenerPort],
    /// `listenerPort → internalPort` (the allocated `targetPort` the shared
    /// proxy binds and keys routing on). A listener port absent from this map
    /// got no internal port (range exhausted) and is omitted from the Service.
    pub(super) internal_ports: &'a BTreeMap<u16, u16>,
    /// Service type for the VIP — `LoadBalancer` by default so each Gateway
    /// gets its own externally-reachable address.
    pub(super) service_type: ServiceType,
    /// A caller-requested static `IPAddress` from `Gateway.spec.addresses`
    /// (GatewayStaticAddresses, #260) to pin as the Service `spec.clusterIP`.
    /// `None` keeps the apiserver's auto-allocation (the default/legacy path).
    /// Only meaningful for ClusterIP-typed VIPs — the apiserver assigns the
    /// requested in-CIDR IP exactly (or rejects an out-of-range one, surfacing
    /// `AddressNotUsable`). `clusterIP` is immutable, so the reconciler
    /// delete+recreates the Service when this diverges from the live one.
    pub(super) requested_cluster_ip: Option<std::net::IpAddr>,
}

/// Render the per-Gateway Service that exposes a shared-mode Gateway on its own
/// VIP (#472), selecting the one shared proxy pod and mapping each advertised
/// listener `port` to the allocated internal `targetPort`.
///
/// Created in the **controller's namespace** (alongside the shared proxy pod) so
/// the selector resolves and the cloud LB assigns a real address — a selector
/// matches only same-namespace pods, and selectorless `LoadBalancer` Services
/// are unreliable across providers. It therefore carries **no owner reference**
/// (cross-namespace owner refs are illegal); the serialized VIP reconciler
/// orphan-prunes it instead. The owning Gateway is recorded in the
/// `gateway-name`/`gateway-namespace` labels.
#[must_use]
pub(super) fn render_shared_gateway_service(inputs: &SharedServiceInputs<'_>) -> Service {
    let gw = inputs.gateway;
    let gw_name =
        gw.metadata.name.as_deref().unwrap_or_else(|| {
            panic!("invariant: Gateway has no name; the API server requires it")
        });
    let gw_ns = gw.metadata.namespace.as_deref().unwrap_or_else(|| {
        panic!("invariant: Gateway has no namespace; the API server requires it")
    });

    // GEP-1867 (#482): overlay `spec.infrastructure.{labels,annotations}` so an
    // operator can stamp cloud-LB annotations (and labels) onto each Gateway's
    // VIP. `final_labels` provides the reserved GEP-1762 set (name/instance/
    // managed-by/gateway-name) + the user's non-reserved labels, with reserved
    // keys protected. The owning-Gateway *namespace* mapping label is not in the
    // reserved set, so insert it LAST — a user infra label must not be able to
    // detach the reflector/prune mapping the VIP reconciler keys on.
    let mut labels = final_labels(gw, SHARED_GATEWAY_VIP_COMPONENT);
    labels.insert(
        coxswain_reflector::port_alloc::VIP_GATEWAY_NAMESPACE_LABEL.to_string(),
        gw_ns.to_string(),
    );
    let annotations = overlay_infra_annotations(BTreeMap::new(), gw);

    Service {
        metadata: ObjectMeta {
            name: Some(shared_gateway_service_name(gw_ns, gw_name)),
            namespace: Some(inputs.controller_namespace.to_string()),
            labels: Some(labels),
            annotations: (!annotations.is_empty()).then_some(annotations),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            type_: Some(service_type_to_k8s_string(inputs.service_type)),
            selector: Some(inputs.shared_proxy_selector.clone()),
            ports: Some(shared_service_ports(
                inputs.effective_ports,
                inputs.internal_ports,
            )),
            // GatewayStaticAddresses (#260): pin a requested IP as the clusterIP.
            cluster_ip: inputs.requested_cluster_ip.map(|ip| ip.to_string()),
            ..Default::default()
        }),
        status: None,
    }
}

/// One `ServicePort` per effective listener port (the Gateway's own listeners
/// plus those merged from attached ListenerSets, GEP-1713), mapping the advertised
/// `port` to its allocated internal `targetPort`. Ports without an allocation
/// (range exhausted) are skipped. `effective_ports` is already deduplicated on
/// port with collision-free names by [`coxswain_reflector::effective_listener_ports`].
fn shared_service_ports(
    effective_ports: &[EffectiveListenerPort],
    internal_ports: &BTreeMap<u16, u16>,
) -> Vec<ServicePort> {
    let mut out = Vec::new();
    for listener in effective_ports {
        let Some(&internal) = internal_ports.get(&listener.port) else {
            continue;
        };
        out.push(ServicePort {
            name: Some(listener.name.clone()),
            port: i32::from(listener.port),
            target_port: Some(IntOrString::Int(i32::from(internal))),
            protocol: Some("TCP".to_string()),
            ..Default::default()
        });
    }
    out
}
