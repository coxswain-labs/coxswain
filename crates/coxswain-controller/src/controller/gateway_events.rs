//! Kubernetes API calls that write `Gateway` status patches.

use super::config::StatusAddress;
use super::gateway_status::build_gateway_status_patch;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use coxswain_reflector::ingress::IngressPorts;
use coxswain_reflector::tls::GatewayListenerHealth;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
};

// Single patch call sets all Gateway conditions, listener statuses, and addresses at once.
// A JSON merge patch replaces the entire conditions array, so splitting calls
// would cause conditions to toggle in a watch-feedback loop.
pub(super) async fn patch_gateway_status(
    client: &Client,
    gw: &Gateway,
    health: &GatewayListenerHealth,
    addr: Option<&StatusAddress>,
    ingress_ports: IngressPorts,
) {
    let name = match gw.metadata.name.as_deref() {
        Some(n) => n,
        None => return,
    };
    let ns = gw.metadata.namespace.as_deref().unwrap_or("default");
    let Some(generation) = gw.metadata.generation else {
        tracing::warn!(
            name,
            ns,
            "Skipping Gateway status patch: metadata.generation is unset"
        );
        return;
    };
    let api: Api<Gateway> = Api::namespaced(client.clone(), ns);
    let now = Time(k8s_openapi::jiff::Timestamp::now());
    // GEP-91 (#86): warn when the frontend CA ref did not resolve so that operators
    // can see the failure in controller logs.  The proxy already fail-closes all
    // handshakes to the affected hostnames until the ConfigMap is corrected.
    if let Some(fv) = health.frontend_validation.as_ref()
        && !fv.resolved_refs
    {
        tracing::warn!(
            name,
            ns,
            message = %fv.message,
            "Gateway frontend CA ref unresolvable — proxy fail-closing mTLS handshakes"
        );
    }
    let patch = build_gateway_status_patch(gw, health, generation, &now, addr, ingress_ports);
    let started = std::time::Instant::now();
    let result = api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await;
    crate::metrics::observe_status_patch("gateway", started, &result);
    match result {
        Ok(_) => tracing::info!(name, ns, "Gateway status patched"),
        Err(e) => tracing::warn!(name, ns, error = %e, "Failed to patch Gateway status"),
    }
}
