//! Kubernetes API calls that write `Gateway` status patches.

use super::config::StatusAddress;
use super::gateway_status::build_gateway_status_patch;
use crate::gw_types::v::gateways::Gateway;
use crate::ingress::IngressPorts;
use crate::tls::GatewayListenerHealth;
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
    let patch = build_gateway_status_patch(gw, health, generation, &now, addr, ingress_ports);
    match api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
    {
        Ok(_) => tracing::info!(name, ns, "Gateway status patched"),
        Err(e) => tracing::warn!(name, ns, error = %e, "Failed to patch Gateway status"),
    }
}
