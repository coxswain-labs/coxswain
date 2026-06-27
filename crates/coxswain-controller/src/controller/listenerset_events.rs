//! Kubernetes API calls that write `ListenerSet` status patches (GEP-1713).

use super::listenerset_status::build_listenerset_status_patch;
use coxswain_reflector::gw_types::ListenerSet;
use coxswain_reflector::ingress::IngressPorts;
use coxswain_reflector::status::GatewayListenerStatus;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
};

/// Patch `ListenerSet.status` with its `Accepted`/`Programmed` conditions and the
/// per-listener stanza. A single JSON merge patch sets everything at once (a
/// split would toggle conditions in a watch-feedback loop, as for Gateways).
pub(super) async fn patch_listenerset_status(
    client: &Client,
    ls: &ListenerSet,
    parent_health: Option<&GatewayListenerStatus>,
    accepted: bool,
    ingress_ports: IngressPorts,
) {
    let name = match ls.metadata.name.as_deref() {
        Some(n) => n,
        None => return,
    };
    let ns = ls.metadata.namespace.as_deref().unwrap_or("default");
    let Some(generation) = ls.metadata.generation else {
        tracing::warn!(
            name,
            ns,
            "Skipping ListenerSet status patch: metadata.generation is unset"
        );
        return;
    };
    let api: Api<ListenerSet> = Api::namespaced(client.clone(), ns);
    let now = Time(k8s_openapi::jiff::Timestamp::now());
    let patch = build_listenerset_status_patch(
        ls,
        parent_health,
        accepted,
        ingress_ports,
        generation,
        &now,
    );
    let started = std::time::Instant::now();
    let result = api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await;
    crate::metrics::observe_status_patch("listenerset", started, &result);
    match result {
        Ok(_) => tracing::info!(name, ns, "ListenerSet status patched"),
        Err(e) => tracing::warn!(name, ns, error = %e, "Failed to patch ListenerSet status"),
    }
}
