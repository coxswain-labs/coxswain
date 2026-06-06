use super::config::StatusAddress;
use super::ingress_status::build_ingress_status_patch;
use k8s_openapi::api::networking::v1::Ingress;
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
};

pub(super) async fn patch_ingress_status(client: &Client, ingress: &Ingress, addr: &StatusAddress) {
    let name = match ingress.metadata.name.as_deref() {
        Some(n) => n,
        None => return,
    };
    let ns = ingress.metadata.namespace.as_deref().unwrap_or("default");
    let api: Api<Ingress> = Api::namespaced(client.clone(), ns);
    let patch = build_ingress_status_patch(addr);
    match api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
    {
        Ok(_) => tracing::info!(name, ns, "Ingress loadBalancer status patched"),
        Err(e) => tracing::warn!(name, ns, error = %e, "Failed to patch Ingress status"),
    }
}
