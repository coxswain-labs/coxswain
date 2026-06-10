//! Kubernetes API calls that write `GatewayClass` status patches.

use super::gateway_class_status::build_gateway_class_status_patch;
use coxswain_reflector::gw_types::v::gatewayclasses::GatewayClass;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
};

pub(super) async fn patch_gateway_class_status(client: &Client, name: &str, generation: i64) {
    let api: Api<GatewayClass> = Api::all(client.clone());
    let now = Time(k8s_openapi::jiff::Timestamp::now());
    let patch = build_gateway_class_status_patch(generation, &now);
    match api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
    {
        Ok(_) => tracing::info!(name, "GatewayClass status patched"),
        Err(e) => tracing::warn!(name, error = %e, "Failed to patch GatewayClass status"),
    }
}
