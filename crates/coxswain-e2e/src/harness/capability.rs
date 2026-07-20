//! Which Gateway API kinds the cluster under test actually serves.
//!
//! Tests that assert on Coxswain's capability degradation must decide "is this
//! kind installed?" the same way the controller does, or they assert against a
//! different cluster than the one the controller sees. The vocabulary is
//! imported from `coxswain_core` rather than restated here, so the two cannot
//! drift.

use coxswain_core::gateway_api_capability::{GATEWAY_API_GROUP, GatewayApiKind};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::{Api, Client, api::ListParams};
use std::collections::HashSet;

/// Plural names of the Gateway API kinds this cluster serves at a version
/// Coxswain watches.
///
/// Presence of the CRD is **not** sufficient. The experimental channel ships
/// `TLSRoute` at `v1alpha2`/`v1alpha3` only until Gateway API v1.5 while
/// Coxswain watches `v1`, so a presence-only check would report a kind as
/// available that no reflector can watch — and every assertion built on it
/// would then fail against a correctly-behaving controller.
///
/// # Errors
///
/// Returns the underlying `kube` error when the CRD list cannot be read.
pub async fn served_gateway_api_kinds(client: &Client) -> Result<HashSet<String>, kube::Error> {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    let installed = crds.list(&ListParams::default()).await?;

    let mut served = HashSet::new();
    for crd in installed {
        if crd.spec.group != GATEWAY_API_GROUP {
            continue;
        }
        let Some(kind) = GatewayApiKind::ALL
            .iter()
            .find(|k| k.plural() == crd.spec.names.plural)
        else {
            continue;
        };
        let serves_watched_version = crd
            .spec
            .versions
            .iter()
            .filter(|v| v.served)
            .any(|v| kind.versions().contains(&v.name.as_str()));
        if serves_watched_version {
            served.insert(crd.spec.names.plural.clone());
        }
    }
    Ok(served)
}
