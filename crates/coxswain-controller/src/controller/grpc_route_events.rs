//! Kubernetes API calls that write `GRPCRoute` status patches.
//!
//! Sibling of `route_events.rs` — forked for the `GRPCRoute` concrete type per the
//! no-generic-reconciler constraint in issue #33.

use super::conditions::make_condition;
use coxswain_core::ownership::{self, ObjectKey};
use coxswain_reflector::gw_types::{
    GrpcRoute,
    v::grpcroutes::{GrpcRouteParentRefs, GrpcRouteStatusParents, GrpcRouteStatusParentsParentRef},
};
use coxswain_reflector::keys::RouteParentKey;
use coxswain_reflector::tls::{HttpRouteHealthMap, RouteParentHealth};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
};
use std::collections::HashSet;

pub(super) async fn mark_grpc_route_programmed(
    client: &Client,
    route: &GrpcRoute,
    controller_name: &str,
    owned_gateways: &HashSet<ObjectKey>,
    route_health: &HttpRouteHealthMap,
) {
    let name = match route.metadata.name.as_deref() {
        Some(n) => n,
        None => return,
    };
    let ns = route.metadata.namespace.as_deref().unwrap_or("default");
    let parent_refs = match route.spec.parent_refs.as_deref() {
        Some(refs) if !refs.is_empty() => refs,
        _ => return,
    };

    let owned_refs = filter_owned_grpc_parent_refs(parent_refs, ns, owned_gateways);
    if owned_refs.is_empty() {
        tracing::debug!(name, ns, "Skipping status patch — no owned parentRefs");
        return;
    }

    let api: Api<GrpcRoute> = Api::namespaced(client.clone(), ns);
    let now = Time(k8s_openapi::jiff::Timestamp::now());
    let Some(observed_gen) = route.metadata.generation else {
        tracing::warn!(
            name,
            ns,
            "Skipping GrpcRoute status patch: metadata.generation is unset"
        );
        return;
    };

    let default_health = RouteParentHealth::default();
    let parents: Vec<GrpcRouteStatusParents> = owned_refs
        .iter()
        .map(|p| {
            let gw_ns = p.namespace.as_deref().unwrap_or(ns);
            let section = p.section_name.as_deref().unwrap_or("").to_string();
            let health_key = RouteParentKey::new(ns, name, gw_ns, &p.name, section);
            let health = route_health.get(&health_key).unwrap_or(&default_health);

            let (acc_status, acc_reason) = if health.accepted {
                ("True", health.accepted_reason)
            } else {
                ("False", health.accepted_reason)
            };
            let (res_status, res_reason) = if health.resolved_refs {
                ("True", health.resolved_refs_reason)
            } else {
                ("False", health.resolved_refs_reason)
            };
            let (prog_status, prog_reason) = if health.accepted {
                ("True", "Programmed")
            } else {
                ("False", health.accepted_reason)
            };

            let accepted_cond = make_condition(
                "Accepted",
                acc_status,
                acc_reason,
                "",
                observed_gen,
                now.clone(),
            );
            let programmed_cond = make_condition(
                "Programmed",
                prog_status,
                prog_reason,
                "",
                observed_gen,
                now.clone(),
            );
            let resolved_refs_cond = make_condition(
                "ResolvedRefs",
                res_status,
                res_reason,
                "",
                observed_gen,
                now.clone(),
            );

            GrpcRouteStatusParents {
                controller_name: controller_name.to_string(),
                parent_ref: GrpcRouteStatusParentsParentRef {
                    group: p.group.clone(),
                    kind: p.kind.clone(),
                    name: p.name.clone(),
                    namespace: p.namespace.clone(),
                    port: p.port,
                    section_name: p.section_name.clone(),
                },
                conditions: vec![accepted_cond, programmed_cond, resolved_refs_cond],
            }
        })
        .collect();

    if route_status_unchanged(
        &parents,
        route.status.as_ref().map(|s| s.parents.as_slice()),
    ) {
        tracing::debug!(
            name,
            ns,
            "GrpcRoute status already current — skipping patch"
        );
        return;
    }

    let patch = serde_json::json!({ "status": { "parents": parents } });
    let started = std::time::Instant::now();
    let result = api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await;
    crate::metrics::observe_status_patch("grpcroute", started, &result);
    match result {
        Ok(_) => tracing::info!(name, ns, "GrpcRoute programmed"),
        Err(e) => tracing::warn!(name, ns, error = %e, "Failed to patch GrpcRoute status"),
    }
}

fn filter_owned_grpc_parent_refs(
    parent_refs: &[GrpcRouteParentRefs],
    default_ns: &str,
    owned_gateways: &HashSet<ObjectKey>,
) -> Vec<GrpcRouteParentRefs> {
    parent_refs
        .iter()
        .filter(|p| {
            ownership::parent_ref_owned(
                p.group.as_deref(),
                p.kind.as_deref(),
                p.namespace.as_deref(),
                &p.name,
                default_ns,
                owned_gateways,
            )
        })
        .cloned()
        .collect()
}

fn route_status_unchanged(
    desired: &[GrpcRouteStatusParents],
    existing: Option<&[GrpcRouteStatusParents]>,
) -> bool {
    let Some(existing) = existing else {
        return desired.is_empty();
    };
    desired.len() == existing.len()
        && desired.iter().all(|d| {
            existing.iter().any(|e| {
                e.controller_name == d.controller_name
                    && parent_ref_eq(&e.parent_ref, &d.parent_ref)
                    && conditions_match(&d.conditions, &e.conditions)
            })
        })
}

fn parent_ref_eq(a: &GrpcRouteStatusParentsParentRef, b: &GrpcRouteStatusParentsParentRef) -> bool {
    a.name == b.name
        && a.namespace == b.namespace
        && a.group == b.group
        && a.kind == b.kind
        && a.port == b.port
        && a.section_name == b.section_name
}

fn conditions_match(desired: &[Condition], existing: &[Condition]) -> bool {
    desired.len() == existing.len()
        && desired.iter().all(|d| {
            existing.iter().any(|e| {
                e.type_ == d.type_
                    && e.status == d.status
                    && e.reason == d.reason
                    && e.message == d.message
                    && e.observed_generation == d.observed_generation
            })
        })
}
