//! Kubernetes API calls that write `TLSRoute` status patches.
//!
//! Sibling of `grpc_route_events.rs` — forked for the `TLSRoute` concrete type per the
//! no-generic-reconciler constraint in issue #33.

use super::conditions::{CoxswainConditionType, make_condition};
use coxswain_core::ownership::{self, ObjectKey};
use coxswain_reflector::gw_types::constants::RouteConditionType;
use coxswain_reflector::gw_types::{
    TlsRoute,
    v::tlsroutes::{TlsRouteParentRefs, TlsRouteStatusParents, TlsRouteStatusParentsParentRef},
};
use coxswain_reflector::keys::RouteParentKey;
use coxswain_reflector::status::{RouteParentStatus, RouteStatusMap};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
};
use std::collections::HashSet;

/// Write `Accepted`, `Programmed`, and `ResolvedRefs` conditions on a `TLSRoute`
/// for every owned parentRef (Gateway) the route is bound to.
///
/// Idempotent: skips the API call when the desired status is already present.
pub(super) async fn mark_tls_route_programmed(
    client: &Client,
    route: &TlsRoute,
    controller_name: &str,
    owned_gateways: &HashSet<ObjectKey>,
    route_status: &RouteStatusMap,
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

    let owned_refs = filter_owned_tls_parent_refs(parent_refs, ns, owned_gateways);
    if owned_refs.is_empty() {
        tracing::debug!(name, ns, "Skipping status patch — no owned parentRefs");
        return;
    }

    let api: Api<TlsRoute> = Api::namespaced(client.clone(), ns);
    let now = Time(k8s_openapi::jiff::Timestamp::now());
    let Some(observed_gen) = route.metadata.generation else {
        tracing::warn!(
            name,
            ns,
            "Skipping TlsRoute status patch: metadata.generation is unset"
        );
        return;
    };

    let default_status = RouteParentStatus::default();
    let parents: Vec<TlsRouteStatusParents> = owned_refs
        .iter()
        .map(|p| {
            let gw_ns = p.namespace.as_deref().unwrap_or(ns);
            let section = p.section_name.as_deref().unwrap_or("").to_string();
            let health_key = RouteParentKey::new(ns, name, gw_ns, &p.name, section);
            let health = route_status.get(&health_key).unwrap_or(&default_status);

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
                RouteConditionType::Accepted,
                acc_status,
                acc_reason,
                "",
                observed_gen,
                now.clone(),
            );
            // See `CoxswainConditionType` for why this isn't a
            // `RouteConditionType` variant.
            let programmed_cond = make_condition(
                CoxswainConditionType::Programmed,
                prog_status,
                prog_reason,
                "",
                observed_gen,
                now.clone(),
            );
            let resolved_refs_cond = make_condition(
                RouteConditionType::ResolvedRefs,
                res_status,
                res_reason,
                "",
                observed_gen,
                now.clone(),
            );

            TlsRouteStatusParents {
                controller_name: controller_name.to_string(),
                parent_ref: TlsRouteStatusParentsParentRef {
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
        tracing::debug!(name, ns, "TlsRoute status already current — skipping patch");
        return;
    }

    let patch = serde_json::json!({ "status": { "parents": parents } });
    let started = std::time::Instant::now();
    let result = api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await;
    crate::metrics::observe_status_patch("tls_route", started, &result);
    match result {
        Ok(_) => tracing::info!(name, ns, "TlsRoute programmed"),
        Err(e) => tracing::warn!(name, ns, error = %e, "Failed to patch TlsRoute status"),
    }
}

fn filter_owned_tls_parent_refs(
    parent_refs: &[TlsRouteParentRefs],
    default_ns: &str,
    owned_gateways: &HashSet<ObjectKey>,
) -> Vec<TlsRouteParentRefs> {
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
    desired: &[TlsRouteStatusParents],
    existing: Option<&[TlsRouteStatusParents]>,
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

fn parent_ref_eq(a: &TlsRouteStatusParentsParentRef, b: &TlsRouteStatusParentsParentRef) -> bool {
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
