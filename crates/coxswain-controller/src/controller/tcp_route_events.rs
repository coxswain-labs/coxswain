//! Kubernetes API calls that write `TCPRoute` status patches.
//!
//! Sibling of `tls_route_events.rs` — forked for the `TCPRoute` concrete type per the
//! no-generic-reconciler constraint in issue #33. TCPRoute has no `hostnames` field and
//! no passthrough/terminate mode split, but its `status.parents` shape and the
//! `Accepted`/`Programmed`/`ResolvedRefs` condition-writing algorithm are identical.

use super::conditions::{CoxswainConditionType, make_condition};
use coxswain_core::ownership::{self, ObjectKey};
use coxswain_reflector::gw_types::constants::RouteConditionType;
use coxswain_reflector::gw_types::{
    TcpRoute,
    v::tcproutes::{TcpRouteParentRefs, TcpRouteStatusParents, TcpRouteStatusParentsParentRef},
};
use coxswain_reflector::keys::RouteParentKey;
use coxswain_reflector::status::{RouteParentStatus, RouteStatusMap};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
};
use std::collections::HashSet;

/// Write `Accepted`, `Programmed`, and `ResolvedRefs` conditions on a `TCPRoute`
/// for every owned parentRef (Gateway) the route is bound to.
///
/// Idempotent: skips the API call when the desired status is already present.
pub(super) async fn mark_tcp_route_programmed(
    client: &Client,
    route: &TcpRoute,
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

    let owned_refs = filter_owned_tcp_parent_refs(parent_refs, ns, owned_gateways);
    if owned_refs.is_empty() {
        tracing::debug!(name, ns, "Skipping status patch — no owned parentRefs");
        return;
    }

    let api: Api<TcpRoute> = Api::namespaced(client.clone(), ns);
    let now = Time(k8s_openapi::jiff::Timestamp::now());
    let Some(observed_gen) = route.metadata.generation else {
        tracing::warn!(
            name,
            ns,
            "Skipping TcpRoute status patch: metadata.generation is unset"
        );
        return;
    };

    let default_status = RouteParentStatus::default();
    let parents: Vec<TcpRouteStatusParents> = owned_refs
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

            TcpRouteStatusParents {
                controller_name: controller_name.to_string(),
                parent_ref: TcpRouteStatusParentsParentRef {
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
        tracing::debug!(name, ns, "TcpRoute status already current — skipping patch");
        return;
    }

    let patch = serde_json::json!({ "status": { "parents": parents } });
    let started = std::time::Instant::now();
    let result = api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await;
    crate::metrics::observe_status_patch("tcp_route", started, &result);
    match result {
        Ok(_) => tracing::info!(name, ns, "TcpRoute programmed"),
        Err(e) => tracing::warn!(name, ns, error = %e, "Failed to patch TcpRoute status"),
    }
}

fn filter_owned_tcp_parent_refs(
    parent_refs: &[TcpRouteParentRefs],
    default_ns: &str,
    owned_gateways: &HashSet<ObjectKey>,
) -> Vec<TcpRouteParentRefs> {
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
    desired: &[TcpRouteStatusParents],
    existing: Option<&[TcpRouteStatusParents]>,
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

fn parent_ref_eq(a: &TcpRouteStatusParentsParentRef, b: &TcpRouteStatusParentsParentRef) -> bool {
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
