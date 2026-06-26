//! Kubernetes API calls that write `HTTPRoute` status patches.

use super::conditions::{filter_owned_parent_refs, make_condition};
use coxswain_core::ownership::ObjectKey;
use coxswain_reflector::gw_types::{
    HttpRoute,
    v::httproutes::{HttpRouteStatusParents, HttpRouteStatusParentsParentRef},
};
use coxswain_reflector::keys::RouteParentKey;
use coxswain_reflector::tls::{RouteHealthMap, RouteParentHealth};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
};
use std::collections::HashSet;

pub(super) async fn mark_http_route_programmed(
    client: &Client,
    route: &HttpRoute,
    controller_name: &str,
    owned_gateways: &HashSet<ObjectKey>,
    route_health: &RouteHealthMap,
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

    let owned_refs = filter_owned_parent_refs(parent_refs, ns, owned_gateways);
    if owned_refs.is_empty() {
        tracing::debug!(name, ns, "Skipping status patch — no owned parentRefs");
        return;
    }

    let api: Api<HttpRoute> = Api::namespaced(client.clone(), ns);
    let now = Time(k8s_openapi::jiff::Timestamp::now());
    let Some(observed_gen) = route.metadata.generation else {
        tracing::warn!(
            name,
            ns,
            "Skipping HttpRoute status patch: metadata.generation is unset"
        );
        return;
    };

    let default_health = RouteParentHealth::default();
    let parents: Vec<HttpRouteStatusParents> = owned_refs
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

            HttpRouteStatusParents {
                controller_name: controller_name.to_string(),
                parent_ref: HttpRouteStatusParentsParentRef {
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

    // Idempotency gate. The status-writer funnels both spec-change events and
    // route-health re-drives through this one call, so it must be safe to
    // invoke on every reconcile: skip the PATCH when the route already carries
    // exactly the conditions we would write. Without this, a relist or an
    // unrelated health tick would re-stamp `lastTransitionTime` on every route
    // (resourceVersion churn + spurious GEP-1364 transitions). Compared on
    // status/reason/observedGeneration — `lastTransitionTime` is deliberately
    // ignored since it is the very field we must not gratuitously bump.
    if route_status_unchanged(
        &parents,
        route.status.as_ref().map(|s| s.parents.as_slice()),
    ) {
        tracing::debug!(
            name,
            ns,
            "HttpRoute status already current — skipping patch"
        );
        return;
    }

    let patch = serde_json::json!({ "status": { "parents": parents } });
    let started = std::time::Instant::now();
    let result = api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await;
    crate::metrics::observe_status_patch("httproute", started, &result);
    match result {
        Ok(_) => tracing::info!(name, ns, "HttpRoute programmed"),
        Err(e) => tracing::warn!(name, ns, error = %e, "Failed to patch HttpRoute status"),
    }
}

/// Returns true when the route's existing `status.parents` already match the
/// `desired` parents we would write, ignoring `lastTransitionTime` (the field
/// the patch must not gratuitously bump). Used to make
/// [`mark_http_route_programmed`] idempotent so it is safe to call on every
/// reconcile.
fn route_status_unchanged(
    desired: &[HttpRouteStatusParents],
    existing: Option<&[HttpRouteStatusParents]>,
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

fn parent_ref_eq(a: &HttpRouteStatusParentsParentRef, b: &HttpRouteStatusParentsParentRef) -> bool {
    a.name == b.name
        && a.namespace == b.namespace
        && a.group == b.group
        && a.kind == b.kind
        && a.port == b.port
        && a.section_name == b.section_name
}

/// Set-equality of conditions on the fields the status writer owns
/// (`type/status/reason/message/observedGeneration`); `lastTransitionTime` is
/// excluded by design.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> Time {
        Time(
            k8s_openapi::jiff::Timestamp::from_second(secs)
                .unwrap_or_else(|e| panic!("invariant: test timestamp must be valid: {e}")),
        )
    }

    fn parent(controller: &str, conditions: Vec<Condition>) -> HttpRouteStatusParents {
        HttpRouteStatusParents {
            controller_name: controller.to_string(),
            parent_ref: HttpRouteStatusParentsParentRef {
                name: "gw".to_string(),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            conditions,
        }
    }

    #[test]
    fn unchanged_when_identical_ignoring_last_transition_time() {
        // Same status/reason/gen, only `lastTransitionTime` differs — the very
        // field the patch must not gratuitously bump.
        let desired = vec![parent(
            "coxswain",
            vec![make_condition(
                "Programmed",
                "True",
                "Programmed",
                "",
                1,
                at(100),
            )],
        )];
        let existing = vec![parent(
            "coxswain",
            vec![make_condition(
                "Programmed",
                "True",
                "Programmed",
                "",
                1,
                at(50),
            )],
        )];
        assert!(route_status_unchanged(&desired, Some(&existing)));
    }

    #[test]
    fn changed_when_condition_status_flips() {
        // A health downgrade (Programmed True → False) must register as changed,
        // even though the generation is unchanged.
        let desired = vec![parent(
            "coxswain",
            vec![make_condition(
                "Programmed",
                "False",
                "Pending",
                "",
                1,
                at(100),
            )],
        )];
        let existing = vec![parent(
            "coxswain",
            vec![make_condition(
                "Programmed",
                "True",
                "Programmed",
                "",
                1,
                at(100),
            )],
        )];
        assert!(!route_status_unchanged(&desired, Some(&existing)));
    }

    #[test]
    fn changed_when_observed_generation_advances() {
        let desired = vec![parent(
            "coxswain",
            vec![make_condition(
                "Programmed",
                "True",
                "Programmed",
                "",
                2,
                at(100),
            )],
        )];
        let existing = vec![parent(
            "coxswain",
            vec![make_condition(
                "Programmed",
                "True",
                "Programmed",
                "",
                1,
                at(100),
            )],
        )];
        assert!(!route_status_unchanged(&desired, Some(&existing)));
    }

    #[test]
    fn none_existing_matches_only_empty_desired() {
        let desired = vec![parent(
            "coxswain",
            vec![make_condition(
                "Programmed",
                "True",
                "Programmed",
                "",
                1,
                at(100),
            )],
        )];
        assert!(!route_status_unchanged(&desired, None));
        assert!(route_status_unchanged(&[], None));
    }
}
