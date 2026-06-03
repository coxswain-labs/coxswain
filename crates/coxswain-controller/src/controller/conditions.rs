use coxswain_core::ownership::{self, ObjectKey};
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::Gateway;
use gateway_api::apis::standard::httproutes::{HTTPRoute, HttpRouteParentRefs};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use std::collections::HashSet;

pub(super) fn make_condition(
    type_: &str,
    status: &str,
    reason: &str,
    message: &str,
    generation: i64,
    now: Time,
) -> Condition {
    Condition {
        type_: type_.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation: Some(generation),
        last_transition_time: now,
    }
}

pub(super) fn has_condition(conditions: Option<&[Condition]>, type_: &str) -> bool {
    has_condition_at_gen(conditions, type_, 0)
}

fn has_condition_at_gen(conditions: Option<&[Condition]>, type_: &str, min_gen: i64) -> bool {
    conditions
        .map(|conds| {
            conds.iter().any(|c| {
                c.type_ == type_
                    && c.status == "True"
                    && c.observed_generation.unwrap_or(0) >= min_gen
            })
        })
        .unwrap_or(false)
}

pub(super) fn gateway_class_accepted(gc: &GatewayClass) -> bool {
    has_condition_at_gen(
        gc.status.as_ref().and_then(|s| s.conditions.as_deref()),
        "Accepted",
        gc.metadata.generation.unwrap_or(0),
    )
}

pub(super) fn gateway_accepted(gw: &Gateway) -> bool {
    has_condition(
        gw.status.as_ref().and_then(|s| s.conditions.as_deref()),
        "Accepted",
    )
}

pub(super) fn gateway_programmed(gw: &Gateway) -> bool {
    has_condition(
        gw.status.as_ref().and_then(|s| s.conditions.as_deref()),
        "Programmed",
    )
}

pub(super) fn http_route_programmed(
    route: &HTTPRoute,
    controller_name: &str,
    owned_gateways: &HashSet<ObjectKey>,
) -> bool {
    let default_ns = route.metadata.namespace.as_deref().unwrap_or("default");
    let expected_gen = route.metadata.generation.unwrap_or(0);
    route
        .status
        .as_ref()
        .map(|s| {
            s.parents.iter().any(|p| {
                p.controller_name == controller_name
                    && p.conditions.iter().any(|c| {
                        c.type_ == "Programmed"
                            && c.observed_generation.unwrap_or(0) >= expected_gen
                    })
                    && p.conditions.iter().any(|c| {
                        c.type_ == "ResolvedRefs"
                            && c.observed_generation.unwrap_or(0) >= expected_gen
                    })
                    && ownership::parent_ref_owned(
                        p.parent_ref.group.as_deref(),
                        p.parent_ref.kind.as_deref(),
                        p.parent_ref.namespace.as_deref(),
                        &p.parent_ref.name,
                        default_ns,
                        owned_gateways,
                    )
            })
        })
        .unwrap_or(false)
}

/// Returns the subset of `parent_refs` that point to a Coxswain-managed Gateway.
pub(super) fn filter_owned_parent_refs(
    parent_refs: &[HttpRouteParentRefs],
    default_ns: &str,
    owned_gateways: &HashSet<ObjectKey>,
) -> Vec<HttpRouteParentRefs> {
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
