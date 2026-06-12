//! Condition helpers: inspect `metav1.Condition` objects on Gateway API resources.
//!
//! The constructor lives in [`crate::status_common::make_condition`] so both
//! the shared-pool status writer and the dedicated-mode status writer use one
//! source of truth for condition layout; this module just re-exports it for
//! call sites that already spell the bare name.

use coxswain_core::ownership::{self, ObjectKey};
use coxswain_reflector::gw_types::v::gatewayclasses::GatewayClass;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use coxswain_reflector::gw_types::v::httproutes::{HTTPRoute, HttpRouteParentRefs};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use std::collections::HashSet;

pub(super) use crate::status_common::make_condition;

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

#[cfg(test)]
mod tests {
    use super::{
        filter_owned_parent_refs, gateway_class_accepted, has_condition, http_route_programmed,
        make_condition,
    };
    use coxswain_core::ownership::ObjectKey;
    use gateway_api::apis::standard::gatewayclasses::{GatewayClass, GatewayClassStatus};
    use gateway_api::apis::standard::httproutes::{
        HttpRouteParentRefs, HttpRouteStatus, HttpRouteStatusParents,
        HttpRouteStatusParentsParentRef,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use kube::api::ObjectMeta;
    use std::collections::HashSet;

    fn owned(ns: &str, name: &str) -> HashSet<ObjectKey> {
        [ObjectKey::new(ns, name)].into()
    }

    fn now() -> Time {
        Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH)
    }

    #[test]
    fn make_condition_sets_all_fields() {
        let c = make_condition("Programmed", "True", "Ready", "all good", 3, now());
        assert_eq!(c.type_, "Programmed");
        assert_eq!(c.status, "True");
        assert_eq!(c.reason, "Ready");
        assert_eq!(c.message, "all good");
        assert_eq!(c.observed_generation, Some(3));
    }

    #[test]
    fn has_condition_returns_false_when_none() {
        assert!(!has_condition(None, "Programmed"));
    }

    #[test]
    fn has_condition_returns_false_when_slice_empty() {
        assert!(!has_condition(Some(&[]), "Programmed"));
    }

    #[test]
    fn gateway_class_accepted_false_when_generation_stale() {
        // condition exists but observed_generation < metadata.generation — must return false
        let gc = GatewayClass {
            metadata: ObjectMeta {
                generation: Some(5),
                ..Default::default()
            },
            status: Some(GatewayClassStatus {
                conditions: Some(vec![make_condition(
                    "Accepted",
                    "True",
                    "ok",
                    "",
                    2, // stale generation
                    now(),
                )]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!gateway_class_accepted(&gc));
    }

    #[test]
    fn gateway_class_accepted_true_when_generation_current() {
        let gc = GatewayClass {
            metadata: ObjectMeta {
                generation: Some(5),
                ..Default::default()
            },
            status: Some(GatewayClassStatus {
                conditions: Some(vec![make_condition("Accepted", "True", "ok", "", 5, now())]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(gateway_class_accepted(&gc));
    }

    #[test]
    fn http_route_not_programmed_when_resolved_refs_missing() {
        // has Programmed=True but no ResolvedRefs — must not be considered programmed
        let route = gateway_api::apis::standard::httproutes::HTTPRoute {
            metadata: ObjectMeta {
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            status: Some(HttpRouteStatus {
                parents: vec![HttpRouteStatusParents {
                    controller_name: "my-ctrl".to_string(),
                    conditions: vec![make_condition("Programmed", "True", "ok", "", 0, now())],
                    parent_ref: HttpRouteStatusParentsParentRef {
                        name: "gw".to_string(),
                        namespace: Some("default".to_string()),
                        ..Default::default()
                    },
                }],
            }),
            ..Default::default()
        };
        assert!(!http_route_programmed(
            &route,
            "my-ctrl",
            &owned("default", "gw")
        ));
    }

    #[test]
    fn http_route_not_programmed_when_no_status() {
        let route = gateway_api::apis::standard::httproutes::HTTPRoute {
            metadata: ObjectMeta {
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            status: None,
            ..Default::default()
        };
        assert!(!http_route_programmed(
            &route,
            "my-ctrl",
            &owned("default", "gw")
        ));
    }

    #[test]
    fn filter_owned_empty_input_returns_empty() {
        let set = owned("default", "gw");
        assert!(filter_owned_parent_refs(&[], "default", &set).is_empty());
    }

    #[test]
    fn filter_owned_keeps_all_when_all_owned() {
        let set: HashSet<ObjectKey> = [ObjectKey::new("ns", "a"), ObjectKey::new("ns", "b")].into();
        let refs = vec![
            HttpRouteParentRefs {
                name: "a".to_string(),
                namespace: Some("ns".to_string()),
                ..Default::default()
            },
            HttpRouteParentRefs {
                name: "b".to_string(),
                namespace: Some("ns".to_string()),
                ..Default::default()
            },
        ];
        let result = filter_owned_parent_refs(&refs, "ns", &set);
        assert_eq!(result.len(), 2);
    }
}
