use super::super::conditions::{
    filter_owned_parent_refs, gateway_class_accepted, has_condition, http_route_programmed,
    make_condition,
};
use coxswain_core::ownership::ObjectKey;
use gateway_api::apis::standard::gatewayclasses::{GatewayClass, GatewayClassStatus};
use gateway_api::apis::standard::httproutes::{
    HttpRouteParentRefs, HttpRouteStatus, HttpRouteStatusParents, HttpRouteStatusParentsParentRef,
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
