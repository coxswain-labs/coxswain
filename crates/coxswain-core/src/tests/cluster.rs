//! JSON-shape tests for [`crate::cluster`] response types.
//!
//! The reflector-side fixture-driven tests (shared-mode / dedicated-mode /
//! ingress-only / mixed) live in `coxswain-reflector` because they require
//! `Store<T>` and ownership inputs. These tests pin the handcrafted types' JSON
//! surface so a future refactor can't silently rename or drop a public field.

use crate::cluster::*;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

#[test]
fn empty_cluster_summary_serialises() {
    let s = ClusterSummary::default();
    let v: serde_json::Value = serde_json::to_value(&s).expect("serialise");
    assert_eq!(
        v,
        serde_json::json!({
            "gateways": [],
            "ingresses": [],
            "controller": { "leader": false }
        })
    );
}

#[test]
fn gateway_summary_round_trips_required_and_optional_fields() {
    let g = GatewaySummary::new("public-gw", "tenant-a")
        .with_proxy(ProxyAssignment::dedicated())
        .with_route_count(12)
        .with_addresses(vec!["10.0.0.5".to_string()])
        .with_conditions(vec![GatewayCondition {
            kind: "Programmed".to_string(),
            status: "True".to_string(),
            reason: "Programmed".to_string(),
            message: "Gateway is programmed".to_string(),
        }]);
    let v: serde_json::Value = serde_json::to_value(&g).expect("serialise");
    assert_eq!(
        v,
        serde_json::json!({
            "name": "public-gw",
            "namespace": "tenant-a",
            "proxy": { "pool": "dedicated" },
            "route_count": 12,
            "addresses": ["10.0.0.5"],
            "conditions": [{
                "type": "Programmed",
                "status": "True",
                "reason": "Programmed",
                "message": "Gateway is programmed"
            }]
        })
    );
}

#[test]
fn gateway_summary_defaults_to_shared_pool_with_zero_routes() {
    let g = GatewaySummary::new("plain", "default");
    let v: serde_json::Value = serde_json::to_value(&g).expect("serialise");
    assert_eq!(
        v,
        serde_json::json!({
            "name": "plain",
            "namespace": "default",
            "proxy": { "pool": "shared" },
            "route_count": 0,
            "addresses": [],
            "conditions": []
        })
    );
}

#[test]
fn ingress_summary_omits_empty_load_balancer() {
    let i = IngressSummary::new("foo", "default").with_route_count(2);
    let v: serde_json::Value = serde_json::to_value(&i).expect("serialise");
    assert_eq!(
        v,
        serde_json::json!({
            "name": "foo",
            "namespace": "default",
            "route_count": 2,
        })
    );
}

#[test]
fn ingress_summary_includes_load_balancer_when_set() {
    let i = IngressSummary::new("foo", "default")
        .with_route_count(2)
        .with_load_balancer("10.0.0.4");
    let v: serde_json::Value = serde_json::to_value(&i).expect("serialise");
    assert_eq!(
        v,
        serde_json::json!({
            "name": "foo",
            "namespace": "default",
            "route_count": 2,
            "load_balancer": "10.0.0.4"
        })
    );
}

#[test]
fn gateway_condition_from_kube_strips_timestamp_and_observed_generation() {
    let kube = Condition {
        last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
        message: "ok".to_string(),
        observed_generation: Some(42),
        reason: "Programmed".to_string(),
        status: "True".to_string(),
        type_: "Programmed".to_string(),
    };
    let c = GatewayCondition::from_kube(&kube);
    let v: serde_json::Value = serde_json::to_value(&c).expect("serialise");
    assert_eq!(
        v,
        serde_json::json!({
            "type": "Programmed",
            "status": "True",
            "reason": "Programmed",
            "message": "ok"
        })
    );
}

#[test]
fn gateway_condition_skips_empty_reason_and_message() {
    let c = GatewayCondition {
        kind: "Accepted".to_string(),
        status: "Unknown".to_string(),
        reason: String::new(),
        message: String::new(),
    };
    let v: serde_json::Value = serde_json::to_value(&c).expect("serialise");
    assert_eq!(
        v,
        serde_json::json!({
            "type": "Accepted",
            "status": "Unknown"
        })
    );
}

#[test]
fn shared_cluster_summary_default_is_empty() {
    let s: SharedClusterSummary = SharedClusterSummary::default();
    let snapshot = s.load();
    assert_eq!(snapshot.gateways.len(), 0);
    assert_eq!(snapshot.ingresses.len(), 0);
    assert!(!snapshot.controller.leader);
}

#[test]
fn parameters_ref_constants_match_crd_metadata() {
    // If anyone changes the CRD group/kind, this should fail so the cluster
    // builder's classification logic doesn't silently drift.
    assert_eq!(PARAMETERS_REF_GROUP, "gateway.coxswain-labs.dev");
    assert_eq!(PARAMETERS_REF_KIND, "CoxswainGatewayParameters");
}
