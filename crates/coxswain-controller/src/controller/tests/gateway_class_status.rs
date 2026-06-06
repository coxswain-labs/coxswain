use super::super::gateway_class_status::{
    SUPPORTED_FEATURES, build_gateway_class_status_patch, gateway_class_needs_status_patch,
};
use crate::gw_types::v::gatewayclasses::{
    GatewayClass, GatewayClassStatus, GatewayClassStatusSupportedFeatures,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

fn accepted_condition(generation: i64) -> Condition {
    Condition {
        type_: "Accepted".to_string(),
        status: "True".to_string(),
        reason: String::new(),
        message: String::new(),
        observed_generation: Some(generation),
        last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
    }
}

fn features(names: &[&str]) -> Vec<GatewayClassStatusSupportedFeatures> {
    names
        .iter()
        .map(|n| GatewayClassStatusSupportedFeatures {
            name: n.to_string(),
        })
        .collect()
}

fn gc_with_status(
    generation: i64,
    conditions: Option<Vec<Condition>>,
    supported_features: Option<Vec<GatewayClassStatusSupportedFeatures>>,
) -> GatewayClass {
    GatewayClass {
        metadata: kube::api::ObjectMeta {
            generation: Some(generation),
            ..Default::default()
        },
        status: Some(GatewayClassStatus {
            conditions,
            supported_features,
        }),
        ..Default::default()
    }
}

#[test]
fn needs_patch_when_no_status() {
    let gc = GatewayClass {
        status: None,
        ..Default::default()
    };
    assert!(gateway_class_needs_status_patch(&gc));
}

#[test]
fn needs_patch_when_accepted_missing() {
    let gc = gc_with_status(1, None, Some(features(SUPPORTED_FEATURES)));
    assert!(gateway_class_needs_status_patch(&gc));
}

#[test]
fn needs_patch_when_accepted_stale_generation() {
    // Condition at gen 0 but metadata.generation is 1 — stale.
    let gc = gc_with_status(
        1,
        Some(vec![accepted_condition(0)]),
        Some(features(SUPPORTED_FEATURES)),
    );
    assert!(gateway_class_needs_status_patch(&gc));
}

#[test]
fn needs_patch_when_supported_features_missing() {
    let gc = gc_with_status(1, Some(vec![accepted_condition(1)]), None);
    assert!(gateway_class_needs_status_patch(&gc));
}

#[test]
fn needs_patch_when_supported_features_differ() {
    let gc = gc_with_status(
        1,
        Some(vec![accepted_condition(1)]),
        Some(features(&["Gateway"])), // incomplete list
    );
    assert!(gateway_class_needs_status_patch(&gc));
}

#[test]
fn no_patch_needed_when_fully_up_to_date() {
    let gc = gc_with_status(
        1,
        Some(vec![accepted_condition(1)]),
        Some(features(SUPPORTED_FEATURES)),
    );
    assert!(!gateway_class_needs_status_patch(&gc));
}

#[test]
fn patch_body_includes_all_supported_features_sorted() {
    let now = Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH);
    let patch = build_gateway_class_status_patch(1, &now);
    let feats = patch["status"]["supportedFeatures"]
        .as_array()
        .expect("supportedFeatures array");
    assert_eq!(feats.len(), SUPPORTED_FEATURES.len());
    let names: Vec<&str> = feats
        .iter()
        .map(|f| f["name"].as_str().expect("name string"))
        .collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted, "features must be sorted");
    assert_eq!(names, SUPPORTED_FEATURES);
}

#[test]
fn patch_body_includes_accepted_condition() {
    let now = Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH);
    let patch = build_gateway_class_status_patch(2, &now);
    let conds = patch["status"]["conditions"]
        .as_array()
        .expect("conditions array");
    let accepted = conds
        .iter()
        .find(|c| c["type"] == "Accepted")
        .expect("Accepted condition");
    assert_eq!(accepted["status"], "True");
    assert_eq!(accepted["observedGeneration"], 2);
}
