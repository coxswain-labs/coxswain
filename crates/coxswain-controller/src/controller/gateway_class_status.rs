//! `GatewayClass` status patch builder and staleness check.

use super::conditions::{gateway_class_accepted, make_condition};
use coxswain_reflector::gw_types::v::gatewayclasses::GatewayClass;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

/// All Gateway API feature names Coxswain advertises support for.
///
/// Must remain sorted ascending by name (GEP-2162 requirement). Update this
/// list whenever a new feature is implemented and add the matching constant to
/// `opts.SupportedFeatures` in `conformance/main_test.go`.
pub(super) const SUPPORTED_FEATURES: &[&str] = &[
    "BackendTLSPolicy",
    "BackendTLSPolicySANValidation",
    "GRPCRoute",
    "Gateway",
    "GatewayAddressEmpty",
    "GatewayBackendClientCertificate",
    "GatewayFrontendClientCertificateValidation",
    "GatewayFrontendClientCertificateValidationInsecureFallback",
    "GatewayHTTPListenerIsolation",
    "GatewayHTTPSListenerDetectMisdirectedRequests",
    "GatewayPort8080",
    "GatewayStaticAddresses",
    "HTTPRoute",
    "HTTPRoute303RedirectStatusCode",
    "HTTPRoute307RedirectStatusCode",
    "HTTPRoute308RedirectStatusCode",
    "HTTPRouteBackendProtocolH2C",
    "HTTPRouteBackendProtocolWebSocket",
    "HTTPRouteBackendRequestHeaderModification",
    "HTTPRouteBackendTimeout",
    "HTTPRouteCORS",
    "HTTPRouteDestinationPortMatching",
    "HTTPRouteHostRewrite",
    "HTTPRouteMethodMatching",
    "HTTPRouteNamedRouteRule",
    "HTTPRouteParentRefPort",
    "HTTPRoutePathRedirect",
    "HTTPRoutePathRewrite",
    "HTTPRoutePortRedirect",
    "HTTPRouteQueryParamMatching",
    "HTTPRouteRequestMirror",
    "HTTPRouteRequestMultipleMirrors",
    "HTTPRouteRequestPercentageMirror",
    "HTTPRouteRequestTimeout",
    "HTTPRouteResponseHeaderModification",
    "HTTPRouteSchemeRedirect",
    "ListenerSet",
    "ReferenceGrant",
    "TLSRoute",
];

/// Returns true when the GatewayClass status needs to be (re-)patched.
///
/// Triggers on:
/// - `Accepted` condition missing or at a stale generation, or
/// - `status.supportedFeatures` is absent or does not match `SUPPORTED_FEATURES`
///   (e.g. after a Coxswain upgrade that adds a new feature).
pub(super) fn gateway_class_needs_status_patch(gc: &GatewayClass) -> bool {
    if !gateway_class_accepted(gc) {
        return true;
    }
    let current: Vec<&str> = gc
        .status
        .as_ref()
        .and_then(|s| s.supported_features.as_deref())
        .map(|feats| feats.iter().map(|f| f.name.as_str()).collect())
        .unwrap_or_default();
    current != SUPPORTED_FEATURES
}

/// Builds a merge-patch body for `GatewayClass.status` with both the `Accepted`
/// condition and the complete `supportedFeatures` list.
pub(super) fn build_gateway_class_status_patch(generation: i64, now: &Time) -> serde_json::Value {
    let condition = make_condition("Accepted", "True", "Accepted", "", generation, now.clone());
    let supported_features: Vec<serde_json::Value> = SUPPORTED_FEATURES
        .iter()
        .map(|name| serde_json::json!({ "name": name }))
        .collect();
    serde_json::json!({
        "status": {
            "conditions": [condition],
            "supportedFeatures": supported_features,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{
        SUPPORTED_FEATURES, build_gateway_class_status_patch, gateway_class_needs_status_patch,
    };
    use coxswain_reflector::gw_types::v::gatewayclasses::{
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
}
