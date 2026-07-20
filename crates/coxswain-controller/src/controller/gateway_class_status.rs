//! `GatewayClass` status patch builder and staleness check.

use super::conditions::{gateway_class_accepted, make_condition};
use coxswain_core::gateway_api_capability::Requirement::{Field, Kind};
use coxswain_core::gateway_api_capability::{GatewayApiField, GatewayApiKind, Requirement};
use coxswain_reflector::capabilities::GatewayApiCapabilities;
use coxswain_reflector::gw_types::constants::{
    GatewayClassConditionReason, GatewayClassConditionType,
};
use coxswain_reflector::gw_types::v::gatewayclasses::GatewayClass;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

/// All Gateway API feature names Coxswain advertises support for, each paired
/// with what the cluster must actually install for it to be true.
///
/// The `Requirement` is what makes a single build work across Gateway API
/// versions: on a cluster whose CRD set lacks a kind or a field, the features
/// naming it are filtered out of `supportedFeatures` rather than advertised and
/// then failing conformance. No version comparison appears anywhere — the
/// requirement is answered from detected capabilities.
///
/// Must remain sorted ascending by name (GEP-2162 requirement). Update this
/// list whenever a new feature is implemented and add the matching constant to
/// `opts.SupportedFeatures` in `conformance/main_test.go`.
pub(super) const SUPPORTED_FEATURES: &[(&str, Requirement)] = &[
    ("BackendTLSPolicy", Kind(GatewayApiKind::BackendTlsPolicy)),
    (
        "BackendTLSPolicySANValidation",
        Kind(GatewayApiKind::BackendTlsPolicy),
    ),
    ("GRPCRoute", Kind(GatewayApiKind::GrpcRoute)),
    ("GRPCRouteNamedRouteRule", Kind(GatewayApiKind::GrpcRoute)),
    ("Gateway", Kind(GatewayApiKind::Gateway)),
    ("GatewayAddressEmpty", Kind(GatewayApiKind::Gateway)),
    (
        "GatewayBackendClientCertificate",
        Kind(GatewayApiKind::Gateway),
    ),
    // GEP-91: gated on the field, not the kind — `Gateway` exists at every
    // supported version but `spec.tls.frontend` only from v1.5.
    (
        "GatewayFrontendClientCertificateValidation",
        Field(GatewayApiField::GatewayFrontendTls),
    ),
    (
        "GatewayFrontendClientCertificateValidationInsecureFallback",
        Field(GatewayApiField::GatewayFrontendTls),
    ),
    (
        "GatewayHTTPListenerIsolation",
        Kind(GatewayApiKind::Gateway),
    ),
    (
        "GatewayHTTPSListenerDetectMisdirectedRequests",
        Kind(GatewayApiKind::Gateway),
    ),
    (
        "GatewayInfrastructurePropagation",
        Kind(GatewayApiKind::Gateway),
    ),
    ("GatewayPort8080", Kind(GatewayApiKind::Gateway)),
    ("GatewayStaticAddresses", Kind(GatewayApiKind::Gateway)),
    ("HTTPRoute", Kind(GatewayApiKind::HttpRoute)),
    (
        "HTTPRoute303RedirectStatusCode",
        Kind(GatewayApiKind::HttpRoute),
    ),
    (
        "HTTPRoute307RedirectStatusCode",
        Kind(GatewayApiKind::HttpRoute),
    ),
    (
        "HTTPRoute308RedirectStatusCode",
        Kind(GatewayApiKind::HttpRoute),
    ),
    (
        "HTTPRouteBackendProtocolH2C",
        Kind(GatewayApiKind::HttpRoute),
    ),
    (
        "HTTPRouteBackendProtocolWebSocket",
        Kind(GatewayApiKind::HttpRoute),
    ),
    (
        "HTTPRouteBackendRequestHeaderModification",
        Kind(GatewayApiKind::HttpRoute),
    ),
    ("HTTPRouteBackendTimeout", Kind(GatewayApiKind::HttpRoute)),
    // GEP-1767: `spec.rules[].filters[].cors` only exists from v1.5.
    ("HTTPRouteCORS", Field(GatewayApiField::HttpRouteCors)),
    (
        "HTTPRouteDestinationPortMatching",
        Kind(GatewayApiKind::HttpRoute),
    ),
    ("HTTPRouteHostRewrite", Kind(GatewayApiKind::HttpRoute)),
    ("HTTPRouteMethodMatching", Kind(GatewayApiKind::HttpRoute)),
    ("HTTPRouteNamedRouteRule", Kind(GatewayApiKind::HttpRoute)),
    ("HTTPRouteParentRefPort", Kind(GatewayApiKind::HttpRoute)),
    ("HTTPRoutePathRedirect", Kind(GatewayApiKind::HttpRoute)),
    ("HTTPRoutePathRewrite", Kind(GatewayApiKind::HttpRoute)),
    ("HTTPRoutePortRedirect", Kind(GatewayApiKind::HttpRoute)),
    (
        "HTTPRouteQueryParamMatching",
        Kind(GatewayApiKind::HttpRoute),
    ),
    ("HTTPRouteRequestMirror", Kind(GatewayApiKind::HttpRoute)),
    (
        "HTTPRouteRequestMultipleMirrors",
        Kind(GatewayApiKind::HttpRoute),
    ),
    (
        "HTTPRouteRequestPercentageMirror",
        Kind(GatewayApiKind::HttpRoute),
    ),
    ("HTTPRouteRequestTimeout", Kind(GatewayApiKind::HttpRoute)),
    (
        "HTTPRouteResponseHeaderModification",
        Kind(GatewayApiKind::HttpRoute),
    ),
    ("HTTPRouteSchemeRedirect", Kind(GatewayApiKind::HttpRoute)),
    ("ListenerSet", Kind(GatewayApiKind::ListenerSet)),
    ("ReferenceGrant", Kind(GatewayApiKind::ReferenceGrant)),
    ("TCPRoute", Kind(GatewayApiKind::TcpRoute)),
    ("TLSRoute", Kind(GatewayApiKind::TlsRoute)),
    ("TLSRouteModeMixed", Kind(GatewayApiKind::TlsRoute)),
    ("TLSRouteModeTerminate", Kind(GatewayApiKind::TlsRoute)),
    ("UDPRoute", Kind(GatewayApiKind::UdpRoute)),
];

/// The feature names satisfied by `caps`, in the same ascending order as
/// [`SUPPORTED_FEATURES`].
///
/// Filtering a sorted slice preserves order, so the GEP-2162 sort requirement
/// and the exact-comparison in [`gateway_class_needs_status_patch`] both keep
/// holding — provided both sides filter through this one function.
fn advertised_features(caps: &GatewayApiCapabilities) -> Vec<&'static str> {
    SUPPORTED_FEATURES
        .iter()
        .filter(|(_, req)| caps.satisfies(*req))
        .map(|(name, _)| *name)
        .collect()
}

/// Returns true when the GatewayClass status needs to be (re-)patched.
///
/// Triggers on:
/// - `Accepted` condition missing or at a stale generation, or
/// - `status.supportedFeatures` is absent or does not match the set `caps`
///   admits (e.g. after a Coxswain upgrade that adds a new feature, or after a
///   Gateway API CRD upgrade that makes a previously-filtered feature real).
pub(super) fn gateway_class_needs_status_patch(
    gc: &GatewayClass,
    caps: &GatewayApiCapabilities,
) -> bool {
    if !gateway_class_accepted(gc) {
        return true;
    }
    // Mirror the builder: when the CRD cannot store `supportedFeatures` the
    // patch omits it, so comparing against a desired list would never be
    // satisfied and every reconcile would re-patch.
    if !caps.has_field(GatewayApiField::GatewayClassSupportedFeatures) {
        return false;
    }
    let current: Vec<&str> = gc
        .status
        .as_ref()
        .and_then(|s| s.supported_features.as_deref())
        .map(|feats| feats.iter().map(|f| f.name.as_str()).collect())
        .unwrap_or_default();
    current != advertised_features(caps)
}

/// Builds a merge-patch body for `GatewayClass.status` with the `Accepted`
/// condition and the `supportedFeatures` list `caps` admits.
///
/// `supportedFeatures` is omitted entirely when the cluster's `GatewayClass`
/// CRD has no such field: the API server prunes an unknown status field
/// silently, so writing it would leave the differ permanently dissatisfied and
/// re-patching on every reconcile.
pub(super) fn build_gateway_class_status_patch(
    generation: i64,
    now: &Time,
    caps: &GatewayApiCapabilities,
) -> serde_json::Value {
    let condition = make_condition(
        GatewayClassConditionType::Accepted,
        "True",
        GatewayClassConditionReason::Accepted,
        "",
        generation,
        now.clone(),
    );
    if !caps.has_field(GatewayApiField::GatewayClassSupportedFeatures) {
        return serde_json::json!({ "status": { "conditions": [condition] } });
    }
    let supported_features: Vec<serde_json::Value> = advertised_features(caps)
        .into_iter()
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
        SUPPORTED_FEATURES, advertised_features, build_gateway_class_status_patch,
        gateway_class_needs_status_patch,
    };
    use coxswain_core::gateway_api_capability::{GatewayApiField, GatewayApiKind};
    use coxswain_reflector::capabilities::GatewayApiCapabilities;
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

    /// A cluster serving every kind and field Coxswain models — the shape of a
    /// current-version Gateway API install.
    fn full_caps() -> GatewayApiCapabilities {
        GatewayApiCapabilities::from_vocabulary(
            GatewayApiKind::ALL.iter().copied(),
            GatewayApiField::ALL.iter().copied(),
        )
    }

    /// The Gateway API v1.4 shape: no ListenerSet/TLSRoute/TCPRoute/UDPRoute
    /// CRDs, and neither the HTTPRoute `cors` filter nor the Gateway
    /// `spec.tls.frontend` subtree — but `GatewayClass.status.supportedFeatures`
    /// does exist, since v1.4.0 is where it landed.
    fn v1_4_caps() -> GatewayApiCapabilities {
        let kinds = GatewayApiKind::ALL.iter().copied().filter(|k| {
            !matches!(
                k,
                GatewayApiKind::ListenerSet
                    | GatewayApiKind::TlsRoute
                    | GatewayApiKind::TcpRoute
                    | GatewayApiKind::UdpRoute
            )
        });
        GatewayApiCapabilities::from_vocabulary(
            kinds,
            [GatewayApiField::GatewayClassSupportedFeatures],
        )
    }

    fn all_feature_names() -> Vec<&'static str> {
        SUPPORTED_FEATURES.iter().map(|(name, _)| *name).collect()
    }

    #[test]
    fn needs_patch_when_no_status() {
        let gc = GatewayClass {
            status: None,
            ..Default::default()
        };
        assert!(gateway_class_needs_status_patch(&gc, &full_caps()));
    }

    #[test]
    fn needs_patch_when_accepted_missing() {
        let gc = gc_with_status(1, None, Some(features(&all_feature_names())));
        assert!(gateway_class_needs_status_patch(&gc, &full_caps()));
    }

    #[test]
    fn needs_patch_when_accepted_stale_generation() {
        // Condition at gen 0 but metadata.generation is 1 — stale.
        let gc = gc_with_status(
            1,
            Some(vec![accepted_condition(0)]),
            Some(features(&all_feature_names())),
        );
        assert!(gateway_class_needs_status_patch(&gc, &full_caps()));
    }

    #[test]
    fn needs_patch_when_supported_features_missing() {
        let gc = gc_with_status(1, Some(vec![accepted_condition(1)]), None);
        assert!(gateway_class_needs_status_patch(&gc, &full_caps()));
    }

    #[test]
    fn needs_patch_when_supported_features_differ() {
        let gc = gc_with_status(
            1,
            Some(vec![accepted_condition(1)]),
            Some(features(&["Gateway"])), // incomplete list
        );
        assert!(gateway_class_needs_status_patch(&gc, &full_caps()));
    }

    #[test]
    fn no_patch_needed_when_fully_up_to_date() {
        let gc = gc_with_status(
            1,
            Some(vec![accepted_condition(1)]),
            Some(features(&all_feature_names())),
        );
        assert!(!gateway_class_needs_status_patch(&gc, &full_caps()));
    }

    #[test]
    fn patch_body_includes_all_supported_features_sorted() {
        let now = Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH);
        let patch = build_gateway_class_status_patch(1, &now, &full_caps());
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
        assert_eq!(names, all_feature_names());
    }

    #[test]
    fn patch_body_includes_accepted_condition() {
        let now = Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH);
        let patch = build_gateway_class_status_patch(2, &now, &full_caps());
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

    #[test]
    fn v1_4_cluster_is_not_advertised_features_its_crds_cannot_express() {
        let now = Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH);
        let patch = build_gateway_class_status_patch(1, &now, &v1_4_caps());
        let names: Vec<&str> = patch["status"]["supportedFeatures"]
            .as_array()
            .expect("supportedFeatures array")
            .iter()
            .map(|f| f["name"].as_str().expect("name string"))
            .collect();

        for absent in [
            "ListenerSet",
            "TLSRoute",
            "TLSRouteModeMixed",
            "TLSRouteModeTerminate",
            "TCPRoute",
            "UDPRoute",
            "HTTPRouteCORS",
            "GatewayFrontendClientCertificateValidation",
            "GatewayFrontendClientCertificateValidationInsecureFallback",
        ] {
            assert!(
                !names.contains(&absent),
                "{absent} must not be advertised on a Gateway API v1.4 cluster"
            );
        }
        // Everything the v1.4 CRD set does express is still advertised.
        for present in ["Gateway", "HTTPRoute", "GRPCRoute", "ReferenceGrant"] {
            assert!(names.contains(&present), "{present} must be advertised");
        }
    }

    #[test]
    fn filtered_features_stay_sorted() {
        // GEP-2162 requires ascending order, and the differ compares exactly.
        let names = advertised_features(&v1_4_caps());
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    #[test]
    fn differ_agrees_with_builder_on_a_downgraded_cluster() {
        // The regression this guards: builder and differ filtering differently
        // makes the status writer re-patch on every single reconcile forever.
        let caps = v1_4_caps();
        let now = Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH);
        let patch = build_gateway_class_status_patch(1, &now, &caps);
        let written: Vec<GatewayClassStatusSupportedFeatures> =
            patch["status"]["supportedFeatures"]
                .as_array()
                .expect("supportedFeatures array")
                .iter()
                .map(|f| GatewayClassStatusSupportedFeatures {
                    name: f["name"].as_str().expect("name string").to_string(),
                })
                .collect();

        let gc = gc_with_status(1, Some(vec![accepted_condition(1)]), Some(written));
        assert!(
            !gateway_class_needs_status_patch(&gc, &caps),
            "a GatewayClass carrying exactly what the builder wrote must not need re-patching"
        );
    }

    #[test]
    fn supported_features_omitted_when_the_crd_cannot_store_them() {
        // Pre-v1.4.0 GatewayClass has no `status.supportedFeatures`; the API
        // server prunes an unknown status field silently, so writing it would
        // leave the differ permanently unsatisfied.
        let caps = GatewayApiCapabilities::from_vocabulary(GatewayApiKind::ALL.iter().copied(), []);
        let now = Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH);
        let patch = build_gateway_class_status_patch(1, &now, &caps);

        assert!(patch["status"]["supportedFeatures"].is_null());
        assert!(patch["status"]["conditions"].is_array());

        let gc = gc_with_status(1, Some(vec![accepted_condition(1)]), None);
        assert!(
            !gateway_class_needs_status_patch(&gc, &caps),
            "the differ must not demand a field the CRD cannot store"
        );
    }
}
