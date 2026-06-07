//! `GatewayClass` status patch builder and staleness check.

use super::conditions::{gateway_class_accepted, make_condition};
use crate::gw_types::v::gatewayclasses::GatewayClass;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

/// All Gateway API feature names Coxswain advertises support for.
///
/// Must remain sorted ascending by name (GEP-2162 requirement). Update this
/// list whenever a new feature is implemented and add the matching constant to
/// `opts.SupportedFeatures` in `conformance/main_test.go`.
pub(super) const SUPPORTED_FEATURES: &[&str] = &[
    "BackendTLSPolicy",
    "Gateway",
    "GatewayAddressEmpty",
    "GatewayHTTPListenerIsolation",
    "GatewayPort8080",
    "HTTPRoute",
    "HTTPRoute303RedirectStatusCode",
    "HTTPRoute307RedirectStatusCode",
    "HTTPRoute308RedirectStatusCode",
    "HTTPRouteBackendProtocolWebSocket",
    "HTTPRouteBackendTimeout",
    "HTTPRouteDestinationPortMatching",
    "HTTPRouteHostRewrite",
    "HTTPRouteMethodMatching",
    "HTTPRouteNamedRouteRule",
    "HTTPRouteParentRefPort",
    "HTTPRoutePathRedirect",
    "HTTPRoutePathRewrite",
    "HTTPRoutePortRedirect",
    "HTTPRouteQueryParamMatching",
    "HTTPRouteRequestTimeout",
    "HTTPRouteResponseHeaderModification",
    "HTTPRouteSchemeRedirect",
    "ReferenceGrant",
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
