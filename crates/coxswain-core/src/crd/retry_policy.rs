//! `RetryPolicy` CRD — per-route upstream retry policy for Gateway-API routes.
//!
//! Attached to an `HTTPRouteRule` or `GRPCRouteRule` via an `ExtensionRef` filter
//! (group `gateway.coxswain-labs.dev`, kind `RetryPolicy`). The reflector resolves
//! the named CR and translates it into the runtime
//! [`RetryPolicyConfig`](crate::routing::RetryPolicyConfig) that a
//! [`BackendGroup`](crate::routing::BackendGroup) carries and the proxy enforces.
//!
//! **Deprecation intent.** The field shape mirrors Gateway API GEP-1731
//! (`HTTPRoute.spec.rules[].retry` — `attempts`/`backoff`/`codes`) so that once
//! GEP-1731 graduates to the Standard channel and #85 lands, this CRD's HTTP
//! surface can be deprecated in favour of the native field with a mechanical
//! mapping. `grpcCodes` is the `GRPCRoute`-only extension and stays permanently
//! (GEP-1731 is HTTPRoute-only).
//!
//! Source of truth is the Rust type below; the on-disk CRD YAML
//! (`deploy/manifests/crds/retrypolicies.yaml` and
//! `charts/coxswain/crds/retrypolicies.yaml`) is generated from it by
//! `examples/crdgen.rs` and pinned by a snapshot test.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Upstream retry policy for an `HTTPRoute` or `GRPCRoute` rule.
///
/// Reference this CR from a rule's `filters` entry with `type: ExtensionRef`
/// pointing at `group: gateway.coxswain-labs.dev`, `kind: RetryPolicy`.
///
/// Retries are gated on `attempts`: when `attempts >= 1` the proxy always retries
/// connection failures and connect-timeouts (the transport layer is
/// protocol-agnostic). Which *responses* are retried is controlled by `codes`
/// (HTTP status) and, for `GRPCRoute`, `grpcCodes` (`grpc-status`). A gRPC
/// response is only retriable when the status arrives **trailers-only** (nothing
/// streamed yet); a `grpc-status` in a mid-stream trailer is not retried.
#[derive(CustomResource, Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.coxswain-labs.dev",
    version = "v1alpha1",
    kind = "RetryPolicy",
    plural = "retrypolicies",
    namespaced
)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RetryPolicySpec {
    /// Maximum number of retries after the initial attempt (GEP-1731 `attempts`).
    ///
    /// Absent defaults to `1` at reconcile time. `0` disables retrying entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,

    /// Minimum delay before a retried attempt, as a Gateway API Duration
    /// (e.g. `"100ms"`, `"1s"`; GEP-1731 `backoff`).
    ///
    /// The proxy applies this as a fixed minimum delay before each retry. An
    /// unparseable value is ignored (reconcile-time WARN, no delay).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backoff: Option<String>,

    /// HTTP response status codes that trigger a retry (GEP-1731 `codes`).
    ///
    /// Absent defaults to `[502, 503, 504]` (the "gateway could not obtain a
    /// processed response" codes — the request almost certainly did not execute,
    /// so retrying is safe). `500` is deliberately excluded from the default: the
    /// application ran, and a retry risks double execution. An explicit empty list
    /// opts out of response-code retries (connection/timeout only). Deduplicated at
    /// reconcile time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codes: Option<Vec<u16>>,

    /// `grpc-status` codes that trigger a retry on a trailers-only gRPC response
    /// (`GRPCRoute` only; numeric canonical codes `0..=16`).
    ///
    /// Absent defaults to `[14]` (`UNAVAILABLE`) — a trailers-only `UNAVAILABLE`
    /// implies the RPC never executed, so retrying is safe without idempotency
    /// metadata. `DEADLINE_EXCEEDED` (4) and `RESOURCE_EXHAUSTED` (8) are excluded
    /// from the default. An explicit empty list opts out. Ignored on `HTTPRoute`.
    /// Deduplicated at reconcile time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_codes: Option<Vec<u16>>,
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResourceExt;

    const MANIFEST_CRD_YAML: &str =
        include_str!("../../../../deploy/manifests/crds/retrypolicies.yaml");
    const CHART_CRD_YAML: &str =
        include_str!("../../../../charts/coxswain/crds/retrypolicies.yaml");

    fn parse_cr(spec_fragment: &str) -> RetryPolicy {
        let indented = spec_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: RetryPolicy\n\
             metadata:\n  name: t\n\
             spec:\n  {indented}\n",
        );
        serde_yaml::from_str(&yaml)
            .unwrap_or_else(|e| panic!("parse failed: {e}\n--- yaml ---\n{yaml}"))
    }

    #[test]
    fn committed_manifest_crd_matches_generator() {
        let on_disk: CustomResourceDefinition = serde_yaml::from_str(MANIFEST_CRD_YAML)
            .unwrap_or_else(|e| panic!("committed CRD YAML must deserialize: {e}"));
        let generated = RetryPolicy::crd();
        assert_eq!(
            on_disk, generated,
            "deploy/manifests/crds/retrypolicies.yaml drifted from the Rust type. \
             Regenerate: cargo run -p coxswain-core --example crdgen -- RetryPolicy \
             > deploy/manifests/crds/retrypolicies.yaml \
             && cp deploy/manifests/crds/retrypolicies.yaml \
             charts/coxswain/crds/retrypolicies.yaml",
        );
    }

    #[test]
    fn chart_crd_is_byte_identical_to_manifest_crd() {
        assert_eq!(
            MANIFEST_CRD_YAML, CHART_CRD_YAML,
            "deploy/manifests/crds and charts/coxswain/crds CRDs diverged; \
             copy the manifest CRD over the chart CRD",
        );
    }

    #[test]
    fn empty_spec_parses_all_none() {
        let cr = parse_cr("{}");
        assert!(cr.spec.attempts.is_none());
        assert!(cr.spec.backoff.is_none());
        assert!(cr.spec.codes.is_none());
        assert!(cr.spec.grpc_codes.is_none());
    }

    #[test]
    fn full_spec_parses() {
        let cr = parse_cr("attempts: 3\nbackoff: 200ms\ncodes: [500, 503]\ngrpcCodes: [14, 4]");
        assert_eq!(cr.spec.attempts, Some(3));
        assert_eq!(cr.spec.backoff.as_deref(), Some("200ms"));
        assert_eq!(cr.spec.codes, Some(vec![500, 503]));
        assert_eq!(cr.spec.grpc_codes, Some(vec![14, 4]));
    }

    #[test]
    fn explicit_empty_codes_distinct_from_absent() {
        let cr = parse_cr("codes: []\ngrpcCodes: []");
        assert_eq!(cr.spec.codes, Some(vec![]));
        assert_eq!(cr.spec.grpc_codes, Some(vec![]));
    }
}
