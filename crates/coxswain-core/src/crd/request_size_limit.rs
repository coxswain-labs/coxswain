//! `RequestSizeLimit` CRD — per-route request-body byte cap for Gateway-API
//! routes.
//!
//! Attached to an `HTTPRouteRule` or `GRPCRouteRule` via an `ExtensionRef`
//! filter (group `gateway.coxswain-labs.dev`, kind `RequestSizeLimit`). The
//! reflector resolves the named CR and stores its byte limit on the route's
//! `max_body_size` field in `coxswain-core::routing` — the same field the
//! Ingress `max-body-size` annotation feeds. The proxy rejects requests whose
//! body exceeds the limit with `413 Payload Too Large`.
//!
//! This is the Gateway-API surface for the Ingress `max-body-size` annotation
//! (#263). Unlike `BasicAuth` and `Compression`, this filter is supported on
//! both `HTTPRoute` and `GRPCRoute` — a proxy-side byte cap protects backends
//! from oversized payloads on either protocol (#443).
//!
//! Source of truth is the Rust type below; the on-disk CRD YAML
//! (`deploy/manifests/crds/requestsizelimits.yaml` and
//! `charts/coxswain/crds/requestsizelimits.yaml`) is generated from it by
//! `examples/crdgen.rs` and pinned by a snapshot test.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Request-body size limit for an `HTTPRoute` or `GRPCRoute` rule.
///
/// Reference this CR from a rule's `filters` entry with `type: ExtensionRef`
/// pointing at `group: gateway.coxswain-labs.dev`, `kind: RequestSizeLimit`.
/// The proxy rejects a request whose body exceeds `maxSize` with `413 Payload
/// Too Large`, checked up front against `Content-Length` when present and
/// mid-stream for chunked/streaming bodies.
#[derive(CustomResource, Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.coxswain-labs.dev",
    version = "v1alpha1",
    kind = "RequestSizeLimit",
    plural = "requestsizelimits",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct RequestSizeLimitSpec {
    /// Maximum request body size — a byte count or `k`/`m`/`g`-suffixed size
    /// (case-insensitive, binary multipliers), e.g. `"8m"`. Matches the
    /// Ingress `max-body-size` annotation's `parse_byte_size` semantics.
    pub max_size: String,
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResourceExt;

    const MANIFEST_CRD_YAML: &str =
        include_str!("../../../../deploy/manifests/crds/requestsizelimits.yaml");
    const CHART_CRD_YAML: &str =
        include_str!("../../../../charts/coxswain/crds/requestsizelimits.yaml");

    fn parse_cr(spec_fragment: &str) -> RequestSizeLimit {
        let indented = spec_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: RequestSizeLimit\n\
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
        let generated = RequestSizeLimit::crd();
        assert_eq!(
            on_disk, generated,
            "deploy/manifests/crds/requestsizelimits.yaml drifted from the Rust type. \
             Regenerate: cargo run -p coxswain-core --example crdgen -- RequestSizeLimit \
             > deploy/manifests/crds/requestsizelimits.yaml \
             && cp deploy/manifests/crds/requestsizelimits.yaml \
             charts/coxswain/crds/requestsizelimits.yaml",
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
    fn max_size_parses() {
        let cr = parse_cr("maxSize: 8m");
        assert_eq!(cr.spec.max_size, "8m");
    }

    #[test]
    fn missing_max_size_is_rejected() {
        let yaml = "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
                    kind: RequestSizeLimit\n\
                    metadata:\n  name: bad\n\
                    spec:\n  {}\n";
        serde_yaml::from_str::<RequestSizeLimit>(yaml)
            .expect_err("missing maxSize must be rejected");
    }
}
