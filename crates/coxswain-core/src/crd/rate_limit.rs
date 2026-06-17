//! `RateLimit` CRD — per-route rate-limiting policy for Gateway-API routes.
//!
//! Attached to an `HTTPRouteRule` via an `ExtensionRef` filter (group
//! `coxswain-labs.dev`, kind `RateLimit`). The reflector resolves the named CR
//! from this CRD and translates it into the governor-free [`RateLimitConfig`]
//! type in `coxswain-core::routing` that the proxy uses for enforcement.
//!
//! Source of truth is the Rust type below; the on-disk CRD YAML
//! (`deploy/manifests/crds/ratelimits.yaml` and
//! `charts/coxswain/crds/ratelimits.yaml`) is generated from it by
//! `examples/crdgen.rs` and pinned by a snapshot test.
//!
//! [`RateLimitConfig`]: crate::routing::RateLimitConfig

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Rate-limiting policy for an `HTTPRoute` rule.
///
/// Reference this CR from an `HTTPRouteRule.filters` entry with
/// `type: ExtensionRef` pointing at `group: coxswain-labs.dev`,
/// `kind: RateLimit`.  The proxy enforces one governor GCRA token bucket per
/// distinct `by_header` value (or per client IP when `by_header` is absent) on
/// the matching route; over-limit requests receive a `429 Too Many Requests`
/// response with a `Retry-After` header.
#[derive(CustomResource, Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "coxswain-labs.dev",
    version = "v1alpha1",
    kind = "RateLimit",
    plural = "ratelimits",
    namespaced
)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RateLimitSpec {
    /// Sustained request rate in requests per second (must be ≥ 1).
    ///
    /// A value of `0` is treated as a misconfiguration at reconcile time
    /// (WARN + fail-open: the route is not limited). Non-zero values are
    /// forwarded as-is to the governor `Quota` as the per-client cell rate.
    pub requests_per_second: u32,

    /// Extra requests allowed above the sustained rate as an initial burst.
    ///
    /// The effective burst capacity is `requests_per_second + burst`, matching
    /// the semantics of the Ingress `rate-limit-burst` annotation. When `0`
    /// (the default), no burst is allowed above the sustained rate.
    #[serde(default)]
    pub burst: u32,

    /// Header name to key rate-limit buckets by (e.g. `"X-Api-Key"`).
    ///
    /// When present, each distinct value of this request header gets its own
    /// token bucket — matched case-insensitively (normalised to lowercase).
    /// Requests that do not carry the header are admitted without consuming
    /// quota (fail-open), matching ingress-nginx and Envoy behaviour.
    ///
    /// When absent (the default), buckets are keyed by real client IP address
    /// (PROXY-protocol peer if present, else L4 downstream peer — the same
    /// resolution used by the allow-source-range filter).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_header: Option<String>,
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResourceExt;

    const MANIFEST_CRD_YAML: &str =
        include_str!("../../../../deploy/manifests/crds/ratelimits.yaml");
    const CHART_CRD_YAML: &str = include_str!("../../../../charts/coxswain/crds/ratelimits.yaml");

    fn parse_cr(spec_fragment: &str) -> RateLimit {
        let indented = spec_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: coxswain-labs.dev/v1alpha1\n\
             kind: RateLimit\n\
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
        let generated = RateLimit::crd();
        assert_eq!(
            on_disk, generated,
            "deploy/manifests/crds/ratelimits.yaml drifted from the Rust type. \
             Regenerate: cargo run -p coxswain-core --example crdgen -- RateLimit \
             > deploy/manifests/crds/ratelimits.yaml \
             && cp deploy/manifests/crds/ratelimits.yaml \
             charts/coxswain/crds/ratelimits.yaml",
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
    fn rps_only_defaults_burst_zero_by_ip() {
        let cr = parse_cr("requestsPerSecond: 10");
        assert_eq!(cr.spec.requests_per_second, 10);
        assert_eq!(cr.spec.burst, 0);
        assert!(
            cr.spec.by_header.is_none(),
            "absent byHeader defaults to IP keying"
        );
    }

    #[test]
    fn burst_can_be_set() {
        let cr = parse_cr("requestsPerSecond: 5\nburst: 20");
        assert_eq!(cr.spec.burst, 20);
    }

    #[test]
    fn by_header_parses() {
        let cr = parse_cr("requestsPerSecond: 5\nbyHeader: X-Api-Key");
        assert_eq!(cr.spec.by_header.as_deref(), Some("X-Api-Key"));
    }

    #[test]
    fn missing_rps_is_rejected() {
        let yaml = "apiVersion: coxswain-labs.dev/v1alpha1\n\
                    kind: RateLimit\n\
                    metadata:\n  name: bad\n\
                    spec:\n  burst: 5\n";
        serde_yaml::from_str::<RateLimit>(yaml)
            .expect_err("missing requestsPerSecond must be rejected");
    }
}
