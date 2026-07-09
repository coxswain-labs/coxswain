//! `IpAccessControl` CRD — per-route source-IP allow/deny policy shared by
//! Gateway-API routes and Ingress.
//!
//! Attached to an `HTTPRouteRule` via an `ExtensionRef` filter (group
//! `gateway.coxswain-labs.dev`, kind `IpAccessControl`), or referenced by an
//! Ingress's `ingress.coxswain-labs.dev/ip-access-control: "namespace/name"`
//! annotation (#553). Both surfaces resolve the named CR through
//! `gateway_api::ip_access_control::resolve_spec`, parse its `allow`/`deny`
//! CIDR sets into `ipnet::IpNet` lists, and store them on the route's
//! `allow_source_range` / `deny_source_range` fields in
//! `coxswain-core::routing`. The proxy evaluates deny before allow.
//!
//! Originally an Ingress-only feature (#264 / #268), then given a Gateway-API
//! `ExtensionRef` surface (#479), then the Ingress annotations converged onto
//! this CR reference (#553) so both surfaces resolve to byte-identical
//! runtime config. It has no upstream Gateway-API standard; its merit anchor
//! is Envoy's `rbac` CIDR-principal filter / Istio `AuthorizationPolicy`
//! `ipBlocks`/`notIpBlocks`.
//!
//! Source of truth is the Rust type below; the on-disk CRD YAML
//! (`deploy/manifests/crds/ipaccesscontrols.yaml` and
//! `charts/coxswain/crds/ipaccesscontrols.yaml`) is generated from it by
//! `examples/crdgen.rs` and pinned by a snapshot test.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Source-IP access-control policy for an `HTTPRoute` rule.
///
/// Reference this CR from an `HTTPRouteRule.filters` entry with
/// `type: ExtensionRef` pointing at `group: gateway.coxswain-labs.dev`,
/// `kind: IpAccessControl`. The proxy resolves the request's effective client
/// IP (PROXY-protocol peer / trusted forwarded header if configured, else the
/// L4 downstream peer — the same resolution the rate-limit and Ingress
/// source-range filters use) and:
///
/// - rejects it with `403 Forbidden` when it falls inside any `deny` CIDR
///   (evaluated **first**, so a denied IP is blocked even if `allow` would
///   admit it), then
/// - when `allow` is non-empty, rejects it with `403` unless it falls inside at
///   least one `allow` CIDR.
///
/// An empty `allow` list imposes no allow-list restriction (only `deny`
/// applies); empty `allow` **and** empty `deny` performs no filtering. Invalid
/// CIDR tokens are logged and skipped at reconcile time rather than rejecting
/// the whole policy — a single typo never locks out (or fails to protect) a
/// route by accident.
#[derive(CustomResource, Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.coxswain-labs.dev",
    version = "v1alpha1",
    kind = "IpAccessControl",
    plural = "ipaccesscontrols",
    namespaced
)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IpAccessControlSpec {
    /// CIDR blocks (IPv4 or IPv6) whose client IPs are **blocked** with `403`.
    ///
    /// Evaluated before [`allow`](Self::allow): an IP inside any `deny` range is
    /// rejected even when `allow` would admit it. A bare address without a
    /// prefix (`10.0.0.1`, `2001:db8::1`) is treated as a host route
    /// (`/32` / `/128`). When empty (the default) nothing is denied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,

    /// CIDR blocks (IPv4 or IPv6) whose client IPs are **admitted**; every other
    /// IP is rejected with `403`.
    ///
    /// A bare address without a prefix is treated as a host route
    /// (`/32` / `/128`). When empty (the default) no allow-list restriction is
    /// imposed — only [`deny`](Self::deny) applies. A client IP that cannot be
    /// determined is rejected against a non-empty allow-list (fail-closed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResourceExt;

    const MANIFEST_CRD_YAML: &str =
        include_str!("../../../../deploy/manifests/crds/ipaccesscontrols.yaml");
    const CHART_CRD_YAML: &str =
        include_str!("../../../../charts/coxswain/crds/ipaccesscontrols.yaml");

    fn parse_cr(spec_fragment: &str) -> IpAccessControl {
        let indented = spec_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: IpAccessControl\n\
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
        let generated = IpAccessControl::crd();
        assert_eq!(
            on_disk, generated,
            "deploy/manifests/crds/ipaccesscontrols.yaml drifted from the Rust type. \
             Regenerate: cargo run -p coxswain-core --example crdgen -- IpAccessControl \
             > deploy/manifests/crds/ipaccesscontrols.yaml \
             && cp deploy/manifests/crds/ipaccesscontrols.yaml \
             charts/coxswain/crds/ipaccesscontrols.yaml",
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
    fn empty_spec_defaults_both_lists_empty() {
        let cr = parse_cr("{}");
        assert!(cr.spec.allow.is_empty(), "absent allow defaults to empty");
        assert!(cr.spec.deny.is_empty(), "absent deny defaults to empty");
    }

    #[test]
    fn allow_only_parses() {
        let cr = parse_cr("allow:\n- 203.0.113.0/24\n- 2001:db8::/32");
        assert_eq!(cr.spec.allow, ["203.0.113.0/24", "2001:db8::/32"]);
        assert!(cr.spec.deny.is_empty());
    }

    #[test]
    fn deny_only_parses() {
        let cr = parse_cr("deny:\n- 10.0.0.0/8");
        assert_eq!(cr.spec.deny, ["10.0.0.0/8"]);
        assert!(cr.spec.allow.is_empty());
    }

    #[test]
    fn allow_and_deny_round_trip() {
        let cr = parse_cr("deny:\n- 10.0.0.0/8\nallow:\n- 203.0.113.0/24");
        assert_eq!(cr.spec.deny, ["10.0.0.0/8"]);
        assert_eq!(cr.spec.allow, ["203.0.113.0/24"]);
    }
}
