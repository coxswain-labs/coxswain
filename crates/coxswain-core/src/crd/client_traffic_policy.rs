//! `ClientTrafficPolicy` CRD — per-listener PROXY protocol acceptance policy.
//!
//! Attaches to a `Gateway` (and optionally a single listener via `sectionName`)
//! to enable HAProxy PROXY protocol v1/v2 acceptance on those listeners.
//! Modelled on Envoy Gateway's `ClientTrafficPolicy` (GEP-713 direct-policy
//! attachment).
//!
//! Source of truth is the Rust type below; the on-disk CRD YAML
//! (`deploy/manifests/crds/clienttrafficpolicies.yaml` and
//! `charts/coxswain/crds/clienttrafficpolicies.yaml`) is generated from it
//! by `examples/crdgen.rs` and pinned by a snapshot test.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Policy that enables PROXY protocol v1/v2 acceptance on one or more Gateway
/// listeners without restarting the proxy.
///
/// A `ClientTrafficPolicy` in namespace `ns` targets the `Gateway` objects in
/// `targetRefs`. When `sectionName` is set it applies to a single named
/// listener; when omitted it applies to every listener on that Gateway.
///
/// Section-scoped policies take precedence over Gateway-scoped ones. If two
/// section-scoped policies target the same listener, the later-created one is
/// accepted and the earlier one receives `Conflicted=True`.
#[derive(CustomResource, Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.coxswain-labs.dev",
    version = "v1alpha1",
    kind = "ClientTrafficPolicy",
    plural = "clienttrafficpolicies",
    namespaced,
    status = "ClientTrafficPolicyStatus"
)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ClientTrafficPolicySpec {
    /// Gateways (and optionally specific listeners) this policy targets.
    ///
    /// Each entry must reference a `gateway.networking.k8s.io/Gateway` in the
    /// same namespace. The `sectionName` field narrows the target to a single
    /// named listener on that Gateway.
    pub target_refs: Vec<LocalPolicyTargetRef>,

    /// PROXY protocol v1/v2 acceptance settings.
    ///
    /// When `None` the policy has no effect (a no-op policy is valid but
    /// immediately accepted with zero impact).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_protocol: Option<ProxyProtocolSpec>,
}

/// A reference to a specific Gateway or one of its named listeners.
///
/// Mirrors the Gateway API `LocalPolicyTargetReferenceWithSectionName` shape
/// without importing the generated types, so we control the schema.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LocalPolicyTargetRef {
    /// API group of the target resource. Must be `gateway.networking.k8s.io`.
    pub group: String,
    /// Kind of the target resource. Must be `Gateway`.
    pub kind: String,
    /// Name of the target Gateway in the same namespace as this policy.
    pub name: String,
    /// Optional name of a specific listener on the Gateway. When omitted the
    /// policy applies to all listeners.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
}

/// PROXY protocol acceptance settings for a listener.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProxyProtocolSpec {
    /// When `true`, every accepted connection must carry a valid PROXY v1 or
    /// v2 header. Connections without a valid header, or from peers outside
    /// `trustedSources`, are dropped immediately.
    pub enabled: bool,

    /// CIDR allow-list of peers permitted to send PROXY headers (e.g.
    /// `["10.0.0.0/8", "192.168.1.0/24"]`). Should be non-empty when
    /// `enabled` is `true`; an empty list causes all connections to be
    /// rejected, which is logged as a warning.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_sources: Vec<String>,
}

/// Status written back to the `ClientTrafficPolicy` by the controller.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientTrafficPolicyStatus {
    /// Per-ancestor policy conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestors: Vec<PolicyAncestorStatus>,
}

/// Status of this policy with respect to one ancestor (Gateway or listener).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyAncestorStatus {
    /// Reference to the Gateway (and optionally listener) this ancestor entry
    /// describes.
    pub ancestor_ref: PolicyAncestorRef,
    /// The controller that wrote this entry.
    pub controller_name: String,
    /// Conditions for this ancestor.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition>,
}

/// Identifies the ancestor (Gateway + optional sectionName) to which a
/// `PolicyAncestorStatus` entry corresponds.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyAncestorRef {
    /// API group of the ancestor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Kind of the ancestor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Namespace of the ancestor (omit for cluster-scoped resources).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Name of the ancestor Gateway.
    pub name: String,
    /// Listener name, if this entry is specific to one listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResourceExt;

    const MANIFEST_CRD_YAML: &str =
        include_str!("../../../../deploy/manifests/crds/clienttrafficpolicies.yaml");
    const CHART_CRD_YAML: &str =
        include_str!("../../../../charts/coxswain/crds/clienttrafficpolicies.yaml");

    fn parse_cr(spec_fragment: &str) -> ClientTrafficPolicy {
        let indented = spec_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: ClientTrafficPolicy\n\
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
        let generated = ClientTrafficPolicy::crd();
        assert_eq!(
            on_disk, generated,
            "deploy/manifests/crds/clienttrafficpolicies.yaml drifted from the Rust type. \
             Regenerate: cargo run -p coxswain-core --example crdgen -- ClientTrafficPolicy \
             > deploy/manifests/crds/clienttrafficpolicies.yaml \
             && cp deploy/manifests/crds/clienttrafficpolicies.yaml \
             charts/coxswain/crds/clienttrafficpolicies.yaml",
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
    fn minimal_spec_deserializes() {
        // Use explicit indentation — Rust `\n\` line continuation strips leading
        // whitespace, which would break YAML list-item nesting.
        let cr = parse_cr(concat!(
            "targetRefs:\n",
            "- group: gateway.networking.k8s.io\n",
            "  kind: Gateway\n",
            "  name: my-gw",
        ));
        assert_eq!(cr.spec.target_refs.len(), 1);
        assert!(cr.spec.proxy_protocol.is_none());
    }

    #[test]
    fn full_spec_round_trips() {
        let cr = parse_cr(concat!(
            "targetRefs:\n",
            "- group: gateway.networking.k8s.io\n",
            "  kind: Gateway\n",
            "  name: my-gw\n",
            "  sectionName: https\n",
            "proxyProtocol:\n",
            "  enabled: true\n",
            "  trustedSources:\n",
            "  - 10.0.0.0/8\n",
            "  - 192.168.0.0/16",
        ));
        let pp = cr
            .spec
            .proxy_protocol
            .as_ref()
            .expect("proxyProtocol present");
        assert!(pp.enabled);
        assert_eq!(pp.trusted_sources, ["10.0.0.0/8", "192.168.0.0/16"]);
        let tr = &cr.spec.target_refs[0];
        assert_eq!(tr.section_name.as_deref(), Some("https"));
    }
}
