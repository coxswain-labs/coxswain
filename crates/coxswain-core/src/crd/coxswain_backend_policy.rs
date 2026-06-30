//! `CoxswainBackendPolicy` CRD — per-backend connection policy for a `Service`.
//!
//! Attaches to a Kubernetes `Service` (GEP-713 direct-policy attachment, the same
//! pattern as [`ClientTrafficPolicy`](super::client_traffic_policy)) and applies
//! per-upstream-connection settings to every Gateway API route whose backend
//! resolves to that Service. This issue (#354) ships `spec.timeouts.connect` and
//! `spec.timeouts.idle`; the CRD is the canonical future home for the rest of the
//! per-backend connection policy surface (LB algorithm #389, circuit breaking
//! #478, upstream-keepalive parity #365).
//!
//! Source of truth is the Rust type below; the on-disk CRD YAML
//! (`deploy/manifests/crds/coxswainbackendpolicies.yaml` and
//! `charts/coxswain/crds/coxswainbackendpolicies.yaml`) is generated from it by
//! `examples/crdgen.rs` and pinned by a snapshot test.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Per-backend connection policy attached to one or more `Service` objects.
///
/// A `CoxswainBackendPolicy` in namespace `ns` targets the `Service` objects in
/// `targetRefs` (each in the same namespace). Its `timeouts` apply to every
/// Gateway API route whose backend resolves to a targeted Service.
///
/// When two policies target the same Service, the older one (by
/// `creationTimestamp`, ties broken by name) wins and the loser receives
/// `Accepted=False, reason=Conflicted` in its status.
#[derive(CustomResource, Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.coxswain-labs.dev",
    version = "v1alpha1",
    kind = "CoxswainBackendPolicy",
    plural = "coxswainbackendpolicies",
    namespaced,
    status = "CoxswainBackendPolicyStatus"
)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CoxswainBackendPolicySpec {
    /// Services this policy targets.
    ///
    /// Each entry must reference a core `Service` in the same namespace as this
    /// policy. The policy's `timeouts` apply to upstream connections to that
    /// Service's endpoints.
    pub target_refs: Vec<BackendPolicyTargetRef>,

    /// Per-upstream-connection timeouts.
    ///
    /// When `None` the policy is a no-op (valid and immediately accepted with no
    /// effect on connection behaviour).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<BackendTimeouts>,
}

/// A reference to a `Service` this policy targets.
///
/// Mirrors the Gateway API `LocalPolicyTargetReference` shape without importing
/// the generated types, so we control the schema. Section-name (per-port)
/// targeting is intentionally omitted for #354 — a policy applies to the whole
/// Service.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendPolicyTargetRef {
    /// API group of the target. Use `""` (the core group) for a `Service`.
    #[serde(default)]
    pub group: String,
    /// Kind of the target resource. Must be `Service`.
    pub kind: String,
    /// Name of the target Service in the same namespace as this policy.
    pub name: String,
}

/// Per-upstream-connection timeout settings.
///
/// Both fields are free-form GEP-2257 duration strings (e.g. `"500ms"`, `"5s"`,
/// `"1m"`). They are intentionally **not** schema-pattern-validated: an
/// unparseable value reaches the reflector, which WARNs and falls back to the
/// default connection behaviour rather than the apiserver rejecting the resource.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendTimeouts {
    /// Upstream TCP-connect timeout. Bounds how long the proxy waits to establish
    /// a connection to a backend endpoint before failing the request (`502`).
    ///
    /// When unset or unparseable, the proxy falls back to the per-route connect
    /// timeout (Ingress `connect-timeout` annotation) or the Gateway API
    /// `backendRequest` budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect: Option<String>,

    /// Upstream keepalive idle timeout. How long an idle pooled connection to a
    /// backend endpoint is retained before eviction.
    ///
    /// When unset or unparseable, Pingora's built-in pool behaviour is unchanged
    /// (connections stay until LRU capacity forces eviction).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle: Option<String>,
}

/// Status written back to the `CoxswainBackendPolicy` by the controller.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CoxswainBackendPolicyStatus {
    /// Per-ancestor (targeted Service) policy conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestors: Vec<BackendPolicyAncestorStatus>,
}

/// Status of this policy with respect to one ancestor (a targeted `Service`).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendPolicyAncestorStatus {
    /// Reference to the `Service` this ancestor entry describes.
    pub ancestor_ref: BackendPolicyAncestorRef,
    /// The controller that wrote this entry.
    pub controller_name: String,
    /// Conditions for this ancestor (e.g. `Accepted`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition>,
}

/// Identifies the ancestor (targeted `Service`) a [`BackendPolicyAncestorStatus`]
/// entry corresponds to.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendPolicyAncestorRef {
    /// API group of the ancestor (`""` for a core `Service`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Kind of the ancestor (`Service`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Namespace of the ancestor Service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Name of the ancestor Service.
    pub name: String,
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResourceExt;

    const MANIFEST_CRD_YAML: &str =
        include_str!("../../../../deploy/manifests/crds/coxswainbackendpolicies.yaml");
    const CHART_CRD_YAML: &str =
        include_str!("../../../../charts/coxswain/crds/coxswainbackendpolicies.yaml");

    fn parse_cr(spec_fragment: &str) -> CoxswainBackendPolicy {
        let indented = spec_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: CoxswainBackendPolicy\n\
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
        let generated = CoxswainBackendPolicy::crd();
        assert_eq!(
            on_disk, generated,
            "deploy/manifests/crds/coxswainbackendpolicies.yaml drifted from the Rust type. \
             Regenerate: cargo run -p coxswain-core --example crdgen -- CoxswainBackendPolicy \
             > deploy/manifests/crds/coxswainbackendpolicies.yaml \
             && cp deploy/manifests/crds/coxswainbackendpolicies.yaml \
             charts/coxswain/crds/coxswainbackendpolicies.yaml",
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
        let cr = parse_cr(concat!(
            "targetRefs:\n",
            "- group: \"\"\n",
            "  kind: Service\n",
            "  name: my-svc",
        ));
        assert_eq!(cr.spec.target_refs.len(), 1);
        assert_eq!(cr.spec.target_refs[0].kind, "Service");
        assert!(cr.spec.timeouts.is_none());
    }

    #[test]
    fn full_spec_round_trips() {
        let cr = parse_cr(concat!(
            "targetRefs:\n",
            "- group: \"\"\n",
            "  kind: Service\n",
            "  name: my-svc\n",
            "timeouts:\n",
            "  connect: 500ms\n",
            "  idle: 60s",
        ));
        let t = cr.spec.timeouts.as_ref().expect("timeouts present");
        assert_eq!(t.connect.as_deref(), Some("500ms"));
        assert_eq!(t.idle.as_deref(), Some("60s"));
    }

    #[test]
    fn group_defaults_to_core() {
        // `group` omitted → core group "" (a Service reference).
        let cr = parse_cr(concat!(
            "targetRefs:\n",
            "- kind: Service\n",
            "  name: my-svc",
        ));
        assert_eq!(cr.spec.target_refs[0].group, "");
    }
}
