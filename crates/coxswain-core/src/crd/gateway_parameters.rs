//! `CoxswainGatewayParameters` CRD — per-Gateway configuration for the
//! dedicated-proxy mode opted into via `Gateway.spec.infrastructure.parametersRef`
//! or `GatewayClass.spec.parametersRef`.
//!
//! The CRD is inert at this stage: the type compiles and the YAML installs,
//! but no controller code reads it yet. Presence of a `parametersRef` pointing
//! at this CRD will become the dedicated-mode opt-in signal in later steps.
//!
//! Source of truth is the Rust type below; the on-disk CRD YAML
//! (`deploy/manifests/crds/coxswaingatewayparameters.yaml` and
//! `charts/coxswain/crds/coxswaingatewayparameters.yaml`) is generated from it
//! by `examples/crdgen.rs` and pinned by a snapshot test.

use k8s_openapi::api::core::v1::ResourceRequirements;
use kube::CustomResource;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

/// Per-Gateway parameters consumed by the dedicated-proxy provisioner.
///
/// Referenced from `Gateway.spec.infrastructure.parametersRef` or
/// `GatewayClass.spec.parametersRef`. The presence of such a reference is the
/// dedicated-mode opt-in; the fields below tune the resulting proxy.
#[derive(CustomResource, Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.coxswain-labs.dev",
    version = "v1alpha1",
    kind = "CoxswainGatewayParameters",
    plural = "coxswaingatewayparameters",
    namespaced
)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CoxswainGatewayParametersSpec {
    /// Desired replica count for the provisioned proxy Deployment. Defaults to `1`.
    #[serde(default = "default_replicas")]
    pub replicas: u32,

    /// Optional resource requests/limits applied to the proxy container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,

    /// Override the proxy image. When `None`, the controller's default image
    /// (matching the running controller version) is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// Service type for the provisioned proxy Service. Defaults to
    /// [`ServiceType::LoadBalancer`].
    #[serde(default)]
    pub service_type: ServiceType,

    /// Raw partial PodTemplateSpec applied on top of the controller-rendered
    /// template — escape hatch for fields not yet first-classed above
    /// (nodeSelector, tolerations, env, sidecars, securityContext).
    ///
    /// The field is opaque to the CRD validator (`x-kubernetes-preserve-unknown-fields`);
    /// the controller is responsible for merging and validating its contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "preserve_unknown_fields_schema")]
    pub pod_template: Option<serde_json::Value>,
}

impl Default for CoxswainGatewayParametersSpec {
    fn default() -> Self {
        Self {
            replicas: default_replicas(),
            resources: None,
            image: None,
            service_type: ServiceType::default(),
            pod_template: None,
        }
    }
}

/// Service type for the provisioned proxy Service.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[non_exhaustive]
pub enum ServiceType {
    /// Provision a cloud LoadBalancer (default).
    #[default]
    LoadBalancer,
    /// Expose the proxy on each node's IP at a static port.
    NodePort,
    /// Cluster-internal only; no external address allocated.
    #[serde(rename = "ClusterIP")]
    ClusterIp,
}

fn default_replicas() -> u32 {
    1
}

fn preserve_unknown_fields_schema(_: &mut SchemaGenerator) -> Schema {
    serde_json::from_value(serde_json::json!({
        "type": "object",
        "x-kubernetes-preserve-unknown-fields": true,
    }))
    .unwrap_or_else(|e| panic!("invariant: preserve-unknown-fields schema is a valid Schema: {e}"))
}
