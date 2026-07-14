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
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::preserve_unknown_fields_schema;

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
#[derive(Default)]
pub struct CoxswainGatewayParametersSpec {
    /// Desired replica count for the provisioned proxy Deployment. When
    /// omitted, falls back to a layer-up default (GatewayClass-level params or
    /// the controller's built-in default of `1`).
    ///
    /// Every field on this spec is `Option` so a per-field overlay between
    /// the GatewayClass's and Gateway's `parametersRef`s can distinguish
    /// "operator omitted this field" from "operator set it to the default
    /// value". Without the `Option` wrap, a Gateway-level override silently
    /// masks the class's setting whenever the override's value happens to
    /// equal the type's natural default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<u32>,

    /// Optional resource requests/limits applied to the proxy container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,

    /// Override the proxy image. When `None`, the controller's default image
    /// (matching the running controller version) is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// Service type for the provisioned proxy Service. When omitted, falls
    /// back to [`ServiceType::LoadBalancer`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_type: Option<ServiceType>,

    /// Raw partial PodTemplateSpec applied on top of the controller-rendered
    /// template — escape hatch for fields not yet first-classed above
    /// (nodeSelector, tolerations, env, sidecars, securityContext).
    ///
    /// The field is opaque to the CRD validator (`x-kubernetes-preserve-unknown-fields`);
    /// the controller is responsible for merging and validating its contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "preserve_unknown_fields_schema")]
    pub pod_template: Option<serde_json::Value>,

    /// Horizontal autoscaling for the provisioned proxy Deployment. When
    /// `enabled` is `true`, the controller provisions an HPA targeting the
    /// dedicated-proxy Deployment; the Deployment's `spec.replicas` is left
    /// unset so the HPA is the sole authority on replica count. When `enabled`
    /// is `false` (the default), the static `replicas` field governs.
    ///
    /// The controller also provisions a PDB whenever the effective replica
    /// floor is ≥ 2: `min_replicas` when autoscaling is enabled, otherwise
    /// `replicas`. A PDB with fewer than 2 replicas is counterproductive
    /// (either blocks drain permanently or allows a full outage).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autoscaling: Option<AutoscalingParams>,
}

/// Horizontal autoscaling parameters for the controller-provisioned dedicated
/// proxy Deployment.
///
/// When `enabled` is `true`, the controller provisions a `HorizontalPodAutoscaler`
/// alongside the Deployment and leaves `Deployment.spec.replicas` unset so the
/// HPA is the sole authority on replica count. The controller also provisions a
/// `PodDisruptionBudget` (maxUnavailable: 1) when `min_replicas >= 2`.
///
/// When `enabled` is `false` (default), the static
/// [`CoxswainGatewayParametersSpec::replicas`] governs and the HPA is not
/// provisioned.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AutoscalingParams {
    /// When `true`, the controller provisions an HPA for the dedicated proxy
    /// Deployment. Must be set explicitly; the `Default` is `false`.
    #[serde(default)]
    pub enabled: bool,

    /// Minimum number of replicas the HPA may scale down to. When omitted,
    /// the HPA's own default (currently 1 in Kubernetes) applies. Set to ≥ 2
    /// for an HA configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_replicas: Option<u32>,

    /// Maximum number of replicas the HPA may scale up to. When omitted,
    /// no explicit cap is set (the HPA's own unlimited behaviour applies).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_replicas: Option<u32>,

    /// Target CPU utilization percentage the HPA aims to maintain.
    /// Canonical Kubernetes casing is preserved via the explicit rename.
    #[serde(
        rename = "targetCPUUtilizationPercentage",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub target_cpu_utilization_percentage: Option<u32>,
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

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use crate::crd::{
        AutoscalingParams, CoxswainGatewayParameters, CoxswainGatewayParametersSpec, ServiceType,
    };
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResourceExt;

    const MANIFEST_CRD_YAML: &str =
        include_str!("../../../../deploy/manifests/crds/coxswaingatewayparameters.yaml");
    const CHART_CRD_YAML: &str =
        include_str!("../../../../charts/coxswain/crds/coxswaingatewayparameters.yaml");
    const SAMPLE_FIXTURE_YAML: &str =
        include_str!("../../../../deploy/dev/sample-gateway-parameters.yaml");

    fn parse_cr(spec_fragment: &str) -> CoxswainGatewayParameters {
        let indented = spec_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: CoxswainGatewayParameters\n\
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
        let generated = CoxswainGatewayParameters::crd();
        assert_eq!(
            on_disk, generated,
            "deploy/manifests/crds/coxswaingatewayparameters.yaml drifted from the Rust type. \
             Regenerate: cargo run -p coxswain-core --example crdgen \
             > deploy/manifests/crds/coxswaingatewayparameters.yaml \
             && cp deploy/manifests/crds/coxswaingatewayparameters.yaml \
             charts/coxswain/crds/coxswaingatewayparameters.yaml",
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
    fn empty_spec_leaves_all_fields_unset() {
        let cr = parse_cr("{}");
        assert!(cr.spec.replicas.is_none());
        assert!(cr.spec.service_type.is_none());
        assert!(cr.spec.image.is_none());
        assert!(cr.spec.resources.is_none());
        assert!(cr.spec.pod_template.is_none());
        assert!(cr.spec.autoscaling.is_none());
    }

    #[test]
    fn partial_specs_leave_unmentioned_fields_unset() {
        let cases: &[(&str, &str, CoxswainGatewayParametersSpec)] = &[
            (
                "replicas only",
                "replicas: 7",
                CoxswainGatewayParametersSpec {
                    replicas: Some(7),
                    ..Default::default()
                },
            ),
            (
                "image only",
                "image: my-registry/coxswain:custom",
                CoxswainGatewayParametersSpec {
                    image: Some("my-registry/coxswain:custom".into()),
                    ..Default::default()
                },
            ),
            (
                "serviceType NodePort",
                "serviceType: NodePort",
                CoxswainGatewayParametersSpec {
                    service_type: Some(ServiceType::NodePort),
                    ..Default::default()
                },
            ),
            (
                "serviceType ClusterIP",
                "serviceType: ClusterIP",
                CoxswainGatewayParametersSpec {
                    service_type: Some(ServiceType::ClusterIp),
                    ..Default::default()
                },
            ),
        ];
        for (name, fragment, expected) in cases {
            let parsed = parse_cr(fragment).spec;
            assert_eq!(&parsed, expected, "case: {name}");
        }
    }

    #[test]
    fn service_type_unknown_value_is_rejected() {
        let yaml = "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
                    kind: CoxswainGatewayParameters\n\
                    metadata:\n  name: bad\n\
                    spec:\n  serviceType: FooBar\n";
        let err = serde_yaml::from_str::<CoxswainGatewayParameters>(yaml)
            .expect_err("unknown serviceType variant must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("FooBar") || msg.contains("variant"),
            "error should mention the bad variant; got: {msg}",
        );
    }

    #[test]
    fn pod_template_preserves_arbitrary_json() {
        let cr = parse_cr(
            "podTemplate:\n  \
             metadata:\n    labels:\n      tier: edge\n  \
             spec:\n    \
             nodeSelector:\n      zone: us-east-1\n    \
             containers:\n    - name: extra\n      image: sidecar:1.0",
        );
        let pt = cr
            .spec
            .pod_template
            .as_ref()
            .expect("podTemplate must be present");
        assert_eq!(pt["metadata"]["labels"]["tier"], "edge");
        assert_eq!(pt["spec"]["nodeSelector"]["zone"], "us-east-1");
        assert_eq!(pt["spec"]["containers"][0]["name"], "extra");
        assert_eq!(pt["spec"]["containers"][0]["image"], "sidecar:1.0");

        let reserialized = serde_json::to_value(pt).expect("re-serialize");
        assert_eq!(&reserialized, pt, "re-serialization must be lossless");
    }

    #[test]
    fn autoscaling_enabled_round_trips() {
        let cr = parse_cr(
            "autoscaling:\n  enabled: true\n  \
             minReplicas: 2\n  maxReplicas: 10\n  \
             targetCPUUtilizationPercentage: 75",
        );
        let a = cr
            .spec
            .autoscaling
            .as_ref()
            .expect("autoscaling must be present");
        assert!(a.enabled, "enabled must be true");
        assert_eq!(a.min_replicas, Some(2), "minReplicas");
        assert_eq!(a.max_replicas, Some(10), "maxReplicas");
        assert_eq!(
            a.target_cpu_utilization_percentage,
            Some(75),
            "targetCPUUtilizationPercentage"
        );
    }

    #[test]
    fn autoscaling_disabled_default_omits_optional_fields() {
        // Only `enabled: false` — optional subfields should default to None.
        let cr = parse_cr("autoscaling:\n  enabled: false");
        let a = cr
            .spec
            .autoscaling
            .as_ref()
            .expect("autoscaling block present");
        assert!(!a.enabled, "enabled must be false");
        assert!(a.min_replicas.is_none(), "minReplicas absent");
        assert!(a.max_replicas.is_none(), "maxReplicas absent");
        assert!(
            a.target_cpu_utilization_percentage.is_none(),
            "targetCPUUtilizationPercentage absent"
        );
    }

    #[test]
    fn autoscaling_serializes_target_cpu_with_canonical_casing() {
        // Verify the explicit rename produces "targetCPUUtilizationPercentage"
        // (uppercase CPU), not "targetCpuUtilizationPercentage" (camelCase default).
        let params = AutoscalingParams {
            enabled: true,
            target_cpu_utilization_percentage: Some(80),
            ..Default::default()
        };
        let json = serde_json::to_value(&params).expect("serialize");
        assert!(
            json.get("targetCPUUtilizationPercentage").is_some(),
            "canonical casing 'targetCPUUtilizationPercentage' must be present; got: {json}"
        );
        assert!(
            json.get("targetCpuUtilizationPercentage").is_none(),
            "camelCase 'targetCpuUtilizationPercentage' must NOT be present"
        );
    }

    #[test]
    fn sample_dev_fixture_deserializes() {
        let parsed: CoxswainGatewayParameters = serde_yaml::from_str(SAMPLE_FIXTURE_YAML)
            .unwrap_or_else(|e| panic!("dev sample fixture must deserialize: {e}"));
        assert_eq!(parsed.spec.replicas, Some(2));
        assert_eq!(parsed.spec.service_type, Some(ServiceType::LoadBalancer));
        assert_eq!(
            parsed.spec.image.as_deref(),
            Some("ghcr.io/coxswain-labs/coxswain:latest"),
        );
        assert!(parsed.spec.resources.is_some(), "resources block present");
        assert!(parsed.spec.pod_template.is_some(), "podTemplate present");
    }
}
