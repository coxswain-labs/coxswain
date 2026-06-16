//! `CoxswainIngressClassParameters` CRD — per-class annotation defaults for the
//! Ingress data plane, referenced from `IngressClass.spec.parameters`.
//!
//! The reflector resolves `IngressClass.spec.parameters` and merges
//! `spec.defaultAnnotations` under each Ingress's own annotation map (#190): a
//! per-Ingress annotation overrides the class default for that key.
//!
//! ## Design rationale
//!
//! The spec is a flat `defaultAnnotations` string-map rather than a typed
//! struct mirroring each annotation. v0.3 adds ~22 new
//! `ingress.coxswain-labs.dev/*` annotations; a typed struct would force
//! every annotation PR to also add a CRD field + override-merge logic. The
//! map defaults the entire annotation namespace — current and future — with
//! zero CRD churn, and matches #190's wording: *"applied as defaults to all
//! Ingress objects claiming that class (can be overridden by per-Ingress
//! annotations)."*
//!
//! ## Override precedence (implemented in #190)
//!
//! 1. Per-Ingress annotation key present → wins.
//! 2. `spec.defaultAnnotations` value for that key.
//! 3. Built-in Coxswain default.
//!
//! ## Multi-class behaviour
//!
//! Coxswain owns every `IngressClass` whose `spec.controller` matches the
//! running controller name. Each owned class can reference its own
//! `CoxswainIngressClassParameters` CR, yielding distinct default maps all
//! served by the same proxy pool. The CR's namespace is a storage location
//! only; the linkage is Ingress → className → IngressClass → CR.
//!
//! Source of truth is the Rust type below; the on-disk CRD YAML
//! (`deploy/manifests/crds/coxswainingressclassparameters.yaml` and
//! `charts/coxswain/crds/coxswainingressclassparameters.yaml`) is generated
//! from it by `examples/crdgen.rs` and pinned by a snapshot test.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Per-class annotation defaults for the Ingress data plane.
///
/// Referenced from `IngressClass.spec.parameters` with
/// `apiGroup: ingress.coxswain-labs.dev` and `scope: Namespace`.
/// Presence of such a reference enables class-level defaults; the fields
/// below supply the default values for every Ingress claiming that class.
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "ingress.coxswain-labs.dev",
    version = "v1alpha1",
    kind = "CoxswainIngressClassParameters",
    plural = "coxswainingressclassparameters",
    namespaced
)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CoxswainIngressClassParametersSpec {
    /// Default `ingress.coxswain-labs.dev/*` annotation values applied to
    /// every Ingress claiming this class.
    ///
    /// Keys must be valid `ingress.coxswain-labs.dev/*` annotation names.
    /// Values follow the same format and validation rules as the corresponding
    /// per-Ingress annotations — invalid values emit a `WARN` at reconcile
    /// time and fall back to the built-in default, exactly as they would if
    /// set directly on an Ingress.
    ///
    /// Per-Ingress annotations override on a per-key basis: a key present in
    /// the Ingress's own annotation map wins over the class default for that
    /// key; unmentioned keys still inherit the class default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_annotations: Option<BTreeMap<String, String>>,
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use crate::crd::{CoxswainIngressClassParameters, CoxswainIngressClassParametersSpec};
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResourceExt;

    const MANIFEST_CRD_YAML: &str =
        include_str!("../../../../deploy/manifests/crds/coxswainingressclassparameters.yaml");
    const CHART_CRD_YAML: &str =
        include_str!("../../../../charts/coxswain/crds/coxswainingressclassparameters.yaml");
    const SAMPLE_FIXTURE_YAML: &str =
        include_str!("../../../../deploy/dev/sample-ingress-class-parameters.yaml");

    fn parse_cr(spec_fragment: &str) -> CoxswainIngressClassParameters {
        let indented = spec_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: ingress.coxswain-labs.dev/v1alpha1\n\
             kind: CoxswainIngressClassParameters\n\
             metadata:\n  name: t\n  namespace: default\n\
             spec:\n  {indented}\n",
        );
        serde_yaml::from_str(&yaml)
            .unwrap_or_else(|e| panic!("parse failed: {e}\n--- yaml ---\n{yaml}"))
    }

    #[test]
    fn committed_manifest_crd_matches_generator() {
        let on_disk: CustomResourceDefinition = serde_yaml::from_str(MANIFEST_CRD_YAML)
            .unwrap_or_else(|e| panic!("committed CRD YAML must deserialize: {e}"));
        let generated = CoxswainIngressClassParameters::crd();
        assert_eq!(
            on_disk, generated,
            "deploy/manifests/crds/coxswainingressclassparameters.yaml drifted from the Rust type. \
             Regenerate: cargo run -p coxswain-core --example crdgen -- IngressClassParameters \
             > deploy/manifests/crds/coxswainingressclassparameters.yaml \
             && cp deploy/manifests/crds/coxswainingressclassparameters.yaml \
             charts/coxswain/crds/coxswainingressclassparameters.yaml",
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
    fn empty_spec_leaves_default_annotations_unset() {
        let cr = parse_cr("{}");
        assert!(cr.spec.default_annotations.is_none());
    }

    #[test]
    fn default_annotations_round_trip() {
        let cr = parse_cr(
            "defaultAnnotations:\n  \
             ingress.coxswain-labs.dev/connect-timeout: \"5s\"\n  \
             ingress.coxswain-labs.dev/retry-on: \"5xx,connect-failure\"\n  \
             ingress.coxswain-labs.dev/max-retries: \"2\"",
        );
        let ann = cr
            .spec
            .default_annotations
            .as_ref()
            .expect("defaultAnnotations must be present");
        assert_eq!(
            ann.get("ingress.coxswain-labs.dev/connect-timeout")
                .map(String::as_str),
            Some("5s"),
        );
        assert_eq!(
            ann.get("ingress.coxswain-labs.dev/retry-on")
                .map(String::as_str),
            Some("5xx,connect-failure"),
        );
        assert_eq!(
            ann.get("ingress.coxswain-labs.dev/max-retries")
                .map(String::as_str),
            Some("2"),
        );

        // Re-serialize and re-parse: round-trip must be lossless.
        let reserialized = serde_json::to_value(&cr.spec).expect("spec must serialize to JSON");
        let reparsed: CoxswainIngressClassParametersSpec =
            serde_json::from_value(reserialized).expect("reserialized spec must round-trip");
        assert_eq!(cr.spec, reparsed);
    }

    #[test]
    fn empty_default_annotations_map_round_trips() {
        let cr = parse_cr("defaultAnnotations: {}");
        // An explicit empty map is Some(BTreeMap::new()), not None.
        let ann = cr
            .spec
            .default_annotations
            .as_ref()
            .expect("explicit empty map must be Some");
        assert!(ann.is_empty());
    }

    #[test]
    fn sample_dev_fixture_deserializes() {
        // The fixture is a multi-doc YAML (two CRs). Collect and parse all
        // non-comment documents (the header comment block is not a YAML doc).
        let crs: Vec<CoxswainIngressClassParameters> =
            serde_yaml::Deserializer::from_str(SAMPLE_FIXTURE_YAML)
                .map(|de| {
                    serde::de::Deserialize::deserialize(de)
                        .unwrap_or_else(|e| panic!("fixture document must deserialize: {e}"))
                })
                .collect();

        assert_eq!(crs.len(), 2, "fixture must contain exactly two documents");
        for (i, cr) in crs.iter().enumerate() {
            assert!(
                cr.spec.default_annotations.is_some(),
                "fixture document {i} must have defaultAnnotations"
            );
        }
        // First CR: public-defaults — check a known key is present.
        let public_ann = crs[0].spec.default_annotations.as_ref().unwrap();
        assert!(
            public_ann.contains_key("ingress.coxswain-labs.dev/connect-timeout"),
            "public-defaults must set connect-timeout"
        );
        // Second CR: internal-defaults — tighter timeout.
        let internal_ann = crs[1].spec.default_annotations.as_ref().unwrap();
        assert_eq!(
            internal_ann
                .get("ingress.coxswain-labs.dev/connect-timeout")
                .map(String::as_str),
            Some("1s"),
            "internal-defaults connect-timeout must be 1s"
        );
    }
}
