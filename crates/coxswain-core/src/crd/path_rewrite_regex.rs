//! `PathRewriteRegex` CRD — per-route path rewrite policy for Gateway-API routes.
//!
//! Attached to an `HTTPRouteRule` via an `ExtensionRef` filter (group
//! `coxswain-labs.dev`, kind `PathRewriteRegex`). The reflector resolves the named CR
//! from this CRD and translates it into a `RegexReplace` path modifier.
//!
//! Source of truth is the Rust type below; the on-disk CRD YAML
//! (`deploy/manifests/crds/pathrewriteregexes.yaml` and
//! `charts/coxswain/crds/pathrewriteregexes.yaml`) is generated from it by
//! `examples/crdgen.rs` and pinned by a snapshot test.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Path rewrite policy using regular expressions.
///
/// Reference this CR from an `HTTPRouteRule.filters` entry with
/// `type: ExtensionRef` pointing at `group: coxswain-labs.dev`,
/// `kind: PathRewriteRegex`.
#[derive(CustomResource, Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "coxswain-labs.dev",
    version = "v1alpha1",
    kind = "PathRewriteRegex",
    plural = "pathrewriteregexes",
    namespaced
)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PathRewriteRegexSpec {
    /// Regular expression pattern to match against the request path.
    ///
    /// Must be a valid Rust `regex` crate pattern.
    pub pattern: String,

    /// Replacement string, which can include capture group references like `$1`.
    pub replacement: String,
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResourceExt;

    const MANIFEST_CRD_YAML: &str =
        include_str!("../../../../deploy/manifests/crds/pathrewriteregexes.yaml");
    const CHART_CRD_YAML: &str =
        include_str!("../../../../charts/coxswain/crds/pathrewriteregexes.yaml");

    #[test]
    fn committed_manifest_crd_matches_generator() {
        let on_disk: CustomResourceDefinition = serde_yaml::from_str(MANIFEST_CRD_YAML)
            .unwrap_or_else(|e| panic!("committed CRD YAML must deserialize: {e}"));
        let generated = PathRewriteRegex::crd();
        assert_eq!(
            on_disk, generated,
            "deploy/manifests/crds/pathrewriteregexes.yaml drifted from the Rust type. \
             Regenerate: cargo run -p coxswain-core --example crdgen -- PathRewriteRegex \
             > deploy/manifests/crds/pathrewriteregexes.yaml \
             && cp deploy/manifests/crds/pathrewriteregexes.yaml \
             charts/coxswain/crds/pathrewriteregexes.yaml",
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
}
