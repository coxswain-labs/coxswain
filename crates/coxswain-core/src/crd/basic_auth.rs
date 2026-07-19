//! `BasicAuth` CRD — per-route HTTP Basic authentication for Gateway-API
//! `HTTPRoute`s.
//!
//! Attached to an `HTTPRouteRule` via an `ExtensionRef` filter (group
//! `gateway.coxswain-labs.dev`, kind `BasicAuth`). The reflector resolves the
//! named CR's `secretRef`, reads the referenced htpasswd `Secret`, and
//! produces the same [`IngressAuthConfig`] the Ingress `auth-basic-secret`
//! annotation feeds — same label-scoped Secret lookup, same fail-closed
//! ladder (missing Secret / missing label / unparseable `auth` key / zero
//! parseable entries → `Unavailable` → `503`).
//!
//! This is the Gateway-API surface for the Ingress `auth-basic-secret`
//! annotation (#24). HTTP Basic auth is a browser/HTTP idiom — gRPC clients
//! authenticate with bearer tokens or mTLS instead — so this filter is
//! **not** supported on `GRPCRoute` (#442).
//!
//! Source of truth is the Rust type below; the on-disk CRD YAML
//! (`deploy/manifests/crds/basicauths.yaml` and
//! `charts/coxswain/crds/basicauths.yaml`) is generated from it by
//! `examples/crdgen.rs` and pinned by a snapshot test.
//!
//! [`IngressAuthConfig`]: crate::routing::IngressAuthConfig

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// HTTP Basic authentication policy for an `HTTPRoute` rule.
///
/// Reference this CR from an `HTTPRouteRule.filters` entry with
/// `type: ExtensionRef` pointing at `group: gateway.coxswain-labs.dev`,
/// `kind: BasicAuth`. The proxy validates `Authorization: Basic` against the
/// credentials in the referenced htpasswd `Secret`; a missing/invalid
/// credential responds `401` with `WWW-Authenticate`, and a missing,
/// unlabeled, or unparseable Secret fails closed with `503`.
#[derive(CustomResource, Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.coxswain-labs.dev",
    version = "v1alpha1",
    kind = "BasicAuth",
    plural = "basicauths",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct BasicAuthSpec {
    /// Reference to the htpasswd `Secret` carrying credentials.
    pub secret_ref: BasicAuthSecretRef,
}

/// Reference to a htpasswd `Secret` consumed by a [`BasicAuth`] policy.
///
/// The Secret **must** carry the label
/// `ingress.coxswain-labs.dev/auth-basic: "true"` and store the htpasswd file
/// under the key `auth` (nginx convention) — identical requirements to the
/// Ingress `auth-basic-secret` annotation, so the same Secret can back both
/// surfaces.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BasicAuthSecretRef {
    /// Secret name.
    pub name: String,
    /// Secret namespace. Required — mirrors the explicit `namespace/name`
    /// form of the Ingress `auth-basic-secret` annotation; no `ReferenceGrant`
    /// is required for cross-namespace refs, matching that precedent.
    pub namespace: String,
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResourceExt;

    const MANIFEST_CRD_YAML: &str =
        include_str!("../../../../deploy/manifests/crds/basicauths.yaml");
    const CHART_CRD_YAML: &str = include_str!("../../../../charts/coxswain/crds/basicauths.yaml");

    fn parse_cr(spec_fragment: &str) -> BasicAuth {
        let indented = spec_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: BasicAuth\n\
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
        let generated = BasicAuth::crd();
        assert_eq!(
            on_disk, generated,
            "deploy/manifests/crds/basicauths.yaml drifted from the Rust type. \
             Regenerate: cargo run -p coxswain-core --example crdgen -- BasicAuth \
             > deploy/manifests/crds/basicauths.yaml \
             && cp deploy/manifests/crds/basicauths.yaml \
             charts/coxswain/crds/basicauths.yaml",
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
    fn secret_ref_parses() {
        let cr = parse_cr("secretRef:\n  name: my-htpasswd\n  namespace: default");
        assert_eq!(cr.spec.secret_ref.name, "my-htpasswd");
        assert_eq!(cr.spec.secret_ref.namespace, "default");
    }

    #[test]
    fn missing_secret_ref_is_rejected() {
        let yaml = "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
                    kind: BasicAuth\n\
                    metadata:\n  name: bad\n\
                    spec:\n  {}\n";
        serde_yaml::from_str::<BasicAuth>(yaml).expect_err("missing secretRef must be rejected");
    }

    #[test]
    fn missing_namespace_is_rejected() {
        let yaml = "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
                    kind: BasicAuth\n\
                    metadata:\n  name: bad\n\
                    spec:\n  secretRef:\n    name: my-htpasswd\n";
        serde_yaml::from_str::<BasicAuth>(yaml).expect_err("missing namespace must be rejected");
    }
}
