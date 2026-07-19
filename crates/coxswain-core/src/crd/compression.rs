//! `Compression` CRD — per-route response-compression policy for Gateway-API
//! `HTTPRoute`s.
//!
//! Attached to an `HTTPRouteRule` via an `ExtensionRef` filter (group
//! `gateway.coxswain-labs.dev`, kind `Compression`). The reflector resolves
//! the named CR into a [`CompressionConfig`] — the same type the Ingress
//! `compression-*` annotations produce.
//!
//! This is the Gateway-API surface for the Ingress `compression-*`
//! annotations (#270). gRPC compresses per-message at the gRPC framing layer
//! (`grpc-encoding`), not HTTP `Content-Encoding` — compressing a gRPC body
//! would corrupt framing — so this filter is **not** supported on
//! `GRPCRoute`, and the proxy skips compression for any response whose
//! `Content-Type` starts with `application/grpc` even on an `HTTPRoute`
//! (#446).
//!
//! Source of truth is the Rust type below; the on-disk CRD YAML
//! (`deploy/manifests/crds/compressions.yaml` and
//! `charts/coxswain/crds/compressions.yaml`) is generated from it by
//! `examples/crdgen.rs` and pinned by a snapshot test.
//!
//! [`CompressionConfig`]: crate::routing::CompressionConfig

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Response-compression policy for an `HTTPRoute` rule.
///
/// Reference this CR from an `HTTPRouteRule.filters` entry with
/// `type: ExtensionRef` pointing at `group: gateway.coxswain-labs.dev`,
/// `kind: Compression`. At least one of [`gzip`](Self::gzip) /
/// [`brotli`](Self::brotli) must be `true` for the filter to have any effect;
/// when both are `false` (the default) the CR is a no-op.
#[derive(CustomResource, Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.coxswain-labs.dev",
    version = "v1alpha1",
    kind = "Compression",
    plural = "compressions",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct CompressionSpec {
    /// Compress responses with gzip when the client advertises `gzip` in
    /// `Accept-Encoding`. Defaults to `false`.
    #[serde(default)]
    pub gzip: bool,
    /// Compress responses with brotli when the client advertises `br` in
    /// `Accept-Encoding`. Brotli is preferred over gzip when both are enabled.
    /// Defaults to `false`.
    #[serde(default)]
    pub brotli: bool,
    /// Compression level, `1`–`9` (default `6` when absent). Applies to both
    /// gzip and brotli.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    /// Minimum response body size in bytes below which compression is
    /// skipped (default `1024`). Compared against `Content-Length` when
    /// present; chunked responses are always compressed regardless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_size: Option<u64>,
    /// Allow-list of media types (the part of `Content-Type` before `;`)
    /// eligible for compression. Defaults to `["text/html", "text/plain",
    /// "text/css", "application/json", "application/javascript"]` when
    /// absent or empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<String>,
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResourceExt;

    const MANIFEST_CRD_YAML: &str =
        include_str!("../../../../deploy/manifests/crds/compressions.yaml");
    const CHART_CRD_YAML: &str = include_str!("../../../../charts/coxswain/crds/compressions.yaml");

    fn parse_cr(spec_fragment: &str) -> Compression {
        let indented = spec_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: Compression\n\
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
        let generated = Compression::crd();
        assert_eq!(
            on_disk, generated,
            "deploy/manifests/crds/compressions.yaml drifted from the Rust type. \
             Regenerate: cargo run -p coxswain-core --example crdgen -- Compression \
             > deploy/manifests/crds/compressions.yaml \
             && cp deploy/manifests/crds/compressions.yaml \
             charts/coxswain/crds/compressions.yaml",
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
    fn empty_spec_defaults_both_disabled() {
        let cr = parse_cr("{}");
        assert!(!cr.spec.gzip);
        assert!(!cr.spec.brotli);
        assert!(cr.spec.level.is_none());
        assert!(cr.spec.min_size.is_none());
        assert!(cr.spec.types.is_empty());
    }

    #[test]
    fn gzip_only_parses() {
        let cr = parse_cr("gzip: true");
        assert!(cr.spec.gzip);
        assert!(!cr.spec.brotli);
    }

    #[test]
    fn full_spec_parses() {
        let cr = parse_cr(
            "gzip: true\nbrotli: true\nlevel: 9\nminSize: 512\ntypes:\n- text/plain\n- application/json",
        );
        assert!(cr.spec.gzip);
        assert!(cr.spec.brotli);
        assert_eq!(cr.spec.level, Some(9));
        assert_eq!(cr.spec.min_size, Some(512));
        assert_eq!(cr.spec.types, vec!["text/plain", "application/json"]);
    }
}
