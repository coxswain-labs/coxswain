//! `Compression` resolution (#550): spec → runtime `CompressionConfig`
//! translation shared by the route-level `ExtensionRef` filter (in
//! [`super::filters`]) and the Ingress `compression` annotation
//! (`crate::ingress`).
//!
//! Like [`super::jwt_auth`], there is nothing to resolve besides the CR's own
//! fields — no `backendRef`, no external cache lookup — so `resolve_spec` is
//! pure, synchronous spec→config translation.

use coxswain_core::crd::CompressionSpec;
use coxswain_core::routing::CompressionConfig;
use std::sync::Arc;

/// The default MIME-type allow-list for compression, lower-cased.
const DEFAULT_TYPES: &[&str] = &[
    "text/html",
    "text/plain",
    "text/css",
    "application/json",
    "application/javascript",
];

/// Default compression level when `spec.level` is absent or out of range.
const DEFAULT_LEVEL: u32 = 6;
/// Default minimum body size in bytes for compression eligibility.
const DEFAULT_MIN_SIZE: u64 = 1024;

/// Resolve a `Compression` spec into the runtime [`CompressionConfig`] the
/// proxy applies.
///
/// Returns `None` when both `gzip` and `brotli` are `false` (the CRD
/// default) — a no-op the proxy never constructs an encoder for. `level` is
/// clamped to `1..=9` (falling back to `6` when absent or out of range);
/// `min_size` defaults to `1024`; `types` falls back to a common
/// compressible-MIME allow-list when absent or empty.
///
/// `pub(crate)` (not `pub(super)` like most Gateway API spec resolvers) —
/// reused directly by [`crate::ingress::reconcile_helpers`] so the Ingress
/// `compression` annotation resolves to the identical [`CompressionConfig`]
/// the HTTPRoute `ExtensionRef` filter produces (Gateway API parity, #550).
#[must_use]
pub(crate) fn resolve_spec(spec: &CompressionSpec) -> Option<Arc<CompressionConfig>> {
    if !spec.gzip && !spec.brotli {
        return None;
    }
    let level = spec
        .level
        .filter(|l| (1..=9).contains(l))
        .unwrap_or(DEFAULT_LEVEL);
    let min_size = spec.min_size.unwrap_or(DEFAULT_MIN_SIZE);
    let types: Box<[Box<str>]> = if spec.types.is_empty() {
        default_types()
    } else {
        spec.types
            .iter()
            .map(|t| t.to_lowercase().into_boxed_str())
            .collect::<Vec<_>>()
            .into_boxed_slice()
    };
    Some(Arc::new(CompressionConfig::new(
        spec.gzip,
        spec.brotli,
        level,
        min_size,
        types,
    )))
}

fn default_types() -> Box<[Box<str>]> {
    DEFAULT_TYPES
        .iter()
        .map(|s| (*s).into())
        .collect::<Vec<Box<str>>>()
        .into_boxed_slice()
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;

    fn spec_with(yaml_fragment: &str) -> CompressionSpec {
        let indented = yaml_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: Compression\n\
             metadata:\n  name: t\n\
             spec:\n  {indented}\n",
        );
        serde_yaml::from_str::<coxswain_core::crd::Compression>(&yaml)
            .unwrap_or_else(|e| panic!("bad yaml: {e}\n---\n{yaml}"))
            .spec
    }

    #[test]
    fn both_disabled_is_none() {
        assert!(resolve_spec(&spec_with("{}")).is_none());
    }

    #[test]
    fn gzip_only_uses_defaults() {
        let cfg = resolve_spec(&spec_with("gzip: true")).expect("gzip enabled");
        assert!(cfg.gzip);
        assert!(!cfg.brotli);
        assert_eq!(cfg.level, DEFAULT_LEVEL);
        assert_eq!(cfg.min_size, DEFAULT_MIN_SIZE);
        assert_eq!(cfg.types.len(), DEFAULT_TYPES.len());
    }

    #[test]
    fn level_out_of_range_falls_back_to_default() {
        let cfg = resolve_spec(&spec_with("gzip: true\nlevel: 42")).expect("gzip enabled");
        assert_eq!(cfg.level, DEFAULT_LEVEL);
    }

    #[test]
    fn custom_level_and_min_size_applied() {
        let cfg =
            resolve_spec(&spec_with("gzip: true\nlevel: 9\nminSize: 512")).expect("gzip enabled");
        assert_eq!(cfg.level, 9);
        assert_eq!(cfg.min_size, 512);
    }

    #[test]
    fn custom_types_are_lowercased() {
        let cfg =
            resolve_spec(&spec_with("gzip: true\ntypes:\n- TEXT/Plain")).expect("gzip enabled");
        assert_eq!(&*cfg.types[0], "text/plain");
    }

    #[test]
    fn brotli_only_resolves() {
        let cfg = resolve_spec(&spec_with("brotli: true")).expect("brotli enabled");
        assert!(!cfg.gzip);
        assert!(cfg.brotli);
    }
}
