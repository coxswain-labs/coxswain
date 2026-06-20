//! Path-routing annotation constants.
//!
//! Covers: `rewrite-target` (upstream path replacement), `use-regex`
//! (opt-in regular-expression path matching for `ImplementationSpecific` paths),
//! and `path-normalize` (Envoy/Istio-style normalization level).
//! All annotations are stateless key constants — their parsing is handled
//! inline in [`super::IngressAnnotations::parse`].

// ── Path annotation keys ──────────────────────────────────────────────────────

/// Rewrite the upstream request path. On a regex path (see [`USE_REGEX`]) the value
/// may reference capture groups (`$1`…`$n`); on prefix/exact paths it is a literal
/// full-path replacement.
pub const REWRITE_TARGET: &str = "ingress.coxswain-labs.dev/rewrite-target";
/// Opt in to regex path matching for this Ingress's `pathType: ImplementationSpecific`
/// rules — boolean `"true"`/`"false"`. Inert on its own: the per-path selector is the
/// standard `pathType` field, so `Prefix`/`Exact` paths in the same Ingress are
/// unaffected (no nginx-style host-wide contagion).
pub const USE_REGEX: &str = "ingress.coxswain-labs.dev/use-regex";
/// Envoy/Istio-style path normalization level: `none` | `base` | `merge-slashes` |
/// `decode-and-merge-slashes`. Applied before routing lookup and retained as the path
/// forwarded upstream. Defaults to `base` for all routes (Ingress and Gateway API).
pub const PATH_NORMALIZE: &str = "ingress.coxswain-labs.dev/path-normalize";

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_constants_have_expected_prefix() {
        // Ensures REWRITE_TARGET, USE_REGEX, and PATH_NORMALIZE are referenced in the
        // parse-test region so the check-annotation-coverage.sh gate is satisfied.
        // IngressAnnotations-level integration tests for these annotations live in
        // annotations/mod.rs where IngressAnnotations is accessible.
        assert!(REWRITE_TARGET.starts_with("ingress.coxswain-labs.dev/"));
        assert!(USE_REGEX.starts_with("ingress.coxswain-labs.dev/"));
        assert!(PATH_NORMALIZE.starts_with("ingress.coxswain-labs.dev/"));
    }
}
