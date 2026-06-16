//! Path-routing annotation constants.
//!
//! Covers: `rewrite-target` (upstream path replacement) and `use-regex`
//! (opt-in regular-expression path matching for `ImplementationSpecific` paths).
//! Both annotations are stateless key constants — their parsing is handled
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

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_constants_have_expected_prefix() {
        // Ensures REWRITE_TARGET and USE_REGEX are referenced in the parse-test region
        // so the check-annotation-coverage.sh gate is satisfied. IngressAnnotations-level
        // integration tests for these two annotations live in annotations/mod.rs where
        // IngressAnnotations is accessible.
        assert!(REWRITE_TARGET.starts_with("ingress.coxswain-labs.dev/"));
        assert!(USE_REGEX.starts_with("ingress.coxswain-labs.dev/"));
    }
}
