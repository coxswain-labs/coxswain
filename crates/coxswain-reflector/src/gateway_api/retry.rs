//! `RetryPolicy` resolution (#551): spec → runtime `RetryPolicyConfig`
//! translation shared by the route-level `ExtensionRef` filter (in
//! [`super::filters`]) and the Ingress `retry` annotation (`crate::ingress`).
//!
//! Like [`super::compression`] and [`super::jwt_auth`], there is nothing to
//! resolve besides the CR's own fields — no `backendRef`, no external cache
//! lookup — so `resolve_spec` is pure, synchronous spec→config translation.
//! The one wrinkle versus those siblings is protocol: `GRPCRoute` also honours
//! `grpcCodes` (defaulted when absent), `HTTPRoute` and Ingress (HTTP-only)
//! ignore it — hence the `is_grpc` flag.

use coxswain_core::crd::RetryPolicySpec;
use coxswain_core::routing::RetryPolicyConfig;

/// Resolve a `RetryPolicy` spec into the runtime [`RetryPolicyConfig`] the
/// proxy enforces.
///
/// Absent `attempts` defaults to `1`; an explicit `0` disables retrying
/// (handled by [`RetryPolicyConfig::is_disabled`]). An unparseable `backoff`
/// emits a `WARN` (keyed by `ctx` — the route or Ingress id) and applies no
/// delay rather than failing the resolve. `is_grpc` selects `grpcCodes`
/// defaulting (`GRPCRoute` only); `HTTPRoute` and Ingress always pass `false`.
///
/// Never fails — the caller (the `ExtensionRef` scanner or the Ingress
/// resolver) is responsible for the *missing CR* fail-open case, returning
/// [`RetryPolicyConfig::default()`] itself.
///
/// `pub(crate)` (not `pub(super)` like most Gateway API spec resolvers) —
/// reused directly by [`crate::ingress::reconcile_helpers`] so the Ingress
/// `retry` annotation resolves to the identical [`RetryPolicyConfig`] the
/// HTTPRoute `ExtensionRef` filter produces (Gateway API parity, #551).
#[must_use]
pub(crate) fn resolve_spec(spec: &RetryPolicySpec, is_grpc: bool, ctx: &str) -> RetryPolicyConfig {
    // Absent `attempts` defaults to 1; an explicit 0 disables (handled by the config).
    let attempts = spec.attempts.unwrap_or(1);
    let backoff = spec.backoff.as_deref().and_then(|s| {
        let d = crate::duration::parse_duration(s);
        if d.is_none() {
            tracing::warn!(
                ctx,
                value = s,
                "RetryPolicy backoff is not a valid duration — no backoff applied"
            );
        }
        d
    });
    let http_codes = spec.codes.clone();
    if is_grpc {
        RetryPolicyConfig::for_grpc(attempts, backoff, http_codes, spec.grpc_codes.clone())
    } else {
        RetryPolicyConfig::for_http(attempts, backoff, http_codes)
    }
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use coxswain_core::crd::RetryPolicy;

    fn spec_with(yaml_fragment: &str) -> RetryPolicySpec {
        let indented = yaml_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: RetryPolicy\n\
             metadata:\n  name: t\n\
             spec:\n  {indented}\n",
        );
        serde_yaml::from_str::<RetryPolicy>(&yaml)
            .unwrap_or_else(|e| panic!("bad yaml: {e}\n---\n{yaml}"))
            .spec
    }

    #[test]
    fn absent_attempts_defaults_to_one() {
        let cfg = resolve_spec(&spec_with("{}"), false, "test");
        assert_eq!(cfg.attempts, 1);
        assert!(!cfg.is_disabled());
    }

    #[test]
    fn explicit_zero_attempts_disables() {
        let cfg = resolve_spec(&spec_with("attempts: 0"), false, "test");
        assert!(cfg.is_disabled());
    }

    #[test]
    fn http_defaults_codes_when_omitted() {
        let cfg = resolve_spec(&spec_with("attempts: 3"), false, "test");
        assert_eq!(&*cfg.http_codes, &[502, 503, 504]);
        assert!(cfg.grpc_codes.is_empty());
    }

    #[test]
    fn http_explicit_codes_and_backoff() {
        let cfg = resolve_spec(
            &spec_with("attempts: 2\ncodes: [500, 503]\nbackoff: 100ms"),
            false,
            "test",
        );
        assert_eq!(&*cfg.http_codes, &[500, 503]);
        assert_eq!(cfg.backoff, Some(std::time::Duration::from_millis(100)));
    }

    #[test]
    fn grpc_defaults_grpc_codes_when_omitted() {
        let cfg = resolve_spec(&spec_with("attempts: 1"), true, "test");
        assert_eq!(&*cfg.grpc_codes, &[14]);
    }

    #[test]
    fn grpc_explicit_empty_codes_opts_out() {
        let cfg = resolve_spec(&spec_with("attempts: 1\ngrpcCodes: []"), true, "test");
        assert!(cfg.grpc_codes.is_empty());
    }

    #[test]
    #[tracing_test::traced_test]
    fn invalid_backoff_warns_and_applies_none() {
        let cfg = resolve_spec(&spec_with("attempts: 1\nbackoff: bogus"), false, "test");
        assert!(cfg.backoff.is_none());
        assert!(logs_contain("RetryPolicy backoff is not a valid duration"));
    }
}
