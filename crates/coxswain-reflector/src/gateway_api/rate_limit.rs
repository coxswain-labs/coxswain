//! `RateLimit` resolution (#552): spec → runtime `RateLimitConfig` translation
//! shared by the route-level `ExtensionRef` filter (in [`super::filters`]) and
//! the Ingress `rate-limit` annotation (`crate::ingress`).
//!
//! Like [`super::compression`] and [`super::retry`], there is nothing to
//! resolve besides the CR's own fields — no `backendRef`, no external cache
//! lookup — so `resolve_spec` is pure, synchronous spec→config translation.

use coxswain_core::crd::RateLimitSpec;
use coxswain_core::routing::{RateLimitConfig, RateLimitKey};
use std::num::NonZeroU32;
use std::sync::Arc;

/// Resolve a `RateLimit` spec into the runtime [`RateLimitConfig`] the proxy
/// enforces.
///
/// Returns `None` when `requestsPerSecond` is `0` — a no-op the proxy never
/// installs a limiter for (fail-open). `byHeader` is lowercased into a
/// [`RateLimitKey::Header`]; its absence defaults to [`RateLimitKey::ClientIp`].
///
/// Never fails — the caller (the `ExtensionRef` scanner or the Ingress
/// resolver) is responsible for the *missing CR* fail-open case.
///
/// `pub(crate)` (not `pub(super)` like most Gateway API spec resolvers) —
/// reused directly by [`crate::ingress::reconcile_helpers`] so the Ingress
/// `rate-limit` annotation resolves to the identical [`RateLimitConfig`] the
/// HTTPRoute/GRPCRoute `ExtensionRef` filter produces (Gateway API parity, #552).
#[must_use]
pub(crate) fn resolve_spec(spec: &RateLimitSpec) -> Option<Arc<RateLimitConfig>> {
    let rps = NonZeroU32::new(spec.requests_per_second)?;
    let key = match &spec.by_header {
        Some(h) => RateLimitKey::Header(Arc::from(h.to_ascii_lowercase().as_str())),
        None => RateLimitKey::ClientIp,
    };
    Some(Arc::new(RateLimitConfig::new(rps, spec.burst, key)))
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use coxswain_core::crd::RateLimit;

    fn spec_with(yaml_fragment: &str) -> RateLimitSpec {
        let indented = yaml_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: RateLimit\n\
             metadata:\n  name: t\n\
             spec:\n  {indented}\n",
        );
        serde_yaml::from_str::<RateLimit>(&yaml)
            .unwrap_or_else(|e| panic!("bad yaml: {e}\n---\n{yaml}"))
            .spec
    }

    #[test]
    fn zero_requests_per_second_is_none() {
        assert!(resolve_spec(&spec_with("requestsPerSecond: 0")).is_none());
    }

    #[test]
    fn absent_by_header_defaults_to_client_ip() {
        let cfg = resolve_spec(&spec_with("requestsPerSecond: 10")).expect("resolved");
        assert_eq!(cfg.requests_per_second.get(), 10);
        assert_eq!(cfg.burst, 0);
        assert_eq!(cfg.key, RateLimitKey::ClientIp);
    }

    #[test]
    fn burst_passes_through() {
        let cfg = resolve_spec(&spec_with("requestsPerSecond: 10\nburst: 5")).expect("resolved");
        assert_eq!(cfg.burst, 5);
    }

    #[test]
    fn by_header_is_lowercased() {
        let cfg = resolve_spec(&spec_with("requestsPerSecond: 10\nbyHeader: X-Api-Key"))
            .expect("resolved");
        assert_eq!(cfg.key, RateLimitKey::Header(Arc::from("x-api-key")));
    }
}
