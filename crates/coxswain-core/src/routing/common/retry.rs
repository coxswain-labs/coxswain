//! Upstream retry policy: the [`RetryPolicyConfig`] that a
//! [`BackendGroup`](super::backend::BackendGroup) carries — retrying is an
//! upstream-connection concern, read by the proxy in `fail_to_connect`,
//! `error_while_proxy`, and `upstream_response_filter`.
//!
//! Named `RetryPolicyConfig` (not `RetryPolicy`) to mirror the
//! [`RateLimitConfig`](super::rate_limit::RateLimitConfig) convention — the
//! runtime config type is distinct from the `RetryPolicy` CRD
//! ([`crate::crd::RetryPolicy`]) that is one of its sources, avoiding a
//! short-name clash.
//!
//! The field shape deliberately mirrors Gateway API GEP-1731
//! (`HTTPRoute.spec.rules[].retry` — `attempts` / `backoff` / `codes`) so the
//! coxswain `RetryPolicy` CRD can be deprecated in favour of the native field
//! with a mechanical swap once GEP-1731 graduates to Standard. `grpc_codes` is
//! the `GRPCRoute`-only extension: GEP-1731 is HTTPRoute-only, so gRPC retry
//! stays on the CRD permanently and this field carries no deprecation debt.
//!
//! Connection failures and connect-timeouts are **not** condition-gated: when
//! `attempts >= 1` the proxy always retries them (the exact-native-mirror model).
//! `http_codes` / `grpc_codes` are the only "which response to retry on" knobs.

use std::sync::Arc;
use std::time::Duration;

/// Default HTTP status codes retried when a policy sets a budget but omits `codes`.
///
/// These are the "gateway could not obtain a processed response" codes — the request
/// almost certainly did not execute, so retrying is safe. `500` is deliberately
/// excluded (the application ran; a retry risks double execution).
pub const DEFAULT_HTTP_RETRY_CODES: [u16; 3] = [502, 503, 504];

/// Default `grpc-status` code retried when a `GRPCRoute` policy omits `grpcCodes`.
///
/// `14` = `UNAVAILABLE`. A trailers-only `UNAVAILABLE` implies the RPC never executed,
/// so retrying is safe without idempotency metadata. `DEADLINE_EXCEEDED` (4) and
/// `RESOURCE_EXHAUSTED` (8) are excluded (retrying them compounds latency / overload).
pub const DEFAULT_GRPC_RETRY_CODES: [u16; 1] = [14];

/// Per-route upstream retry policy resolved from a `RetryPolicy` CRD
/// `ExtensionRef` (Gateway API `HTTPRoute` / `GRPCRoute`) or the Ingress
/// `retry-*` annotations.
///
/// Carried on [`BackendGroup`](super::backend::BackendGroup) (alongside
/// `protocol` / `tls`) because retrying is an upstream-connection concern. A
/// policy with `attempts == 0` never retries. Note that an empty `http_codes` /
/// `grpc_codes` no longer disables retries — connection and connect-timeout
/// failures are still retried whenever `attempts >= 1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryPolicyConfig {
    /// Maximum number of retries after the initial attempt (GEP-1731 `attempts`).
    /// `0` disables retrying entirely.
    pub attempts: u32,
    /// Minimum delay before a retried attempt (GEP-1731 `backoff`). `None` retries
    /// immediately. The proxy applies this as a fixed minimum; exponential backoff
    /// and jitter are a permitted future refinement.
    pub backoff: Option<Duration>,
    /// HTTP response status codes that trigger a retry (GEP-1731 `codes`).
    /// Sorted and deduplicated at reconcile time; matched by the proxy against the
    /// upstream response status. Meaningful for `HTTPRoute` (and the gRPC transport
    /// layer, where a real 5xx can still surface).
    pub http_codes: Arc<[u16]>,
    /// `grpc-status` codes that trigger a retry on a **trailers-only** gRPC response
    /// (`GRPCRoute` only). Numeric canonical codes `0..=16` (e.g. `14` = `UNAVAILABLE`).
    /// Ignored on `HTTPRoute`.
    pub grpc_codes: Arc<[u16]>,
}

impl Default for RetryPolicyConfig {
    fn default() -> Self {
        Self {
            attempts: 0,
            backoff: None,
            http_codes: empty_codes(),
            grpc_codes: empty_codes(),
        }
    }
}

/// An empty, shareable code list — the `Arc<[u16]>` fields need a non-derivable default.
fn empty_codes() -> Arc<[u16]> {
    Vec::new().into()
}

/// Apply the "omitted → default, explicit-empty → opt-out" rule and normalise
/// (sort + dedup, matching the native field's uniqueness constraint).
fn normalize_codes(codes: Option<Vec<u16>>, default: &[u16]) -> Arc<[u16]> {
    let mut v = codes.unwrap_or_else(|| default.to_vec());
    v.sort_unstable();
    v.dedup();
    v.into()
}

impl RetryPolicyConfig {
    /// Construct a retry policy from its GEP-1731-shaped parts.
    ///
    /// `http_codes` / `grpc_codes` are taken as already normalised (sorted, deduped)
    /// by the reconcile-time resolver.
    #[must_use]
    pub fn new(
        attempts: u32,
        backoff: Option<Duration>,
        http_codes: Arc<[u16]>,
        grpc_codes: Arc<[u16]>,
    ) -> Self {
        Self {
            attempts,
            backoff,
            http_codes,
            grpc_codes,
        }
    }

    /// Build an `HTTPRoute` retry policy from optional GEP-1731 parts, applying the
    /// symmetric defaults. `http_codes == None` → `DEFAULT_HTTP_RETRY_CODES`;
    /// `Some([])` opts out (connection/timeout retries only). `grpc_codes` is empty
    /// (gRPC status matching is meaningless off a `GRPCRoute`).
    #[must_use]
    pub fn for_http(
        attempts: u32,
        backoff: Option<Duration>,
        http_codes: Option<Vec<u16>>,
    ) -> Self {
        Self {
            attempts,
            backoff,
            http_codes: normalize_codes(http_codes, &DEFAULT_HTTP_RETRY_CODES),
            grpc_codes: empty_codes(),
        }
    }

    /// Build a `GRPCRoute` retry policy. `http_codes` still applies (a real transport
    /// 5xx can surface); `grpc_codes == None` → `DEFAULT_GRPC_RETRY_CODES`, `Some([])`
    /// opts out. Both lists are deduped/sorted.
    #[must_use]
    pub fn for_grpc(
        attempts: u32,
        backoff: Option<Duration>,
        http_codes: Option<Vec<u16>>,
        grpc_codes: Option<Vec<u16>>,
    ) -> Self {
        Self {
            attempts,
            backoff,
            http_codes: normalize_codes(http_codes, &DEFAULT_HTTP_RETRY_CODES),
            grpc_codes: normalize_codes(grpc_codes, &DEFAULT_GRPC_RETRY_CODES),
        }
    }

    /// `true` when this policy will never retry (no attempt budget).
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        self.attempts == 0
    }

    /// `true` when an HTTP response with `status` should be retried.
    #[must_use]
    pub fn retries_http(&self, status: u16) -> bool {
        self.http_codes.contains(&status)
    }

    /// `true` when a trailers-only gRPC response with `grpc-status` `code` should be
    /// retried.
    #[must_use]
    pub fn retries_grpc(&self, code: u16) -> bool {
        self.grpc_codes.contains(&code)
    }
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;

    #[test]
    fn default_is_disabled() {
        let p = RetryPolicyConfig::default();
        assert!(p.is_disabled());
        assert!(p.http_codes.is_empty());
        assert!(p.grpc_codes.is_empty());
    }

    #[test]
    fn attempts_zero_disables_even_with_codes() {
        let p = RetryPolicyConfig::new(0, None, vec![503].into(), vec![14].into());
        assert!(p.is_disabled());
    }

    #[test]
    fn empty_codes_still_enabled_for_connection_retry() {
        // Model (A): connection/timeout retries are gated on attempts alone, so a
        // policy with a budget but no response codes is NOT disabled.
        let p = RetryPolicyConfig::new(2, None, empty_codes(), empty_codes());
        assert!(!p.is_disabled());
        assert!(!p.retries_http(503));
        assert!(!p.retries_grpc(14));
    }

    #[test]
    fn matches_configured_codes() {
        let p = RetryPolicyConfig::new(
            1,
            Some(Duration::from_millis(100)),
            vec![502, 503, 504].into(),
            vec![14].into(),
        );
        assert!(p.retries_http(503));
        assert!(!p.retries_http(500));
        assert!(p.retries_grpc(14));
        assert!(!p.retries_grpc(4));
        assert_eq!(p.backoff, Some(Duration::from_millis(100)));
    }
}
