//! Per-route rate-limiting configuration types.
//!
//! These types are intentionally governor-free — they carry only the parsed
//! configuration from an Ingress annotation or a `RateLimit` CRD, not any live
//! limiter state. The `coxswain-proxy` crate owns the governor dependency and
//! the per-process [`RateLimiterRegistry`] that maintains bucket state across
//! reconciles.
//!
//! [`RateLimiterRegistry`]: https://docs.rs/coxswain-proxy/latest/coxswain_proxy/ratelimit/struct.RateLimiterRegistry.html

use std::num::NonZeroU32;
use std::sync::Arc;

/// The request attribute used as the rate-limit key for a route.
///
/// Both variants yield one `String`-like key per request (client IP or header
/// value). The proxy uses this key to look up the per-client bucket inside the
/// keyed governor limiter for the route.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RateLimitKey {
    /// Limit by real client IP address (the default).
    ///
    /// Uses the PROXY-protocol peer when present, else the L4 downstream peer
    /// — the same resolution the allow-source-range filter uses. A request
    /// whose peer address is indeterminate is admitted (fail-open); the proxy
    /// cannot attribute it to a key and so cannot enforce a per-client limit.
    ClientIp,

    /// Limit by the value of a named request header.
    ///
    /// The [`Arc<str>`] is the lowercase header name (e.g. `"x-api-key"`).
    /// Requests that do not carry the header are admitted (fail-open), matching
    /// ingress-nginx and Envoy behaviour.
    Header(Arc<str>),
}

/// Per-route rate-limiting configuration, shared between the Ingress annotation
/// binding and the Gateway API `RateLimit` CRD binding.
///
/// Both bindings parse into this type so the proxy enforcement path is unified.
/// The config is attached to a [`RouteEntry`](super::entry::RouteEntry) at
/// reconcile time and snapshotted into [`RouteMatch`](super::host_router::RouteMatch)
/// on each request — immutable config only. Mutable bucket state lives
/// separately in the per-process `RateLimiterRegistry`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Sustained request rate — cells allowed per second in steady state.
    ///
    /// Invariant: always `>= 1`. A value of `0` is rejected at parse time
    /// (WARN + fail-open) so this is guaranteed non-zero when the config
    /// reaches the proxy.
    pub requests_per_second: NonZeroU32,

    /// Extra cells allowed above the sustained rate as an initial burst.
    ///
    /// The governor quota is configured as `rps + burst` total burst capacity,
    /// meaning a client that has been idle may fire up to `rps + burst` requests
    /// before the limiter starts enforcing the sustained rate. `0` (the default)
    /// means no burst above the sustained rate.
    pub burst: u32,

    /// The request attribute used as the per-client key.
    pub key: RateLimitKey,
}

impl RateLimitConfig {
    /// Construct a [`RateLimitConfig`].
    pub fn new(requests_per_second: NonZeroU32, burst: u32, key: RateLimitKey) -> Self {
        Self {
            requests_per_second,
            burst,
            key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_config_clone_is_independent() {
        let cfg = RateLimitConfig {
            requests_per_second: NonZeroU32::new(10).expect("10 > 0"),
            burst: 5,
            key: RateLimitKey::ClientIp,
        };
        let cfg2 = cfg.clone();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn rate_limit_key_variants_not_equal() {
        let ip = RateLimitKey::ClientIp;
        let hdr = RateLimitKey::Header(Arc::from("x-api-key"));
        assert_ne!(ip, hdr);
    }

    #[test]
    fn rate_limit_key_header_equality_by_value() {
        let a = RateLimitKey::Header(Arc::from("x-api-key"));
        let b = RateLimitKey::Header(Arc::from("x-api-key"));
        assert_eq!(a, b);
    }
}
