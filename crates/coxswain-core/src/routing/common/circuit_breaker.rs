//! Per-route circuit-breaker configuration types.
//!
//! These types are intentionally failsafe-free — they carry only the parsed
//! configuration from the Ingress annotations, not any live breaker state.
//! The `coxswain-proxy` crate owns the `failsafe` dependency and the
//! per-process [`CircuitBreakerRegistry`] that maintains per-endpoint state.
//!
//! [`CircuitBreakerRegistry`]: https://docs.rs/coxswain-proxy/latest/coxswain_proxy/circuit_breaker/struct.CircuitBreakerRegistry.html

use std::time::Duration;

/// Per-route circuit-breaker configuration, derived from the
/// `ingress.coxswain-labs.dev/circuit-breaker-*` annotation family.
///
/// The config is carried on [`RouteEntry`](super::entry::RouteEntry) and
/// snapshotted into [`ResolvedRoute`] on each request — immutable config only.
/// Live per-endpoint breaker state lives separately in the proxy-side
/// `CircuitBreakerRegistry`, keyed by `(metric_route_id, SocketAddr)`.
///
/// ## Semantics
///
/// Built on top of `failsafe`'s `success_rate_over_time_window` policy, which
/// computes an **EWMA** success rate (biased to recent requests) over `window`.
/// The threshold is mapped as `required_success_rate = 1 - threshold_pct / 100`.
///
/// `min_requests` prevents a single early failure from tripping the breaker on
/// a low-traffic route — the policy does not act until at least `min_requests`
/// have been observed in the window.
///
/// [`ResolvedRoute`]: https://docs.rs/coxswain-proxy/latest/coxswain_proxy/ctx/struct.ResolvedRoute.html
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitBreakerConfig {
    /// Error rate (%) that trips the breaker (1–100).
    ///
    /// Mapped to `failsafe`'s `required_success_rate = 1 - threshold_pct / 100`.
    /// The breaker opens when the EWMA error rate meets or exceeds this value.
    ///
    /// Invariant: 1 ≤ `threshold_pct` ≤ 100. Zero is rejected at parse time
    /// (WARN + disabled) so the proxy never sees it.
    pub threshold_pct: u8,

    /// Minimum requests in the window before the policy can trip the breaker.
    ///
    /// Maps to `failsafe`'s `min_request_threshold`. Prevents a single early
    /// failure from opening the breaker on low-traffic routes. Default: 10.
    pub min_requests: u32,

    /// Rolling window over which the EWMA success rate is computed.
    ///
    /// Maps to `failsafe`'s `window` parameter. Default: 10 seconds.
    pub window: Duration,

    /// Base open-duration: how long to stay open before allowing a probe.
    ///
    /// Used as the constant backoff duration when `max_open_duration` is `None`.
    /// When `max_open_duration` is `Some`, this is the starting duration for
    /// `failsafe`'s exponential backoff. Default: 5 seconds.
    pub open_duration: Duration,

    /// Maximum open-duration cap for exponential backoff.
    ///
    /// `Some(max)` enables `failsafe::backoff::exponential(open_duration, max)`,
    /// so the breaker stays open progressively longer across repeated trips (up to
    /// `max`). `None` (the default) uses `failsafe::backoff::constant(open_duration)`.
    pub max_open_duration: Option<Duration>,
}

impl CircuitBreakerConfig {
    /// Construct a [`CircuitBreakerConfig`].
    pub fn new(
        threshold_pct: u8,
        min_requests: u32,
        window: Duration,
        open_duration: Duration,
        max_open_duration: Option<Duration>,
    ) -> Self {
        Self {
            threshold_pct,
            min_requests,
            window,
            open_duration,
            max_open_duration,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_breaker_config_clone_is_independent() {
        let cfg = CircuitBreakerConfig::new(
            50,
            10,
            Duration::from_secs(10),
            Duration::from_secs(5),
            None,
        );
        let cfg2 = cfg.clone();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn circuit_breaker_config_with_max_open_duration() {
        let cfg = CircuitBreakerConfig::new(
            75,
            5,
            Duration::from_secs(30),
            Duration::from_secs(5),
            Some(Duration::from_secs(60)),
        );
        assert_eq!(cfg.max_open_duration, Some(Duration::from_secs(60)));
    }
}
