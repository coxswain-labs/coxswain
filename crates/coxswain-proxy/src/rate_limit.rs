//! Per-process, per-route, per-client rate-limiter registry backed by
//! [`governor`](https://docs.rs/governor) GCRA token buckets.
//!
//! # Design
//! Only this module depends on `governor`. The config types (`RateLimitConfig`,
//! `RateLimitKey`) live in `coxswain-core` and are governor-free; this module
//! translates them into live limiters on first use.
//!
//! The registry is built once at process startup and shared via `Arc` across
//! `IngressProxy` and `GatewayProxy`. It survives routing-table reconciles —
//! bucket state is keyed by `metric_route_id` and `ClientKey`, not by route
//! object identity, so pod-scaling events that rebuild the routing snapshot do
//! not reset rate counters.
//!
//! # Memory bounding
//! Each per-route limiter is a `governor` `DashMapStateStore` that holds one
//! GCRA cell per distinct `ClientKey`. Call [`RateLimiterRegistry::sweep`]
//! periodically (every ~60 s) to invoke `retain_recent` on each limiter and
//! drop entries with zero live keys, preventing unbounded growth under a
//! high-cardinality client key space.

use coxswain_core::routing::{RateLimitConfig, RateLimitKey};
use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

/// The per-client dimension used as the governor `DashMapStateStore` key.
///
/// Both variants are `Hash + Eq + Clone` so governor can manage one bucket per
/// distinct client.
#[derive(Clone, Hash, PartialEq, Eq)]
pub(crate) enum ClientKey {
    /// Real client IP address (PROXY-protocol peer or L4 downstream peer).
    Ip(IpAddr),
    /// Value of a named request header (normalised to a `Box<str>` to keep
    /// the heap footprint minimal per key insert).
    Header(Box<str>),
}

/// Outcome of a single rate-limit check.
pub(crate) enum CheckOutcome {
    /// The request is within the rate limit — proceed normally.
    Allowed,
    /// The request exceeds the rate limit. The proxy should emit 429 with a
    /// `Retry-After` header set to this many whole seconds (minimum 1).
    Limited { retry_after_secs: u64 },
}

type KeyedLimiter = RateLimiter<ClientKey, DashMapStateStore<ClientKey>, DefaultClock>;

struct RouteLimiterEntry {
    config: RateLimitConfig,
    limiter: Arc<KeyedLimiter>,
}

/// Per-process registry of live governor rate limiters, one per route that has
/// rate limiting configured.
///
/// Cloning is cheap (the inner `Arc<Mutex<…>>` is reference-counted). Both
/// `IngressProxy` and `GatewayProxy` hold a clone of the same registry so
/// they share a single limit pool.
#[non_exhaustive]
#[derive(Clone)]
pub struct RateLimiterRegistry {
    inner: Arc<Mutex<HashMap<Arc<str>, RouteLimiterEntry>>>,
    clock: DefaultClock,
}

impl RateLimiterRegistry {
    /// Construct an empty registry. Call once at process startup.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            clock: DefaultClock::default(),
        }
    }

    /// Check whether a request identified by `route_id` + `client_key` is within
    /// the rate limit described by `config`.
    ///
    /// On first use (or when `config` has changed since the last check), a new
    /// governor limiter is built and inserted into the registry. Subsequent calls
    /// reuse the live limiter, preserving accumulated bucket state.
    ///
    /// Returns [`CheckOutcome::Allowed`] when the request is within the limit,
    /// or [`CheckOutcome::Limited`] with the seconds until the next allowed
    /// request when it is not.
    pub(crate) fn check(
        &self,
        route_id: &Arc<str>,
        config: &RateLimitConfig,
        client_key: ClientKey,
    ) -> CheckOutcome {
        let limiter = self.get_or_build(route_id, config);
        match limiter.check_key(&client_key) {
            Ok(()) => CheckOutcome::Allowed,
            Err(not_until) => {
                let wait = not_until.wait_time_from(self.clock.now());
                let secs = wait.as_secs_f64().ceil() as u64;
                CheckOutcome::Limited {
                    retry_after_secs: secs.max(1),
                }
            }
        }
    }

    /// Remove stale per-client entries from every live limiter.
    ///
    /// Calls `retain_recent` on each `DashMapStateStore`, which evicts keys
    /// whose GCRA state has fully recovered (i.e. they could freely receive
    /// their full burst again). Entries whose limiters are now empty are
    /// removed from the registry entirely. Call this from a periodic background
    /// service (~60 s interval) to bound memory growth.
    pub fn sweep(&self) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| {
            panic!("invariant: RateLimiterRegistry mutex must not be poisoned: {e}")
        });
        guard.retain(|_, entry| {
            entry.limiter.retain_recent();
            !entry.limiter.is_empty()
        });
    }

    /// Get the live limiter for `route_id`, rebuilding it when `config` has
    /// changed since last use.
    fn get_or_build(&self, route_id: &Arc<str>, config: &RateLimitConfig) -> Arc<KeyedLimiter> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| {
            panic!("invariant: RateLimiterRegistry mutex must not be poisoned: {e}")
        });
        let entry = guard
            .entry(Arc::clone(route_id))
            .or_insert_with(|| RouteLimiterEntry {
                config: config.clone(),
                limiter: Arc::new(build_limiter(config)),
            });
        if &entry.config != config {
            entry.config = config.clone();
            entry.limiter = Arc::new(build_limiter(config));
        }
        Arc::clone(&entry.limiter)
    }
}

impl Default for RateLimiterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a new keyed governor limiter from a [`RateLimitConfig`].
///
/// The quota is: sustained rate = `rps` cells/s; burst capacity = `rps + burst`
/// cells total (so a fully idle client can fire up to `rps + burst` requests
/// before the sustained rate kicks in). When `burst == 0` the burst capacity
/// equals the sustained rate (one second's worth), which is governor's default.
fn build_limiter(config: &RateLimitConfig) -> KeyedLimiter {
    let rps = config.requests_per_second;
    let quota = if config.burst > 0 {
        let burst_cap = rps.get().saturating_add(config.burst);
        let burst_nonzero = NonZeroU32::new(burst_cap).unwrap_or(rps);
        Quota::per_second(rps).allow_burst(burst_nonzero)
    } else {
        Quota::per_second(rps)
    };
    RateLimiter::dashmap(quota)
}

/// Build a [`ClientKey`] from the request context.
///
/// Returns `None` when the keying dimension is not available for this
/// request (undeterminable IP, or absent header on a header-keyed route) —
/// the caller treats `None` as fail-open (request not counted).
pub(crate) fn extract_client_key(
    config: &RateLimitConfig,
    client_ip: Option<IpAddr>,
    header_value: Option<&str>,
) -> Option<ClientKey> {
    match &config.key {
        RateLimitKey::ClientIp => client_ip.map(ClientKey::Ip),
        RateLimitKey::Header(_) => header_value.map(|v| ClientKey::Header(Box::from(v))),
        _ => unreachable!("invariant: RateLimitKey has only ClientIp and Header variants"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(rps: u32, burst: u32) -> RateLimitConfig {
        RateLimitConfig::new(
            NonZeroU32::new(rps).expect("rps > 0"),
            burst,
            RateLimitKey::ClientIp,
        )
    }

    fn route_id() -> Arc<str> {
        Arc::from("ingress/default/test:0.0")
    }

    fn ip_key(addr: &str) -> ClientKey {
        ClientKey::Ip(addr.parse().expect("valid IP"))
    }

    #[test]
    fn allowed_within_limit() {
        let registry = RateLimiterRegistry::new();
        let config = make_config(10, 0);
        let id = route_id();

        // A single request should always be allowed.
        assert!(
            matches!(
                registry.check(&id, &config, ip_key("10.0.0.1")),
                CheckOutcome::Allowed
            ),
            "first request must be allowed"
        );
    }

    #[test]
    fn limited_after_burst_exhausted() {
        let registry = RateLimiterRegistry::new();
        // rps=1 burst=0: only 1 cell in the bucket at a time.
        let config = make_config(1, 0);
        let id = route_id();
        let key = ip_key("10.0.0.1");

        // First call fills the bucket; first request is allowed.
        registry.check(&id, &config, key.clone());
        // Second call immediately after must be limited.
        let outcome = registry.check(&id, &config, key);
        assert!(
            matches!(outcome, CheckOutcome::Limited { .. }),
            "second request at rps=1 must be limited"
        );
    }

    #[test]
    fn limited_outcome_has_positive_retry_after() {
        let registry = RateLimiterRegistry::new();
        let config = make_config(1, 0);
        let id = route_id();
        let key = ip_key("10.0.0.1");

        registry.check(&id, &config, key.clone());
        if let CheckOutcome::Limited { retry_after_secs } = registry.check(&id, &config, key) {
            assert!(
                retry_after_secs >= 1,
                "Retry-After must be at least 1 second"
            );
        }
    }

    #[test]
    fn per_ip_isolation() {
        let registry = RateLimiterRegistry::new();
        let config = make_config(1, 0);
        let id = route_id();

        // Exhaust client A's bucket.
        registry.check(&id, &config, ip_key("10.0.0.1"));
        registry.check(&id, &config, ip_key("10.0.0.1"));

        // Client B should still be allowed — independent bucket.
        assert!(
            matches!(
                registry.check(&id, &config, ip_key("10.0.0.2")),
                CheckOutcome::Allowed
            ),
            "distinct client IP must have its own bucket"
        );
    }

    #[test]
    fn config_change_rebuilds_limiter() {
        let registry = RateLimiterRegistry::new();
        let id = route_id();
        let key = ip_key("10.0.0.1");

        // Fill bucket at rps=1.
        let low = make_config(1, 0);
        registry.check(&id, &low, key.clone());
        assert!(matches!(
            registry.check(&id, &low, key.clone()),
            CheckOutcome::Limited { .. }
        ));

        // Swap to rps=100 — new limiter with a fresh, full bucket.
        let high = make_config(100, 0);
        assert!(
            matches!(registry.check(&id, &high, key), CheckOutcome::Allowed),
            "config change must rebuild limiter and allow new request"
        );
    }

    #[test]
    fn sweep_does_not_panic() {
        let registry = RateLimiterRegistry::new();
        let config = make_config(10, 0);
        let id = route_id();
        registry.check(&id, &config, ip_key("10.0.0.1"));
        registry.sweep();
    }

    #[test]
    fn extract_client_key_ip() {
        let cfg = make_config(10, 0);
        let k = extract_client_key(&cfg, Some("1.2.3.4".parse().unwrap()), None);
        assert!(matches!(k, Some(ClientKey::Ip(_))));
    }

    #[test]
    fn extract_client_key_no_ip_is_none() {
        let cfg = make_config(10, 0);
        let k = extract_client_key(&cfg, None, None);
        assert!(k.is_none(), "undeterminable IP must be fail-open (None)");
    }

    #[test]
    fn extract_client_key_header() {
        let cfg = RateLimitConfig::new(
            NonZeroU32::new(5).unwrap(),
            0,
            RateLimitKey::Header(Arc::from("x-api-key")),
        );
        let k = extract_client_key(&cfg, None, Some("token-abc"));
        assert!(matches!(k, Some(ClientKey::Header(_))));
    }

    #[test]
    fn extract_client_key_missing_header_is_none() {
        let cfg = RateLimitConfig::new(
            NonZeroU32::new(5).unwrap(),
            0,
            RateLimitKey::Header(Arc::from("x-api-key")),
        );
        // Header absent → fail-open.
        let k = extract_client_key(&cfg, None, None);
        assert!(k.is_none(), "missing header must be fail-open (None)");
    }
}
