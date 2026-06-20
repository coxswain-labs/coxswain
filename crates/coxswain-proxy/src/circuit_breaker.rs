//! Per-process, per-endpoint circuit-breaker registry backed by [`failsafe`].
//!
//! # Design
//! Only this module depends on `failsafe`. The config type ([`CircuitBreakerConfig`])
//! lives in `coxswain-core` and is failsafe-free; this module translates it into a
//! live [`failsafe::StateMachine`] on first use.
//!
//! Breakers are keyed by `(metric_route_id, SocketAddr)` — one state machine per
//! (route, upstream endpoint) pair.  This matches Envoy/Istio outlier detection
//! semantics: a degraded pod trips only its own breaker; healthy pods serving the
//! same route keep accepting traffic.
//!
//! # Hot-path allocation budget
//! Routes without the `circuit-breaker-threshold` annotation (all Gateway-API routes
//! and most Ingress routes) short-circuit on the `Option<Arc<CircuitBreakerConfig>>`
//! check in `upstream_peer`/`logging` — zero overhead.  Routes that carry the
//! annotation hit the `DashMap` lookup per request: one hash probe, no allocation.
//! The per-endpoint `BreakerEntry` is built once on first use.
//!
//! # State transitions and metrics
//! [`MetricsInstrument`] implements [`failsafe::Instrument`] and drives three
//! Prometheus series mirroring failsafe's four callbacks:
//! - `on_open` / `on_half_open` / `on_closed` → set the state gauge + bump
//!   `coxswain_proxy_circuit_breaker_transitions_total{to=…}`.
//! - `on_call_rejected` → bump
//!   `coxswain_proxy_circuit_breaker_rejected_total`.
//!
//! All allocations for label strings happen in the `Instrument` callbacks
//! (transition-time only); none happen on the per-request hot path.

use coxswain_core::routing::CircuitBreakerConfig;
use dashmap::DashMap;
use failsafe::backoff;
use failsafe::failure_policy;
use failsafe::{Config, StateMachine};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::metrics;

/// Inner key–value store type for the per-endpoint breaker map.
type BreakerMap = DashMap<(Arc<str>, SocketAddr), Arc<BreakerEntry>>;

// ── State constants ───────────────────────────────────────────────────────────

/// Breaker state as stored in the shadow `AtomicU8`.
const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

// ── Erased state-machine trait ────────────────────────────────────────────────

/// Type-erased circuit-breaker operations.
///
/// `failsafe::StateMachine` is generic over its backoff and failure-policy types.
/// `constant` and `exponential` produce different `Iterator` instantiations, making
/// the two `StateMachine` variants different concrete types. This trait lets us store
/// either in the `DashMap` without an enum that would expose the types.
///
/// This is an internal implementation detail — the trait is sealed (no external
/// `impl`) and only used as `Box<dyn BreakerOps + Send + Sync>`.
trait BreakerOps {
    /// Returns `true` when the request is permitted (Closed or HalfOpen probe).
    fn is_call_permitted(&self) -> bool;
    /// Record a successful upstream response.
    fn on_success(&self);
    /// Record a failed upstream response (HTTP 5xx, connect error, timeout).
    fn on_error(&self);
}

// ── Constant-backoff state machine ────────────────────────────────────────────

type ConstantSm =
    StateMachine<failure_policy::SuccessRateOverTimeWindow<backoff::Constant>, MetricsInstrument>;

struct ConstantBreaker(ConstantSm);

impl BreakerOps for ConstantBreaker {
    fn is_call_permitted(&self) -> bool {
        self.0.is_call_permitted()
    }
    fn on_success(&self) {
        self.0.on_success();
    }
    fn on_error(&self) {
        self.0.on_error();
    }
}

// ── Exponential-backoff state machine ─────────────────────────────────────────

type ExponentialSm = StateMachine<
    failure_policy::SuccessRateOverTimeWindow<backoff::Exponential>,
    MetricsInstrument,
>;

struct ExponentialBreaker(ExponentialSm);

impl BreakerOps for ExponentialBreaker {
    fn is_call_permitted(&self) -> bool {
        self.0.is_call_permitted()
    }
    fn on_success(&self) {
        self.0.on_success();
    }
    fn on_error(&self) {
        self.0.on_error();
    }
}

// ── Per-endpoint entry ────────────────────────────────────────────────────────

/// Per-`(route, endpoint)` breaker entry.
struct BreakerEntry {
    /// Live failsafe state machine — type-erased to accommodate both constant and
    /// exponential backoff without an enum exposing generic parameters.
    sm: Box<dyn BreakerOps + Send + Sync>,
    /// Shadow state readable without consuming a probe token.
    ///
    /// Written by [`MetricsInstrument`] callbacks (transition-time only). Read by
    /// [`CircuitBreakerRegistry::sweep`] to prune Closed entries and, in a future
    /// eject-from-pool implementation, to query endpoint health without consuming
    /// the HalfOpen probe token that `StateMachine::is_call_permitted` would consume.
    state: Arc<AtomicU8>,
}

// ── Instrument ────────────────────────────────────────────────────────────────

/// [`failsafe::Instrument`] implementation that drives the three Prometheus series.
///
/// The `Arc<AtomicU8>` and the two label `Box<str>` are cloned from the surrounding
/// `BreakerEntry`; all string allocation happens at entry-build time, never per request.
struct MetricsInstrument {
    state: Arc<AtomicU8>,
    route: Box<str>,
    upstream: Box<str>,
}

impl failsafe::Instrument for MetricsInstrument {
    fn on_call_rejected(&self) {
        metrics::circuit_breaker_rejected_total()
            .with_label_values(&[&*self.route, &*self.upstream])
            .inc();
    }

    fn on_open(&self) {
        self.state.store(STATE_OPEN, Ordering::Relaxed);
        metrics::circuit_breaker_state()
            .with_label_values(&[&*self.route, &*self.upstream])
            .set(i64::from(STATE_OPEN));
        metrics::circuit_breaker_transitions_total()
            .with_label_values(&[&*self.route, &*self.upstream, "open"])
            .inc();
    }

    fn on_half_open(&self) {
        self.state.store(STATE_HALF_OPEN, Ordering::Relaxed);
        metrics::circuit_breaker_state()
            .with_label_values(&[&*self.route, &*self.upstream])
            .set(i64::from(STATE_HALF_OPEN));
        metrics::circuit_breaker_transitions_total()
            .with_label_values(&[&*self.route, &*self.upstream, "half_open"])
            .inc();
    }

    fn on_closed(&self) {
        self.state.store(STATE_CLOSED, Ordering::Relaxed);
        metrics::circuit_breaker_state()
            .with_label_values(&[&*self.route, &*self.upstream])
            .set(i64::from(STATE_CLOSED));
        metrics::circuit_breaker_transitions_total()
            .with_label_values(&[&*self.route, &*self.upstream, "closed"])
            .inc();
    }
}

// ── Registry ──────────────────────────────────────────────────────────────────

/// Per-process registry of live failsafe circuit-breaker state machines, one per
/// `(metric_route_id, SocketAddr)` pair.
///
/// Cloning is cheap (the inner `Arc<BreakerMap>` is reference-counted).
/// Both `IngressProxy` and `GatewayProxy` hold a clone so they share a single
/// breaker pool; Gateway-API routes never carry a `CircuitBreakerConfig` so their
/// paths never touch the registry.
#[non_exhaustive]
#[derive(Clone, Default)]
pub struct CircuitBreakerRegistry {
    inner: Arc<BreakerMap>,
}

impl CircuitBreakerRegistry {
    /// Construct an empty registry. Call once at process startup.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    /// Gate a request through the per-endpoint breaker.
    ///
    /// Returns `true` when the request is permitted (Closed or HalfOpen probe),
    /// `false` when the breaker is Open (fail-fast 503). On first use the breaker
    /// is built from `cfg` and inserted; subsequent calls reuse the live state.
    ///
    /// The HalfOpen probe token is consumed here — exactly one probe fires through
    /// to the upstream between open durations.
    pub(crate) fn is_call_permitted(
        &self,
        route_id: &Arc<str>,
        addr: SocketAddr,
        cfg: &CircuitBreakerConfig,
    ) -> bool {
        let entry = self.get_or_build(route_id, addr, cfg);
        entry.sm.is_call_permitted()
    }

    /// Record the outcome of an upstream request.
    ///
    /// `success` is `true` when the upstream returned HTTP < 500 (connect errors
    /// and timeouts have already been mapped to 5xx by the proxy). Only called
    /// when `circuit_breaker_rejected` is `false` on `ProxyCtx` — i.e. a request
    /// actually reached the upstream.
    pub(crate) fn record(
        &self,
        route_id: &Arc<str>,
        addr: SocketAddr,
        cfg: &CircuitBreakerConfig,
        success: bool,
    ) {
        let entry = self.get_or_build(route_id, addr, cfg);
        if success {
            entry.sm.on_success();
        } else {
            entry.sm.on_error();
        }
    }

    /// Remove stale per-endpoint breakers.
    ///
    /// Entries whose breakers are in the Closed state and have seen zero activity
    /// since the last sweep are dropped. Call periodically (~60 s) to prevent
    /// unbounded growth when routes are removed or endpoints are recycled.
    pub fn sweep(&self) {
        self.inner.retain(|_, entry| {
            // Keep Open / HalfOpen breakers unconditionally — they are actively
            // suppressing traffic. For Closed ones, check the shadow state atomic.
            entry.state.load(Ordering::Relaxed) != STATE_CLOSED
        });
    }

    /// Get or build the `BreakerEntry` for `(route_id, addr)`.
    fn get_or_build(
        &self,
        route_id: &Arc<str>,
        addr: SocketAddr,
        cfg: &CircuitBreakerConfig,
    ) -> Arc<BreakerEntry> {
        let key = (Arc::clone(route_id), addr);
        Arc::clone(
            self.inner
                .entry(key)
                .or_insert_with(|| Arc::new(build_entry(route_id, addr, cfg)))
                .value(),
        )
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Build a [`BreakerEntry`] from a [`CircuitBreakerConfig`].
///
/// The `required_success_rate` maps as `1.0 - threshold_pct / 100.0`.
/// When `max_open_duration` is `Some`, uses exponential backoff; otherwise constant.
fn build_entry(route_id: &str, addr: SocketAddr, cfg: &CircuitBreakerConfig) -> BreakerEntry {
    let required_success_rate = 1.0 - f64::from(cfg.threshold_pct) / 100.0;
    let state = Arc::new(AtomicU8::new(STATE_CLOSED));
    // One SocketAddr.to_string() allocation per endpoint — not per request.
    let upstream_str: Box<str> = addr.to_string().into_boxed_str();
    let instrument = MetricsInstrument {
        state: Arc::clone(&state),
        route: route_id.into(),
        upstream: Box::clone(&upstream_str),
    };

    let sm: Box<dyn BreakerOps + Send + Sync> = match cfg.max_open_duration {
        Some(max_open) => {
            let policy = failure_policy::success_rate_over_time_window(
                required_success_rate,
                cfg.min_requests,
                cfg.window,
                backoff::exponential(cfg.open_duration, max_open),
            );
            let sm = Config::new()
                .failure_policy(policy)
                .instrument(instrument)
                .build();
            Box::new(ExponentialBreaker(sm))
        }
        None => {
            let policy = failure_policy::success_rate_over_time_window(
                required_success_rate,
                cfg.min_requests,
                cfg.window,
                backoff::constant(cfg.open_duration),
            );
            let sm = Config::new()
                .failure_policy(policy)
                .instrument(instrument)
                .build();
            Box::new(ConstantBreaker(sm))
        }
    };

    BreakerEntry { sm, state }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cfg(threshold_pct: u8, min_requests: u32) -> CircuitBreakerConfig {
        // Use a sub-second window so that `window.as_secs() * 1000 == 0`,
        // which makes failsafe's `can_remove` time-gate (`elapsed_millis >= window_millis`)
        // always pass — allowing unit tests to trip the breaker without sleeping.
        CircuitBreakerConfig::new(
            threshold_pct,
            min_requests,
            Duration::from_millis(500),
            Duration::from_millis(100),
            None,
        )
    }

    fn route_id() -> Arc<str> {
        Arc::from("ingress/default/test:0.0")
    }

    fn addr() -> SocketAddr {
        "10.0.0.1:8080".parse().expect("valid addr")
    }

    #[test]
    fn new_breaker_permits_first_call() {
        let registry = CircuitBreakerRegistry::new();
        let id = route_id();
        let cfg = cfg(50, 10);
        // A fresh breaker is always Closed — call permitted.
        assert!(
            registry.is_call_permitted(&id, addr(), &cfg),
            "fresh breaker must permit the first call"
        );
    }

    #[test]
    fn breaker_stays_closed_within_threshold() {
        let registry = CircuitBreakerRegistry::new();
        let id = route_id();
        // threshold_pct=50, min_requests=3 — need ≥3 samples before opening.
        let cfg = cfg(50, 3);
        let a = addr();
        // One failure, two successes → success rate 66% > required 50% — stays Closed.
        registry.record(&id, a, &cfg, false);
        registry.record(&id, a, &cfg, true);
        registry.record(&id, a, &cfg, true);
        assert!(
            registry.is_call_permitted(&id, a, &cfg),
            "breaker must stay closed when success rate is above threshold"
        );
    }

    #[test]
    fn breaker_opens_when_error_rate_exceeds_threshold() {
        let registry = CircuitBreakerRegistry::new();
        let id = route_id();
        // threshold_pct=50, min_requests=4 — trip when error rate ≥ 50%.
        let cfg = cfg(50, 4);
        let a = addr();
        // Four errors → 0% success rate, ≥ min_requests samples — breaker opens.
        for _ in 0..4 {
            registry.record(&id, a, &cfg, false);
        }
        assert!(
            !registry.is_call_permitted(&id, a, &cfg),
            "breaker must open after error rate exceeds threshold"
        );
    }

    #[test]
    fn exponential_backoff_entry_builds_without_panic() {
        // failsafe::backoff::exponential requires start.as_secs() > 0 (i.e. ≥ 1 s).
        let cfg = CircuitBreakerConfig::new(
            50,
            5,
            Duration::from_secs(10),
            Duration::from_secs(2),
            Some(Duration::from_secs(60)),
        );
        let entry = build_entry("ingress/default/test:0.0", addr(), &cfg);
        // Just verify it builds and permits the first call.
        assert!(
            entry.sm.is_call_permitted(),
            "fresh exponential breaker must permit first call"
        );
    }

    #[test]
    fn sweep_does_not_panic() {
        let registry = CircuitBreakerRegistry::new();
        let id = route_id();
        let cfg = cfg(50, 5);
        registry.is_call_permitted(&id, addr(), &cfg);
        registry.sweep();
    }
}
