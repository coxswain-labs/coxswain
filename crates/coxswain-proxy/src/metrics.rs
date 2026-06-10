//! Prometheus metrics for the proxy data plane.
//!
//! All metrics are registered against the global default registry on first
//! access and are automatically exposed by `coxswain-admin`'s
//! `prometheus::gather()` call.  The naming convention is
//! `coxswain_proxy_<subsystem>_<name>_<unit>`.

use prometheus::{
    HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, register_histogram_vec,
    register_int_counter_vec, register_int_gauge_vec,
};
use std::sync::OnceLock;

/// Gauge: number of listeners currently in `"serving"` or `"draining"` state.
///
/// Labels: `state ∈ {"serving", "draining"}`.
pub(crate) fn listeners_active() -> &'static IntGaugeVec {
    static GAUGE: OnceLock<IntGaugeVec> = OnceLock::new();
    GAUGE.get_or_init(|| {
        register_int_gauge_vec!(
            Opts::new(
                "coxswain_proxy_listeners_active",
                "Number of proxy listeners in each lifecycle state",
            ),
            &["state"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: cumulative listener lifecycle events.
///
/// Labels: `event ∈ {"added", "removed", "drain_completed", "drain_exceeded"}`.
pub(crate) fn lifecycle() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_proxy_listener_lifecycle_total",
                "Cumulative listener lifecycle events",
            ),
            &["event"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Histogram: listener drain duration in seconds (from removal signal to drain
/// complete or timeout).
///
/// Buckets span 0.1 s – 120 s to cover the default 30 s drain timeout with
/// headroom.
pub(crate) fn drain_duration() -> &'static HistogramVec {
    static HIST: OnceLock<HistogramVec> = OnceLock::new();
    HIST.get_or_init(|| {
        register_histogram_vec!(
            HistogramOpts::new(
                "coxswain_proxy_listener_drain_duration_seconds",
                "Time from listener removal signal to drain completion or timeout",
            )
            .buckets(vec![
                0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 15.0, 30.0, 60.0, 120.0,
            ]),
            &[]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: connections (and by extension in-progress requests) force-closed
/// because the per-listener drain timeout was exhausted.
///
/// Labels: `reason ∈ {"drain_exceeded"}`.
///
/// **This counter is the correctness canary**: under sustained traffic with a
/// properly-sized drain timeout it must remain at 0.
pub(crate) fn requests_force_closed() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_proxy_requests_force_closed_total",
                "Connections aborted because the per-listener drain timeout was exhausted",
            ),
            &["reason"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}
