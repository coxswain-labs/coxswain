//! Prometheus metrics for the discovery subsystem (control-plane gRPC channel).
//!
//! Two roles emit from this module, in two different processes:
//! - **Server** (controller process): connected-proxy gauge, stream-auth
//!   outcomes, Ack throughput. Surfaced on the controller admin `/metrics`.
//! - **Client** (proxy process): reconnect count and channel state. Surfaced on
//!   the proxy admin `/metrics`.
//!
//! Both sides register against the global default prometheus registry on first
//! emission (the `OnceLock` pattern shared with `coxswain_controller::metrics`
//! and `coxswain_proxy::metrics`); `coxswain_admin`'s `prometheus::gather()`
//! picks them up automatically wherever an `AdminServer` runs.

use prometheus::{
    IntCounter, IntCounterVec, IntGauge, Opts, register_int_counter, register_int_counter_vec,
    register_int_gauge,
};
use std::sync::OnceLock;

// ── Client channel-state encoding ───────────────────────────────────────────

/// `client_state` gauge value before the first snapshot is applied (the proxy
/// is `NotReady`, `/readyz` returns 503).
pub const STATE_PENDING: i64 = 0;
/// `client_state` gauge value once a snapshot has been applied and Ack'd.
pub const STATE_READY: i64 = 1;
/// `client_state` gauge value after the stream drops post-snapshot — the proxy
/// serves its last-good snapshot and `/readyz` stays 200.
pub const STATE_DEGRADED: i64 = 2;

// ── Server-side metrics (controller process) ────────────────────────────────

/// Gauge: number of proxy nodes with a live discovery stream right now.
///
/// Incremented when a stream is accepted and the node is registered;
/// decremented when the per-stream task exits (disconnect). `sum()` across
/// controller replicas is meaningless — only the leader serves streams — so
/// scrape the leader. A drop to `0` during steady-state means the whole proxy
/// fleet lost its control-plane link.
///
/// # Panics
///
/// Panics if the registry already contains a series with this name via a
/// different registration path. The [`OnceLock`] makes this unreachable in
/// practice; a failure indicates a duplicate-registration bug.
pub fn connected_proxies() -> &'static IntGauge {
    static GAUGE: OnceLock<IntGauge> = OnceLock::new();
    GAUGE.get_or_init(|| {
        register_int_gauge!(
            "coxswain_discovery_connected_proxies",
            "Number of proxy nodes with a live discovery stream"
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: cumulative discovery stream-open outcomes, by result.
///
/// Labels: `result` (`accepted` — Subscribe validated and node registered;
/// `rejected` — wire-version mismatch, malformed scope, or SVID/scope-binding
/// denial before registration). A rising `rejected` rate flags misconfigured or
/// hostile clients.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn streams_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_discovery_streams_total",
                "Cumulative discovery stream-open outcomes, by result"
            ),
            &["result"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: cumulative Acks received from connected proxies. Each Ack confirms a
/// proxy applied a pushed snapshot; the rate tracks fleet-wide convergence
/// throughput.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn acks_total() -> &'static IntCounter {
    static COUNTER: OnceLock<IntCounter> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter!(
            "coxswain_discovery_acks_total",
            "Cumulative snapshot Acks received from connected proxies"
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

// ── Client-side metrics (proxy process) ─────────────────────────────────────

/// Counter: cumulative reconnect attempts made by the proxy's discovery
/// supervisor. The first connect is not counted; every subsequent channel
/// rebuild (after a drop or an SVID rotation) increments this. A climbing rate
/// signals an unstable control-plane link.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn client_reconnects_total() -> &'static IntCounter {
    static COUNTER: OnceLock<IntCounter> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter!(
            "coxswain_discovery_client_reconnects_total",
            "Cumulative discovery-client reconnect attempts (excludes the first connect)"
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Gauge: current discovery-client channel state — [`STATE_PENDING`],
/// [`STATE_READY`], or [`STATE_DEGRADED`]. Mirrors the proxy health subsystem
/// state, exposed as a scalar so dashboards/alerts can gate on it without
/// scraping the health JSON.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn client_state() -> &'static IntGauge {
    static GAUGE: OnceLock<IntGauge> = OnceLock::new();
    GAUGE.get_or_init(|| {
        register_int_gauge!(
            "coxswain_discovery_client_state",
            "Discovery-client channel state: 0=pending, 1=ready, 2=degraded"
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}
