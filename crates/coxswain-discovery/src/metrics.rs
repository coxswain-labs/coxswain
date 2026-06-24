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

// ── Server-side bootstrap/PKI metrics (controller process) ──────────────────

/// Counter: cumulative Bootstrap RPC outcomes, by result and reason.
///
/// Labels:
/// - `result` — `accepted` (SVID issued) or `rejected` (any failure before issue).
/// - `reason` — the discriminating cause. `ok` for accepts; for rejects one of
///   `wire_version`, `sa_token`, `token_review_error`, `invalid_principal`,
///   `ca_not_ready`, `malformed_csr`, `signing_error`, `internal`.
///
/// `sum(result="rejected")` answers "is the fleet failing to bootstrap"; the
/// `reason` breakdown distinguishes a misconfigured client (`sa_token`,
/// `wire_version`) from a controller-side fault (`ca_not_ready`,
/// `token_review_error`). Surfaced on the controller admin `/metrics`.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn bootstrap_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_discovery_bootstrap_total",
                "Cumulative Bootstrap RPC outcomes, by result and reason"
            ),
            &["result", "reason"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: cumulative SVIDs signed by the CA on the Bootstrap path.
///
/// Incremented once per CSR the controller signs for a bootstrapping proxy; the
/// controller's own self-issued server cert is not counted. The rate tracks
/// fleet-wide SVID issuance throughput; a flat line while proxies report
/// expiring SVIDs flags a stuck issuance path.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn svid_issued_total() -> &'static IntCounter {
    static COUNTER: OnceLock<IntCounter> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter!(
            "coxswain_discovery_svid_issued_total",
            "Cumulative SVIDs signed by the CA on the Bootstrap path"
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

// ── Client-side metrics (proxy process) ─────────────────────────────────────

/// Counter: cumulative proxy-side Bootstrap outcomes, by result.
///
/// Labels: `result` (`success` — an SVID was issued and stored; `failure` — the
/// rotation attempt failed at token read, CA-bundle read, CSR build, transport
/// setup, or the RPC). A climbing `failure` rate with no `success` means the
/// proxy is serving its last-good SVID and will eventually expire out. Surfaced
/// on the proxy admin `/metrics`.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn client_bootstrap_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_discovery_client_bootstrap_total",
                "Cumulative proxy-side Bootstrap outcomes, by result"
            ),
            &["result"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Gauge: seconds until the proxy's current SVID `not_after`.
///
/// Set on every successful bootstrap to `not_after - now`. A value approaching
/// zero (or going negative) means rotation is not keeping up with the SVID TTL —
/// the proxy will lose its control-plane credential. Mirrors the
/// `coxswain_proxy_tls_cert_expiry_seconds` precedent. Surfaced on the proxy
/// admin `/metrics`.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn client_svid_expiry_seconds() -> &'static IntGauge {
    static GAUGE: OnceLock<IntGauge> = OnceLock::new();
    GAUGE.get_or_init(|| {
        register_int_gauge!(
            "coxswain_discovery_client_svid_expiry_seconds",
            "Seconds until the proxy's current SVID notAfter"
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

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
