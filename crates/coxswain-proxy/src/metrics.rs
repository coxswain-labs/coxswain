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

/// Histogram buckets for HTTP request latency in seconds, sized for typical
/// proxy paths (sub-millisecond local hops through multi-second slow upstreams).
const REQUEST_DURATION_BUCKETS: &[f64] = &[
    0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Histogram buckets for TCP connection lifetime in seconds. Short-lived HTTP/1
/// requests sit near 0.05–0.5; long-lived keep-alive or HTTP/2 streams stretch
/// into the minutes.
const CONNECTION_DURATION_BUCKETS: &[f64] = &[0.05, 0.5, 5.0, 30.0, 60.0, 300.0];

/// Gauge: number of listeners currently in `"serving"` or `"draining"` state.
///
/// Labels: `state ∈ {"serving", "draining"}`.
///
/// # Panics
///
/// Panics if the prometheus registry already contains a series with this name
/// via a different registration path. The [`OnceLock`] makes this unreachable
/// in practice; a failure indicates a duplicate registration bug.
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
/// Labels: `event ∈ {"added", "removed", "drain_completed", "drain_exceeded",
/// "bind_failed"}`. `bind_failed` counts a listener whose `bind()` failed (the
/// port stays dark until a later reconcile retries) — a data-plane signal worth
/// alerting on.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
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
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
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
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
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

/// Counter: HTTP requests proxied, keyed by listener, matched route, method,
/// and final response status code.
///
/// The `route` label is the canonical rule id
/// (`httproute/<ns>/<name>:<rule_index>` or `ingress/<ns>/<name>:<r>.<p>`) —
/// the same string emitted in the access log so an operator pivoting from
/// Grafana to logs has an exact join key.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
pub(crate) fn requests_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_proxy_requests_total",
                "HTTP requests proxied, by listener, route, method, and status",
            ),
            &["listener", "route", "method", "status_code"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Histogram: request latency in seconds, from `request_filter` entry to
/// `logging` invocation.
///
/// Carries only `listener` and `route` — `status_code` and `method` deliberately
/// omitted to keep the histogram cardinality bounded. Operators correlate
/// latency to status via the counter above.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
pub(crate) fn request_duration_seconds() -> &'static HistogramVec {
    static HIST: OnceLock<HistogramVec> = OnceLock::new();
    HIST.get_or_init(|| {
        register_histogram_vec!(
            HistogramOpts::new(
                "coxswain_proxy_request_duration_seconds",
                "End-to-end request latency in seconds, by listener and route",
            )
            .buckets(REQUEST_DURATION_BUCKETS.to_vec()),
            &["listener", "route"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: upstream-side request failures, classified by error type.
///
/// Labels: `error_type ∈ {"connect", "timeout", "refused", "tls", "5xx", "other"}`.
/// Incremented in `fail_to_proxy` (connect/timeout/refused/tls) and
/// `upstream_response_filter` (5xx). The `"other"` bucket catches Pingora
/// error types not mapped explicitly so unexpected classes don't silently
/// misattribute.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
pub(crate) fn upstream_errors_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_proxy_upstream_errors_total",
                "Upstream errors observed by the proxy, classified by error type",
            ),
            &["listener", "route", "upstream", "error_type"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: upstream retry attempts fired by the proxy, classified by retry condition.
///
/// Incremented once per retry attempt (not per request) immediately when the retry
/// decision is made — in `fail_to_connect` for `connect-failure`/`timeout` conditions
/// and in `upstream_response_filter` for the `5xx` condition. The final (non-retried)
/// attempt is NOT counted here; it is captured by [`upstream_errors_total`] instead.
///
/// Labels: `condition ∈ {"connect-failure", "timeout", "5xx"}`.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
pub(crate) fn upstream_retries_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_proxy_upstream_retries_total",
                "Upstream retry attempts fired by the proxy, by retry condition",
            ),
            &["listener", "route", "upstream", "condition"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: mirror requests dispatched fire-and-forget by the proxy.
///
/// Keyed by the matched route and the mirror upstream address selected at
/// dispatch time.  Incremented once per mirror dispatch regardless of whether
/// the mirror upstream returns an error — the counter reflects *attempts*, not
/// successes.  Use in conjunction with the mirror-specific access log rows
/// (`mirror = true`) for per-request outcome detail.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
pub(crate) fn mirror_requests_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_proxy_mirror_requests_total",
                "Mirror requests dispatched fire-and-forget by the proxy, by route and upstream",
            ),
            &["route", "upstream"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

// `active_upstreams`, `tls_certs_loaded`, and `tls_cert_expiry_seconds` are
// registered by `coxswain_reflector::metrics` — the proxy crate doesn't
// duplicate them here because both modules would try to register the same
// global name and the second registration would panic. The proxy reads its
// values via the reflector's `ReflectorMetrics` handle.

/// Counter: TLS handshakes completed by the proxy, by negotiated version and
/// success/failure result.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
pub(crate) fn tls_handshakes_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_proxy_tls_handshakes_total",
                "TLS handshakes completed by the proxy, by result and version",
            ),
            &["result", "version"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Gauge: open downstream connections to the proxy, by listener.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
pub(crate) fn connections_active() -> &'static IntGaugeVec {
    static GAUGE: OnceLock<IntGaugeVec> = OnceLock::new();
    GAUGE.get_or_init(|| {
        register_int_gauge_vec!(
            Opts::new(
                "coxswain_proxy_connections_active",
                "Open downstream connections to the proxy, by listener",
            ),
            &["listener"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: cumulative downstream connections accepted by the proxy.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
pub(crate) fn connections_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_proxy_connections_total",
                "Cumulative downstream connections accepted, by listener",
            ),
            &["listener"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: upstream connections established by the proxy, classified by whether
/// the connection was freshly opened or reused from the keepalive pool.
///
/// Incremented once per request in the `connected_to_upstream` Pingora hook.
///
/// Labels: `state ∈ {"new", "reused"}`.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
pub(crate) fn upstream_connections_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_proxy_upstream_connections_total",
                "Upstream connections established by the proxy, by connection state",
            ),
            &["state"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

// ── Circuit-breaker metrics (#282) ────────────────────────────────────────────

/// Gauge: current circuit-breaker state per `(route, upstream)` pair.
///
/// Values: `0` = Closed, `1` = Open, `2` = HalfOpen.
/// Labels: `route` (the `metric_route_id`), `upstream` (the `SocketAddr` string).
///
/// Updated by [`crate::policy::circuit_breaker::MetricsInstrument`] in the `on_open`,
/// `on_half_open`, and `on_closed` [`failsafe::Instrument`] callbacks — transition
/// time only, never on the per-request hot path.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
pub(crate) fn circuit_breaker_state() -> &'static IntGaugeVec {
    static GAUGE: OnceLock<IntGaugeVec> = OnceLock::new();
    GAUGE.get_or_init(|| {
        register_int_gauge_vec!(
            Opts::new(
                "coxswain_proxy_circuit_breaker_state",
                "Per-endpoint circuit-breaker state: 0=closed, 1=open, 2=half_open",
            ),
            &["route", "upstream"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: cumulative requests rejected by an Open circuit breaker (fail-fast 503s).
///
/// Labels: `route` (the `metric_route_id`), `upstream` (the `SocketAddr` string).
///
/// Bumped in the `on_call_rejected` [`failsafe::Instrument`] callback.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
pub(crate) fn circuit_breaker_rejected_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_proxy_circuit_breaker_rejected_total",
                "Cumulative requests rejected by an open circuit breaker (fail-fast 503s)",
            ),
            &["route", "upstream"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: cumulative circuit-breaker state transitions.
///
/// Labels: `route` (the `metric_route_id`), `upstream` (the `SocketAddr` string),
/// `to ∈ {"open", "half_open", "closed"}`.
///
/// Bumped in the `on_open`, `on_half_open`, and `on_closed` [`failsafe::Instrument`]
/// callbacks alongside the state gauge update.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
pub(crate) fn circuit_breaker_transitions_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_proxy_circuit_breaker_transitions_total",
                "Cumulative circuit-breaker state transitions, by target state",
            ),
            &["route", "upstream", "to"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Histogram: downstream connection lifetime in seconds, observed on close.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`listeners_active`].
pub(crate) fn connection_duration_seconds() -> &'static HistogramVec {
    static HIST: OnceLock<HistogramVec> = OnceLock::new();
    HIST.get_or_init(|| {
        register_histogram_vec!(
            HistogramOpts::new(
                "coxswain_proxy_connection_duration_seconds",
                "Downstream connection lifetime in seconds, by listener",
            )
            .buckets(CONNECTION_DURATION_BUCKETS.to_vec()),
            &["listener"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}
