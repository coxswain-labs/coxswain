//! Prometheus metrics emitted by the controller pod role.
//!
//! Owned by `coxswain-controller` because every series here is controller-only
//! (leader election, reconcile loop, `*/status` patches). Reflector-shared
//! series live in `coxswain_reflector::metrics`.
//!
//! All metrics are registered against the global default registry on first
//! emission (matching the `OnceLock` pattern in
//! `crates/coxswain-proxy/src/metrics.rs`). `coxswain_admin`'s
//! `prometheus::gather()` call picks them up automatically.

use prometheus::{
    HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, register_histogram_vec,
    register_int_counter, register_int_counter_vec, register_int_gauge,
};
use std::sync::OnceLock;

/// Histogram buckets shared by `reconcile_duration_seconds` and
/// `status_patch_duration_seconds`. Same shape as the reflector's
/// `routing_table_rebuild_duration_seconds` — operators dashboard on
/// "controller-side latency" consistently across the three histograms.
const CONTROLLER_LATENCY_BUCKETS: &[f64] =
    &[0.005, 0.025, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0];

/// Gauge: `1` when this controller replica holds the leader lease, `0`
/// otherwise. Always at most one replica reports `1` cluster-wide; operators
/// can `sum()` this metric to assert exactly one leader at all times.
pub(crate) fn leader() -> &'static IntGauge {
    static GAUGE: OnceLock<IntGauge> = OnceLock::new();
    GAUGE.get_or_init(|| {
        register_int_gauge!(
            "coxswain_controller_leader",
            "1 when this controller replica holds the leader lease, 0 otherwise"
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: cumulative leader-flip transitions observed by this replica.
/// Spikes here usually mean an unstable lease (network partition, slow node)
/// — under steady-state operation this stays at 0 or 1 for the replica's
/// lifetime.
pub(crate) fn leader_transitions_total() -> &'static IntCounter {
    static COUNTER: OnceLock<IntCounter> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter!(
            "coxswain_controller_leader_transitions_total",
            "Cumulative leader-flip transitions observed by this replica"
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: cumulative reconcile-loop iterations, by controller key and outcome.
///
/// Labels: `controller` (e.g. `operator`), `result` (`ok` / `error` / `requeue`).
pub(crate) fn reconcile_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_controller_reconcile_total",
                "Cumulative reconcile-loop iterations, by controller key and outcome"
            ),
            &["controller", "result"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Histogram: reconcile-loop wall-clock duration, by controller key.
pub(crate) fn reconcile_duration_seconds() -> &'static HistogramVec {
    static HIST: OnceLock<HistogramVec> = OnceLock::new();
    HIST.get_or_init(|| {
        register_histogram_vec!(
            HistogramOpts::new(
                "coxswain_controller_reconcile_duration_seconds",
                "Reconcile-loop wall-clock duration, by controller key"
            )
            .buckets(CONTROLLER_LATENCY_BUCKETS.to_vec()),
            &["controller"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: reconcile errors, by controller key. Exposed separately from
/// `reconcile_total{result="error"}` so alerting rules can target it
/// without ambiguity.
pub(crate) fn reconcile_errors_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_controller_reconcile_errors_total",
                "Reconcile errors, by controller key"
            ),
            &["controller"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: `*/status` patch attempts, by resource kind and outcome.
///
/// Labels: `kind` (`httproute`, `gateway`, `gateway_class`, `ingress`,
/// `backend_tls_policy`), `result` (`ok` / `error` / `conflict`).
pub(crate) fn status_patch_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_controller_status_patch_total",
                "Status-patch attempts, by resource kind and outcome"
            ),
            &["kind", "result"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Histogram: `*/status` patch wall-clock duration, by resource kind.
pub(crate) fn status_patch_duration_seconds() -> &'static HistogramVec {
    static HIST: OnceLock<HistogramVec> = OnceLock::new();
    HIST.get_or_init(|| {
        register_histogram_vec!(
            HistogramOpts::new(
                "coxswain_controller_status_patch_duration_seconds",
                "Status-patch wall-clock duration, by resource kind"
            )
            .buckets(CONTROLLER_LATENCY_BUCKETS.to_vec()),
            &["kind"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Classify a Kubernetes patch outcome into the `status_patch_total` result
/// label. Used by every status-patch wrapper so the label vocabulary stays
/// consistent.
pub(crate) fn classify_patch_result<T>(res: &Result<T, kube::Error>) -> &'static str {
    match res {
        Ok(_) => "ok",
        Err(kube::Error::Api(e)) if e.code == 409 => "conflict",
        Err(_) => "error",
    }
}

/// Observe one status-patch outcome on `status_patch_total{kind, result}`
/// and `status_patch_duration_seconds{kind}`. The result is derived via
/// [`classify_patch_result`].
pub(crate) fn observe_status_patch<T>(
    kind: &'static str,
    started_at: std::time::Instant,
    res: &Result<T, kube::Error>,
) {
    let result = classify_patch_result(res);
    status_patch_total()
        .with_label_values(&[kind, result])
        .inc();
    status_patch_duration_seconds()
        .with_label_values(&[kind])
        .observe(started_at.elapsed().as_secs_f64());
}

/// Observe one reconcile-loop iteration on
/// `reconcile_total{controller, result}` and
/// `reconcile_duration_seconds{controller}`. On `Err`, also increments
/// `reconcile_errors_total{controller}`.
pub(crate) fn observe_reconcile<T, E>(
    controller: &'static str,
    started_at: std::time::Instant,
    res: &Result<T, E>,
) {
    let result = if res.is_ok() { "ok" } else { "error" };
    reconcile_total()
        .with_label_values(&[controller, result])
        .inc();
    reconcile_duration_seconds()
        .with_label_values(&[controller])
        .observe(started_at.elapsed().as_secs_f64());
    if res.is_err() {
        reconcile_errors_total()
            .with_label_values(&[controller])
            .inc();
    }
}
