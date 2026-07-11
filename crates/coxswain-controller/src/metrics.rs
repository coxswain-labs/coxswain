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
///
/// # Panics
///
/// Panics if the prometheus registry already contains a series with this name
/// via a different registration path. The [`OnceLock`] makes this unreachable
/// in practice; a failure indicates a duplicate registration bug.
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
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`leader`].
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
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`leader`].
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
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`leader`].
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

/// Counter: reconcile errors, by controller key and bounded error reason.
/// Exposed separately from `reconcile_total{result="error"}` so alerting
/// rules can target it without ambiguity.
///
/// The `reason` vocabulary is [`classify_kube_error`]'s (#570):
/// `namespace_terminating`, `conflict`, `forbidden`, `not_found`, `invalid`,
/// `api_other`, `transport`, `internal`. Mirrors
/// `coxswain_discovery_bootstrap_total{result,reason}` so error causes stay
/// identifiable from `/metrics` after container log rotation drops the
/// WARN-level samples.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`leader`].
pub(crate) fn reconcile_errors_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_controller_reconcile_errors_total",
                "Reconcile errors, by controller key and bounded error reason"
            ),
            &["controller", "reason"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Gauge: shared-mode Gateways currently held with `Programmed` deferred
/// (`False/Pending` at `observedGeneration = generation - 1`) awaiting VIP
/// resolution / proxy bind / snapshot ack. A Gateway stuck here is otherwise
/// invisible: each held pass counts as `reconcile_total{result="ok"}` (#570).
/// Alert on this staying non-zero — legitimate holds clear within seconds.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`leader`].
pub(crate) fn gateways_held_pending() -> &'static IntGauge {
    static GAUGE: OnceLock<IntGauge> = OnceLock::new();
    GAUGE.get_or_init(|| {
        register_int_gauge!(
            "coxswain_controller_gateways_held_pending",
            "Shared-mode Gateways currently holding Programmed deferred (not yet converged)"
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: VIP reconciler passes, by outcome (`ok` / `degraded`). A pass is
/// `degraded` when at least one per-Gateway apply/delete failed or the
/// authoritative LIST fell back to the watch-lagged store — the pass completed
/// but some Gateway's VIP state may be stale until the next tick (#570: these
/// failures were previously log-only and invisible to alerting).
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`leader`].
pub(crate) fn vip_reconcile_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_controller_vip_reconcile_total",
                "VIP reconciler passes, by outcome"
            ),
            &["result"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: individual VIP Service apply/delete failures inside a reconciler
/// pass. Complements `vip_reconcile_total{result="degraded"}` with the raw
/// failure volume (one degraded pass can carry many failures).
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`leader`].
pub(crate) fn vip_apply_failures_total() -> &'static IntCounter {
    static COUNTER: OnceLock<IntCounter> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter!(
            "coxswain_controller_vip_apply_failures_total",
            "Individual VIP Service apply/delete failures inside reconciler passes"
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: `*/status` patch attempts, by resource kind and outcome.
///
/// Labels: `kind` (`httproute`, `gateway`, `gateway_class`, `ingress`,
/// `backend_tls_policy`), `result` (`ok` / `error` / `conflict`).
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`leader`].
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
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`leader`].
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

/// Classify a [`kube::Error`] into the bounded `reason` label recorded on
/// `reconcile_errors_total{reason}` (#570). Bounded by construction — every
/// arm returns a static slug, so tenant-controlled strings can never explode
/// the label cardinality.
///
/// `namespace_terminating` is split out from `forbidden` because the two
/// demand opposite responses: the former is a self-resolving race (the
/// namespace is being deleted; the Gateway's own DELETE event follows), the
/// latter is an RBAC misconfiguration that retrying cannot fix.
pub(crate) fn classify_kube_error(err: &kube::Error) -> &'static str {
    match err {
        kube::Error::Api(status) => match status.code {
            403 if is_namespace_terminating(status) => "namespace_terminating",
            403 => "forbidden",
            404 => "not_found",
            409 => "conflict",
            422 => "invalid",
            _ => "api_other",
        },
        kube::Error::HyperError(_) | kube::Error::Service(_) => "transport",
        _ => "internal",
    }
}

/// True when a [`classify_kube_error`] reason names a persistent failure —
/// one that faster retries cannot fix (RBAC misconfiguration, a spec the
/// apiserver rejects as invalid). The operator's error backoff polls these at
/// its cap instead of burning short retries (#570). Kept beside the
/// vocabulary so the two can never drift.
pub(crate) fn reason_is_persistent(reason: &str) -> bool {
    matches!(reason, "forbidden" | "invalid")
}

/// True when a 403 `Status` is the apiserver's `NamespaceTerminating`
/// rejection (new content in a namespace mid-deletion). Matched on the
/// structured cause first; the message substring is the fallback for
/// apiservers that omit the cause (same signal `log_vip_apply_failure`
/// keys on).
fn is_namespace_terminating(status: &kube::core::Status) -> bool {
    status
        .details
        .as_ref()
        .is_some_and(|d| d.causes.iter().any(|c| c.reason == "NamespaceTerminating"))
        || status.message.contains("is being terminated")
}

/// Bounded `reason`-label source for [`observe_reconcile`]. Implemented by
/// every reconcile error type; the label set must stay static (see
/// [`classify_kube_error`]) so a misbehaving apiserver cannot mint new
/// series.
pub(crate) trait ReconcileErrorReason {
    /// The bounded reason slug recorded on `reconcile_errors_total{reason}`.
    fn reason(&self) -> &'static str;
}

/// The shared status writer's reconcilers are infallible; this impl exists so
/// they can share [`observe_reconcile`] and is vacuously uncallable.
impl ReconcileErrorReason for std::convert::Infallible {
    fn reason(&self) -> &'static str {
        match *self {}
    }
}

/// Observe one reconcile-loop iteration on
/// `reconcile_total{controller, result}` and
/// `reconcile_duration_seconds{controller}`. On `Err`, also increments
/// `reconcile_errors_total{controller, reason}` with the error's bounded
/// [`ReconcileErrorReason`] slug.
pub(crate) fn observe_reconcile<T, E: ReconcileErrorReason>(
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
    if let Err(e) = res {
        reconcile_errors_total()
            .with_label_values(&[controller, e.reason()])
            .inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::response::{Status, StatusCause, StatusDetails};

    fn api_error(code: u16, message: &str, cause_reason: Option<&str>) -> kube::Error {
        kube::Error::Api(Box::new(Status {
            status: None,
            metadata: None,
            reason: String::new(),
            code,
            message: message.to_string(),
            details: cause_reason.map(|r| StatusDetails {
                name: String::new(),
                group: String::new(),
                kind: String::new(),
                uid: String::new(),
                causes: vec![StatusCause {
                    reason: r.to_string(),
                    message: String::new(),
                    field: String::new(),
                }],
                retry_after_seconds: 0,
            }),
        }))
    }

    #[test]
    fn classify_kube_error_covers_the_bounded_vocabulary() {
        // The verbatim #570 sample: 403 with the NamespaceTerminating cause.
        let ns_term = api_error(
            403,
            "configmaps \"coxswain-discovery-trust\" is forbidden: unable to create new \
             content in namespace e2e-x because it is being terminated",
            Some("NamespaceTerminating"),
        );
        assert_eq!(classify_kube_error(&ns_term), "namespace_terminating");
        // Message-only fallback (no structured cause).
        let ns_term_msg = api_error(403, "namespace is being terminated", None);
        assert_eq!(classify_kube_error(&ns_term_msg), "namespace_terminating");

        assert_eq!(
            classify_kube_error(&api_error(403, "rbac", None)),
            "forbidden"
        );
        assert_eq!(classify_kube_error(&api_error(404, "", None)), "not_found");
        assert_eq!(classify_kube_error(&api_error(409, "", None)), "conflict");
        assert_eq!(classify_kube_error(&api_error(422, "", None)), "invalid");
        assert_eq!(classify_kube_error(&api_error(500, "", None)), "api_other");
    }
}
