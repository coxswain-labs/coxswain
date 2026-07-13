//! Prometheus metrics emitted by the reflector debounced rebuild loop.
//!
//! Shared between the proxy and the controller pods. Construction takes a
//! [`MetricsPrefix`] variant; every emitted series uses the matching prefix
//! (`coxswain_proxy_*` or `coxswain_controller_*`) so a single binary
//! self-identifies which pod role it's running in.
//!
//! All metrics are registered against the global default registry on first
//! emission (matching the lazy-OnceLock pattern used by
//! `crates/coxswain-proxy/src/metrics.rs`). The admin handler's
//! `prometheus::gather()` call sees them automatically.
//!
//! A handful of series are role-specific:
//! - `*_tls_cert_expiry_seconds` and `*_active_upstreams` are emitted only
//!   under the `coxswain_proxy_*` prefix — the controller pod doesn't own a
//!   data plane and these series have no operator value there.
//! - `*_watch_events_total` and `*_watch_errors_total` are emitted only under
//!   the `coxswain_controller_*` prefix — the controller is the authoritative
//!   watch surface; the proxy's watch counters duplicate signal that
//!   already lands in the controller's drift mirrors.

use prometheus::{
    Histogram, HistogramOpts, IntCounterVec, IntGauge, IntGaugeVec, Opts, register_histogram,
    register_int_counter_vec, register_int_gauge, register_int_gauge_vec,
};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

/// Histogram buckets for routing-table rebuild duration in seconds.
const REBUILD_DURATION_BUCKETS: &[f64] = &[0.005, 0.025, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0];

/// Histogram buckets for the debounce-wait stage (#513). Fine-grained below
/// 500ms — the fixed trailing-edge debounce (`reconciler/proxy.rs`) is the
/// floor #512 targets, so the interesting mass is sub-ceiling, not near it.
const DEBOUNCE_WAIT_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 2.0,
];

/// Identifies which pod role is emitting the reflector's series.
///
/// Selects the `coxswain_proxy_*` vs `coxswain_controller_*` series prefix at
/// metric-handle construction time.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricsPrefix {
    /// Proxy pod (`serve proxy --shared` or `serve proxy --dedicated`). Emits
    /// routing-table mirrors, TLS expiry, and active-upstream gauges.
    Proxy,
    /// Controller pod (`serve controller`). Emits routing-table mirrors and
    /// watch counters.
    Controller,
}

/// Reflector metric handles, dispatched by [`MetricsPrefix`].
///
/// Cheap to construct (`MetricsPrefix` is `Copy`); cheap to call (each emission
/// is a `OnceLock::get_or_init` followed by a label lookup).
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct ReflectorMetrics {
    prefix: MetricsPrefix,
}

impl ReflectorMetrics {
    /// Construct a [`ReflectorMetrics`] bound to one pod role's series prefix.
    #[must_use]
    pub fn new(prefix: MetricsPrefix) -> Self {
        Self { prefix }
    }

    /// Observe one routing-table rebuild attempt: increments the
    /// `routing_table_rebuilds_total{result}` counter and records the duration
    /// on `routing_table_rebuild_duration_seconds`.
    ///
    /// `result` is the literal label value — typically `"ok"` or `"error"`.
    pub fn observe_rebuild(&self, duration: Duration, result: &'static str) {
        routing_table_rebuilds_total(self.prefix)
            .with_label_values(&[result])
            .inc();
        routing_table_rebuild_duration_seconds(self.prefix).observe(duration.as_secs_f64());
    }

    /// Observe one debounce-wait stage (#513): wall time from the first
    /// watch-event notification that opens a debounce cycle to the trailing-edge
    /// timer firing and `rebuild()` starting. Emitted once per rebuild cycle by
    /// the debounce loop, immediately before [`Self::observe_rebuild`] — the two
    /// histograms together account for "watch event → routing table published".
    pub fn observe_debounce_wait(&self, duration: Duration) {
        reconcile_debounce_seconds(self.prefix).observe(duration.as_secs_f64());
    }

    /// Set the routing-table size gauges from the result of a successful build.
    pub fn set_routing_table(&self, hosts: usize, ingress_routes: usize, gateway_routes: usize) {
        routing_table_hosts(self.prefix).set(i64_from_usize(hosts));
        routing_table_routes(self.prefix)
            .with_label_values(&["ingress"])
            .set(i64_from_usize(ingress_routes));
        routing_table_routes(self.prefix)
            .with_label_values(&["gateway"])
            .set(i64_from_usize(gateway_routes));
    }

    /// Replace the `active_upstreams{upstream}` gauge set with the active
    /// Service identities present in the new routing table. Proxy-only.
    pub fn set_active_upstreams(&self, services: &[String]) {
        if !matches!(self.prefix, MetricsPrefix::Proxy) {
            return;
        }
        let gauge = active_upstreams();
        // Resetting the vector before setting is the only way to clear
        // labels that have disappeared since the previous rebuild — the
        // prometheus crate keeps every label combination ever observed.
        gauge.reset();
        for svc in services {
            gauge.with_label_values(&[svc]).set(1);
        }
    }

    /// Replace the TLS gauges from a fresh `TlsStore` snapshot.
    ///
    /// `expiries` is the `(sni, not_after)` slice; entries whose `not_after`
    /// is in the past clamp to 0 seconds. Empty `expiries` is allowed —
    /// `tls_cert_expiry_seconds` is reset to drop stale series.
    pub fn set_tls(
        &self,
        exact: usize,
        wildcard: usize,
        default: usize,
        expiries: &[(String, String, SystemTime)],
    ) {
        let loaded = tls_certs_loaded(self.prefix);
        loaded
            .with_label_values(&["exact"])
            .set(i64_from_usize(exact));
        loaded
            .with_label_values(&["wildcard"])
            .set(i64_from_usize(wildcard));
        loaded
            .with_label_values(&["default"])
            .set(i64_from_usize(default));

        if !matches!(self.prefix, MetricsPrefix::Proxy) {
            return;
        }
        let expiry = tls_cert_expiry_seconds();
        expiry.reset();
        let now = SystemTime::now();
        for (sni, source, not_after) in expiries {
            let secs = not_after
                .duration_since(now)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            expiry
                .with_label_values(&[sni, source])
                .set(i64::try_from(secs).unwrap_or(i64::MAX));
        }
    }

    /// Increment `watch_events_total{kind, event}` for one reflector event.
    /// Controller-only. No-op on proxy.
    pub fn observe_watch_event(&self, kind: &str, event: &str) {
        if !matches!(self.prefix, MetricsPrefix::Controller) {
            return;
        }
        watch_events_total().with_label_values(&[kind, event]).inc();
    }

    /// Increment `watch_errors_total{kind}` for one reflector error.
    /// Controller-only. No-op on proxy.
    pub fn observe_watch_error(&self, kind: &str) {
        if !matches!(self.prefix, MetricsPrefix::Controller) {
            return;
        }
        watch_errors_total().with_label_values(&[kind]).inc();
    }

    /// Record relist *progress* for `kind` — an `Event::Init` (relist began) or
    /// `Event::InitApply` (an object streamed in during the list phase).
    ///
    /// Controller-only. Marks the kind's relist in-flight and (re)starts its
    /// stall timer at now, so the liveness backstop (#573) measures time since
    /// the *last* progress, not since the relist began. A relist that keeps
    /// streaming objects — or keeps retrying its LIST — never looks stalled; only
    /// one truly frozen mid-relist (no further progress, no `InitDone`) does.
    pub fn observe_relist_progress(&self, kind: &'static str) {
        if !matches!(self.prefix, MetricsPrefix::Controller) {
            return;
        }
        relist_registry().progress(kind, tokio::time::Instant::now());
    }

    /// Record that a watch relist *completed* (`Event::InitDone`) for `kind`.
    ///
    /// Controller-only. Clears the in-flight state (`watch_relists_pending{kind}`
    /// → 0) and arms the backstop for that kind — a kind is only eligible to trip
    /// liveness once it has completed at least one relist, so a slow cold-start
    /// initial sync is never mistaken for a wedge.
    pub fn observe_relist_completed(&self, kind: &'static str) {
        if !matches!(self.prefix, MetricsPrefix::Controller) {
            return;
        }
        relist_registry().completed(kind);
    }
}

fn i64_from_usize(v: usize) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Bounded window a *single in-flight relist may make no progress* before the
/// liveness backstop trips (#573). Deliberately generous — far beyond any
/// legitimate apiserver LIST page latency — so a slow-but-streaming initial sync
/// never restarts a healthy pod. Measured from the last relist *progress*
/// (`Event::Init`/`InitApply`), not from when the relist began, so a large
/// relist that keeps streaming objects is never mistaken for a wedge.
pub const RELIST_STUCK_WINDOW: Duration = Duration::from_secs(150);

/// Poll cadence of the relist liveness monitor.
const RELIST_MONITOR_TICK: Duration = Duration::from_secs(15);

/// Per-kind relist state.
///
/// The wedge signal is deliberately **not** a cumulative `started - completed`
/// diff: kube's watcher emits an `Event::Init` on every relist *attempt* but an
/// `Event::InitDone` only on success, so a single transient LIST failure leaves
/// an orphaned `Init` and would peg such a diff above zero forever — restarting
/// a healthy controller. Instead we track a single "relist in flight since"
/// instant, refreshed on every progress event and cleared on `InitDone`. A
/// frozen relist stops refreshing it; a retrying or streaming one keeps it
/// current.
#[derive(Default, Clone, Copy)]
struct KindRelist {
    /// When the current in-flight relist last made progress, or `None` once the
    /// relist has completed (`InitDone`). `Some` and old = stalled.
    in_flight_since: Option<tokio::time::Instant>,
    /// A kind is "armed" once it has completed at least one relist. Until then a
    /// slow cold-start initial sync would look identical to a wedge, so the
    /// backstop ignores it.
    armed: bool,
}

/// Process-global relist accounting, keyed by the reflector `kind` label.
struct RelistRegistry {
    kinds: parking_lot::Mutex<std::collections::HashMap<&'static str, KindRelist>>,
}

fn relist_registry() -> &'static RelistRegistry {
    static R: OnceLock<RelistRegistry> = OnceLock::new();
    R.get_or_init(|| RelistRegistry {
        kinds: parking_lot::Mutex::new(std::collections::HashMap::new()),
    })
}

impl RelistRegistry {
    /// A relist made progress (`Init` or `InitApply`) for `kind` at `now`.
    fn progress(&self, kind: &'static str, now: tokio::time::Instant) {
        let mut kinds = self.kinds.lock();
        kinds.entry(kind).or_default().in_flight_since = Some(now);
        drop(kinds);
        set_relist_in_flight(kind, true);
    }

    /// A relist completed (`InitDone`) for `kind`: clears in-flight and arms it.
    fn completed(&self, kind: &'static str) {
        let mut kinds = self.kinds.lock();
        let entry = kinds.entry(kind).or_default();
        entry.in_flight_since = None;
        entry.armed = true;
        drop(kinds);
        set_relist_in_flight(kind, false);
    }

    /// `(kind, stalled_for, armed)` for every kind: `stalled_for` is how long the
    /// kind's in-flight relist has gone without progress, or `None` if no relist
    /// is in flight.
    fn snapshot(&self, now: tokio::time::Instant) -> Vec<(&'static str, Option<Duration>, bool)> {
        self.kinds
            .lock()
            .iter()
            .map(|(kind, r)| {
                let stalled_for = r.in_flight_since.map(|since| now.duration_since(since));
                (*kind, stalled_for, r.armed)
            })
            .collect()
    }
}

fn set_relist_in_flight(kind: &'static str, in_flight: bool) {
    watch_relists_pending()
        .with_label_values(&[kind])
        .set(i64::from(in_flight));
}

fn watch_relists_pending() -> &'static IntGaugeVec {
    static GAUGE: OnceLock<IntGaugeVec> = OnceLock::new();
    GAUGE.get_or_init(|| {
        register_int_gauge_vec!(
            Opts::new(
                "coxswain_controller_watch_relists_pending",
                "1 while a reflector's watch relist is in flight (Init seen, InitDone not yet), by kind. A kind pinned at 1 for minutes is the #573 wedge signature (relist began but never completed)."
            ),
            &["kind"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Decide whether the liveness backstop should trip for one kind. Pure so the
/// guard logic is unit-testable without the monitor's clock or the global
/// registry:
/// - no relist in flight (`stalled_for` is `None`) never trips;
/// - a kind that has never completed a relist (`!armed`) never trips — a slow
///   cold-start initial sync is not a wedge;
/// - otherwise it trips once an in-flight relist has made no progress for
///   `window` (`Init`/`InitApply` refresh the clock, so only a *frozen* relist
///   reaches it).
fn relist_backstop_trips(stalled_for: Option<Duration>, armed: bool, window: Duration) -> bool {
    armed && stalled_for.is_some_and(|d| d >= window)
}

/// Run the relist liveness backstop (#573). Controller role only.
///
/// Every `RELIST_MONITOR_TICK` it inspects each kind. A kind that is armed
/// (has completed ≥1 relist) but whose in-flight relist has made no progress for
/// [`RELIST_STUCK_WINDOW`] trips `gate`, failing `/healthz` so kubelet restarts
/// the pod — reflectors then relist from scratch. The primary #573 fix should
/// make this unreachable; it is the self-heal backstop of last resort.
///
/// Runs forever; drop the driving task to stop it.
pub async fn run_relist_liveness_monitor(gate: coxswain_core::health::LivenessGate) {
    let mut ticker = tokio::time::interval(RELIST_MONITOR_TICK);
    loop {
        ticker.tick().await;
        let now = tokio::time::Instant::now();
        for (kind, stalled_for, armed) in relist_registry().snapshot(now) {
            if relist_backstop_trips(stalled_for, armed, RELIST_STUCK_WINDOW) {
                tracing::error!(
                    kind,
                    stalled_secs = stalled_for.map(|d| d.as_secs()),
                    window_secs = RELIST_STUCK_WINDOW.as_secs(),
                    "watch relist has made no progress within the liveness window; \
                     tripping liveness to force a pod restart (#573)"
                );
                gate.trip();
            }
        }
    }
}

fn routing_table_hosts(prefix: MetricsPrefix) -> &'static IntGauge {
    static PROXY: OnceLock<IntGauge> = OnceLock::new();
    static CTRL: OnceLock<IntGauge> = OnceLock::new();
    match prefix {
        MetricsPrefix::Proxy => PROXY.get_or_init(|| {
            register_int_gauge!(
                "coxswain_proxy_routing_table_hosts",
                "Distinct hostnames in the proxy routing table"
            )
            .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
        }),
        MetricsPrefix::Controller => CTRL.get_or_init(|| {
            register_int_gauge!(
                "coxswain_controller_routing_table_hosts",
                "Distinct hostnames in the controller's reconciler view of the routing table"
            )
            .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
        }),
    }
}

fn routing_table_routes(prefix: MetricsPrefix) -> &'static IntGaugeVec {
    static PROXY: OnceLock<IntGaugeVec> = OnceLock::new();
    static CTRL: OnceLock<IntGaugeVec> = OnceLock::new();
    match prefix {
        MetricsPrefix::Proxy => PROXY.get_or_init(|| {
            register_int_gauge_vec!(
                Opts::new(
                    "coxswain_proxy_routing_table_routes",
                    "Active route entries in the proxy routing table, by source kind"
                ),
                &["kind"]
            )
            .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
        }),
        MetricsPrefix::Controller => CTRL.get_or_init(|| {
            register_int_gauge_vec!(
                Opts::new(
                    "coxswain_controller_routing_table_routes",
                    "Active route entries in the controller's reconciler view, by source kind"
                ),
                &["kind"]
            )
            .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
        }),
    }
}

fn routing_table_rebuilds_total(prefix: MetricsPrefix) -> &'static IntCounterVec {
    static PROXY: OnceLock<IntCounterVec> = OnceLock::new();
    static CTRL: OnceLock<IntCounterVec> = OnceLock::new();
    match prefix {
        MetricsPrefix::Proxy => PROXY.get_or_init(|| {
            register_int_counter_vec!(
                Opts::new(
                    "coxswain_proxy_routing_table_rebuilds_total",
                    "Cumulative routing-table rebuild attempts in the proxy, by result"
                ),
                &["result"]
            )
            .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
        }),
        MetricsPrefix::Controller => CTRL.get_or_init(|| {
            register_int_counter_vec!(
                Opts::new(
                    "coxswain_controller_routing_table_rebuilds_total",
                    "Cumulative routing-table rebuild attempts in the controller, by result"
                ),
                &["result"]
            )
            .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
        }),
    }
}

fn routing_table_rebuild_duration_seconds(prefix: MetricsPrefix) -> &'static Histogram {
    static PROXY: OnceLock<Histogram> = OnceLock::new();
    static CTRL: OnceLock<Histogram> = OnceLock::new();
    match prefix {
        MetricsPrefix::Proxy => PROXY.get_or_init(|| {
            register_histogram!(
                HistogramOpts::new(
                    "coxswain_proxy_routing_table_rebuild_duration_seconds",
                    "Wall-clock duration of one proxy routing-table rebuild"
                )
                .buckets(REBUILD_DURATION_BUCKETS.to_vec())
            )
            .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
        }),
        MetricsPrefix::Controller => CTRL.get_or_init(|| {
            register_histogram!(
                HistogramOpts::new(
                    "coxswain_controller_routing_table_rebuild_duration_seconds",
                    "Wall-clock duration of one controller routing-table rebuild"
                )
                .buckets(REBUILD_DURATION_BUCKETS.to_vec())
            )
            .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
        }),
    }
}

/// `reconcile_debounce_seconds` — the #513 debounce-wait stage. See
/// [`ReflectorMetrics::observe_debounce_wait`].
fn reconcile_debounce_seconds(prefix: MetricsPrefix) -> &'static Histogram {
    static PROXY: OnceLock<Histogram> = OnceLock::new();
    static CTRL: OnceLock<Histogram> = OnceLock::new();
    match prefix {
        MetricsPrefix::Proxy => PROXY.get_or_init(|| {
            register_histogram!(
                HistogramOpts::new(
                    "coxswain_proxy_reconcile_debounce_seconds",
                    "Wall time from the first coalesced watch event to the debounce timer firing, in the proxy reflector"
                )
                .buckets(DEBOUNCE_WAIT_BUCKETS.to_vec())
            )
            .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
        }),
        MetricsPrefix::Controller => CTRL.get_or_init(|| {
            register_histogram!(
                HistogramOpts::new(
                    "coxswain_controller_reconcile_debounce_seconds",
                    "Wall time from the first coalesced watch event to the debounce timer firing, in the controller reflector"
                )
                .buckets(DEBOUNCE_WAIT_BUCKETS.to_vec())
            )
            .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
        }),
    }
}

fn tls_certs_loaded(prefix: MetricsPrefix) -> &'static IntGaugeVec {
    static PROXY: OnceLock<IntGaugeVec> = OnceLock::new();
    static CTRL: OnceLock<IntGaugeVec> = OnceLock::new();
    match prefix {
        MetricsPrefix::Proxy => PROXY.get_or_init(|| {
            register_int_gauge_vec!(
                Opts::new(
                    "coxswain_proxy_tls_certs_loaded",
                    "TLS certificates currently loaded in the proxy TLS store, by bucket"
                ),
                &["bucket"]
            )
            .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
        }),
        MetricsPrefix::Controller => CTRL.get_or_init(|| {
            register_int_gauge_vec!(
                Opts::new(
                    "coxswain_controller_tls_certs_loaded",
                    "TLS certificates the controller's reconciler view holds, by bucket"
                ),
                &["bucket"]
            )
            .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
        }),
    }
}

fn active_upstreams() -> &'static IntGaugeVec {
    static GAUGE: OnceLock<IntGaugeVec> = OnceLock::new();
    GAUGE.get_or_init(|| {
        register_int_gauge_vec!(
            Opts::new(
                "coxswain_proxy_active_upstreams",
                "Active upstream Services referenced by the proxy's routing table"
            ),
            &["upstream"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

fn tls_cert_expiry_seconds() -> &'static IntGaugeVec {
    static GAUGE: OnceLock<IntGaugeVec> = OnceLock::new();
    GAUGE.get_or_init(|| {
        register_int_gauge_vec!(
            Opts::new(
                "coxswain_proxy_tls_cert_expiry_seconds",
                "Seconds until each loaded TLS cert's notAfter, by SNI hostname and source Secret"
            ),
            &["sni", "source"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

fn watch_events_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_controller_watch_events_total",
                "Cumulative Kubernetes watch events received by the controller, by kind and event type"
            ),
            &["kind", "event"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

fn watch_errors_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_controller_watch_errors_total",
                "Cumulative Kubernetes watch errors observed by the controller, by kind"
            ),
            &["kind"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]
    use super::*;
    use coxswain_core::health::LivenessGate;

    fn fresh_registry() -> RelistRegistry {
        RelistRegistry {
            kinds: parking_lot::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// `(in_flight, armed)` for `kind`, evaluated at `now`.
    fn state(reg: &RelistRegistry, kind: &str, now: tokio::time::Instant) -> (bool, bool) {
        reg.snapshot(now)
            .into_iter()
            .find(|(k, _, _)| *k == kind)
            .map(|(_, stalled, armed)| (stalled.is_some(), armed))
            .unwrap_or_else(|| panic!("kind {kind:?} not tracked"))
    }

    #[tokio::test(start_paused = true)]
    async fn relist_registry_tracks_in_flight_and_arming() {
        let reg = fresh_registry();
        let now = tokio::time::Instant::now();
        // Cold start: a relist begins, none completed → in flight, NOT armed. A
        // slow initial sync must not look like a wedge to the backstop.
        reg.progress("k", now);
        assert_eq!(
            state(&reg, "k", now),
            (true, false),
            "an uncompleted first relist is in flight but not yet armed"
        );
        // Relist completes → not in flight, now armed.
        reg.completed("k");
        assert_eq!(
            state(&reg, "k", now),
            (false, true),
            "a completed relist clears in-flight and arms the kind"
        );
        // A second relist starts and never completes → in flight again, still armed.
        // This is the #573 wedge shape the monitor watches for.
        reg.progress("k", now);
        assert_eq!(
            state(&reg, "k", now),
            (true, true),
            "a stuck relist after arming is the wedge signature"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn orphaned_init_does_not_look_wedged_after_recovery() {
        // Regression: kube emits `Init` on every relist attempt but `InitDone`
        // only on success, so a transient LIST failure leaves an orphaned
        // progress event. A cumulative started-minus-completed diff would peg
        // "pending" forever and restart a healthy pod. The in-flight model must
        // clear cleanly once the retry finally completes.
        let reg = fresh_registry();
        let now = tokio::time::Instant::now();
        reg.progress("k", now); // Init (attempt 1)
        reg.completed("k"); // arm
        reg.progress("k", now); // Init (attempt 2 — LIST fails before InitDone)
        reg.progress("k", now); // Init (attempt 3 — retry)
        reg.completed("k"); // InitDone at last
        assert_eq!(
            state(&reg, "k", now),
            (false, true),
            "after the retry completes, no relist is in flight — the orphaned Init attempts leave no residue"
        );
    }

    #[test]
    fn relist_backstop_trip_decision() {
        let window = RELIST_STUCK_WINDOW;
        // Armed + in-flight relist stalled past the window → trip.
        assert!(
            relist_backstop_trips(Some(window), true, window),
            "an armed kind whose relist stalled for the full window must trip"
        );
        assert!(
            relist_backstop_trips(Some(window * 2), true, window),
            "still trips well past the window"
        );
        // Not yet at the window → no trip (generous grace for slow relists).
        assert!(
            !relist_backstop_trips(Some(window - Duration::from_millis(1)), true, window),
            "must not trip before the window elapses"
        );
        // Never completed a relist (cold start) → never trips, however long.
        assert!(
            !relist_backstop_trips(Some(window * 10), false, window),
            "an unarmed cold-start relist is not a wedge"
        );
        // No relist in flight → nothing to trip on.
        assert!(
            !relist_backstop_trips(None, true, window),
            "a fully-converged kind (no relist in flight) never trips"
        );
    }

    #[test]
    fn liveness_gate_used_by_monitor_starts_alive_and_trips_once() {
        // Sanity on the gate the monitor drives (core owns the type; this guards
        // the reflector's use of it).
        let gate = LivenessGate::new();
        assert!(gate.is_alive());
        gate.trip();
        assert!(!gate.is_alive(), "trip is one-way");
    }
}
