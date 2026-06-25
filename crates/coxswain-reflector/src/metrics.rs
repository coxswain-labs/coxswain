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
}

fn i64_from_usize(v: usize) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
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
