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
    Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts, register_histogram,
    register_int_counter, register_int_counter_vec, register_int_gauge,
};
use std::sync::OnceLock;

/// Histogram buckets for the #513 convergence-stage timings this module
/// exposes (`snapshot_build_seconds`, `ack_latency_seconds`,
/// `snapshot_apply_seconds`). Snapshot build/apply are sub-millisecond to
/// low-millisecond (serialization/decoding of an in-memory DTO); ack latency
/// spans a network round trip plus proxy-side apply, so its useful mass runs
/// wider — the shared bucket set covers both without a second table.
const STAGE_DURATION_BUCKETS: &[f64] = &[
    0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

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
/// decremented when the per-stream task exits (disconnect). The `Stream` RPC is
/// leader-gated (#531): standby replicas reject streams at accept
/// (`streams_total{result="rejected_not_leader"}`) and hold this gauge at `0`,
/// so `sum()` across controller replicas equals the leader's value and a
/// non-zero reading on a standby indicates a gating bug. A drop to `0` on the
/// leader during steady-state means the whole proxy fleet lost its
/// control-plane link.
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
/// denial before registration; `rejected_not_leader` — dial reached a standby
/// replica while the Stream RPC is leader-gated, #531). A rising `rejected`
/// rate flags misconfigured or hostile clients; a steady `rejected_not_leader`
/// trickle during leader churn is expected (proxies redial until they land on
/// the leader).
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

/// Histogram: wall-clock cost of one [`crate::server`] `build_snapshot` call —
/// the "snapshot build" stage of the #513 convergence pipeline (reading the
/// routing cells and serializing them into the wire DTO). Observed on every
/// build, whether or not the content differs from the last Ack (a same-content
/// rebuild still pays this cost before the no-op is detected).
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn snapshot_build_seconds() -> &'static Histogram {
    static HIST: OnceLock<Histogram> = OnceLock::new();
    HIST.get_or_init(|| {
        register_histogram!(
            HistogramOpts::new(
                "coxswain_discovery_snapshot_build_seconds",
                "Wall-clock duration of one discovery snapshot build (routing cells -> wire DTO)"
            )
            .buckets(STAGE_DURATION_BUCKETS.to_vec())
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Histogram: wall-clock time from a snapshot being sent to a proxy to that
/// proxy's matching Ack arriving — the "push to proxy apply to Ack" leg of the
/// #513 convergence pipeline in one number (network round trip plus
/// client-side decode and apply). Observed in [`crate::server::run_stream`]'s
/// Ack handler; a Nack or a stream drop before Ack never observes — last-good
/// is retained, and there is no completed convergence to time.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn ack_latency_seconds() -> &'static Histogram {
    static HIST: OnceLock<Histogram> = OnceLock::new();
    HIST.get_or_init(|| {
        register_histogram!(
            HistogramOpts::new(
                "coxswain_discovery_ack_latency_seconds",
                "Wall-clock time from a snapshot push to the matching client Ack"
            )
            .buckets(STAGE_DURATION_BUCKETS.to_vec())
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: cumulative snapshot messages the server pushed, by `kind`
/// (`full` | `delta`) (#383). The per-stream delta engine sends a `full` only on
/// the first message of a session (connect / reconnect) or a Nack-driven resync;
/// every steady-state routing change ships as a `delta`. A healthy steady state
/// is a climbing `delta` against a near-static `full` — a rising `full` rate
/// signals control-plane link churn or repeated self-healing resyncs, mirroring
/// the client-side [`client_snapshots_applied_total`] from the sending end.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn snapshot_messages_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_discovery_snapshot_messages_total",
                "Cumulative snapshot messages the server pushed, by kind (full|delta)"
            ),
            &["kind"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: cumulative resource DTOs the server placed in a snapshot's `resources`
/// field — i.e. upserts (#383). A full contributes its whole world; a delta
/// contributes only the changed resources. Divided by
/// [`snapshot_messages_total`] it gives the average payload width; under endpoint
/// churn a delta carries a single `endpoints|…` resource, so the average collapses
/// toward one — the whole point of EDS-style deltas.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn snapshot_resources_sent_total() -> &'static IntCounter {
    static COUNTER: OnceLock<IntCounter> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter!(
            "coxswain_discovery_snapshot_resources_sent_total",
            "Cumulative resource upserts the server placed in pushed snapshots"
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: cumulative resource tombstones (`removed_resources` canonical keys)
/// the server placed in delta snapshots (#383). A full never contributes (its
/// `removed_resources` is empty); a delta contributes one entry per resource that
/// left the world since the client's acked baseline. A route deletion or an
/// endpoint's last-referrer removal shows up here.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn snapshot_resources_removed_total() -> &'static IntCounter {
    static COUNTER: OnceLock<IntCounter> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter!(
            "coxswain_discovery_snapshot_resources_removed_total",
            "Cumulative resource tombstones the server placed in delta snapshots"
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

/// Counter: cumulative route partitions the client **recompiled** on the apply
/// path (#383). A partition is recompiled when its wire DTO changed or an
/// endpoint it references changed; unchanged partitions are spliced from the
/// live table instead (see [`client_partitions_reused_total`]). The ratio of
/// reused to recompiled is the payoff of the partitioned apply: under endpoint
/// churn only the referencing partitions recompile.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn client_partitions_recompiled_total() -> &'static IntCounter {
    static COUNTER: OnceLock<IntCounter> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter!(
            "coxswain_discovery_client_partitions_recompiled_total",
            "Cumulative route partitions recompiled on the discovery-client apply path"
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: cumulative route partitions the client **reused** (spliced the
/// live compiled `Arc<HostRouter>` for) on the apply path (#383) instead of
/// recompiling. Counterpart to [`client_partitions_recompiled_total`].
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn client_partitions_reused_total() -> &'static IntCounter {
    static COUNTER: OnceLock<IntCounter> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter!(
            "coxswain_discovery_client_partitions_reused_total",
            "Cumulative route partitions reused (spliced) on the discovery-client apply path"
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Counter: cumulative snapshots the client successfully applied (Ack'd),
/// labelled by `kind` (`full` | `delta`) (#383). A healthy steady state is a
/// climbing `delta` with a near-static `full`: fulls happen only on the first
/// message of a session (connect / reconnect) or after a Nack-driven resync, so
/// a rising `full` rate signals churn on the control-plane link or repeated
/// self-healing resyncs.
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn client_snapshots_applied_total() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "coxswain_discovery_client_snapshots_applied_total",
                "Cumulative snapshots the client applied, by kind (full|delta)"
            ),
            &["kind"]
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}

/// Histogram: wall-clock cost of one `apply::apply_message` call in
/// [`crate::client`] — the "proxy apply" stage of the #513 convergence
/// pipeline (staging every wire DTO and, on success, publishing the
/// [`Shared`] routing cells). Observed on every call regardless of outcome —
/// a rejected (Nack'd) decode still pays most of the cost this histogram
/// times before failing, and that cost is exactly what a malformed-snapshot
/// regression would inflate.
///
/// [`Shared`]: coxswain_core::Shared
///
/// # Panics
///
/// Panics on duplicate prometheus registration — see [`connected_proxies`].
pub fn snapshot_apply_seconds() -> &'static Histogram {
    static HIST: OnceLock<Histogram> = OnceLock::new();
    HIST.get_or_init(|| {
        register_histogram!(
            HistogramOpts::new(
                "coxswain_discovery_snapshot_apply_seconds",
                "Wall-clock duration of one discovery-client snapshot apply (wire DTO -> routing cells)"
            )
            .buckets(STAGE_DURATION_BUCKETS.to_vec())
        )
        .unwrap_or_else(|e| panic!("invariant: metric already registered — this is a bug: {e}"))
    })
}
