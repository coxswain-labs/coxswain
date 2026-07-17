#![allow(missing_docs)]
//! Observability surface: readiness/status, Prometheus metrics, and access
//! logs.
//!
//! This suite replaces the original `tests/health.rs` (issue #158) and adds
//! e2e coverage for issue #20 (Prometheus metric surface) and the access-log
//! work that shipped under #21 without dedicated tests.
//!
//! Layout:
//! - `readyz_starts_not_ready_then_transitions_to_ready` + `status_exposes_per_subsystem_checks`
//!   — migrated verbatim from `health.rs`.
//! - `proxy_pod_emits_proxy_prefix_metrics` + `controller_pod_emits_controller_prefix_metrics`
//!   — Prometheus surface scoped per pod role.
//! - `convergence_stage_metrics_recorded_after_route_change` + `stage_metrics_are_role_scoped`
//!   — #513 per-stage convergence timing: a route change advances every stage's
//!   histogram sample count, and each stage's series is scoped to the pod role
//!   that owns it (reflector stages controller-only, discovery-apply proxy-only).
//! - `isolated_route_change_debounces_well_under_fixed_floor` +
//!   `event_burst_within_window_coalesces_to_few_rebuilds` — #512 adaptive
//!   debounce: an isolated change settles far under the old fixed 500ms floor,
//!   and a rapid burst on one Ingress still coalesces into few rebuilds.
//! - `access_log_*` — five cases that pin the access-log contract: required
//!   fields (including the new `route_id` join key), path-mode behaviour,
//!   error-path emission, and disabled-mode silence.
//! - `pod_logs_stream_from_controller_not_proxy` — the `/api/v1/pods/{name}/logs`
//!   relay (#285): controller serves it, proxy 404s, unknown pod 404s.
//! - `conflict_emits_warning_event_on_loser` — route conflict (`#390`): the losing
//!   Ingress receives a `Warning RouteConflict` Event naming the winner; the winner
//!   does not.
//! - `invalid_annotation_emits_warning_event` — annotation parse failure (`#401`): the
//!   misconfigured Ingress receives a `Warning InvalidAnnotation` Event; a valid
//!   Ingress receives none.
//! - `rate_limit_by_header_without_auth_emits_warning_event` — header keying without auth
//!   (`#411`): the controller emits `InvalidAnnotation` Warning Event; when auth IS paired
//!   no event is emitted.
//! - `sha1_htpasswd_credential_emits_warning_event` — weak htpasswd hash (`#412`): a `{SHA}`
//!   credential triggers an `InvalidAnnotation` Warning Event naming the username; a
//!   bcrypt-only secret emits none.

use anyhow::Context as _;
use coxswain_e2e::{
    ControllerOptions, FixtureVars, Harness, IngressClassGuard, NamespaceGuard,
    fixtures::{self, backends, gateway_api as gwa, ingress},
    harness::wait,
};
use gateway_api_types::apis::standard::gateways::Gateway;
use k8s_openapi::api::events::v1::Event as K8sEvent;
use k8s_openapi::api::networking::v1::Ingress;
use kube::Api;
use kube::api::{DeleteParams, Patch, PatchParams};
use std::time::Duration;

mod common;

/// Controller-subsystem checks asserted in `/status.subsystems.controller.checks`.
///
/// Order is irrelevant. Keep in lockstep with `ALWAYS_ON_CHECKS`, `INGRESS_CHECKS`,
/// and `GATEWAY_API_CHECKS` in `status_writer.rs` — the default install enables
/// both surfaces so all three sets are registered.
const CONTROLLER_CHECKS: &[&str] = &[
    // always-on
    "endpoint_slice",
    "secret",
    "service",
    "pod",
    "routing_table_built",
    // ingress surface
    "ingress",
    "ingress_class",
    "ingress_class_parameters",
    "auth_secret",
    "auth_tls_secret",
    // gateway-api surface
    "gateway_api_crds",
    "httproute",
    "grpcroute",
    "tls_route",
    "gateway",
    "gateway_class",
    "listener_set",
    "namespace",
    "reference_grant",
    "backend_tls_policy",
    "config_map",
    "rate_limit",
    "path_rewrite_regex",
];

// Note: the original `readyz_starts_not_ready_then_transitions_to_ready` test
// from `health.rs` was deleted alongside the move to the Helm-deployed harness
// (#236). It depended on observing the proxy *during* its initial cold-start
// transition, but the harness now connects to a long-running, already-Ready
// pod via a port-forward — there is no cold-start window to observe. The
// initial readiness gate is still exercised end-to-end:
//   - `helm install --wait` blocks until `/readyz` returns 200, so all tests
//     transitively assert it;
//   - `status_exposes_per_subsystem_checks` (below) verifies the per-subsystem
//     check detail behind that gate.

#[tokio::test]
async fn status_exposes_per_subsystem_checks() -> anyhow::Result<()> {
    let h = Harness::start().await?;

    // The aggregated fleet health (controller + proxy subsystems) is served by
    // the CONTROLLER admin port — the proxy's own /api/v1/health reports only
    // its local `proxy` subsystem. The controller aggregates the proxy's health
    // via the discovery NodeRegistry, which populates shortly after the proxy's
    // discovery handshake completes, so poll rather than racing a single fetch.
    let url = h.controller_admin_url("/api/v1/health");
    let health: serde_json::Value = wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async { "controller + proxy subsystems to report ready".to_string() },
        || {
            let url = url.clone();
            async move {
                let h: serde_json::Value = reqwest::get(&url).await.ok()?.json().await.ok()?;
                let subs = h.get("subsystems")?.as_object()?;
                let ready = |name: &str| {
                    subs.get(name).and_then(|s| s["state"]["state"].as_str()) == Some("ready")
                };
                (ready("controller") && ready("proxy")).then_some(h)
            }
        },
    )
    .await?;

    let subsystems = health["subsystems"]
        .as_object()
        .expect("/api/v1/health.subsystems must be an object");
    assert!(subsystems.contains_key("controller"));
    assert!(subsystems.contains_key("proxy"));

    let controller = &health["subsystems"]["controller"];
    assert_eq!(controller["state"]["state"], "ready");
    let controller_checks = controller["checks"]
        .as_object()
        .expect("controller.checks must be an object");
    for expected in CONTROLLER_CHECKS {
        let entry = controller_checks
            .get(*expected)
            .unwrap_or_else(|| panic!("controller.checks must contain '{expected}'"));
        assert_eq!(entry["state"], "ready");
    }

    let proxy = &health["subsystems"]["proxy"];
    assert_eq!(proxy["state"]["state"], "ready");
    let proxy_checks = proxy["checks"]
        .as_object()
        .expect("proxy.checks must be an object");
    assert_eq!(proxy_checks["routing_table_loaded"]["state"], "ready");

    Ok(())
}

/// Driving 10 requests through the shared proxy should populate the
/// `coxswain_proxy_*` Prometheus series and leave the `coxswain_controller_*`
/// prefix absent on the proxy-pod scrape target.
#[tokio::test]
async fn proxy_pod_emits_proxy_prefix_metrics() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-proxy").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("ingress.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;
    for _ in 0..10 {
        h.http.get(&host, "/a").await?;
    }

    let metrics = reqwest::get(h.admin_url("/metrics")).await?.text().await?;
    assert!(
        metrics.contains("coxswain_proxy_requests_total{"),
        "proxy /metrics must expose coxswain_proxy_requests_total"
    );
    assert!(
        metrics.contains("coxswain_proxy_request_duration_seconds_count"),
        "proxy /metrics must expose request_duration_seconds histogram"
    );
    // Note: `coxswain_proxy_routing_table_rebuilds_total` is intentionally NOT
    // asserted here — post-#424 the proxy is a pure discovery client that
    // applies pushed snapshots rather than rebuilding routing tables, so the
    // rebuild counter is emitted only by the controller (with the
    // `coxswain_controller_` prefix), never the proxy.
    assert!(
        metrics.contains("status_code=\"200\""),
        "requests_total must carry the status_code=200 sample after the 10 requests"
    );
    let route_label = format!("route=\"ingress/{}/echo-ingress:", ns.name);
    assert!(
        metrics.lines().any(|l| l.contains(&route_label)),
        "requests_total must carry a route label rooted in `{}`",
        route_label
    );
    assert!(
        !metrics.contains("coxswain_controller_"),
        "proxy-pod /metrics must NOT expose coxswain_controller_* series"
    );

    Ok(())
}

/// The controller pod's admin endpoint should expose `coxswain_controller_*`
/// series (reconcile, leader, routing-table mirror) and never expose the
/// `coxswain_proxy_*` request counters.
#[tokio::test]
async fn controller_pod_emits_controller_prefix_metrics() -> anyhow::Result<()> {
    let h = Harness::start().await?;

    let metrics = reqwest::get(h.controller_admin_url("/metrics"))
        .await?
        .text()
        .await?;
    assert!(
        metrics.contains("coxswain_controller_leader "),
        "controller /metrics must expose coxswain_controller_leader gauge"
    );
    assert!(
        metrics.contains("coxswain_controller_routing_table_hosts"),
        "controller /metrics must mirror routing_table_hosts"
    );
    assert!(
        metrics.contains("coxswain_controller_routing_table_rebuilds_total"),
        "controller /metrics must expose routing_table_rebuilds_total"
    );
    assert!(
        !metrics.contains("coxswain_proxy_requests_total"),
        "controller-pod /metrics must NOT expose coxswain_proxy_requests_total"
    );

    Ok(())
}

/// Read a bare (no-label) Prometheus histogram/counter sample, defaulting to
/// `0.0` when the series is absent — lets a before/after comparison treat
/// "not yet registered" the same as "zero observations so far".
fn count_or_zero(body: &str, metric: &str) -> f64 {
    wait::parse_metric_value(body, metric).unwrap_or(0.0)
}

/// `true` iff `controller_metrics` is a scrape of the LEADING controller
/// replica. The controller runs 2 replicas under leader election
/// (`coxswain_controller_leader` gauge); the discovery server's `Stream` RPC
/// is leader-gated (#531), so `snapshot_build_seconds`/`ack_latency_seconds`
/// are only ever observed on the leader — a standby's `build_snapshot`/
/// `handle_ack` code paths never run. The e2e harness's controller
/// port-forward targets `svc/coxswain-controller`, which non-deterministically
/// lands on whichever replica was up when the tunnel was established, so
/// assertions on those two series must gate on this, exactly as a real
/// Prometheus query would (`coxswain_controller_leader == 1`).
fn is_leader(controller_metrics: &str) -> bool {
    wait::parse_metric_value(controller_metrics, "coxswain_controller_leader") == Some(1.0)
}

/// #513: a resource change that actually converges (the route starts serving)
/// must advance every convergence-pipeline stage's histogram sample count past
/// a pre-change baseline — debounce-wait and rebuild on the controller,
/// snapshot-build and ack-latency on the discovery server (leader-only, see
/// [`is_leader`]), and snapshot-apply on the discovery client (the proxy
/// process). Comparing against a captured baseline (rather than asserting
/// bare presence) proves the pipeline is wired end-to-end for THIS
/// convergence, not just that the series exist from an earlier one.
#[tokio::test]
async fn convergence_stage_metrics_recorded_after_route_change() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-conv").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let before_controller = reqwest::get(h.controller_admin_url("/metrics"))
        .await?
        .text()
        .await?;
    let before_proxy = reqwest::get(h.admin_url("/metrics")).await?.text().await?;
    let leader = is_leader(&before_controller);
    let before_debounce = count_or_zero(
        &before_controller,
        "coxswain_controller_reconcile_debounce_seconds_count",
    );
    let before_rebuild = count_or_zero(
        &before_controller,
        "coxswain_controller_routing_table_rebuild_duration_seconds_count",
    );
    let before_build = count_or_zero(
        &before_controller,
        "coxswain_discovery_snapshot_build_seconds_count",
    );
    let before_ack = count_or_zero(
        &before_controller,
        "coxswain_discovery_ack_latency_seconds_count",
    );
    let before_apply = count_or_zero(
        &before_proxy,
        "coxswain_discovery_snapshot_apply_seconds_count",
    );

    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;
    let host = format!("ingress.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;

    wait::poll_until(
        Duration::from_secs(30),
        Duration::from_millis(200),
        || async {
            "timed out waiting for convergence stage metrics to advance past their pre-change baseline"
                .to_string()
        },
        || async {
            let controller = reqwest::get(h.controller_admin_url("/metrics"))
                .await
                .ok()?
                .text()
                .await
                .ok()?;
            let proxy = reqwest::get(h.admin_url("/metrics")).await.ok()?.text().await.ok()?;
            let advanced = count_or_zero(
                &controller,
                "coxswain_controller_reconcile_debounce_seconds_count",
            ) > before_debounce
                && count_or_zero(
                    &controller,
                    "coxswain_controller_routing_table_rebuild_duration_seconds_count",
                ) > before_rebuild
                && (!leader
                    || count_or_zero(&controller, "coxswain_discovery_snapshot_build_seconds_count")
                        > before_build)
                && (!leader
                    || count_or_zero(&controller, "coxswain_discovery_ack_latency_seconds_count")
                        > before_ack)
                && count_or_zero(&proxy, "coxswain_discovery_snapshot_apply_seconds_count")
                    > before_apply;
            advanced.then_some(())
        },
    )
    .await?;

    Ok(())
}

/// #513 role-scoping (sad path, companion to the happy-path test above):
/// mirrors the `*_emits_*_prefix_metrics` role-split contract. Reflector
/// stages (debounce, rebuild) live on every controller replica; discovery-server
/// stages (snapshot-build, ack-latency) are additionally leader-gated (see
/// [`is_leader`]) — a standby controller never runs them, by design (#531),
/// not by bug. Post-#424 the shared proxy is a pure discovery client, never a
/// reflector, and never runs the discovery server. The discovery-client apply
/// stage is the mirror image — proxy-only. A stage metric leaking to the
/// wrong role is the failure this test guards.
#[tokio::test]
async fn stage_metrics_are_role_scoped() -> anyhow::Result<()> {
    let h = Harness::start().await?;

    let controller = reqwest::get(h.controller_admin_url("/metrics"))
        .await?
        .text()
        .await?;
    let proxy = reqwest::get(h.admin_url("/metrics")).await?.text().await?;

    assert!(
        controller.contains("coxswain_controller_reconcile_debounce_seconds"),
        "controller /metrics must expose the reflector debounce-wait stage"
    );
    if is_leader(&controller) {
        assert!(
            controller.contains("coxswain_discovery_snapshot_build_seconds"),
            "the LEADING controller's /metrics must expose the discovery-server snapshot-build stage"
        );
    }
    assert!(
        proxy.contains("coxswain_discovery_snapshot_apply_seconds"),
        "proxy /metrics must expose the discovery-client apply stage"
    );

    assert!(
        !proxy.contains("coxswain_controller_reconcile_debounce_seconds"),
        "proxy-pod /metrics must NOT expose the controller-only debounce stage"
    );
    assert!(
        !proxy.contains("coxswain_controller_routing_table_rebuild_duration_seconds"),
        "proxy-pod /metrics must NOT expose the controller-only rebuild stage"
    );
    assert!(
        !proxy.contains("coxswain_discovery_snapshot_build_seconds"),
        "proxy-pod /metrics must NOT expose the server-only snapshot-build stage"
    );
    assert!(
        !proxy.contains("coxswain_discovery_ack_latency_seconds"),
        "proxy-pod /metrics must NOT expose the server-only ack-latency stage"
    );
    assert!(
        !controller.contains("coxswain_discovery_snapshot_apply_seconds"),
        "controller-pod /metrics must NOT expose the proxy-only apply stage"
    );

    Ok(())
}

/// #512 happy path: a single isolated Ingress apply (no concurrent churn)
/// must settle in well under the reflector's old fixed 500ms debounce floor.
/// Compares the mean debounce-wait (`_sum`/`_count` delta) against a 300ms
/// bound — comfortably above the default 20ms quiet window, comfortably below
/// the 500ms ceiling this replaces — and confirms via `wait_for_route` that
/// the change actually converged, not just that a metric moved.
#[tokio::test]
async fn isolated_route_change_debounces_well_under_fixed_floor() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-debounce-fast").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let before = reqwest::get(h.controller_admin_url("/metrics"))
        .await?
        .text()
        .await?;
    let before_sum = count_or_zero(
        &before,
        "coxswain_controller_reconcile_debounce_seconds_sum",
    );
    let before_count = count_or_zero(
        &before,
        "coxswain_controller_reconcile_debounce_seconds_count",
    );

    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;
    let host = format!("ingress.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;

    let (after_sum, after_count) = wait::poll_until(
        Duration::from_secs(30),
        wait::POLL_FAST,
        || async {
            "timed out waiting for the debounce-wait histogram to advance past its pre-change baseline"
                .to_string()
        },
        || async {
            let body = reqwest::get(h.controller_admin_url("/metrics"))
                .await
                .ok()?
                .text()
                .await
                .ok()?;
            let sum = count_or_zero(&body, "coxswain_controller_reconcile_debounce_seconds_sum");
            let count = count_or_zero(
                &body,
                "coxswain_controller_reconcile_debounce_seconds_count",
            );
            (count > before_count).then_some((sum, count))
        },
    )
    .await?;

    let mean_wait = (after_sum - before_sum) / (after_count - before_count);
    assert!(
        mean_wait < 0.3,
        "expected an isolated Ingress apply to debounce in well under the old 500ms fixed \
         floor, got a mean debounce-wait of {mean_wait}s (sum {before_sum}->{after_sum}, \
         count {before_count}->{after_count})"
    );

    Ok(())
}

/// #512 sad-path companion: a rapid burst of annotation patches to ONE owned
/// Ingress — all dispatched CONCURRENTLY (not one-at-a-time with an awaited
/// round trip between each, which stretches real inter-event gaps well past
/// the debounce window and isn't a faithful "burst") — must still coalesce
/// into far fewer rebuilds than the number of patches (no per-event rebuild
/// storm).
///
/// `coxswain_controller_routing_table_rebuild_duration_seconds_count` is a
/// cluster-wide series shared with every OTHER concurrently-running e2e test
/// that touches routing (this suite runs tests in parallel against one
/// controller pod), so it never goes quiet — an earlier version of this test
/// polled for the count to stop changing and flaked/timed out under that
/// noise. Instead this reads the delta over a FIXED, bounded real-time window
/// (`SETTLE_BUDGET`, comfortably above the default 500ms debounce ceiling)
/// measured from the first patch, then compares against a loose threshold
/// (half the burst size) that tolerates a handful of noise increments from
/// sibling tests while still failing hard on an actual per-event storm.
#[tokio::test]
async fn event_burst_within_window_coalesces_to_few_rebuilds() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-debounce-burst").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;
    let host = format!("ingress.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;

    let before = reqwest::get(h.controller_admin_url("/metrics"))
        .await?
        .text()
        .await?;
    let before_rebuild = count_or_zero(
        &before,
        "coxswain_controller_routing_table_rebuild_duration_seconds_count",
    );

    const BURST: usize = 30;
    const POKE_ANNOTATION: &str = "e2e.coxswain-labs.dev/poke";
    let ingresses: Api<Ingress> = Api::namespaced(h.client.clone(), &ns.name);
    let burst_start = std::time::Instant::now();
    let patches = (0..BURST).map(|i| {
        let ingresses = ingresses.clone();
        async move {
            let poke =
                serde_json::json!({ "metadata": { "annotations": { POKE_ANNOTATION: i.to_string() } } });
            ingresses
                .patch(
                    "echo-ingress",
                    &PatchParams::default(),
                    &Patch::Merge(&poke),
                )
                .await
        }
    });
    for result in futures::future::join_all(patches).await {
        result?;
    }

    // 3x the default 500ms debounce ceiling: comfortably long enough for every
    // one of the burst's debounce cycles to settle and rebuild, short enough
    // to bound (not eliminate) noise exposure from concurrent sibling tests.
    const SETTLE_BUDGET: Duration = Duration::from_millis(1500);
    let after_rebuild = wait::poll_until(
        Duration::from_secs(10),
        wait::POLL_FAST,
        || async { "timed out waiting out the post-burst settle budget".to_string() },
        || async {
            if burst_start.elapsed() < SETTLE_BUDGET {
                return None;
            }
            let body = reqwest::get(h.controller_admin_url("/metrics"))
                .await
                .ok()?
                .text()
                .await
                .ok()?;
            Some(count_or_zero(
                &body,
                "coxswain_controller_routing_table_rebuild_duration_seconds_count",
            ))
        },
    )
    .await?;

    let rebuilds = after_rebuild - before_rebuild;
    assert!(
        rebuilds >= 1.0,
        "expected the burst to trigger at least one rebuild, got {rebuilds}"
    );
    assert!(
        rebuilds < (BURST / 2) as f64,
        "expected {BURST} rapid annotation patches to coalesce into far fewer rebuilds, got \
         {rebuilds} (routing_table_rebuild_duration_seconds_count advanced from \
         {before_rebuild} to {after_rebuild}) — a rebuild-per-event storm defeats the debounce"
    );

    Ok(())
}

/// Every successful proxied request emits one access-log line carrying the
/// documented field set. The new `route_id` field is the metric→log join key
/// from the #20 design refinement.
#[tokio::test]
async fn access_log_emits_required_fields_on_success() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-access-fields").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("ingress.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;
    h.http.get(&host, "/a").await?;

    let logs = h.controller.shared_proxy_access_logs().await?;
    let row = logs
        .iter()
        .rev()
        .find(|line| {
            line.get("host").and_then(|h| h.as_str()) == Some(host.as_str())
                && line.get("method").and_then(|m| m.as_str()) == Some("GET")
                && line.get("status").and_then(|s| s.as_u64()) == Some(200)
        })
        .expect("at least one access-log row matching the driven request");

    for required in ["host", "method", "path", "status", "route_id", "upstream"] {
        assert!(
            !row.get(required).map(|v| v.is_null()).unwrap_or(true),
            "access-log row must carry `{required}` — got: {row}"
        );
    }
    let route_id = row["route_id"].as_str().expect("route_id is a string");
    assert!(
        route_id.starts_with(&format!("ingress/{}/", ns.name)),
        "route_id must be `ingress/<ns>/<name>:<r>.<p>` for an Ingress hit, got `{route_id}`"
    );
    Ok(())
}

/// An `HTTPRoute` rule carrying `.name` (GEP-995, `HTTPRouteNamedRouteRule`)
/// has the name surface as the identifier in both the Prometheus `route`
/// label and the access-log `route_id` field, replacing the positional rule
/// index that unnamed rules still use.
#[tokio::test]
async fn named_http_rule_surfaces_rule_name_in_route_metric() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-http-named-rule").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::HTTP_ROUTE_NAMED_RULE, FixtureVars::new(&ns.name)).await?;

    let host = format!("http-named-rule.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    let resp = wait::wait_for_route(&gw, &host, "/a", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    let expected_route_id = format!("httproute/{}/http-named-rule-route:named-rule", ns.name);

    let metrics = reqwest::get(h.admin_url("/metrics")).await?.text().await?;
    let named_label = format!("route=\"{expected_route_id}\"");
    assert!(
        metrics.lines().any(|l| l.contains(&named_label)),
        "requests_total must carry a route label using the rule name `{named_label}`, metrics:\n{metrics}"
    );

    let logs = h.controller.shared_proxy_access_logs().await?;
    let row = logs
        .iter()
        .rev()
        .find(|line| {
            line.get("host").and_then(|h| h.as_str()) == Some(host.as_str())
                && line.get("path").and_then(|p| p.as_str()) == Some("/a")
        })
        .expect("at least one access-log row for the named-rule request");
    let route_id = row["route_id"].as_str().expect("route_id is a string");
    assert_eq!(
        route_id, expected_route_id,
        "route_id must use the rule name for a named rule, got `{route_id}`"
    );

    Ok(())
}

/// `--access-log-path-mode=pattern` replaces the concrete request path with
/// the matched rule's `path_pattern`. Same Ingress, same backend, just a
/// redacted `path` field.
///
/// Note: `pattern` is used here intentionally to exercise the mode under test.
/// The chart default is `full`; production deployments feeding a security
/// pipeline must retain `full` to keep path-traversal attempts visible.
#[tokio::test]
async fn access_log_path_mode_pattern_uses_rule_pattern() -> anyhow::Result<()> {
    let h = Harness::start_with_options(ControllerOptions {
        // pattern is intentional here — this test exercises the mode; it is NOT
        // a production recommendation (chart default is full).
        access_log_path_mode: Some("pattern".to_string()),
        ..Default::default()
    })
    .await?;
    let ns = NamespaceGuard::create(&h.client, "obs-access-pattern").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("ingress.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;
    h.http.get(&host, "/a/deep/path").await?;

    // Poll the access log rather than read once: this test reached here via a
    // `helm upgrade` (access-log-path-mode flip) that rolled the proxy pod, so
    // the freshly-driven request's log line can lag the first read.
    let path = wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async { format!("an access-log row for {host} with status 200 and a path") },
        || async {
            let logs = h.controller.shared_proxy_access_logs().await.ok()?;
            logs.iter()
                .rev()
                .find(|line| {
                    line.get("host").and_then(|h| h.as_str()) == Some(host.as_str())
                        && line.get("status").and_then(|s| s.as_u64()) == Some(200)
                })?
                .get("path")
                .and_then(|p| p.as_str())
                .map(str::to_owned)
        },
    )
    .await?;
    assert!(
        path.starts_with("/a"),
        "pattern mode must emit the matched rule pattern, got {path:?}"
    );
    assert_ne!(
        path, "/a/deep/path",
        "pattern mode must NOT emit the concrete request path"
    );
    Ok(())
}

/// `--access-log-path-mode=none` drops the `path` field entirely while
/// keeping every other documented field.
#[tokio::test]
async fn access_log_path_mode_none_omits_path() -> anyhow::Result<()> {
    let h = Harness::start_with_options(ControllerOptions {
        access_log_path_mode: Some("none".to_string()),
        ..Default::default()
    })
    .await?;
    let ns = NamespaceGuard::create(&h.client, "obs-access-none").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("ingress.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;
    h.http.get(&host, "/a").await?;

    let logs = h.controller.shared_proxy_access_logs().await?;
    let row = logs
        .iter()
        .rev()
        .find(|line| {
            line.get("host").and_then(|h| h.as_str()) == Some(host.as_str())
                && line.get("status").and_then(|s| s.as_u64()) == Some(200)
        })
        .expect("at least one matching access-log row");
    assert!(
        row.get("path").map(|v| v.is_null()).unwrap_or(true),
        "none mode must omit `path`, got {row}"
    );
    for required in ["host", "method", "status", "route_id", "upstream"] {
        assert!(
            !row.get(required).map(|v| v.is_null()).unwrap_or(true),
            "none mode must still emit `{required}`"
        );
    }
    Ok(())
}

/// An unmatched host yields a 404 from the proxy; the access log row carries
/// `status=404` and an `error` field describing why no route matched.
#[tokio::test]
async fn access_log_error_path_carries_error_field() -> anyhow::Result<()> {
    let h = Harness::start().await?;

    // No route is ever installed for this host: the proxy responds 404 from
    // `resolve_outcome::NoHost`. We use `get_status` (not `get`) because the
    // latter propagates non-2xx as Err.
    let status = h
        .http
        .get_status("nonexistent.coxswain-e2e.invalid", "/")
        .await?;
    assert_eq!(status, 404, "unmatched host must yield 404 from the proxy");

    let logs = h.controller.shared_proxy_access_logs().await?;
    let row = logs
        .iter()
        .rev()
        .find(|line| {
            line.get("host")
                .and_then(|h| h.as_str())
                .map(|h| h.starts_with("nonexistent."))
                .unwrap_or(false)
        })
        .expect("at least one access-log row for the unmatched-host request");
    assert!(
        row.get("error")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "error path must populate the `error` field on the access log row"
    );
    Ok(())
}

/// `--access-log=false` disables emission entirely — no access-log lines on
/// any subsequent traffic. Metrics still flow (see `proxy_pod_emits_*`); the
/// silencing is log-only.
#[tokio::test]
async fn access_log_disabled_emits_nothing() -> anyhow::Result<()> {
    let h = Harness::start_with_options(ControllerOptions {
        access_log: Some(false),
        ..Default::default()
    })
    .await?;
    let ns = NamespaceGuard::create(&h.client, "obs-access-off").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("ingress.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;
    for _ in 0..5 {
        h.http.get(&host, "/a").await?;
    }

    let logs = h.controller.shared_proxy_access_logs().await?;
    let recent: Vec<_> = logs
        .iter()
        .filter(|line| line.get("host").and_then(|h| h.as_str()) == Some(host.as_str()))
        .collect();
    assert!(
        recent.is_empty(),
        "access-log disabled must produce zero rows for the driven traffic, got {} rows",
        recent.len()
    );

    // Metrics must still be observed even when access logging is off.
    let metrics = reqwest::get(h.admin_url("/metrics")).await?.text().await?;
    assert!(
        metrics.contains("coxswain_proxy_requests_total{"),
        "metrics must still emit even with access logging disabled"
    );
    Ok(())
}

/// `CoxswainIngressClassParameters.spec.accessLog: false` suppresses access-log
/// lines for every request matched through Ingresses claiming that class, while
/// a normal-class Ingress in the same namespace continues to emit rows (#279).
///
/// The test applies:
///  - a suppressed-class Ingress (host A, bound to a class with `accessLog: false`);
///  - a default-class Ingress (host B, no class params) as the negative control.
///
/// After several GETs to each host, the assertion verifies zero rows for host A and
/// at least one row for host B (proving the proxy is logging at all and suppression is
/// class-scoped, not global). Metrics still flow for both hosts; the per-class field
/// never silences them.
///
/// Uses the default harness (no `helm upgrade`) so the test stays in the parallel
/// pass — only the class CR is mutated, not the proxy-wide `--access-log` flag.
#[tokio::test]
async fn access_log_suppressed_for_class_with_access_log_false() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-cls-alog-off").await?;

    // Cluster-scoped IngressClass — guard deletes it on drop.
    // Name matches the fixture's `coxswain-clsalogoff-${TESTNS}`.
    let ic_name = format!("coxswain-clsalogoff-{}", ns.name);
    let _ic_guard = IngressClassGuard::new(&ic_name);

    // Suppressed-class Ingress (host A).
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::CLASS_ACCESS_LOG_OFF, FixtureVars::new(&ns.name)).await?;

    // Normal-class Ingress (host B) — negative control; uses PATH_MATCHING which
    // does NOT set a class params CR, so the global flag governs (logging on).
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host_a = format!("clsalog-off.{}.local", ns.name);
    let host_b = format!("ingress.{}.local", ns.name);

    // Wait for both routes to be ready.
    wait::wait_for_route(&h.http, &host_a, "/", Duration::from_secs(60)).await?;
    wait::wait_for_route(&h.http, &host_b, "/a", Duration::from_secs(60)).await?;

    // Drive traffic to both hosts.
    for _ in 0..5 {
        h.http.get(&host_a, "/").await?;
        h.http.get(&host_b, "/a").await?;
    }

    let logs = h.controller.shared_proxy_access_logs().await?;

    // Exclude status=404 rows: during wait_for_route polling, requests reach
    // the proxy before the route is programmed and return "no route for host"
    // 404s. Those have no IngressClass context, so class-level suppression
    // cannot apply. Only routed (non-404) requests are in scope.
    let rows_a: Vec<_> = logs
        .iter()
        .filter(|line| line.get("host").and_then(|v| v.as_str()) == Some(host_a.as_str()))
        .filter(|line| line.get("status").and_then(|v| v.as_u64()) != Some(404))
        .collect();
    assert!(
        rows_a.is_empty(),
        "class with accessLog: false must produce zero routed access-log rows for host A, got {}",
        rows_a.len()
    );

    let rows_b: Vec<_> = logs
        .iter()
        .filter(|line| line.get("host").and_then(|v| v.as_str()) == Some(host_b.as_str()))
        .collect();
    assert!(
        !rows_b.is_empty(),
        "normal-class Ingress (host B) must still produce access-log rows; \
         got 0 — is the proxy logging at all?"
    );

    Ok(())
}

/// Poll the controller's `/api/v1/problems` until `pick` returns a matching
/// problem row in the routing aggregate, or fail after `timeout`. The aggregator
/// fans out to proxies and the reconciler debounces, so allow a generous window.
///
/// `/problems` is the namespaced shape `{ fleet, routing: { conflicts,
/// dead_routes } }` (#301), so `bucket` (`conflicts` | `dead_routes`) is read
/// under `routing`, not at the top level.
async fn wait_for_problem(
    h: &Harness,
    bucket: &str,
    pick: impl Fn(&serde_json::Value) -> bool,
    timeout: Duration,
) -> anyhow::Result<serde_json::Value> {
    let url = h.controller_admin_url("/api/v1/problems");
    let client = reqwest::Client::new();
    wait::poll_until(
        timeout,
        wait::POLL,
        || async {
            match client.get(&url).send().await {
                Ok(r) => match r.json::<serde_json::Value>().await {
                    Ok(json) => {
                        format!("a matching `routing.{bucket}` problem; last body={json}")
                    }
                    Err(e) => {
                        format!("a matching `routing.{bucket}` problem; body decode error: {e}")
                    }
                },
                Err(e) => format!("a matching `routing.{bucket}` problem; request error: {e}"),
            }
        },
        || async {
            let json: serde_json::Value = client.get(&url).send().await.ok()?.json().await.ok()?;
            json["routing"][bucket]
                .as_array()
                .and_then(|a| a.iter().find(|r| pick(r)))
                .cloned()
        },
    )
    .await
}

/// A dead backend (Service with zero ready endpoints) must appear in
/// `/api/v1/problems.dead_routes` carrying its source route's identity, so the
/// Dashboard card can deep-link to the Route Inspector.
#[tokio::test]
async fn problems_dead_backend_carries_route_identity() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-dead").await?;

    fixtures::apply_fixture(ingress::PROBLEMS_DEAD_BACKEND, FixtureVars::new(&ns.name)).await?;

    // The route is installed as a 503 dead route; once it serves 503 the table
    // is built and the problem is observable.
    let host = format!("dead.{}.local", ns.name);
    wait::wait_for_route_status(&h.http, &host, "/", 503, Duration::from_secs(60)).await?;

    let row = wait_for_problem(
        &h,
        "dead_routes",
        |r| r["host"] == host && r["path"] == "/",
        Duration::from_secs(30),
    )
    .await?;

    assert_eq!(row["route"]["kind"], "Ingress");
    assert_eq!(row["route"]["namespace"], ns.name);
    assert_eq!(row["route"]["name"], "dead-ingress");
    Ok(())
}

/// A routing conflict (two distinct Ingresses claiming the same host+path) must
/// appear in `/api/v1/problems.conflicts` carrying the rejected (shadowed)
/// route's identity — proving the routing core captures it end-to-end.
#[tokio::test]
async fn problems_conflict_carries_rejected_route_identity() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-conflict").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PROBLEMS_CONFLICT, FixtureVars::new(&ns.name)).await?;

    // Both Ingresses claim conflict.<ns>.local/; the winner serves 200 once the
    // table is built, and the shadowed one is recorded as a conflict.
    let host = format!("conflict.{}.local", ns.name);
    wait::wait_for_route_status(&h.http, &host, "/", 200, Duration::from_secs(60)).await?;

    let row = wait_for_problem(
        &h,
        "conflicts",
        |r| r["host"] == host,
        Duration::from_secs(30),
    )
    .await?;

    assert_eq!(row["kind"], "ingress");
    assert_eq!(row["route"]["kind"], "Ingress");
    assert_eq!(row["route"]["namespace"], ns.name);
    // The rejected route is whichever of the two lost the precedence tie.
    let rejected = row["route"]["name"].as_str().unwrap_or("");
    assert!(
        rejected == "conflict-a" || rejected == "conflict-b",
        "rejected route should be one of the two conflicting Ingresses, got {rejected:?}"
    );
    Ok(())
}

/// The controller relays a pod's logs at `/api/v1/pods/{name}/logs` (#285). A
/// bounded snapshot (`follow=false`) returns a non-empty body, and the
/// read-only-proxy invariant holds: the same path 404s on a proxy admin port
/// (proxy roles wire no aggregator), and an unknown pod 404s on the controller
/// (the name is resolved against the fleet, never the URL).
#[tokio::test]
async fn pod_logs_stream_from_controller_not_proxy() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let client = reqwest::Client::new();

    // Discover a live controller pod name from the aggregator's fleet view.
    let controllers: serde_json::Value = client
        .get(h.controller_admin_url("/api/v1/fleet/controllers"))
        .send()
        .await?
        .json()
        .await?;
    let pod = controllers["controllers"][0]["pod_name"]
        .as_str()
        .expect("/api/v1/fleet/controllers must list at least one controller pod");
    let logs_path = format!("/api/v1/pods/{pod}/logs?tail=10&follow=false");

    // Controller relays the snapshot: 200 with a non-empty body.
    let resp = client
        .get(h.controller_admin_url(&logs_path))
        .send()
        .await?;
    assert_eq!(resp.status(), 200, "controller must relay pod logs");
    let body = resp.text().await?;
    assert!(
        !body.trim().is_empty(),
        "controller log snapshot must be non-empty"
    );

    // Proxy admin: same path 404s — proxies wire no aggregator.
    let proxy_status = client.get(h.admin_url(&logs_path)).send().await?.status();
    assert_eq!(
        proxy_status, 404,
        "proxy admin must not expose pod logs (read-only-proxy invariant)"
    );

    // Unknown pod: 404 from the controller (resolved against the fleet).
    let unknown = client
        .get(h.controller_admin_url("/api/v1/pods/does-not-exist/logs?tail=10&follow=false"))
        .send()
        .await?
        .status();
    assert_eq!(unknown, 404, "unknown pod name must 404");
    Ok(())
}

/// `/api/v1/routing/gateways` list endpoint: after applying a Gateway +
/// HTTPRoute, the controller's response must include the Gateway with
/// `proxy.pool == "shared"`, a positive `route_count`, a `status`, and at least
/// one condition, all within one reconcile cycle (#301; replaces the retired
/// `/api/v1/cluster` aggregate). Also asserts `/api/v1/health` now carries the
/// apiserver GitVersion (`kubernetes_version`, relocated from `/cluster`, #287),
/// and `/api/v1/routing/httproutes` lists the applied route as first-class
/// (#293), and `/api/v1/problems` is the nested cross-cutting aggregate (#301).
#[tokio::test]
async fn routing_api_surfaces_gateways_routes_and_problems() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-gw-routing-endpoints").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    // Resolve this Gateway's own per-Gateway VIP once, after the fixture apply.
    let gw = h.gateway_http(&ns.name).await?;

    // First wait for the route to be live so we know the reconciler has built
    // the routing table at least once after our Gateway was applied.
    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&gw, &host, "/a", Duration::from_secs(60)).await?;

    let gateways_url = h.controller_admin_url("/api/v1/routing/gateways");
    let client = reqwest::Client::new();

    // Poll /api/v1/routing/gateways until the Gateway we just applied is visible.
    // The reconciler rebuilds with a 500 ms trailing-edge debounce so allow a
    // generous window.
    let listing = wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            match client.get(&gateways_url).send().await {
                Ok(r) => {
                    let status = r.status();
                    let body = r.json::<serde_json::Value>().await.unwrap_or_default();
                    format!(
                        "Gateway coxswain-test/{} to appear in /routing/gateways; last status={status}, body={body}",
                        ns.name
                    )
                }
                Err(e) => format!(
                    "Gateway coxswain-test/{} to appear in /routing/gateways; request error: {e}",
                    ns.name
                ),
            }
        },
        || async {
            let resp = client.get(&gateways_url).send().await.ok()?;
            if resp.status() != 200 {
                return None;
            }
            let json: serde_json::Value = resp.json().await.ok()?;
            let gateways = json["gateways"].as_array().cloned().unwrap_or_default();
            let visible = gateways
                .iter()
                .any(|g| g["namespace"] == ns.name && g["name"] == "coxswain-test");
            visible.then_some(json)
        },
    )
    .await?;

    // Envelope fields are present on the list response.
    assert!(
        listing["total"].is_u64(),
        "list envelope must carry `total`"
    );
    assert!(
        listing["returned"].is_u64(),
        "list envelope must carry `returned`"
    );

    let gw = listing["gateways"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["namespace"] == ns.name && g["name"] == "coxswain-test")
        .expect("Gateway entry");
    assert_eq!(
        gw["proxy"]["pool"], "shared",
        "Gateway without parametersRef must be classified as shared"
    );
    assert!(
        gw["status"].is_string(),
        "gateway entry must carry a traffic-served `status` (#301), got {gw}"
    );
    let route_count = gw["route_count"].as_u64().unwrap_or(0);
    assert!(
        route_count >= 1,
        "expected at least one attached route, got {route_count} (gw={gw})"
    );
    let cond_types: Vec<&str> = gw["conditions"]
        .as_array()
        .expect("conditions array")
        .iter()
        .filter_map(|c| c["type"].as_str())
        .collect();
    assert!(
        cond_types.contains(&"Programmed") || cond_types.contains(&"Accepted"),
        "expected Programmed or Accepted condition, got {cond_types:?}"
    );

    // /api/v1/health carries the apiserver GitVersion (relocated from /cluster, #287).
    let health: serde_json::Value = client
        .get(h.controller_admin_url("/api/v1/health"))
        .send()
        .await?
        .json()
        .await?;
    let k8s_version = health["kubernetes_version"]
        .as_str()
        .expect("/api/v1/health must include kubernetes_version against a live controller");
    // GitVersion looks like `v1.31.2`: a `v`, then a major.minor numeric prefix.
    let looks_like_version = k8s_version
        .strip_prefix('v')
        .and_then(|rest| rest.split_once('.'))
        .is_some_and(|(major, rest)| {
            !major.is_empty()
                && major.bytes().all(|b| b.is_ascii_digit())
                && rest.bytes().next().is_some_and(|b| b.is_ascii_digit())
        });
    assert!(
        looks_like_version,
        "kubernetes_version must look like a server GitVersion (got {k8s_version:?})"
    );

    // /api/v1/routing/httproutes lists the applied HTTPRoute as a first-class
    // resource (#293), carrying parent_gateways + status + envelope fields.
    let httproutes: serde_json::Value = client
        .get(h.controller_admin_url("/api/v1/routing/httproutes"))
        .send()
        .await?
        .json()
        .await?;
    assert!(
        httproutes["total"].is_u64(),
        "httproutes list must carry the `total` envelope field"
    );
    let route = httproutes["httproutes"]
        .as_array()
        .expect("httproutes array")
        .iter()
        .find(|r| r["namespace"] == ns.name)
        .unwrap_or_else(|| panic!("no HTTPRoute listed in {}: {httproutes}", ns.name));
    assert!(
        route["status"].is_string(),
        "httproute entry must carry a `status` (#301)"
    );
    assert!(
        route["parent_gateways"]
            .as_array()
            .is_some_and(|p| !p.is_empty()),
        "httproute must list its parent Gateway(s), got {route}"
    );

    // /api/v1/problems is the nested cross-cutting aggregate (#301).
    let problems: serde_json::Value = client
        .get(h.controller_admin_url("/api/v1/problems"))
        .send()
        .await?
        .json()
        .await?;
    assert!(
        problems["fleet"]["leaderless"].is_boolean(),
        "problems.fleet.leaderless must be present"
    );
    for key in ["unreachable", "degraded"] {
        assert!(
            problems["fleet"][key].is_array(),
            "problems.fleet.{key} must be an array"
        );
    }
    for key in ["conflicts", "dead_routes"] {
        assert!(
            problems["routing"][key].is_array(),
            "problems.routing.{key} must be an array"
        );
    }

    Ok(())
}

/// A routing conflict must emit a `Warning RouteConflict` Kubernetes Event on the losing
/// Ingress, naming the winner, host, and path. The winning Ingress must have no such Events
/// (#390).
#[tokio::test]
async fn conflict_emits_warning_event_on_loser() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-conflict-event").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PROBLEMS_CONFLICT, FixtureVars::new(&ns.name)).await?;

    // Winner serves 200 once the table is built.
    let host = format!("conflict.{}.local", ns.name);
    wait::wait_for_route_status(&h.http, &host, "/", 200, Duration::from_secs(60)).await?;

    // Resolve winner/loser from the problems API so we don't hard-code precedence order.
    let problem_row = wait_for_problem(
        &h,
        "conflicts",
        |r| r["host"] == host,
        Duration::from_secs(30),
    )
    .await?;
    let loser_name = problem_row["route"]["name"]
        .as_str()
        .expect("conflict row must carry rejected route name")
        .to_owned();
    let winner_name = if loser_name == "conflict-a" {
        "conflict-b"
    } else {
        "conflict-a"
    };

    // Assert Warning RouteConflict Event on the loser.
    let event = wait::wait_for_ingress_warning_event(
        &h.client,
        &ns.name,
        &loser_name,
        "RouteConflict",
        Duration::from_secs(60),
    )
    .await?;
    let note = event.note.as_deref().unwrap_or("");
    assert!(
        note.contains(winner_name),
        "RouteConflict Event note must name the winner {winner_name:?}; got {note:?}"
    );
    assert!(
        note.contains(&host),
        "RouteConflict Event note must name the conflict host {host:?}; got {note:?}"
    );

    // Negative: winner must have no RouteConflict Warning Events.
    // By this point the reconciler has run and the controller has emitted the loser's
    // event — at least one full event-processing cycle has completed.
    let all_events = Api::<K8sEvent>::namespaced(h.client.clone(), &ns.name)
        .list(&kube::api::ListParams::default())
        .await?;
    let winner_conflict_events: Vec<_> = all_events
        .items
        .iter()
        .filter(|e| {
            e.type_.as_deref() == Some("Warning")
                && e.reason.as_deref() == Some("RouteConflict")
                && e.regarding.as_ref().and_then(|r| r.name.as_deref()) == Some(winner_name)
        })
        .collect();
    assert!(
        winner_conflict_events.is_empty(),
        "winning Ingress {winner_name:?} must have no RouteConflict Warning Events; \
         got {} event(s)",
        winner_conflict_events.len()
    );

    Ok(())
}

/// An Ingress with an invalid `ingress.coxswain-labs.dev/*` annotation value that slips past
/// the VAP must receive a `Warning InvalidAnnotation` Kubernetes Event naming the annotation.
/// A valid Ingress in the same namespace must receive no such Events (#401).
///
/// Uses `path-normalize: "none"` — accepted by the VAP's enum check (still a listed
/// member) but explicitly rejected downstream by the controller parse path (#483:
/// `none` disabled normalization, re-opening path-traversal bypass), so it generates
/// a `Warning` Event while the route continues to serve on the hardened `base`
/// fallback (fail-open). Retargeted from `session-cookie-name` after #554 converged
/// session affinity to `CoxswainBackendPolicy`.
#[tokio::test]
async fn invalid_annotation_emits_warning_event() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-invalid-ann-event").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    // Ingress with `path-normalize: "none"` — dropped in #483 (it disabled
    // normalization). The VAP still accepts it (in the enum list), but the
    // controller rejects it downstream, falls back to `base`, and emits a
    // Warning InvalidAnnotation Event on the Ingress.
    fixtures::apply_fixture(
        ingress::ANNOTATION_PATH_NORMALIZE_NONE_FALLS_BACK,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let bad_host = format!("pn-none.{}.local", ns.name);
    wait::wait_for_route_status(&h.http, &bad_host, "/v1", 200, Duration::from_secs(60)).await?;

    // Also apply a valid Ingress in the same namespace (no annotation → no event).
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;
    let valid_host = format!("ingress.{}.local", ns.name);
    wait::wait_for_route_status(&h.http, &valid_host, "/a", 200, Duration::from_secs(60)).await?;

    // Assert Warning InvalidAnnotation Event on the misconfigured Ingress.
    let event = wait::wait_for_ingress_warning_event(
        &h.client,
        &ns.name,
        "pn-none",
        "InvalidAnnotation",
        Duration::from_secs(60),
    )
    .await?;
    let note = event.note.as_deref().unwrap_or("");
    assert!(
        note.contains("path-normalize"),
        "InvalidAnnotation Event note must mention the annotation name; got {note:?}"
    );

    // Negative: valid Ingress must have no InvalidAnnotation Events. By the time the
    // invalid-annotation event appeared, the controller has processed at least one full
    // reconcile round that also covered the valid Ingress — so absence now is conclusive.
    let all_events = Api::<K8sEvent>::namespaced(h.client.clone(), &ns.name)
        .list(&kube::api::ListParams::default())
        .await?;
    let valid_invalid_events: Vec<_> = all_events
        .items
        .iter()
        .filter(|e| {
            e.type_.as_deref() == Some("Warning")
                && e.reason.as_deref() == Some("InvalidAnnotation")
                && e.regarding.as_ref().and_then(|r| r.name.as_deref()) == Some("echo-ingress")
        })
        .collect();
    assert!(
        valid_invalid_events.is_empty(),
        "valid Ingress 'echo-ingress' must have no InvalidAnnotation Warning Events; \
         got {} event(s)",
        valid_invalid_events.len()
    );

    Ok(())
}

/// An Ingress whose `rate-limit` CR sets `byHeader` but carries no auth
/// annotation must receive a `Warning InvalidAnnotation` Event with a note
/// mentioning `rate-limit` and bypass risk. An Ingress that pairs the same
/// header-keying with an auth annotation must receive no such Event (#411,
/// #552 — the check moved from parse-time to CR-resolve-time when `by_header`
/// became a CR field).
#[tokio::test]
async fn rate_limit_by_header_without_auth_emits_warning_event() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-rl-header-warn").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    // Positive: rate-limit-by header without auth — bypass-risk advisory fires.
    fixtures::apply_fixture(
        ingress::ANNOTATION_RATE_LIMIT_BY_HEADER,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let rl_host = format!("ratelimitheader.{}.local", ns.name);
    wait::wait_for_route_status(&h.http, &rl_host, "/", 200, Duration::from_secs(60)).await?;

    let event = wait::wait_for_ingress_warning_event(
        &h.client,
        &ns.name,
        "rate-limit-by-header-ingress",
        "InvalidAnnotation",
        Duration::from_secs(60),
    )
    .await?;
    let note = event.note.as_deref().unwrap_or("");
    assert!(
        note.contains("rate-limit-by") || note.contains("rate-limit"),
        "InvalidAnnotation Event note must mention the annotation; got {note:?}"
    );
    assert!(
        note.contains("bypass") || note.contains("rotation"),
        "InvalidAnnotation Event note must mention the bypass risk; got {note:?}"
    );

    // Negative: rate-limit-by header + auth-basic-secret — advisory must not fire.
    // Apply the bcrypt-only secret first (proxy fails closed to 503 on unlabelled
    // secrets; the secret must be visible before the Ingress is reconciled).
    fixtures::apply_fixture(
        ingress::AUTH_BASIC_SECRET_BCRYPT_ONLY,
        FixtureVars::new(&ns.name),
    )
    .await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_RATE_LIMIT_BY_HEADER_WITH_AUTH,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let auth_host = format!("ratelimitheaderauth.{}.local", ns.name);
    wait::wait_for_route_status(&h.http, &auth_host, "/", 401, Duration::from_secs(60)).await?;

    let all_events = Api::<K8sEvent>::namespaced(h.client.clone(), &ns.name)
        .list(&kube::api::ListParams::default())
        .await?;
    let auth_bypass_events: Vec<_> = all_events
        .items
        .iter()
        .filter(|e| {
            e.type_.as_deref() == Some("Warning")
                && e.reason.as_deref() == Some("InvalidAnnotation")
                && e.regarding.as_ref().and_then(|r| r.name.as_deref())
                    == Some("rate-limit-by-header-auth-ingress")
        })
        .collect();
    assert!(
        auth_bypass_events.is_empty(),
        "Ingress with auth must have no rate-limit bypass Warning Events; \
         got {} event(s)",
        auth_bypass_events.len()
    );

    Ok(())
}

/// An Ingress whose `auth-basic-secret` points at a Secret with a `{SHA}` htpasswd entry
/// must receive a `Warning InvalidAnnotation` Event naming the affected username. An Ingress
/// whose secret contains only bcrypt entries must receive no such Event (#412).
#[tokio::test]
async fn sha1_htpasswd_credential_emits_warning_event() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-sha1-htpasswd-warn").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    // Positive: secret with SHA1 entry (bob) + Ingress using it — advisory fires.
    fixtures::apply_fixture(ingress::AUTH_BASIC_SECRET, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(ingress::ANNOTATION_AUTH_BASIC, FixtureVars::new(&ns.name)).await?;
    let sha1_host = format!("authbasic.{}.local", ns.name);
    wait::wait_for_route_status(&h.http, &sha1_host, "/", 401, Duration::from_secs(60)).await?;

    let event = wait::wait_for_ingress_warning_event(
        &h.client,
        &ns.name,
        "auth-basic-ingress",
        "InvalidAnnotation",
        Duration::from_secs(60),
    )
    .await?;
    let note = event.note.as_deref().unwrap_or("");
    assert!(
        note.contains("bob"),
        "InvalidAnnotation Event note must name the SHA1 user; got {note:?}"
    );
    assert!(
        note.contains("SHA1"),
        "InvalidAnnotation Event note must mention SHA1; got {note:?}"
    );

    // Negative: bcrypt-only secret — no advisory Event.
    fixtures::apply_fixture(
        ingress::AUTH_BASIC_SECRET_BCRYPT_ONLY,
        FixtureVars::new(&ns.name),
    )
    .await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_AUTH_BASIC_BCRYPT_ONLY,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let bcrypt_host = format!("authbasicbcrypt.{}.local", ns.name);
    wait::wait_for_route_status(&h.http, &bcrypt_host, "/", 401, Duration::from_secs(60)).await?;

    let all_events = Api::<K8sEvent>::namespaced(h.client.clone(), &ns.name)
        .list(&kube::api::ListParams::default())
        .await?;
    let bcrypt_events: Vec<_> = all_events
        .items
        .iter()
        .filter(|e| {
            e.type_.as_deref() == Some("Warning")
                && e.reason.as_deref() == Some("InvalidAnnotation")
                && e.regarding.as_ref().and_then(|r| r.name.as_deref())
                    == Some("auth-basic-bcrypt-only-ingress")
        })
        .collect();
    assert!(
        bcrypt_events.is_empty(),
        "bcrypt-only Ingress must have no SHA1 Warning Events; got {} event(s)",
        bcrypt_events.len()
    );

    Ok(())
}

/// After the shared proxy connects and completes its initial discovery handshake,
/// `/api/v1/topology` must show a SharedPool node with `in_sync == true` and
/// `/api/v1/fleet/summary` must carry `all_in_sync == true` (#379).
///
/// The test polls until convergence rather than doing a single fetch: the proxy
/// may not have Ack'd the first snapshot by the time we reach this assertion.
#[tokio::test]
async fn topology_shows_proxy_in_sync_after_ack() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let client = reqwest::Client::new();

    // Poll /api/v1/topology until a SharedPool node with in_sync=true appears.
    let topo_url = h.controller_admin_url("/api/v1/topology");
    let topo: serde_json::Value = wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || {
            let url = topo_url.clone();
            let c = client.clone();
            async move {
                match c.get(&url).send().await {
                    Ok(r) => match r.json::<serde_json::Value>().await {
                        Ok(j) => format!(
                            "a SharedPool node with in_sync=true in /api/v1/topology; \
                             last body={j}"
                        ),
                        Err(e) => format!("a SharedPool node with in_sync=true; decode error: {e}"),
                    },
                    Err(e) => format!("a SharedPool node with in_sync=true; request error: {e}"),
                }
            }
        },
        || {
            let url = topo_url.clone();
            let c = client.clone();
            async move {
                let json: serde_json::Value = c.get(&url).send().await.ok()?.json().await.ok()?;
                let nodes = json["nodes"].as_array()?;
                let any_in_sync = nodes.iter().any(|n| {
                    n["scope"]["kind"].as_str() == Some("SharedPool")
                        && n["in_sync"].as_bool() == Some(true)
                });
                any_in_sync.then_some(json)
            }
        },
    )
    .await?;

    // discovery_active must be true on the controller role.
    assert_eq!(
        topo["discovery_active"],
        serde_json::Value::Bool(true),
        "controller role must report discovery_active=true"
    );

    // controller_version must be populated (discovery built at least one snapshot).
    assert!(
        topo["controller_version"].is_string(),
        "controller_version must be a string when nodes are connected; got: {topo}"
    );

    // Every connected SharedPool node must be in sync (steady state).
    let nodes = topo["nodes"]
        .as_array()
        .expect("topology.nodes must be an array");
    let shared: Vec<_> = nodes
        .iter()
        .filter(|n| n["scope"]["kind"].as_str() == Some("SharedPool"))
        .collect();
    assert!(
        !shared.is_empty(),
        "at least one SharedPool node must be connected"
    );
    for n in &shared {
        assert_eq!(
            n["in_sync"],
            serde_json::Value::Bool(true),
            "SharedPool node {} must be in sync; got {n}",
            n["node_id"]
        );
        // last_acked_version must match controller_version.
        assert_eq!(
            n["last_acked_version"], topo["controller_version"],
            "SharedPool node {} must have acked the current controller version",
            n["node_id"]
        );
    }

    // /api/v1/fleet/summary must report THIS test's shared-proxy tier converged
    // and healthy. We scope to `shared_proxies` rather than the global
    // `all_in_sync` flag: `all_in_sync` spans the entire node registry, and in the
    // parallel e2e pass concurrent tests' dedicated proxies are mid-provisioning
    // (transiently not-in-sync / unreachable), which would flip it false through no
    // fault of the shared proxy. The shared proxy's own sync is already proven
    // authoritatively by the /topology `in_sync` check above.
    let summary_url = h.controller_admin_url("/api/v1/fleet/summary");
    let summary: serde_json::Value = client.get(&summary_url).send().await?.json().await?;
    assert_eq!(
        summary["shared_proxies"]["worst"],
        serde_json::Value::String("ok".to_owned()),
        "fleet/summary shared-proxy tier must be healthy after ack; got {summary}"
    );

    Ok(())
}

/// After a routing change causes the controller to build a new SharedPool snapshot,
/// the proxy re-converges: `/api/v1/topology` transitions back to `in_sync == true`
/// and `/api/v1/fleet/summary.all_in_sync` returns to `true` (#379).
///
/// We trigger the routing change by applying a new Ingress, wait for the route to
/// be live (guarantees the snapshot advanced), then poll until re-convergence.
/// The transient `in_sync=false` state is non-deterministic (proxy may Ack before
/// we check), so we assert the steady-state outcome, not the transient. A core
/// unit test covers the lag-arithmetic path deterministically.
#[tokio::test]
async fn topology_reconverges_after_routing_change() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-topo-reconverge").await?;
    let client = reqwest::Client::new();

    // Apply a backend + Ingress to trigger a routing-table rebuild.
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("ingress.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;

    // Poll /api/v1/topology until the proxy has re-converged on the new version.
    let topo_url = h.controller_admin_url("/api/v1/topology");
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || {
            let url = topo_url.clone();
            let c = client.clone();
            async move {
                match c.get(&url).send().await {
                    Ok(r) => match r.json::<serde_json::Value>().await {
                        Ok(j) => format!(
                            "all SharedPool nodes to re-converge after routing change; \
                             last body={j}"
                        ),
                        Err(e) => format!("re-convergence; decode error: {e}"),
                    },
                    Err(e) => format!("re-convergence; request error: {e}"),
                }
            }
        },
        || {
            let url = topo_url.clone();
            let c = client.clone();
            async move {
                let json: serde_json::Value = c.get(&url).send().await.ok()?.json().await.ok()?;
                let nodes = json["nodes"].as_array()?;
                let shared: Vec<_> = nodes
                    .iter()
                    .filter(|n| n["scope"]["kind"].as_str() == Some("SharedPool"))
                    .collect();
                let all_synced = !shared.is_empty()
                    && shared.iter().all(|n| n["in_sync"].as_bool() == Some(true));
                all_synced.then_some(json)
            }
        },
    )
    .await?;

    // Confirm the shared-proxy tier is healthy in the fleet summary after
    // re-convergence. Scoped to `shared_proxies` rather than the global
    // `all_in_sync` flag, which the parallel e2e pass pollutes with concurrent
    // tests' mid-provisioning dedicated proxies (this proxy's re-convergence is
    // already proven by the /topology `in_sync` poll above).
    let summary_url = h.controller_admin_url("/api/v1/fleet/summary");
    let summary: serde_json::Value = client.get(&summary_url).send().await?.json().await?;
    assert_eq!(
        summary["shared_proxies"]["worst"],
        serde_json::Value::String("ok".to_owned()),
        "fleet/summary shared-proxy tier must be healthy after re-convergence; got {summary}"
    );

    Ok(())
}

// ── Gateway data-plane liveness gauge (#585) ──────────────────────────────────

/// The live per-Gateway data-plane gauge tracks connected dedicated proxies
/// (#585): it reads `>= 1` while the Gateway's proxy is connected, and its
/// series is removed on deprovision (reads absent → 0). This is the non-latched
/// liveness signal operators alert on for a total-loss blind spot — distinct
/// from the latched `Programmed` status, which by design stays `True` through
/// churn.
///
/// Plane: **observability** — the primary assertion is on the metric series.
#[tokio::test]
async fn dedicated_dataplane_gauge_tracks_leaf_presence() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-dataplane-gauge").await?;

    // Provision a dedicated Gateway; cut-over means its proxy is connected as a
    // `Gateway`-scoped node the gauge counts.
    common::dedicated::apply_and_wait(&h, &ns).await?;
    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    common::dedicated::wait_for_cut_over(
        &gateways,
        common::dedicated::GATEWAY_NAME,
        Duration::from_secs(90),
    )
    .await?;

    // The gauge is emitted by the operator reconcile loop, which runs ONLY on the
    // leader — the harness's Service-level forward pins an arbitrary replica, so
    // scrape the leader specifically (hold the forward across the poll loops).
    let (_leader_forward, metrics_url) =
        common::discovery::leader_discovery_metrics(&h.client).await?;
    // Scope the label filter to THIS test's unique namespace, not the shared
    // `GATEWAY_NAME` constant: the controller is shared and parallel tests reuse
    // that Gateway name, so a `gateway="dedicated-gw"`-only filter would sum in a
    // sibling test's series and flake the sad-path `== 0` assertion.
    let label = format!("namespace=\"{}\"", ns.name);
    const GAUGE: &str = "coxswain_gateway_dataplane_proxies";

    // Happy: the gauge reads >= 1 while the dedicated proxy is connected.
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || {
            let label = label.clone();
            async move { format!("{GAUGE}{{{label}}} to reach >= 1 for the connected dedicated proxy") }
        },
        || {
            let (url, label) = (metrics_url.clone(), label.clone());
            async move {
                let v = common::discovery::scrape_metric_label_sum(&url, GAUGE, &label).await?;
                (v >= 1.0).then_some(())
            }
        },
    )
    .await
    .context("dataplane gauge never reached >= 1 for the connected dedicated proxy")?;

    // Sad: deprovision the Gateway → the controller drops the series (reads 0).
    gateways
        .delete(common::dedicated::GATEWAY_NAME, &DeleteParams::default())
        .await
        .context("delete dedicated Gateway")?;

    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async { format!("{GAUGE} series removed after Gateway deprovision") },
        || {
            let (url, label) = (metrics_url.clone(), label.clone());
            async move {
                let v = common::discovery::scrape_metric_label_sum(&url, GAUGE, &label)
                    .await
                    .unwrap_or(0.0);
                (v == 0.0).then_some(())
            }
        },
    )
    .await
    .context("dataplane gauge series was not removed after Gateway deprovision")?;

    Ok(())
}

// ── UDP datagram drops (#618) ────────────────────────────────────────────────

/// A UDP datagram the proxy discards must be counted, not just `debug!`-logged.
///
/// UDP carries no status code and no reset, so a dropped datagram is invisible to
/// the client by construction. Before `coxswain_proxy_udp_datagrams_dropped_total`
/// every drop path logged at `debug` and stopped there, leaving "no traffic" and
/// "every datagram discarded" indistinguishable on a dashboard.
///
/// Drives `reason="no_route"`, the one drop an e2e can provoke deterministically:
/// a `protocol: UDP` listener with no UDPRoute attached binds the port and
/// discards everything that arrives.
#[tokio::test]
async fn udp_datagram_to_unrouted_port_increments_drop_counter() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-udp-drop").await?;

    fixtures::apply_fixture(
        gwa::UDP_ROUTE_GW_ONLY,
        FixtureVars::new(&ns.name).with(
            "GATEWAY_UDP_PROXY_PORT",
            coxswain_e2e::harness::GATEWAY_UDP_PROXY_PORT.to_string(),
        ),
    )
    .await?;
    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-udp-gw-only",
        &ns.name,
        "Programmed",
        "True",
        Duration::from_secs(60),
    )
    .await?;

    let udp_addr = h.gateway_udp_addr(&ns.name).await?;
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind UDP client")?;
    sock.connect(&udp_addr)
        .await
        .context("connect UDP client")?;

    // The listener binds before its (empty) route snapshot lands, so `no_route`
    // is the steady state here rather than a race — but poll anyway: the counter
    // only moves once a datagram has actually reached the bound port.
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            "coxswain_proxy_udp_datagrams_dropped_total{reason=\"no_route\"} to be \
             incremented by a datagram sent to a routeless UDP listener; without \
             it, UDP loss is invisible to the operator"
                .to_string()
        },
        || async {
            sock.send(b"into-the-void").await.ok()?;
            let body = reqwest::get(h.admin_url("/metrics"))
                .await
                .ok()?
                .text()
                .await
                .ok()?;
            body.lines()
                .filter(|l| !l.starts_with('#'))
                .any(|l| {
                    l.starts_with("coxswain_proxy_udp_datagrams_dropped_total{")
                        && l.contains(r#"reason="no_route""#)
                })
                .then_some(())
        },
    )
    .await?;

    Ok(())
}
