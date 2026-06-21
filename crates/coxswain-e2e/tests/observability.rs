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
//! - `access_log_*` — five cases that pin the access-log contract: required
//!   fields (including the new `route_id` join key), path-mode behaviour,
//!   error-path emission, and disabled-mode silence.
//! - `pod_logs_stream_from_controller_not_proxy` — the `/api/v1/pods/{name}/logs`
//!   relay (#285): controller serves it, proxy 404s, unknown pod 404s.

use coxswain_e2e::{
    ControllerOptions, FixtureVars, Harness, IngressClassGuard, NamespaceGuard,
    fixtures::{self, backends, gateway_api as gwa, ingress},
    harness::wait,
};
use std::time::Duration;

mod common;

/// Controller-subsystem checks asserted in `/status.subsystems.controller.checks`.
///
/// Order is irrelevant but the set must match what `main.rs` registers — keep in
/// lockstep with the `controller_handle` registration call.
const CONTROLLER_CHECKS: &[&str] = &[
    "httproute",
    "ingress",
    "ingress_class",
    "ingress_class_parameters",
    "gateway",
    "gateway_class",
    "endpoint_slice",
    "reference_grant",
    "secret",
    "service",
    "backend_tls_policy",
    "config_map",
    "routing_table_built",
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

    let health: serde_json::Value = reqwest::get(h.admin_url("/api/v1/health"))
        .await?
        .json()
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
    assert!(
        metrics.contains("coxswain_proxy_routing_table_rebuilds_total"),
        "proxy /metrics must expose routing_table_rebuilds_total"
    );
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

/// `--access-log-path-mode=pattern` replaces the concrete request path with
/// the matched rule's `path_pattern`. Same Ingress, same backend, just a
/// redacted `path` field.
#[tokio::test]
async fn access_log_path_mode_pattern_uses_rule_pattern() -> anyhow::Result<()> {
    let h = Harness::start_with_options(ControllerOptions {
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

    let logs = h.controller.shared_proxy_access_logs().await?;
    let row = logs
        .iter()
        .rev()
        .find(|line| {
            line.get("host").and_then(|h| h.as_str()) == Some(host.as_str())
                && line.get("status").and_then(|s| s.as_u64()) == Some(200)
        })
        .expect("at least one matching access-log row");
    let path = row.get("path").and_then(|p| p.as_str());
    assert!(
        path.unwrap_or("").starts_with("/a"),
        "pattern mode must emit the matched rule pattern, got {path:?}"
    );
    assert_ne!(
        path,
        Some("/a/deep/path"),
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

    let rows_a: Vec<_> = logs
        .iter()
        .filter(|line| line.get("host").and_then(|v| v.as_str()) == Some(host_a.as_str()))
        .collect();
    assert!(
        rows_a.is_empty(),
        "class with accessLog: false must produce zero access-log rows for host A, got {}",
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

    // First wait for the route to be live so we know the reconciler has built
    // the routing table at least once after our Gateway was applied.
    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/a", Duration::from_secs(60)).await?;

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

/// Sum the values of all `<name>{...}` series whose label set contains
/// `label_substr`. Returns `None` when no matching series is present.
fn metric_sum_for_label(body: &str, name: &str, label_substr: &str) -> Option<f64> {
    let prefix = format!("{name}{{");
    let mut total = 0.0;
    let mut seen = false;
    for line in body.lines().filter(|l| !l.starts_with('#')) {
        let Some(rest) = line.strip_prefix(&prefix) else {
            continue;
        };
        let Some((labels, value)) = rest.split_once('}') else {
            continue;
        };
        if !labels.contains(label_substr) {
            continue;
        }
        if let Ok(v) = value.trim().parse::<f64>() {
            total += v;
            seen = true;
        }
    }
    seen.then_some(total)
}

/// Cache observability (#40): the proxy emits `coxswain_cache_misses_total` for
/// the first (uncached) request and `coxswain_cache_hits_total` once the entry
/// is served from cache, both labelled with the matched route. Scopes the
/// assertion to this test's route label so it is independent of other traffic on
/// the shared proxy.
#[tokio::test]
async fn cache_hit_and_miss_counters_increment_when_caching() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "obs-cache").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_CACHE_ENABLED,
        FixtureVars::new(&ns.name).with("CACHE_CONTROL", "max-age=300"),
    )
    .await?;

    let host = format!("cache.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // Drive a miss-then-hit sequence: poll an identical GET until it is served
    // from cache (`Age` present), which guarantees both a miss and a hit have
    // been recorded for this route.
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            match h.http.get_full(&host, "/").await {
                Ok((s, hdrs, _)) => {
                    format!(
                        "a cache hit; status={s}, age={}",
                        hdrs.contains_key(reqwest::header::AGE)
                    )
                }
                Err(e) => format!("a cache hit; failed: {e}"),
            }
        },
        || async {
            match h.http.get_full(&host, "/").await {
                Ok((200, hdrs, _)) if hdrs.contains_key(reqwest::header::AGE) => Some(()),
                _ => None,
            }
        },
    )
    .await?;

    let route_label = format!("route=\"ingress/{}/cache-ingress:", ns.name);
    let metrics = reqwest::get(h.admin_url("/metrics")).await?.text().await?;

    let misses = metric_sum_for_label(&metrics, "coxswain_cache_misses_total", &route_label);
    let hits = metric_sum_for_label(&metrics, "coxswain_cache_hits_total", &route_label);
    assert!(
        misses.is_some_and(|v| v >= 1.0),
        "coxswain_cache_misses_total must record at least one miss for {route_label}; \
         got {misses:?}"
    );
    assert!(
        hits.is_some_and(|v| v >= 1.0),
        "coxswain_cache_hits_total must record at least one hit for {route_label}; \
         got {hits:?}"
    );

    Ok(())
}
