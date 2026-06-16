#![allow(missing_docs)]
//! Traffic-policy data-plane: per-route/per-backend behavior knobs.
//!
//! Plane: **data-plane**. Execution: **parallel** — every test owns a fresh
//! namespace and asserts only traffic served through that partition.
//!
//! Classification rule: a test belongs to the plane of its *primary assertion
//! target*. This file is the home for the v0.3 traffic-policy annotation/knob
//! effect tests — compression, response buffering, upstream keepalive,
//! circuit-breaker, load-balance algorithm, upstream-hash, max-body-size,
//! limit-connections, mirror-target, drain-timeout
//! (#263/#266/#270/#274/#275/#276/#277/#281/#282/#283) — each landing with its
//! feature. Seeded here today: the connect-retry annotation (`max-retries`,
//! `retry-on`). Routing-shape behavior lives in `routing.rs`; TLS in `tls.rs`.

use coxswain_e2e::{
    FixtureVars, Harness, IngressClassGuard, NamespaceGuard,
    fixtures::{self, backends, ingress},
    harness::wait,
};
use std::time::Duration;

mod common;

/// Verifies that `ingress.coxswain-labs.dev/max-retries` and `retry-on:
/// connect-failure` annotations are parsed and stored on the route:
/// - A backend whose endpoints all refuse connections (wrong port on real pods)
///   should produce a 502 (not a 503 dead-route) when retries are exhausted.
/// - 502 vs 503 distinguishes "tried to connect and failed" from "no endpoints
///   were ever resolved" — the `error_status: 503` dead-route short-circuit is
///   bypassed when endpoints are present regardless of retry settings.
///
/// Note: the exact retry count (3 attempts for max-retries=2) is deterministic
/// and covered by the unit tests in `coxswain-proxy::common::hooks`; e2e
/// cannot observe individual retry attempts without a dedicated metric.
#[tokio::test]
async fn annotation_connect_retry_retries_failed_connect() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-retry").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_CONNECT_RETRY,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("retry.{}.local", ns.name);

    // Wait until the route is installed (502, not "no route yet").
    // A 503 here would indicate the reflector treated the endpoint-less service
    // as a dead route instead of installing a live route with failing endpoints.
    wait::wait_for_route_status(&h.http, &host, "/", 502, Duration::from_secs(60)).await?;

    // Confirm the upstream-error metric is being emitted for this route.
    // (Exact retry-attempt count is validated by unit tests.)
    let metrics = reqwest::get(h.admin_url("/metrics")).await?.text().await?;
    assert!(
        metrics.contains("coxswain_proxy_upstream_errors_total{"),
        "proxy /metrics must expose coxswain_proxy_upstream_errors_total after a connect failure"
    );

    Ok(())
}

/// Verifies that `ingress.coxswain-labs.dev/connect-timeout` bounds the upstream
/// TCP-connect phase. The backend's only EndpointSlice address is `192.0.2.1`
/// (RFC 5737 TEST-NET-1), so the SYN is black-holed and `connect()` hangs.
///
/// With `connect-timeout: 500ms` the proxy abandons the connect after 500ms and
/// returns 502 (`ConnectTimedout`). The proof is that the 502 arrives within the
/// test client's 5s budget: without the annotation the connect would hang past it
/// and the route would never return a clean 502.
#[tokio::test]
async fn annotation_connect_timeout_returns_502() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-connect-timeout").await?;

    fixtures::apply_fixture(
        ingress::ANNOTATION_CONNECT_TIMEOUT,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("connect-timeout.{}.local", ns.name);

    // 502 doubles as the readiness signal: once the route is installed every
    // request black-holes on connect and returns 502 within the 500ms deadline.
    wait::wait_for_route_status(&h.http, &host, "/", 502, Duration::from_secs(60)).await?;

    Ok(())
}

/// Verifies that `ingress.coxswain-labs.dev/read-timeout` bounds the upstream
/// response-read phase. The slow-echo backend accepts the connection but never
/// writes a response, holding the socket ~30s.
///
/// With `read-timeout: 500ms` the proxy abandons the read after 500ms and returns
/// 502 (`ReadTimedout`, `esource=Upstream` — a pure Ingress read-timeout carries
/// no request budget, so it maps to 502 rather than the Gateway-API 504). The
/// proof is the prompt 502: without the annotation the read would block past the
/// test client's 5s budget and the route would never return a clean 502.
#[tokio::test]
async fn annotation_read_timeout_returns_502() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-read-timeout").await?;

    fixtures::apply_fixture(backends::SLOW_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["slow-echo"]).await?;
    fixtures::apply_fixture(ingress::ANNOTATION_READ_TIMEOUT, FixtureVars::new(&ns.name)).await?;

    let host = format!("read-timeout.{}.local", ns.name);

    // 502 doubles as the readiness signal: once the route is installed every
    // request times out on the upstream read and returns 502 within 500ms.
    wait::wait_for_route_status(&h.http, &host, "/", 502, Duration::from_secs(60)).await?;

    Ok(())
}

/// Verifies a class-level `connect-timeout` default sourced from
/// `IngressClass.spec.parameters` (#190) reaches the data plane — proving the
/// class-defaults merge is annotation-agnostic, not specific to `rewrite-target`.
///
/// The Ingress sets no `connect-timeout` of its own; the class default (500ms)
/// bounds the connect to a black-holed backend (192.0.2.1, RFC 5737) and yields a
/// prompt 502. Without the class default the connect would hang past the client's
/// 5s budget, so the prompt 502 is the proof the class default applied.
#[tokio::test]
async fn class_default_connect_timeout_returns_502() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-cls-timeout").await?;

    // Cluster-scoped IngressClass — guard deletes it on drop. Name matches the
    // fixture's `coxswain-clstimeout-${TESTNS}`.
    let ic_name = format!("coxswain-clstimeout-{}", ns.name);
    let _ic_guard = IngressClassGuard::new(&h.client, &ic_name);

    fixtures::apply_fixture(ingress::CLASS_DEFAULT_TIMEOUT, FixtureVars::new(&ns.name)).await?;

    let host = format!("clstimeout.{}.local", ns.name);

    // 502 doubles as the readiness signal: once the route is installed every
    // request black-holes on connect and returns 502 within the 500ms deadline
    // supplied by the class default.
    wait::wait_for_route_status(&h.http, &host, "/", 502, Duration::from_secs(60)).await?;

    Ok(())
}
