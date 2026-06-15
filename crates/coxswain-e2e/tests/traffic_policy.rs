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
    FixtureVars, Harness, NamespaceGuard,
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
async fn annotation_connect_retry() -> anyhow::Result<()> {
    common::init_tracing();
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
