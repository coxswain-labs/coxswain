#![allow(missing_docs)]
//! Security data-plane: edge access control.
//!
//! Plane: **data-plane**. Execution: the `allow-source-range` tests need the
//! shared controller running with `--proxy-accept-proxy-protocol` (the only way
//! to drive a real client IP through the in-cluster LB, which NATs the L4 peer),
//! so they reconfigure the shared control plane and run in the **serial** pass
//! (registered in `.config/nextest.toml`).
//!
//! Classification rule: a test belongs to the plane of its *primary assertion
//! target*. This file is the home for the v0.3 edge-security feature effect
//! tests as they land: IP allow/deny source-range (#264), client-cert mTLS
//! (#267), `satisfy` any/all (#268), external authorization (#273), and
//! per-client rate limiting (#24/#25). Upstream TLS verification
//! (`BackendTLSPolicy`, mTLS to the backend) lives in `tls.rs`.

use coxswain_e2e::{
    ControllerOptions, ControllerProcess, FixtureVars, Harness, NamespaceGuard, bootstrap,
    fixtures::{self, backends, gateway_api as gwa, ingress},
    harness::{http::EchoResponse, wait},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// `allow-source-range`: a request whose **real client IP** (carried in the PROXY
/// header) is inside the allow-listed CIDR is served normally (#264 happy path).
#[tokio::test]
async fn allow_source_range_in_range_allowed() -> anyhow::Result<()> {
    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "allow-range-in").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_ALLOW_SOURCE_RANGE,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let controller = ControllerProcess::start_with_options(ControllerOptions {
        accept_proxy_protocol: true,
        trusted_sources: vec!["0.0.0.0/0".to_string()],
        ..Default::default()
    })
    .await?;
    wait::wait_for_ready(controller.health_addr, Duration::from_secs(30)).await?;

    let host = format!("allowrange.{}.local", ns.name);
    // 203.0.113.10 ∈ 203.0.113.0/24 — admitted.
    let proxy_line = "PROXY TCP4 203.0.113.10 10.0.0.1 12345 80\r\n";
    let http_req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    // Poll until 200 — handles route-install latency; once installed, the in-range
    // client stays admitted.
    let body = wait_for_proxy_v1_status(
        controller.proxy_addr,
        proxy_line,
        &http_req,
        200,
        Duration::from_secs(60),
    )
    .await?;

    // Assert backend identity so a mis-route can't masquerade as a pass.
    let echo: EchoResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("expected echo JSON body, got {body:?}: {e}"))?;
    echo.assert_backend("echo-a");

    Ok(())
}

/// `allow-source-range`: a request whose real client IP is outside every allow-listed
/// CIDR is rejected with 403 before reaching any backend (#264 sad path).
#[tokio::test]
async fn allow_source_range_out_of_range_rejected() -> anyhow::Result<()> {
    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "allow-range-out").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_ALLOW_SOURCE_RANGE,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let controller = ControllerProcess::start_with_options(ControllerOptions {
        accept_proxy_protocol: true,
        trusted_sources: vec!["0.0.0.0/0".to_string()],
        ..Default::default()
    })
    .await?;
    wait::wait_for_ready(controller.health_addr, Duration::from_secs(30)).await?;

    let host = format!("allowrange.{}.local", ns.name);
    // 192.0.2.1 ∉ 203.0.113.0/24 — rejected. Polling until 403 absorbs route-install
    // latency: before the route exists the proxy answers 404, never 403, so a 403 is an
    // unambiguous signal that the route is live AND the allow-list denied this client.
    let proxy_line = "PROXY TCP4 192.0.2.1 10.0.0.1 12345 80\r\n";
    let http_req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    wait_for_proxy_v1_status(
        controller.proxy_addr,
        proxy_line,
        &http_req,
        403,
        Duration::from_secs(60),
    )
    .await?;

    Ok(())
}

/// Poll: send a v1 PROXY header + HTTP request over raw TCP until the response status
/// equals `want_status`; returns the response body. Self-diagnosing on timeout (renders
/// the last observed status/error).
async fn wait_for_proxy_v1_status(
    proxy_addr: std::net::SocketAddr,
    proxy_line: &str,
    http_req: &str,
    want_status: u16,
    timeout: Duration,
) -> anyhow::Result<String> {
    wait::poll_until(
        timeout,
        wait::POLL,
        || async {
            match raw_http_status(proxy_addr, proxy_line.as_bytes(), http_req).await {
                Ok((status, _)) => format!("status {want_status}; last observed {status}"),
                Err(e) => format!("status {want_status}; last attempt failed: {e}"),
            }
        },
        || async {
            match raw_http_status(proxy_addr, proxy_line.as_bytes(), http_req).await {
                Ok((status, body)) if status == want_status => Some(body),
                _ => None,
            }
        },
    )
    .await
}

// ── Rate limiting (Ingress annotations) ──────────────────────────────────────

/// `rate-limit-rps`: a single request within the 1-req/s quota is served
/// normally (#25 happy path — IP-keyed).
#[tokio::test]
async fn requests_allowed_when_under_rate_limit() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rl-allowed").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_RATE_LIMIT_RPS,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let host = format!("ratelimit.{}.local", ns.name);

    // A single request within quota (rps=1, burst=0) must reach the backend.
    let resp = wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");
    Ok(())
}

/// `rate-limit-rps`: rapid-fire requests at rps=1 (no burst) cause the proxy to
/// return 429 + `Retry-After` once the per-client budget is exhausted (#25 sad path).
#[tokio::test]
async fn requests_rejected_with_429_when_rate_limit_exceeded() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rl-rejected").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_RATE_LIMIT_RPS,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let host = format!("ratelimit.{}.local", ns.name);

    // Wait for the route to become live; this first 200 drains the single token.
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // Fire more requests immediately — the bucket is empty and replenishes at 1/s,
    // so at least one of the 20 rapid-fire requests must be 429 + Retry-After.
    let mut got_429_with_retry_after = false;
    for _ in 0..20 {
        let (status, headers, _) = h.http.get_full(&host, "/").await?;
        if status == 429 && headers.contains_key("retry-after") {
            got_429_with_retry_after = true;
            break;
        }
    }
    anyhow::ensure!(
        got_429_with_retry_after,
        "expected 429 + Retry-After on rapid-fire requests (rps=1, burst=0)"
    );
    Ok(())
}

/// `rate-limit-burst`: an initial spike up to burst+rps is absorbed; requests
/// beyond the burst capacity are rejected with 429 (#25 sad path — burst field).
#[tokio::test]
async fn burst_absorbs_spike_then_limits() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rl-burst").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_RATE_LIMIT_BURST,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let host = format!("ratelimitburst.{}.local", ns.name);

    // Wait until the route is live (first request admitted from the burst capacity).
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // Fire 20 requests rapidly; burst capacity is rps+burst=6, so at least 14 of
    // the remaining requests must be 429.
    let mut statuses: Vec<u16> = Vec::new();
    for _ in 0..20 {
        let (status, _, _) = h.http.get_full(&host, "/").await?;
        statuses.push(status);
    }
    anyhow::ensure!(
        statuses.iter().any(|&s| s == 429),
        "expected at least one 429 after burst exhausted (rps=1, burst=5); got: {statuses:?}"
    );
    Ok(())
}

/// `rate-limit-by: header:X-Rate-Key`: when the keying header is absent the
/// rate limiter is bypassed (fail-open) — all requests are admitted (#25 sad
/// path — missing key header).
#[tokio::test]
async fn rate_limit_not_applied_when_keying_header_absent() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rl-no-header").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_RATE_LIMIT_BY_HEADER,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let host = format!("ratelimitheader.{}.local", ns.name);

    // Route must be live before firing the rapid-fire batch.
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // 10 requests without X-Rate-Key — no bucket to check against, so all must pass.
    let mut statuses: Vec<u16> = Vec::new();
    for _ in 0..10 {
        let (status, _, _) = h.http.get_full(&host, "/").await?;
        statuses.push(status);
    }
    anyhow::ensure!(
        statuses.iter().all(|&s| s == 200),
        "absent keying header must be fail-open (all 200), got: {statuses:?}"
    );
    Ok(())
}

/// `rate-limit-rps: notanumber`: an invalid annotation value is ignored with a
/// WARN and traffic flows unthrottled (#25 sad path — invalid annotation).
#[tokio::test]
async fn invalid_rate_limit_annotation_ignored() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rl-invalid").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_RATE_LIMIT_INVALID,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let host = format!("ratelimitinvalid.{}.local", ns.name);

    // The route must be live and unthrottled — invalid annotation is warn+drop.
    let resp = wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");
    Ok(())
}

// ── Rate limiting (Gateway API ExtensionRef) ──────────────────────────────────

/// Gateway API `ExtensionRef` + `RateLimit` CR: within-quota requests reach the
/// backend (200); over-quota requests are rejected with 429 + `Retry-After`
/// (#25 happy + sad path).
#[tokio::test]
async fn gateway_route_rate_limited_via_extensionref() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rl-gw-cr").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(gwa::RATE_LIMIT_EXTENSIONREF, FixtureVars::new(&ns.name)).await?;
    let host = format!("gwratelimit.{}.local", ns.name);

    // Wait until the Gateway route is live (first request admits within the 1-cell budget).
    wait::wait_for_route(&h.gateway_http, &host, "/rl/", Duration::from_secs(60)).await?;

    // Rapid-fire — bucket is drained; at least one must return 429 + Retry-After.
    let mut got_429_with_retry_after = false;
    for _ in 0..20 {
        let (status, headers, _) = h.gateway_http.get_full(&host, "/rl/").await?;
        if status == 429 && headers.contains_key("retry-after") {
            got_429_with_retry_after = true;
            break;
        }
    }
    anyhow::ensure!(
        got_429_with_retry_after,
        "expected 429 + Retry-After on rapid-fire Gateway requests (RateLimit CR rps=1)"
    );
    Ok(())
}

/// Gateway API `ExtensionRef` pointing at a `RateLimit` CR that does not exist:
/// the reflector warns and fails-open — all requests are admitted (#25 sad path
/// — dangling ExtensionRef).
#[tokio::test]
async fn gateway_route_unthrottled_when_ratelimit_cr_missing() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rl-gw-norl").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(gwa::RATE_LIMIT_MISSING_CR, FixtureVars::new(&ns.name)).await?;
    let host = format!("gwnorl.{}.local", ns.name);

    // Route must be live; missing CR → fail-open → all requests admitted.
    wait::wait_for_route(&h.gateway_http, &host, "/rl/", Duration::from_secs(60)).await?;

    // 10 rapid requests — no rate limiter was installed, so all must be 200.
    let mut statuses: Vec<u16> = Vec::new();
    for _ in 0..10 {
        let (status, _, _) = h.gateway_http.get_full(&host, "/rl/").await?;
        statuses.push(status);
    }
    anyhow::ensure!(
        statuses.iter().all(|&s| s == 200),
        "missing RateLimit CR must be fail-open (all 200), got: {statuses:?}"
    );
    Ok(())
}

/// Make one raw TCP request (write `preamble` then the HTTP request) and return the
/// response `(status_code, body)`.
async fn raw_http_status(
    addr: std::net::SocketAddr,
    preamble: &[u8],
    http_req: &str,
) -> anyhow::Result<(u16, String)> {
    let mut tcp = tokio::net::TcpStream::connect(addr).await?;
    tcp.write_all(preamble).await?;
    tcp.write_all(http_req.as_bytes()).await?;
    tcp.flush().await?;

    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await?;
    let s = String::from_utf8_lossy(&response);

    let status_line = s
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty response"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("no status code in line: {status_line:?}"))?;
    let body = s.split("\r\n\r\n").nth(1).unwrap_or("").to_string();

    Ok((status, body))
}
