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
    ControllerOptions, ControllerProcess, FixtureVars, NamespaceGuard, bootstrap,
    fixtures::{self, backends, ingress},
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
