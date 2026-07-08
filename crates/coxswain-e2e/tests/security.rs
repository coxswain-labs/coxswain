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
    ControllerOptions, ControllerProcess, FixtureVars, GeneratedCert, Harness, MtlsCerts,
    NamespaceGuard, bootstrap,
    fixtures::{self, backends, gateway_api as gwa, ingress},
    harness::{
        http::{EchoResponse, https_get, https_get_with_client_cert},
        wait,
    },
};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

mod common;

// Minimal `grpcecho` proto (hand-derived from grpcecho.proto to avoid a
// prost-build dependency) for the GRPCRoute ExtensionRef parity tests (#479, #25).
// Service: gateway_api_conformance.echo_basic.grpcecho.GrpcEcho
mod grpcecho {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct EchoRequest {}

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct GrpcContext {
        #[prost(string, tag = "4")]
        pub pod: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct EchoAssertions {
        #[prost(message, optional, tag = "4")]
        pub context: Option<GrpcContext>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct EchoResponse {
        #[prost(message, optional, tag = "1")]
        pub assertions: Option<EchoAssertions>,
    }
}

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

/// `deny-source-range`: a request whose **real client IP** (carried in the PROXY header)
/// is inside the deny-listed CIDR is rejected with 403 before reaching any backend
/// (#268 happy path — block in effect).
#[tokio::test]
async fn deny_source_range_blocks_listed_client() -> anyhow::Result<()> {
    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "deny-range-in").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_DENY_SOURCE_RANGE,
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

    let host = format!("denyrange.{}.local", ns.name);
    // 203.0.113.10 ∈ 203.0.113.0/24 — blocked.
    // Polling until 403 absorbs route-install latency: before the route exists the
    // proxy answers 404, so a 403 is an unambiguous signal that the route is live
    // AND the deny-list blocked this client.
    let proxy_line = "PROXY TCP4 203.0.113.10 10.0.0.1 12345 80\r\n";
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

/// `deny-source-range`: a request whose real client IP is **outside** the deny-listed
/// CIDR is served normally (#268 negative path — block list does not over-block).
#[tokio::test]
async fn deny_source_range_allows_unlisted_client() -> anyhow::Result<()> {
    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "deny-range-out").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_DENY_SOURCE_RANGE,
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

    let host = format!("denyrange.{}.local", ns.name);
    // 192.0.2.1 ∉ 203.0.113.0/24 — admitted.
    let proxy_line = "PROXY TCP4 192.0.2.1 10.0.0.1 12345 80\r\n";
    let http_req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    let body = wait_for_proxy_v1_status(
        controller.proxy_addr,
        proxy_line,
        &http_req,
        200,
        Duration::from_secs(60),
    )
    .await?;

    let echo: EchoResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("expected echo JSON body, got {body:?}: {e}"))?;
    echo.assert_backend("echo-a");

    Ok(())
}

/// `deny-source-range` + `allow-source-range`: when both are set, deny is evaluated
/// first — a client matching both lists is rejected with 403 (#268 precedence test).
/// A client in the allow range but not the deny range is admitted normally.
#[tokio::test]
async fn deny_takes_precedence_over_allow_when_both_match() -> anyhow::Result<()> {
    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "deny-allow-prec").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_DENY_AND_ALLOW_SOURCE_RANGE,
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

    let host = format!("denyallow.{}.local", ns.name);

    // 203.0.113.5 ∈ deny-list (203.0.113.5/32) AND ∈ allow-list (203.0.113.0/24) — blocked.
    // Deny wins: polling until 403 confirms the route is live and deny has priority.
    let deny_line = "PROXY TCP4 203.0.113.5 10.0.0.1 12345 80\r\n";
    let http_req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    wait_for_proxy_v1_status(
        controller.proxy_addr,
        deny_line,
        &http_req,
        403,
        Duration::from_secs(60),
    )
    .await?;

    // 203.0.113.9 ∉ deny-list AND ∈ allow-list — admitted.
    let allow_line = "PROXY TCP4 203.0.113.9 10.0.0.1 12345 80\r\n";
    let body = wait_for_proxy_v1_status(
        controller.proxy_addr,
        allow_line,
        &http_req,
        200,
        Duration::from_secs(10),
    )
    .await?;

    let echo: EchoResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("expected echo JSON body, got {body:?}: {e}"))?;
    echo.assert_backend("echo-a");

    Ok(())
}

// ── Trusted proxy headers (trust-forwarded-for / forwarded-for-header / -trusted-cidrs) ──

/// `trust-forwarded-for` fail-closed: when the annotation is `"true"` but no
/// `forwarded-for-trusted-cidrs` are configured, the forwarded header is **ignored**
/// (trust no peer). A client cannot spoof an in-range IP via the header; the L4 peer
/// address is used, so an out-of-range L4 peer is rejected even though the header
/// carries an allow-listed IP (#271 / S2 — empty trusted-cidrs is fail-closed).
#[tokio::test]
async fn forwarded_header_ignored_without_trusted_cidrs_fail_closed() -> anyhow::Result<()> {
    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "trust-fwd-failclosed").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_TRUST_FORWARDED_FOR,
        FixtureVars::new(&ns.name),
    )
    .await?;

    // L4 peer 10.0.0.1 is outside the allow-range; the header carries an in-range IP
    // (203.0.113.10). With no trusted-cidrs the proxy is fail-closed and ignores the
    // header, so the effective IP is 10.0.0.1 ∉ 203.0.113.0/24 → 403. Polling to 403 is
    // an unambiguous signal that the route is live AND the header was NOT trusted.
    let controller = ControllerProcess::start_with_options(ControllerOptions {
        accept_proxy_protocol: true,
        trusted_sources: vec!["0.0.0.0/0".to_string()],
        ..Default::default()
    })
    .await?;
    wait::wait_for_ready(controller.health_addr, Duration::from_secs(30)).await?;

    let host = format!("trustfwd.{}.local", ns.name);
    let proxy_line = "PROXY TCP4 10.0.0.1 10.0.0.2 12345 80\r\n";
    let http_req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-For: 203.0.113.10\r\nConnection: close\r\n\r\n"
    );

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

/// `trust-forwarded-for` with trusted-cidrs: when the L4 peer IS a trusted proxy but
/// the forwarded header carries only private/reserved hops, no untrusted address can be
/// resolved, so the proxy falls back to the (trusted) L4 peer IP. Here that L4 IP is
/// itself allow-listed, so the request is admitted — proving the private-hop skip +
/// L4 fallback path (#271 — trusted peer, header all-private).
#[tokio::test]
async fn forwarded_header_all_private_under_trusted_peer_falls_back_to_l4() -> anyhow::Result<()> {
    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "trust-fwd-priv").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_TRUST_FORWARDED_FOR_CIDRS,
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

    let host = format!("trustfwdcidr.{}.local", ns.name);
    // L4 peer 10.0.0.1 ∈ trusted-cidrs (10.0.0.1/32) → header trusted. Header carries
    // only 10.0.0.5 (private) → no untrusted address → fall back to L4 10.0.0.1, which
    // ∈ allow-source-range (10.0.0.1/32) → 200. Polling to 200 + backend identity
    // confirms the fallback resolved to the trusted L4 peer.
    let proxy_line = "PROXY TCP4 10.0.0.1 10.0.0.2 12345 80\r\n";
    let http_req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nX-Real-IP: 10.0.0.5\r\nConnection: close\r\n\r\n"
    );

    let body = wait_for_proxy_v1_status(
        controller.proxy_addr,
        proxy_line,
        &http_req,
        200,
        Duration::from_secs(60),
    )
    .await?;

    let echo: EchoResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("expected echo JSON body, got {body:?}: {e}"))?;
    echo.assert_backend("echo-a");

    Ok(())
}

/// `forwarded-for-header` + `forwarded-for-trusted-cidrs`: when the L4 peer is inside the
/// trusted CIDR gate, the proxy reads the custom header and uses its IP as the effective
/// client IP (#271 happy path — custom header, trusted peer).
#[tokio::test]
async fn custom_forwarded_header_from_trusted_peer_resolves_client_ip() -> anyhow::Result<()> {
    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "trust-fwd-cidr-ok").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_TRUST_FORWARDED_FOR_CIDRS,
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

    let host = format!("trustfwdcidr.{}.local", ns.name);
    // L4 peer 10.0.0.1 ∈ forwarded-for-trusted-cidrs (10.0.0.1/32) → header trusted.
    // X-Real-IP: 203.0.113.10 ∈ allow-source-range (203.0.113.0/24) → admitted.
    let proxy_line = "PROXY TCP4 10.0.0.1 10.0.0.2 12345 80\r\n";
    let http_req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nX-Real-IP: 203.0.113.10\r\nConnection: close\r\n\r\n"
    );

    let body = wait_for_proxy_v1_status(
        controller.proxy_addr,
        proxy_line,
        &http_req,
        200,
        Duration::from_secs(60),
    )
    .await?;

    let echo: EchoResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("expected echo JSON body, got {body:?}: {e}"))?;
    echo.assert_backend("echo-a");

    Ok(())
}

/// `forwarded-for-trusted-cidrs` anti-spoofing gate: when the L4 peer is **outside** the
/// trusted CIDR the forwarded header is ignored; the proxy uses the L4 IP and rejects a
/// request that would have been admitted via the (forged) header (#271 sad path — spoofing
/// attempt blocked).
#[tokio::test]
async fn spoofed_forwarded_header_from_untrusted_peer_is_rejected() -> anyhow::Result<()> {
    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "trust-fwd-spoof").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_TRUST_FORWARDED_FOR_CIDRS,
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

    let host = format!("trustfwdcidr.{}.local", ns.name);
    // L4 peer 192.168.1.1 ∉ forwarded-for-trusted-cidrs (10.0.0.1/32) → header ignored.
    // Effective IP = 192.168.1.1, which is private and ∉ allow-source-range → 403.
    // Polling to 403 unambiguously signals the route is live AND the anti-spoofing gate fired.
    let proxy_line = "PROXY TCP4 192.168.1.1 10.0.0.2 12345 80\r\n";
    let http_req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nX-Real-IP: 203.0.113.10\r\nConnection: close\r\n\r\n"
    );

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

/// Rightmost-untrusted resolution: a client that forges a leftmost token in the
/// trusted forwarded header cannot bypass `allow-source-range`. The trusted LB appends
/// the client's real (out-of-range) IP to the right; the proxy resolves the rightmost
/// untrusted address, ignoring the in-range value the client injected on the left, and
/// rejects the request (S1 — leftmost-XFF spoofing defeated).
#[tokio::test]
async fn forwarded_header_forged_leftmost_cannot_bypass_allow_list() -> anyhow::Result<()> {
    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "trust-fwd-forge").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_TRUST_FORWARDED_FOR_CIDRS,
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

    let host = format!("trustfwdcidr.{}.local", ns.name);
    // L4 peer 10.0.0.1 ∈ trusted-cidrs → header trusted. The client forges an in-range
    // leftmost token (203.0.113.10 ∈ allow-range) hoping to be admitted; the trusted LB
    // appends the real client 8.8.8.8 to the right. Rightmost-untrusted resolves 8.8.8.8
    // ∉ allow-range → 403. The old leftmost-wins scan would have picked 203.0.113.10 and
    // admitted (200) — polling to 403 proves the forgery is defeated.
    let proxy_line = "PROXY TCP4 10.0.0.1 10.0.0.2 12345 80\r\n";
    let http_req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nX-Real-IP: 203.0.113.10, 8.8.8.8\r\nConnection: close\r\n\r\n"
    );

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

/// IPv4-mapped IPv6 deny-list canonicalization: a client whose real IP arrives in the
/// `::ffff:a.b.c.d` mapped form is canonicalized before the CIDR check, so it cannot
/// evade an IPv4 `deny-source-range` by presenting the mapped form (SEC-1 — no
/// mapped-v6 deny evasion).
#[tokio::test]
async fn mapped_v6_client_matches_deny_v4_cidr() -> anyhow::Result<()> {
    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "deny-mapped-v6").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_DENY_SOURCE_RANGE,
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

    let host = format!("denyrange.{}.local", ns.name);
    // L4 peer arrives as the IPv4-mapped IPv6 form of 203.0.113.10, which ∈ the denied
    // 203.0.113.0/24 after canonicalization → 403. Without canonicalization the mapped
    // form would not match the v4 CIDR and slip through (200) — polling to 403 proves
    // the mapped-v6 evasion is closed.
    let proxy_line = "PROXY TCP6 ::ffff:203.0.113.10 ::ffff:10.0.0.1 12345 80\r\n";
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

/// `rate-limit-rps: notanumber`: the VAP rejects the Ingress at admission time
/// (#25 sad path — invalid annotation, #29 VAP).
///
/// Fail-open proxy semantics (warn + serve unthrottled) remain the backstop for
/// VAP-disabled installs, covered by the `parse_rate_limit_rps_invalid` unit test.
#[tokio::test]
async fn invalid_rate_limit_annotation_rejected_by_vap() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "rl-invalid").await?;
    let msg = fixtures::apply_fixture_expect_rejected(
        ingress::ANNOTATION_RATE_LIMIT_INVALID,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("rate-limit-rps"),
        "VAP rejection message must name the offending annotation, got: {msg}"
    );
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
    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwratelimit.{}.local", ns.name);

    // Wait until the Gateway route is live (first request admits within the 1-cell budget).
    wait::wait_for_route(&gw, &host, "/rl/", Duration::from_secs(60)).await?;

    // Rapid-fire — bucket is drained; at least one must return 429 + Retry-After.
    let mut got_429_with_retry_after = false;
    for _ in 0..20 {
        let (status, headers, _) = gw.get_full(&host, "/rl/").await?;
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
    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwnorl.{}.local", ns.name);

    // Route must be live; missing CR → fail-open → all requests admitted.
    wait::wait_for_route(&gw, &host, "/rl/", Duration::from_secs(60)).await?;

    // 10 rapid requests — no rate limiter was installed, so all must be 200.
    let mut statuses: Vec<u16> = Vec::new();
    for _ in 0..10 {
        let (status, _, _) = gw.get_full(&host, "/rl/").await?;
        statuses.push(status);
    }
    anyhow::ensure!(
        statuses.iter().all(|&s| s == 200),
        "missing RateLimit CR must be fail-open (all 200), got: {statuses:?}"
    );
    Ok(())
}

// ── IP access control (Gateway API ExtensionRef) ──────────────────────────────
//
// Gateway-side parity for the Ingress allow/deny-source-range annotations (#479).
// PROXY protocol is enabled per-Gateway via a ClientTrafficPolicy (bundled in the
// fixture) so a synthetic client IP can be injected — the same client-IP path the
// filter evaluates. The dest port in the PROXY line (8000) matches GATEWAY_HTTP_PORT.

/// `IpAccessControl` allow-list: a client whose real IP is inside the allow-listed
/// CIDR reaches the backend (200) (#479 happy path).
#[tokio::test]
async fn gateway_ip_allow_in_range_admitted() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ipac-allow-in").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(gwa::IP_ACCESS_ALLOW, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-ipac",
        &ns.name,
        "Programmed",
        "True",
        Duration::from_secs(60),
    )
    .await?;
    let addr = h.gateway_http_addr(&ns.name).await?;

    let host = format!("gwipac.{}.local", ns.name);
    // 203.0.113.10 ∈ 203.0.113.0/24 — admitted. Poll to 200 (404 before install).
    let proxy_line = "PROXY TCP4 203.0.113.10 10.0.0.1 12345 8000\r\n";
    let http_req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    let body =
        wait_for_proxy_v1_status(addr, proxy_line, &http_req, 200, Duration::from_secs(60)).await?;
    let echo: EchoResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("expected echo JSON body, got {body:?}: {e}"))?;
    echo.assert_backend("echo-a");
    Ok(())
}

/// `IpAccessControl` allow-list: a client outside every allow-listed CIDR is
/// rejected with 403 before reaching any backend (#479 sad path).
#[tokio::test]
async fn gateway_ip_allow_out_of_range_rejected() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ipac-allow-out").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(gwa::IP_ACCESS_ALLOW, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-ipac",
        &ns.name,
        "Programmed",
        "True",
        Duration::from_secs(60),
    )
    .await?;
    let addr = h.gateway_http_addr(&ns.name).await?;

    let host = format!("gwipac.{}.local", ns.name);
    // 192.0.2.1 ∉ 203.0.113.0/24 — rejected. Polling to 403 disambiguates the
    // pre-install 404 from the allow-list denial.
    let proxy_line = "PROXY TCP4 192.0.2.1 10.0.0.1 12345 8000\r\n";
    let http_req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    wait_for_proxy_v1_status(addr, proxy_line, &http_req, 403, Duration::from_secs(60)).await?;
    Ok(())
}

/// `IpAccessControl` deny-list: a client whose real IP is inside the deny-listed
/// CIDR is rejected with 403 (#479 happy path — block in effect).
#[tokio::test]
async fn gateway_ip_deny_blocks_listed_client() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ipac-deny-in").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(gwa::IP_ACCESS_DENY, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-ipac",
        &ns.name,
        "Programmed",
        "True",
        Duration::from_secs(60),
    )
    .await?;
    let addr = h.gateway_http_addr(&ns.name).await?;

    let host = format!("gwipac.{}.local", ns.name);
    // 203.0.113.10 ∈ 203.0.113.0/24 — blocked. Poll to 403 (404 before install).
    let proxy_line = "PROXY TCP4 203.0.113.10 10.0.0.1 12345 8000\r\n";
    let http_req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    wait_for_proxy_v1_status(addr, proxy_line, &http_req, 403, Duration::from_secs(60)).await?;
    Ok(())
}

/// `IpAccessControl` deny-list with no allow-list: a client outside the deny CIDR
/// is admitted — an empty allow-list imposes no restriction (#479 sad path).
#[tokio::test]
async fn gateway_ip_deny_allows_unlisted_client() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ipac-deny-out").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(gwa::IP_ACCESS_DENY, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-ipac",
        &ns.name,
        "Programmed",
        "True",
        Duration::from_secs(60),
    )
    .await?;
    let addr = h.gateway_http_addr(&ns.name).await?;

    let host = format!("gwipac.{}.local", ns.name);
    // 192.0.2.1 ∉ 203.0.113.0/24 deny — admitted (no allow-list restriction).
    let proxy_line = "PROXY TCP4 192.0.2.1 10.0.0.1 12345 8000\r\n";
    let http_req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    let body =
        wait_for_proxy_v1_status(addr, proxy_line, &http_req, 200, Duration::from_secs(60)).await?;
    let echo: EchoResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("expected echo JSON body, got {body:?}: {e}"))?;
    echo.assert_backend("echo-a");
    Ok(())
}

/// `IpAccessControl` with a CIDR in BOTH allow and deny: deny is evaluated first,
/// so a client in that range is rejected 403 (#479 precedence test).
#[tokio::test]
async fn gateway_ip_deny_precedes_allow_when_both_match() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ipac-precedence").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(gwa::IP_ACCESS_DENY_PRECEDENCE, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-ipac",
        &ns.name,
        "Programmed",
        "True",
        Duration::from_secs(60),
    )
    .await?;
    let addr = h.gateway_http_addr(&ns.name).await?;

    let host = format!("gwipac.{}.local", ns.name);
    // 203.0.113.10 ∈ both lists — deny wins, so 403 confirms deny-before-allow.
    let proxy_line = "PROXY TCP4 203.0.113.10 10.0.0.1 12345 8000\r\n";
    let http_req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    wait_for_proxy_v1_status(addr, proxy_line, &http_req, 403, Duration::from_secs(60)).await?;
    Ok(())
}

// ── IP access control + rate limiting on GRPCRoute (#479, #25 gRPC parity) ─────
//
// The protocol-agnostic ExtensionRef filters apply to gRPC (HTTP/2) identically.
// gRPC maps proxy HTTP errors to gRPC status codes, so the filter outcome is
// observable without PROXY protocol: 403 → PermissionDenied, 429 → Unavailable,
// 404 (route not yet live) → Unimplemented. The last mapping lets a sad-path test
// distinguish "blocked" from "not yet installed" while polling.

/// Issue one `GrpcEcho/Echo` unary call through the Gateway VIP for `host`.
/// Connect/transport failures are folded into `Status::unavailable` so callers
/// can match on `tonic::Code` uniformly.
async fn grpc_echo_call(
    gw_addr: std::net::SocketAddr,
    host: &str,
) -> Result<grpcecho::EchoResponse, tonic::Status> {
    let origin: tonic::transport::Uri = format!("http://{host}:{}", gw_addr.port())
        .parse()
        .map_err(|e| tonic::Status::unavailable(format!("uri: {e}")))?;
    let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{gw_addr}"))
        .map_err(|e| tonic::Status::unavailable(format!("endpoint: {e}")))?
        .origin(origin);
    let channel = endpoint
        .connect()
        .await
        .map_err(|e| tonic::Status::unavailable(format!("connect: {e}")))?;
    let mut client = tonic::client::Grpc::new(channel);
    client
        .ready()
        .await
        .map_err(|e| tonic::Status::unavailable(format!("ready: {e}")))?;
    let path = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/Echo"
        .parse::<tonic::codegen::http::uri::PathAndQuery>()
        .map_err(|e| tonic::Status::unavailable(format!("path: {e}")))?;
    let codec = tonic_prost::ProstCodec::<grpcecho::EchoRequest, grpcecho::EchoResponse>::default();
    client
        .unary(tonic::Request::new(grpcecho::EchoRequest {}), path, codec)
        .await
        .map(tonic::Response::into_inner)
}

/// Like [`grpc_echo_call`] but attaches `authorization: Bearer <token>` as gRPC
/// metadata when `token` is `Some` — the gRPC equivalent of an HTTP
/// `Authorization` header, exercised by the `JwtAuth` ExtensionRef tests (#441).
async fn grpc_echo_call_with_bearer(
    gw_addr: std::net::SocketAddr,
    host: &str,
    token: Option<&str>,
) -> Result<grpcecho::EchoResponse, tonic::Status> {
    let origin: tonic::transport::Uri = format!("http://{host}:{}", gw_addr.port())
        .parse()
        .map_err(|e| tonic::Status::unavailable(format!("uri: {e}")))?;
    let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{gw_addr}"))
        .map_err(|e| tonic::Status::unavailable(format!("endpoint: {e}")))?
        .origin(origin);
    let channel = endpoint
        .connect()
        .await
        .map_err(|e| tonic::Status::unavailable(format!("connect: {e}")))?;
    let mut client = tonic::client::Grpc::new(channel);
    client
        .ready()
        .await
        .map_err(|e| tonic::Status::unavailable(format!("ready: {e}")))?;
    let path = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/Echo"
        .parse::<tonic::codegen::http::uri::PathAndQuery>()
        .map_err(|e| tonic::Status::unavailable(format!("path: {e}")))?;
    let codec = tonic_prost::ProstCodec::<grpcecho::EchoRequest, grpcecho::EchoResponse>::default();
    let mut request = tonic::Request::new(grpcecho::EchoRequest {});
    if let Some(token) = token {
        let value = format!("Bearer {token}")
            .parse()
            .map_err(|e| tonic::Status::unavailable(format!("metadata value: {e}")))?;
        request.metadata_mut().insert("authorization", value);
    }
    client
        .unary(request, path, codec)
        .await
        .map(tonic::Response::into_inner)
}

/// `IpAccessControl` on a GRPCRoute: an allow-list covering all sources admits the
/// client and the gRPC call reaches the backend (#479 gRPC happy path — also proves
/// the ExtensionRef is accepted on GRPCRoute).
#[tokio::test]
async fn grpc_route_ip_access_admits_when_client_allowed() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "grpc-ipac-ok").await?;
    fixtures::apply_fixture(backends::GRPC_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["grpc-echo"]).await?;
    fixtures::apply_fixture(gwa::GRPC_IP_ACCESS_ALLOW, FixtureVars::new(&ns.name)).await?;

    let host = format!("grpc-ipac.{}.local", ns.name);
    let gw_addr = h.gateway_http_addr(&ns.name).await?;

    // Poll until the data plane serves the call — an admitted client reaches grpc-echo.
    let resp = wait::poll_until(
        Duration::from_secs(60),
        Duration::from_millis(500),
        || async { format!("allowed gRPC Echo via {host} to succeed") },
        || async { grpc_echo_call(gw_addr, &host).await.ok() },
    )
    .await?;

    let pod = resp
        .assertions
        .and_then(|a| a.context)
        .map(|c| c.pod)
        .unwrap_or_default();
    assert!(
        pod.starts_with("grpc-echo-"),
        "response must come from grpc-echo-* pod, got {pod:?}"
    );
    Ok(())
}

/// `IpAccessControl` on a GRPCRoute: an allow-list the client is not part of
/// rejects the call before the backend. The proxy's 403 surfaces as gRPC
/// `PermissionDenied`, distinct from the `Unimplemented` (404) seen before the
/// route is live — so polling for `PermissionDenied` confirms the block is in
/// effect (#479 gRPC sad path).
#[tokio::test]
async fn grpc_route_ip_access_blocks_when_client_not_allowed() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "grpc-ipac-deny").await?;
    fixtures::apply_fixture(backends::GRPC_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["grpc-echo"]).await?;
    fixtures::apply_fixture(gwa::GRPC_IP_ACCESS_RESTRICTED, FixtureVars::new(&ns.name)).await?;

    let host = format!("grpc-ipac.{}.local", ns.name);
    let gw_addr = h.gateway_http_addr(&ns.name).await?;

    // Poll until the call is rejected with PermissionDenied (403). Unimplemented
    // (404, route not yet live) does not match, so this waits for the route to be
    // live AND the source-IP allow-list to fire.
    wait::poll_until(
        Duration::from_secs(60),
        Duration::from_millis(500),
        || async { format!("restricted gRPC Echo via {host} to be denied (PermissionDenied)") },
        || async {
            match grpc_echo_call(gw_addr, &host).await {
                Err(s) if s.code() == tonic::Code::PermissionDenied => Some(()),
                _ => None,
            }
        },
    )
    .await?;
    Ok(())
}

/// `RateLimit` on a GRPCRoute (rps=1): the first call is served (proving the route
/// is live and the ExtensionRef accepted), then rapid follow-ups are rejected —
/// the proxy's 429 surfaces as gRPC `Unavailable` (#25 gRPC parity).
#[tokio::test]
async fn grpc_route_rate_limited_via_extensionref() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "grpc-rl").await?;
    fixtures::apply_fixture(backends::GRPC_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["grpc-echo"]).await?;
    fixtures::apply_fixture(gwa::GRPC_RATE_LIMIT, FixtureVars::new(&ns.name)).await?;

    let host = format!("grpc-rl.{}.local", ns.name);
    let gw_addr = h.gateway_http_addr(&ns.name).await?;

    // First, wait until a call succeeds — confirms the route is live and admits
    // within the 1-cell budget (also drains the token).
    wait::poll_until(
        Duration::from_secs(60),
        Duration::from_millis(500),
        || async { format!("gRPC Echo via {host} to succeed once (within quota)") },
        || async { grpc_echo_call(gw_addr, &host).await.ok() },
    )
    .await?;

    // Rapid-fire: the bucket is drained, so at least one call must be rejected.
    // The route is confirmed live, so a rejection is the rate limit — the proxy's
    // 429 maps to gRPC `Unavailable`. Match that code specifically rather than any
    // error, so a stray transport hiccup can't masquerade as enforcement.
    let mut rate_limited = false;
    for _ in 0..20 {
        if let Err(s) = grpc_echo_call(gw_addr, &host).await
            && s.code() == tonic::Code::Unavailable
        {
            rate_limited = true;
            break;
        }
    }
    anyhow::ensure!(
        rate_limited,
        "expected at least one gRPC call to be rate-limited (RateLimit rps=1, 429 → Unavailable) on rapid-fire"
    );
    Ok(())
}

// ── JwtAuth on GRPCRoute (#441 gRPC parity) ───────────────────────────────────

/// `JwtAuth` on a GRPCRoute: a call carrying a valid, signed, unexpired,
/// correct-issuer bearer token (as the "authorization" gRPC metadata key) is
/// admitted and reaches grpc-echo (#441 gRPC happy path — also proves the
/// ExtensionRef is accepted on GRPCRoute).
#[tokio::test]
async fn grpc_route_jwt_auth_admits_valid_token() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "grpc-jwtauth-ok").await?;
    fixtures::apply_fixture(backends::GRPC_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["grpc-echo"]).await?;
    fixtures::apply_fixture(gwa::GRPC_JWT_AUTH, FixtureVars::new(&ns.name)).await?;

    let host = format!("grpc-jwtauth.{}.local", ns.name);
    let gw_addr = h.gateway_http_addr(&ns.name).await?;
    let token = coxswain_e2e::jwt::valid_token();

    let resp = wait::poll_until(
        Duration::from_secs(60),
        Duration::from_millis(500),
        || async { format!("gRPC Echo via {host} to admit a valid bearer token") },
        || async {
            grpc_echo_call_with_bearer(gw_addr, &host, Some(&token))
                .await
                .ok()
        },
    )
    .await?;

    let pod = resp
        .assertions
        .and_then(|a| a.context)
        .map(|c| c.pod)
        .unwrap_or_default();
    assert!(
        pod.starts_with("grpc-echo-"),
        "response must come from grpc-echo-* pod, got {pod:?}"
    );
    Ok(())
}

/// `JwtAuth` on a GRPCRoute: a call with no bearer token, or one signed by the
/// right key but with the wrong issuer, is rejected — the proxy's 401 surfaces
/// as gRPC `Unauthenticated` (#441 gRPC sad path). The backend must never be
/// reached.
#[tokio::test]
async fn grpc_route_jwt_auth_rejects_missing_or_invalid_token() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "grpc-jwtauth-bad").await?;
    fixtures::apply_fixture(backends::GRPC_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["grpc-echo"]).await?;
    fixtures::apply_fixture(gwa::GRPC_JWT_AUTH, FixtureVars::new(&ns.name)).await?;

    let host = format!("grpc-jwtauth.{}.local", ns.name);
    let gw_addr = h.gateway_http_addr(&ns.name).await?;

    // Poll until the call is rejected with Unauthenticated (401). Unimplemented
    // (404, route not yet live) does not match, so this waits for the route to
    // be live AND the JWT check to fire.
    wait::poll_until(
        Duration::from_secs(60),
        Duration::from_millis(500),
        || async { format!("gRPC Echo via {host} with no token to be Unauthenticated") },
        || async {
            match grpc_echo_call_with_bearer(gw_addr, &host, None).await {
                Err(s) if s.code() == tonic::Code::Unauthenticated => Some(()),
                _ => None,
            }
        },
    )
    .await?;

    // A wrong-issuer token must also be rejected — proves the check inspects
    // the token, not merely its presence.
    let wrong_issuer = coxswain_e2e::jwt::wrong_issuer_token();
    match grpc_echo_call_with_bearer(gw_addr, &host, Some(&wrong_issuer)).await {
        Err(s) if s.code() == tonic::Code::Unauthenticated => {}
        other => anyhow::bail!("expected Unauthenticated for a wrong-issuer token, got {other:?}"),
    }
    Ok(())
}

// ── External auth (ext_authz HTTP) ───────────────────────────────────────────

/// `auth-url` allow path: the auth stub returns 200 → proxy forwards the request
/// to the upstream backend (#24 happy path).
#[tokio::test]
async fn request_allowed_when_ext_authz_returns_2xx() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "auth-ok").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::AUTH_STUB, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_AUTH_EXT_ALLOW,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let host = format!("authextallow.{}.local", ns.name);

    // Poll until the route is live with a 200: both the route and auth-allow Pod
    // must be ready. auth-allow returns 200 → proxy allows → echo-a responds.
    let resp = wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(90)).await?;
    resp.assert_backend("echo-a");
    Ok(())
}

/// `auth-url` deny path: the auth stub returns 403 → proxy returns 403 to the
/// client, backend never reached (#24 sad path).
#[tokio::test]
async fn request_rejected_with_auth_status_when_ext_authz_denies() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "auth-deny").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::AUTH_STUB, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_AUTH_EXT_DENY,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let host = format!("authextdeny.{}.local", ns.name);

    // Poll until we see 403: route programmed and auth-deny Pod ready.
    // 404 = not yet programmed; 503 = auth-deny Pod not ready yet; keep polling.
    // The busybox nc stub is one-shot per invocation so we rely on poll success
    // as the assertion — a single 403 proves the proxy forwarded the deny status.
    wait::wait_for_route_status(&h.http, &host, "/", 403, Duration::from_secs(90)).await?;
    Ok(())
}

/// `auth-timeout`: when the auth sub-request exceeds `auth-timeout`, the proxy
/// returns 503 and never reaches the upstream backend (#24 sad path).
#[tokio::test]
async fn request_rejected_when_ext_authz_times_out() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "auth-timeout").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::SLOW_ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(ingress::ANNOTATION_AUTH_TIMEOUT, FixtureVars::new(&ns.name)).await?;
    let host = format!("authtimeout.{}.local", ns.name);

    // Each poll attempt takes ≥500ms (auth-timeout fires), so the 90s deadline
    // gives ample room for slow-echo to start and the route to be installed.
    // 404 = not yet programmed; 200 would be wrong (auth must timeout); target is 503.
    wait::wait_for_route_status(&h.http, &host, "/", 503, Duration::from_secs(90)).await?;
    Ok(())
}

/// `ext-auth-fail-closed: "false"`: when the auth service is unreachable (times
/// out), the proxy fails **open** and forwards the request to the upstream
/// unauthorized instead of returning 503 (#23 happy path — the fail-open
/// opt-in). Mirror of `request_rejected_when_ext_authz_times_out`, which fails
/// closed by default.
#[tokio::test]
async fn request_allowed_when_ext_auth_times_out_and_fail_open() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "auth-fail-open").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::SLOW_ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_AUTH_FAIL_OPEN,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let host = format!("authfailopen.{}.local", ns.name);

    // The auth check to slow-echo times out at 500ms; fail-closed=false means the
    // request then proceeds to echo-a rather than 503. Assert it reaches the backend.
    let resp = wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(90)).await?;
    resp.assert_backend("echo-a");
    Ok(())
}

/// `ext-auth-protocol: grpc` allow path (#23): the Ingress ext-auth check speaks
/// the Envoy `envoy.service.auth.v3` proto; a request with `x-ext-authz: allow`
/// is allowed to the backend. This is the e2e effect test for the
/// `ext-auth-protocol` annotation.
#[tokio::test]
async fn request_allowed_when_ext_authz_grpc_allows() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "auth-grpc-ok").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::EXT_AUTHZ_GRPC, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(ingress::ANNOTATION_AUTH_GRPC, FixtureVars::new(&ns.name)).await?;
    let host = format!("authgrpc.{}.local", ns.name);

    wait::poll_until(
        Duration::from_secs(120),
        wait::POLL,
        || async { format!("Ingress gRPC ext_authz to allow x-ext-authz:allow at {host}") },
        || async {
            match h
                .http
                .get_full_with_headers(&host, "/", &[("x-ext-authz", "allow")])
                .await
            {
                Ok((200, _, Some(body))) => Some(body),
                _ => None,
            }
        },
    )
    .await?
    .assert_backend("echo-a");
    Ok(())
}

/// `ext-auth-protocol: grpc` deny path (#23): a request WITHOUT `x-ext-authz:
/// allow` is denied by the gRPC auth service → 403, backend never reached.
#[tokio::test]
async fn request_denied_when_ext_authz_grpc_denies() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "auth-grpc-deny").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::EXT_AUTHZ_GRPC, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(ingress::ANNOTATION_AUTH_GRPC, FixtureVars::new(&ns.name)).await?;
    let host = format!("authgrpc.{}.local", ns.name);

    wait::wait_for_route_status(&h.http, &host, "/", 403, Duration::from_secs(120)).await?;
    Ok(())
}

/// gRPC ext_authz channel pooling (#544 happy path): once the pooled channel to
/// `ext-authz-grpc` is warm, many sequential checks all succeed. Before pooling,
/// each check dialled a fresh TCP+HTTP/2 connection per request; a regression
/// that leaks/corrupts the pooled channel after first use would surface here as
/// a later request timing out or failing to connect.
#[tokio::test]
async fn request_allowed_when_ext_authz_grpc_channel_reused_across_requests() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "auth-grpc-reuse").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::EXT_AUTHZ_GRPC, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(ingress::ANNOTATION_AUTH_GRPC, FixtureVars::new(&ns.name)).await?;
    let host = format!("authgrpc.{}.local", ns.name);

    // Establish the route first — the pool's cold-start (first dial) is not
    // what this test targets; the reuse path after that is.
    wait::poll_until(
        Duration::from_secs(120),
        wait::POLL,
        || async { format!("Ingress gRPC ext_authz to allow x-ext-authz:allow at {host}") },
        || async {
            match h
                .http
                .get_full_with_headers(&host, "/", &[("x-ext-authz", "allow")])
                .await
            {
                Ok((200, _, Some(body))) => Some(body),
                _ => None,
            }
        },
    )
    .await?
    .assert_backend("echo-a");

    for i in 0..30u32 {
        let (status, _, body) = h
            .http
            .get_full_with_headers(&host, "/", &[("x-ext-authz", "allow")])
            .await?;
        anyhow::ensure!(status == 200, "request {i}: expected 200, got {status}");
        body.ok_or_else(|| anyhow::anyhow!("request {i}: 200 with no parseable body"))?
            .assert_backend("echo-a");
    }
    Ok(())
}

/// gRPC ext_authz channel pooling (#544 sad path): `kubectl rollout restart`
/// replaces `ext-authz-grpc` with a new pod at a new `SocketAddr` (endpoint
/// churn, not a same-address reconnect — pod IPs are not reused). Reconcile
/// updates `ExtAuthConfig.endpoints`, so the round-robin picker must move on to
/// the new address; the pool's `SocketAddr`-keyed design means the old, now-dead
/// entry is simply never selected again (no explicit invalidation exists or is
/// needed — see `crate::policy::grpc_channel`'s module doc). A regression that
/// left the picker or the cache pinned to the stale endpoint would fail every
/// check closed (`failClosed` defaults true) instead of recovering.
#[tokio::test]
async fn request_recovers_after_ext_authz_grpc_pod_restart() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "auth-grpc-restart").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::EXT_AUTHZ_GRPC, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(ingress::ANNOTATION_AUTH_GRPC, FixtureVars::new(&ns.name)).await?;
    let host = format!("authgrpc.{}.local", ns.name);

    wait::poll_until(
        Duration::from_secs(120),
        wait::POLL,
        || async { format!("Ingress gRPC ext_authz to allow x-ext-authz:allow at {host}") },
        || async {
            match h
                .http
                .get_full_with_headers(&host, "/", &[("x-ext-authz", "allow")])
                .await
            {
                Ok((200, _, Some(body))) => Some(body),
                _ => None,
            }
        },
    )
    .await?
    .assert_backend("echo-a");

    // Fixture Deployment is namespace-scoped and owned exclusively by this
    // test's namespace — safe in the parallel pass (see common::rollout).
    common::rollout::rollout_restart_deployment(&ns.name, "ext-authz-grpc").await?;

    // Allow still allows (reconnect to the replacement pod), and deny still
    // denies — the pool did not wedge open or leave a stale allow/deny cached.
    wait::poll_until(
        Duration::from_secs(120),
        wait::POLL,
        || async { format!("gRPC ext_authz to recover after auth-pod restart at {host}") },
        || async {
            match h
                .http
                .get_full_with_headers(&host, "/", &[("x-ext-authz", "allow")])
                .await
            {
                Ok((200, _, Some(body))) => Some(body),
                _ => None,
            }
        },
    )
    .await?
    .assert_backend("echo-a");

    wait::wait_for_route_status(&h.http, &host, "/", 403, Duration::from_secs(90)).await?;
    Ok(())
}

/// `auth-response-headers`: when auth allows (2xx), the named response headers
/// from the auth service are forwarded to the upstream on the request (#24).
#[tokio::test]
async fn upstream_receives_auth_response_headers_when_configured() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "auth-hdrs").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::AUTH_STUB, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_AUTH_RESPONSE_HEADERS,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let host = format!("authhdr.{}.local", ns.name);

    // auth-allow returns X-Auth-User: testuser; the Ingress annotation lists it in
    // auth-response-headers; the proxy injects it into the upstream request.
    // echo-a reflects all request headers in the JSON body.
    let resp = wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(90)).await?;
    let auth_user = resp
        .headers
        .get("X-Auth-User")
        .and_then(|v| v[0].as_str())
        .unwrap_or("");
    anyhow::ensure!(
        auth_user == "testuser",
        "expected upstream to receive X-Auth-User: testuser from auth response, got: {auth_user:?}"
    );
    Ok(())
}

/// `auth-always-set-cookie`: when auth denies and `auth-always-set-cookie: "true"`,
/// the proxy forwards `Set-Cookie` from the auth deny response to the client (#24).
#[tokio::test]
async fn set_cookie_forwarded_on_deny_when_auth_always_set_cookie() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "auth-cookie").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::AUTH_STUB, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_AUTH_ALWAYS_SET_COOKIE,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let host = format!("authcookie.{}.local", ns.name);

    // Poll until the route returns 403 AND Set-Cookie: session=test123 is present.
    // auth-deny returns one response per nc invocation, then nc restarts (small gap).
    // Polling the combined condition avoids a second serial request hitting the
    // restart window when the cluster is under load.
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async { format!("route {host}/ to return 403 with Set-Cookie: session=test123") },
        || async {
            match h.http.get_full(&host, "/").await {
                Ok((403, hdrs, _)) => {
                    let cookie = hdrs
                        .get(reqwest::header::SET_COOKIE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    if cookie.contains("session=test123") {
                        Some(())
                    } else {
                        None
                    }
                }
                _ => None,
            }
        },
    )
    .await?;
    Ok(())
}

// ── Basic auth (htpasswd) ─────────────────────────────────────────────────────

/// `auth-basic-secret` with a bcrypt entry: a request carrying the correct
/// `Authorization: Basic` credentials is admitted (200) (#24 happy path).
#[tokio::test]
async fn request_allowed_when_basic_auth_bcrypt_credential_valid() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "auth-bcrypt").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(ingress::AUTH_BASIC_SECRET, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(ingress::ANNOTATION_AUTH_BASIC, FixtureVars::new(&ns.name)).await?;
    let host = format!("authbasic.{}.local", ns.name);

    // alice:secret (bcrypt) → Authorization: Basic YWxpY2U6c2VjcmV0.
    // Poll until 200: route programmed + Secret resolved + bcrypt verify passes.
    // bcrypt may take several hundred ms in spawn_blocking → generous deadline.
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async { format!("basic auth route to admit alice:secret (bcrypt) at {host}") },
        || async {
            let result = h
                .http
                .get_full_with_headers(&host, "/", &[("authorization", "Basic YWxpY2U6c2VjcmV0")])
                .await;
            match result {
                Ok((200, _, Some(body))) => Some(body),
                _ => None,
            }
        },
    )
    .await?
    .assert_backend("echo-a");
    Ok(())
}

/// `auth-basic-secret` with a SHA1 entry: a request carrying the correct
/// `Authorization: Basic` credentials is admitted (200) (#24 happy path).
#[tokio::test]
async fn request_allowed_when_basic_auth_sha1_credential_valid() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "auth-sha1").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(ingress::AUTH_BASIC_SECRET, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(ingress::ANNOTATION_AUTH_BASIC, FixtureVars::new(&ns.name)).await?;
    let host = format!("authbasic.{}.local", ns.name);

    // bob:secret (SHA1) → Authorization: Basic Ym9iOnNlY3JldA==.
    // Poll until 200: route programmed + Secret resolved + SHA1 verify passes.
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async { format!("basic auth route to admit bob:secret (SHA1) at {host}") },
        || async {
            let result = h
                .http
                .get_full_with_headers(&host, "/", &[("authorization", "Basic Ym9iOnNlY3JldA==")])
                .await;
            match result {
                Ok((200, _, Some(body))) => Some(body),
                _ => None,
            }
        },
    )
    .await?
    .assert_backend("echo-a");
    Ok(())
}

/// `auth-basic-secret`: a request with wrong credentials is rejected with
/// 401 + `WWW-Authenticate` (#24 sad path — invalid credentials).
#[tokio::test]
async fn request_rejected_when_basic_auth_credentials_invalid() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "auth-bad").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(ingress::AUTH_BASIC_SECRET, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(ingress::ANNOTATION_AUTH_BASIC, FixtureVars::new(&ns.name)).await?;
    let host = format!("authbasic.{}.local", ns.name);

    // Wait until the route is programmed and basic auth is active:
    // a request without credentials should return 401 (challenge), not 404.
    wait::wait_for_route_status(&h.http, &host, "/", 401, Duration::from_secs(90)).await?;

    // wrong:password → Authorization: Basic d3Jvbmc6cGFzc3dvcmQ=
    // Must return 401 + WWW-Authenticate; backend must not be reached.
    let (status, resp_hdrs, _) = h
        .http
        .get_full_with_headers(
            &host,
            "/",
            &[("authorization", "Basic d3Jvbmc6cGFzc3dvcmQ=")],
        )
        .await?;
    anyhow::ensure!(
        status == 401,
        "expected 401 for wrong credentials, got {status}"
    );
    anyhow::ensure!(
        resp_hdrs.contains_key(reqwest::header::WWW_AUTHENTICATE),
        "expected WWW-Authenticate header in 401 response; got: {resp_hdrs:?}"
    );
    Ok(())
}

/// `auth-basic-secret` pointing at an UNLABELED Secret: the reflector never
/// includes it, so the proxy fails closed with 503 — even valid credentials
/// are refused (#24 sad path — fail-closed label requirement).
#[tokio::test]
async fn request_rejected_when_basic_auth_secret_unlabeled() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "auth-nolabel").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        ingress::AUTH_BASIC_SECRET_UNLABELED,
        FixtureVars::new(&ns.name),
    )
    .await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_AUTH_BASIC_UNLABELED,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let host = format!("authunlabeled.{}.local", ns.name);

    // Route programmed with IngressAuthConfig::Unavailable → always 503.
    // Even alice:secret (valid creds) must be refused before the Secret is read.
    wait::wait_for_route_status(&h.http, &host, "/", 503, Duration::from_secs(90)).await?;

    // Confirm even valid credentials return 503 (proxy never consults the Secret).
    let status = h.http.get_status(&host, "/").await?;
    anyhow::ensure!(
        status == 503,
        "expected 503 (fail-closed: unlabeled secret), got {status}"
    );
    Ok(())
}

// ── BasicAuth ExtensionRef (Gateway API, #442) ────────────────────────────────

/// `BasicAuth` CR via `ExtensionRef`: a request carrying valid `Authorization:
/// Basic` credentials is admitted (200) (#442 happy path — also proves the
/// ExtensionRef is accepted on HTTPRoute).
#[tokio::test]
async fn gateway_basic_auth_valid_credential_admitted() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-basicauth-ok").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(gwa::BASIC_AUTH_EXTENSIONREF, FixtureVars::new(&ns.name)).await?;
    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwbasicauth.{}.local", ns.name);

    // alice:secret (bcrypt) → Authorization: Basic YWxpY2U6c2VjcmV0.
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async { format!("gateway BasicAuth route to admit alice:secret at {host}") },
        || async {
            let result = gw
                .get_full_with_headers(&host, "/", &[("authorization", "Basic YWxpY2U6c2VjcmV0")])
                .await;
            match result {
                Ok((200, _, Some(body))) => Some(body),
                _ => None,
            }
        },
    )
    .await?
    .assert_backend("echo-a");
    Ok(())
}

/// `BasicAuth` CR via `ExtensionRef`: a request with wrong credentials is
/// rejected with 401 + `WWW-Authenticate` (#442 sad path — invalid credentials).
#[tokio::test]
async fn gateway_basic_auth_invalid_credential_rejected() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-basicauth-bad").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(gwa::BASIC_AUTH_EXTENSIONREF, FixtureVars::new(&ns.name)).await?;
    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwbasicauth.{}.local", ns.name);

    // Wait until the route is live and enforcing: no credentials → 401 (not 404).
    wait::wait_for_route_status(&gw, &host, "/", 401, Duration::from_secs(90)).await?;

    // wrong:password → Authorization: Basic d3Jvbmc6cGFzc3dvcmQ=
    let (status, resp_hdrs, _) = gw
        .get_full_with_headers(
            &host,
            "/",
            &[("authorization", "Basic d3Jvbmc6cGFzc3dvcmQ=")],
        )
        .await?;
    anyhow::ensure!(
        status == 401,
        "expected 401 for wrong credentials, got {status}"
    );
    anyhow::ensure!(
        resp_hdrs.contains_key(reqwest::header::WWW_AUTHENTICATE),
        "expected WWW-Authenticate header in 401 response; got: {resp_hdrs:?}"
    );
    Ok(())
}

/// `BasicAuth` CR referencing an UNLABELED Secret: the reflector never loads
/// it, so the proxy fails closed with 503 — even valid credentials are refused
/// (#442 sad path — fail-closed label requirement).
#[tokio::test]
async fn gateway_basic_auth_unlabeled_secret_fails_closed() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-basicauth-nolabel").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        gwa::BASIC_AUTH_EXTENSIONREF_UNLABELED,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwbasicauthnolabel.{}.local", ns.name);

    wait::wait_for_route_status(&gw, &host, "/", 503, Duration::from_secs(90)).await?;

    // Confirm even valid credentials return 503 (proxy never consults the Secret).
    let status = gw.get_status(&host, "/").await?;
    anyhow::ensure!(
        status == 503,
        "expected 503 (fail-closed: unlabeled secret), got {status}"
    );
    Ok(())
}

/// Cross-namespace `BasicAuth` secretRef requires a ReferenceGrant (#520): with a
/// matching `BasicAuth → Secret` grant the cross-ns htpasswd Secret resolves and
/// valid credentials are admitted (200). Deleting the grant makes the ref fail
/// closed (503) even for valid credentials — a tenant cannot bind another
/// namespace's auth Secret without permission.
#[tokio::test]
async fn gateway_basic_auth_cross_namespace_requires_reference_grant() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-basicauth-xns").await?;
    let tenant = NamespaceGuard::create(&h.client, "gw-basicauth-xns-tenant").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    // Tenant ns: htpasswd Secret + a BasicAuth→Secret ReferenceGrant permitting ns.
    fixtures::apply_fixture(
        gwa::BASIC_AUTH_XNS_TENANT,
        FixtureVars::new(&tenant.name).with("TESTNS", &ns.name),
    )
    .await?;

    // Route ns: Gateway + BasicAuth CR (secretRef → tenant) + HTTPRoute.
    fixtures::apply_fixture(
        gwa::BASIC_AUTH_XNS_ROUTE,
        FixtureVars::new(&ns.name).with("TENANTNS", &tenant.name),
    )
    .await?;

    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwbasicauthxns.{}.local", ns.name);

    // Happy: with the grant in place, valid creds (alice:secret) are admitted.
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async { format!("cross-ns BasicAuth to admit alice:secret at {host}") },
        || async {
            match gw
                .get_full_with_headers(&host, "/", &[("authorization", "Basic YWxpY2U6c2VjcmV0")])
                .await
            {
                Ok((200, _, Some(body))) => Some(body),
                _ => None,
            }
        },
    )
    .await?
    .assert_backend("echo-a");

    // Sad: delete the ReferenceGrant → the cross-ns secretRef fails closed (503),
    // even for valid credentials. Proves the grant is load-bearing, not decorative.
    let grant_name = format!("allow-basicauth-from-{}", ns.name);
    let deleted = tokio::process::Command::new("kubectl")
        .args([
            "delete",
            "referencegrant",
            &grant_name,
            "-n",
            &tenant.name,
            "--ignore-not-found",
        ])
        .status()
        .await
        .map_err(|e| anyhow::anyhow!("delete ReferenceGrant: {e}"))?;
    anyhow::ensure!(deleted.success(), "kubectl delete referencegrant failed");

    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            format!("cross-ns BasicAuth to fail closed (503) after grant deletion at {host}")
        },
        || async {
            match gw
                .get_full_with_headers(&host, "/", &[("authorization", "Basic YWxpY2U6c2VjcmV0")])
                .await
            {
                Ok((503, _, _)) => Some(()),
                _ => None,
            }
        },
    )
    .await?;

    Ok(())
}

// ── JwtAuth ExtensionRef (Gateway API, #441) ──────────────────────────────────

/// `JwtAuth` CR via `ExtensionRef`: a request carrying a valid, signed,
/// unexpired, correct-issuer bearer token is admitted (200), and the verified
/// `sub` claim is forwarded to the backend as `x-user-id` (#441 happy path —
/// also proves the ExtensionRef is accepted on HTTPRoute and claim forwarding
/// works end to end).
#[tokio::test]
async fn gateway_jwt_auth_valid_token_admitted() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-jwtauth-ok").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(gwa::JWT_AUTH_EXTENSIONREF, FixtureVars::new(&ns.name)).await?;
    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwjwtauth.{}.local", ns.name);
    let token = coxswain_e2e::jwt::valid_token();
    let bearer = format!("Bearer {token}");

    let resp = wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async { format!("gateway JwtAuth route to admit a valid token at {host}") },
        || async {
            let result = gw
                .get_full_with_headers(&host, "/", &[("authorization", &bearer)])
                .await;
            match result {
                Ok((200, _, Some(body))) => Some(body),
                _ => None,
            }
        },
    )
    .await?;
    resp.assert_backend("echo-a");
    let forwarded = resp
        .headers
        .get("x-user-id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    anyhow::ensure!(
        forwarded == "e2e-test-user",
        "expected the verified `sub` claim forwarded as x-user-id=e2e-test-user, got '{forwarded}'"
    );
    Ok(())
}

/// `JwtAuth` CR via `ExtensionRef`: a request with no bearer token is rejected
/// with 401 + `WWW-Authenticate: Bearer` (#441 sad path — missing credential).
/// The backend must never be reached.
#[tokio::test]
async fn gateway_jwt_auth_missing_token_rejected() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-jwtauth-missing").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(gwa::JWT_AUTH_EXTENSIONREF, FixtureVars::new(&ns.name)).await?;
    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwjwtauth.{}.local", ns.name);

    // Wait until the route is live and enforcing: no token → 401 (not 404).
    wait::wait_for_route_status(&gw, &host, "/", 401, Duration::from_secs(90)).await?;

    let (status, resp_hdrs, _) = gw.get_full(&host, "/").await?;
    anyhow::ensure!(
        status == 401,
        "expected 401 for a missing token, got {status}"
    );
    anyhow::ensure!(
        resp_hdrs.contains_key(reqwest::header::WWW_AUTHENTICATE),
        "expected WWW-Authenticate header in 401 response; got: {resp_hdrs:?}"
    );

    // A wrong-issuer token and an expired token must also be rejected — proves
    // the check inspects the token, not merely its presence.
    for (label, token) in [
        ("wrong issuer", coxswain_e2e::jwt::wrong_issuer_token()),
        ("expired", coxswain_e2e::jwt::expired_token()),
    ] {
        let bearer = format!("Bearer {token}");
        let (status, _, _) = gw
            .get_full_with_headers(&host, "/", &[("authorization", &bearer)])
            .await?;
        anyhow::ensure!(
            status == 401,
            "expected 401 for a {label} token, got {status}"
        );
    }
    Ok(())
}

// ── auth-jwt annotation (Ingress, #441) ───────────────────────────────────────

/// `ingress.coxswain-labs.dev/auth-jwt` naming a `JwtAuth` CR: a request
/// carrying a valid, signed, unexpired, correct-issuer bearer token is
/// admitted (200), with the verified `sub` claim forwarded as `x-user-id`
/// (#441 happy path — Ingress parity with the HTTPRoute ExtensionRef).
#[tokio::test]
async fn ingress_jwt_auth_valid_token_admitted() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-jwtauth-ok").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(ingress::ANNOTATION_AUTH_JWT, FixtureVars::new(&ns.name)).await?;
    let host = format!("authjwt.{}.local", ns.name);
    let token = coxswain_e2e::jwt::valid_token();
    let bearer = format!("Bearer {token}");

    let resp = wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async { format!("Ingress auth-jwt route to admit a valid token at {host}") },
        || async {
            let result = h
                .http
                .get_full_with_headers(&host, "/", &[("authorization", &bearer)])
                .await;
            match result {
                Ok((200, _, Some(body))) => Some(body),
                _ => None,
            }
        },
    )
    .await?;
    resp.assert_backend("echo-a");
    let forwarded = resp
        .headers
        .get("x-user-id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    anyhow::ensure!(
        forwarded == "e2e-test-user",
        "expected the verified `sub` claim forwarded as x-user-id=e2e-test-user, got '{forwarded}'"
    );
    Ok(())
}

/// `auth-jwt`: a request with no bearer token is rejected with 401 +
/// `WWW-Authenticate: Bearer`; a wrong-issuer or expired token is rejected the
/// same way (#441 sad path). The backend must never be reached.
#[tokio::test]
async fn ingress_jwt_auth_invalid_token_rejected() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-jwtauth-bad").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(ingress::ANNOTATION_AUTH_JWT, FixtureVars::new(&ns.name)).await?;
    let host = format!("authjwt.{}.local", ns.name);

    // Wait until the route is live and enforcing: no token → 401 (not 404).
    wait::wait_for_route_status(&h.http, &host, "/", 401, Duration::from_secs(90)).await?;

    let (status, resp_hdrs, _) = h.http.get_full(&host, "/").await?;
    anyhow::ensure!(
        status == 401,
        "expected 401 for a missing token, got {status}"
    );
    anyhow::ensure!(
        resp_hdrs.contains_key(reqwest::header::WWW_AUTHENTICATE),
        "expected WWW-Authenticate header in 401 response; got: {resp_hdrs:?}"
    );

    for (label, token) in [
        ("wrong issuer", coxswain_e2e::jwt::wrong_issuer_token()),
        ("expired", coxswain_e2e::jwt::expired_token()),
    ] {
        let bearer = format!("Bearer {token}");
        let (status, _, _) = h
            .http
            .get_full_with_headers(&host, "/", &[("authorization", &bearer)])
            .await?;
        anyhow::ensure!(
            status == 401,
            "expected 401 for a {label} token, got {status}"
        );
    }
    Ok(())
}

// ── CoxswainExternalAuth ExtensionRef + Gateway policy (Gateway API, #23) ─────

/// `CoxswainExternalAuth` via `ExtensionRef`: the ext_authz service allows (200),
/// so the request reaches the backend (#23 happy path — also proves the
/// `ExternalAuth` ExtensionRef kind is accepted on HTTPRoute).
#[tokio::test]
async fn gateway_external_auth_extensionref_allows_when_authz_2xx() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-extauth-ok").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::AUTH_STUB, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(gwa::EXTERNAL_AUTH_ROUTE_ALLOW, FixtureVars::new(&ns.name)).await?;
    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwextauthallow.{}.local", ns.name);

    // The route + auth-allow Pod must both be ready; auth-allow returns 200 → the
    // proxy allows → echo-a responds. 404 = not programmed; 503 = auth Pod not ready.
    let resp = wait::wait_for_route(&gw, &host, "/", Duration::from_secs(90)).await?;
    resp.assert_backend("echo-a");
    Ok(())
}

/// `CoxswainExternalAuth` via `ExtensionRef`: the ext_authz service denies (403),
/// so the proxy returns 403 and the backend is never reached (#23 sad path).
#[tokio::test]
async fn gateway_external_auth_extensionref_denies_when_authz_403() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-extauth-deny").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::AUTH_STUB, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(gwa::EXTERNAL_AUTH_ROUTE_DENY, FixtureVars::new(&ns.name)).await?;
    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwextauthdeny.{}.local", ns.name);

    // 404 = not yet programmed; a single 403 proves the proxy forwarded the deny.
    wait::wait_for_route_status(&gw, &host, "/", 403, Duration::from_secs(90)).await?;
    Ok(())
}

/// Gateway-attached `CoxswainExternalAuth` mandate (`targetRefs`): every route on
/// the Gateway is subject to the check even with no route-level filter, so a route
/// pointed at a denying auth service returns 403 (#23 — the Gateway policy surface).
#[tokio::test]
async fn gateway_external_auth_policy_applies_to_route_without_filter() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-extauth-mandate").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::AUTH_STUB, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        gwa::EXTERNAL_AUTH_GATEWAY_ADDITIVE,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let gw = h.gateway_http(&ns.name).await?;
    // This route carries NO ExtensionRef filter — the Gateway-level mandate alone
    // (auth-deny) must deny it.
    let host = format!("gwextauthmandate.{}.local", ns.name);

    wait::wait_for_route_status(&gw, &host, "/", 403, Duration::from_secs(90)).await?;
    Ok(())
}

/// Additive precedence (GEP-713 override posture): a route whose OWN `ExtensionRef`
/// would allow is still denied because the Gateway-attached mandate is prepended
/// and both checks run — a route cannot weaken a Gateway-level auth mandate (#23).
#[tokio::test]
async fn gateway_external_auth_policy_is_additive_and_cannot_be_removed() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-extauth-additive").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::AUTH_STUB, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        gwa::EXTERNAL_AUTH_GATEWAY_ADDITIVE,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let gw = h.gateway_http(&ns.name).await?;
    // This route's ExtensionRef points at auth-allow (would pass on its own), but
    // the Gateway mandate (auth-deny) runs first and denies → 403, proving the
    // mandate is additive and not removable from below.
    let host = format!("gwextauthadditive.{}.local", ns.name);

    wait::wait_for_route_status(&gw, &host, "/", 403, Duration::from_secs(90)).await?;
    Ok(())
}

/// gRPC ext_authz transport (#23 happy path): the proxy speaks the Envoy
/// `envoy.service.auth.v3` Check proto to the auth pod. A request carrying
/// `x-ext-authz: allow` is allowed → echo-a.
#[tokio::test]
async fn gateway_external_auth_grpc_allows_with_header() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-extauth-grpc-ok").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::EXT_AUTHZ_GRPC, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(gwa::EXTERNAL_AUTH_GRPC, FixtureVars::new(&ns.name)).await?;
    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwextauthgrpc.{}.local", ns.name);

    // Route + ext-authz gRPC Pod must be ready; `x-ext-authz: allow` → allow → echo-a.
    wait::poll_until(
        Duration::from_secs(120),
        wait::POLL,
        || async { format!("gRPC ext_authz to allow x-ext-authz:allow at {host}") },
        || async {
            match gw
                .get_full_with_headers(&host, "/", &[("x-ext-authz", "allow")])
                .await
            {
                Ok((200, _, Some(body))) => Some(body),
                _ => None,
            }
        },
    )
    .await?
    .assert_backend("echo-a");
    Ok(())
}

/// gRPC ext_authz transport (#23 sad path): a request WITHOUT `x-ext-authz: allow`
/// is denied by the auth service (PermissionDenied) → the proxy returns 403 and
/// the backend is never reached.
#[tokio::test]
async fn gateway_external_auth_grpc_denies_without_header() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-extauth-grpc-deny").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(backends::EXT_AUTHZ_GRPC, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(gwa::EXTERNAL_AUTH_GRPC, FixtureVars::new(&ns.name)).await?;
    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwextauthgrpc.{}.local", ns.name);

    // No `x-ext-authz` header → the gRPC auth service denies → 403 (404 while the
    // route is not yet programmed; 503 while the auth Pod is not ready — keep polling).
    wait::wait_for_route_status(&gw, &host, "/", 403, Duration::from_secs(120)).await?;
    Ok(())
}

// ── Per-Ingress client-certificate mTLS (#267) ───────────────────────────────

/// `auth-tls-secret` + `auth-tls-pass-certificate-to-upstream`: a TLS connection
/// presenting a valid client certificate (signed by the configured CA) is admitted
/// (200) and the verified cert is forwarded to the backend as `X-SSL-Client-Cert`
/// (#267 happy path).
#[tokio::test]
async fn client_cert_mtls_valid_cert_forwarded_to_backend() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "mtls-valid").await?;

    // Generate a fresh CA + client leaf pair (CA-signed, clientAuth EKU).
    let mtls = MtlsCerts::generate();
    // Generate a self-signed server certificate for the TLS listener.
    let server_cert = GeneratedCert::for_host(&format!("mtls.{}.local", ns.name));

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    // Apply the CA Secret first so the reflector can resolve it before the Ingress lands.
    fixtures::apply_fixture(
        ingress::AUTH_TLS_CA_SECRET,
        FixtureVars::new(&ns.name).with("CA_CRT_B64", mtls.ca_cert_b64()),
    )
    .await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_AUTH_TLS,
        FixtureVars::new(&ns.name)
            .with("SECRET_NAME", "mtls-server-cert")
            .with("TLS_CRT_B64", server_cert.cert_b64())
            .with("TLS_KEY_B64", server_cert.key_b64()),
    )
    .await?;

    let host = format!("mtls.{}.local", ns.name);

    // Poll until the mTLS-protected route admits the valid client cert and routes to
    // echo-a.  This also confirms the CA Secret has been reconciled into the proxy's
    // ClientCertStore.  Before the CA arrives the route is either absent (404) or
    // returns a non-2xx; once the CA is applied the handshake succeeds and we get a
    // 2xx echo body.
    let resp = wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async { format!("mTLS route {host}/ to admit a valid client cert (200 echo body)") },
        || async {
            match https_get_with_client_cert(
                &host,
                "/",
                h.tls_addr,
                &mtls.client_cert_pem,
                &mtls.client_key_pem,
            )
            .await
            {
                Ok((_, Some(body))) => Some(body),
                _ => None,
            }
        },
    )
    .await?;

    resp.assert_backend("echo-a");

    // The proxy must forward the verified cert as X-SSL-Client-Cert when
    // auth-tls-pass-certificate-to-upstream is "true".
    anyhow::ensure!(
        resp.headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("x-ssl-client-cert")),
        "expected X-SSL-Client-Cert header in echo response \
         (auth-tls-pass-certificate-to-upstream=true); \
         got headers: {:?}",
        resp.headers.keys().collect::<Vec<_>>()
    );

    Ok(())
}

/// `auth-tls-secret`: a TLS connection that presents **no** client certificate is
/// rejected at the TLS handshake — the server aborts before the HTTP layer is ever
/// reached (#267 sad path — Istio MUTUAL model, no HTTP 400).
#[tokio::test]
async fn client_cert_mtls_missing_cert_rejected_at_handshake() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "mtls-nocert").await?;

    let mtls = MtlsCerts::generate();
    let server_cert = GeneratedCert::for_host(&format!("mtls.{}.local", ns.name));

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        ingress::AUTH_TLS_CA_SECRET,
        FixtureVars::new(&ns.name).with("CA_CRT_B64", mtls.ca_cert_b64()),
    )
    .await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_AUTH_TLS,
        FixtureVars::new(&ns.name)
            .with("SECRET_NAME", "mtls-server-cert")
            .with("TLS_CRT_B64", server_cert.cert_b64())
            .with("TLS_KEY_B64", server_cert.key_b64()),
    )
    .await?;

    let host = format!("mtls.{}.local", ns.name);

    // Wait until the CA Secret is reconciled and mTLS is active on this host: a valid
    // client cert must be accepted (200).  This is the reliable pre-condition before
    // testing the negative — we know the handshake policy is enforced.
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async {
            format!("mTLS route {host}/ to be active (valid cert accepted, CA reconciled)")
        },
        || async {
            match https_get_with_client_cert(
                &host,
                "/",
                h.tls_addr,
                &mtls.client_cert_pem,
                &mtls.client_key_pem,
            )
            .await
            {
                Ok((_, Some(_))) => Some(()),
                _ => None,
            }
        },
    )
    .await?;

    // Now attempt without a client certificate.  The server must abort the TLS
    // handshake (BoringSSL SslVerifyMode::FAIL_IF_NO_PEER_CERT), so reqwest returns
    // an error before any HTTP response can be decoded.  The backend is never hit.
    let result = https_get(&host, "/", h.tls_addr).await;
    anyhow::ensure!(
        result.is_err(),
        "expected TLS handshake failure when no client cert is presented on mTLS host {host}; \
         got Ok: {:?}",
        result.ok()
    );

    Ok(())
}

/// No auth annotation: requests reach the backend without any credential check
/// (#24 control — auth is opt-in, not default).
#[tokio::test]
async fn request_forwarded_without_auth_when_no_annotation() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "auth-none").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;
    let host = format!("ingress.{}.local", ns.name);

    // Plain 200 — no credentials required, no auth annotation on the route.
    let resp = wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");
    Ok(())
}

// ── Header ownership (#409) ───────────────────────────────────────────────────

/// Client-injected `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Proto`, and
/// `X-Real-IP` headers are stripped before reaching the backend (#409 happy path
/// — no PROXY protocol, plain HTTP).
///
/// Any backend that trusts these headers for access-control or audit decisions
/// can be spoofed if the proxy passes them through. Coxswain must own these
/// headers and strip whatever the client sent.
#[tokio::test]
async fn client_injected_forwarding_headers_are_stripped() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "fwd-strip").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;
    let host = format!("ingress.{}.local", ns.name);

    // Wait until the route is live.
    wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;

    // Send all four spoofed forwarding headers and confirm none reach the backend.
    let (status, _resp_headers, body) = h
        .http
        .get_full_with_headers(
            &host,
            "/a",
            &[
                ("Forwarded", "for=1.2.3.4;by=evil"),
                ("X-Forwarded-For", "1.2.3.4"),
                ("X-Forwarded-Proto", "https"),
                ("X-Real-IP", "1.2.3.4"),
            ],
        )
        .await?;
    anyhow::ensure!(status == 200, "expected 200 from backend, got {status}");
    let echo = body.ok_or_else(|| anyhow::anyhow!("expected echo JSON body"))?;

    // echo-basic returns headers as Title-Case keys (Go net/http canonical form).
    for header in &[
        "Forwarded",
        "X-Forwarded-For",
        "X-Forwarded-Proto",
        "X-Real-Ip",
    ] {
        anyhow::ensure!(
            !echo.headers.contains_key(*header),
            "spoofed header {header:?} leaked through to the backend — \
             proxy must strip all client-supplied forwarding headers (issue #409)"
        );
    }
    Ok(())
}

/// Proxy-generated `Forwarded` header (derived from PROXY-protocol data) reaches
/// the backend and overrides any client-supplied spoof (#409 — strip-then-replace
/// path). Verifies the strip and the proxy-generated replacement in one assertion.
#[tokio::test]
async fn proxy_generated_forwarded_reaches_backend_and_overrides_spoof() -> anyhow::Result<()> {
    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "fwd-override").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let controller = ControllerProcess::start_with_options(ControllerOptions {
        accept_proxy_protocol: true,
        trusted_sources: vec!["0.0.0.0/0".to_string()],
        ..Default::default()
    })
    .await?;
    wait::wait_for_ready(controller.health_addr, Duration::from_secs(30)).await?;

    let host = format!("ingress.{}.local", ns.name);
    // PROXY line carries the real client IP 203.0.113.10.
    // The HTTP request also sends a spoofed Forwarded header; the proxy must strip
    // it and replace with its own value derived from the PROXY-protocol address.
    let proxy_line = "PROXY TCP4 203.0.113.10 10.0.0.1 12345 80\r\n";
    let http_req = format!(
        "GET /a HTTP/1.1\r\nHost: {host}\r\nForwarded: for=1.2.3.4;by=spoof\r\nConnection: close\r\n\r\n"
    );

    let body = wait_for_proxy_v1_status(
        controller.proxy_addr,
        proxy_line,
        &http_req,
        200,
        Duration::from_secs(60),
    )
    .await?;

    let echo: EchoResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("expected echo JSON body, got {body:?}: {e}"))?;
    echo.assert_backend("echo-a");

    // The backend must see the proxy-generated Forwarded (from PROXY-protocol data),
    // not the spoofed client value.
    // echo-basic returns headers as Title-Case keys with array values (Go net/http canonical form).
    let forwarded = echo
        .headers
        .get("Forwarded")
        .and_then(|v| v[0].as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "backend did not receive a `Forwarded` header — \
                 proxy must inject one on the PROXY-protocol path (issue #409)"
            )
        })?;
    anyhow::ensure!(
        forwarded.contains("203.0.113.10"),
        "expected proxy-generated Forwarded to contain the real client IP 203.0.113.10, \
         got {forwarded:?} — wrong value injected or PROXY-protocol data not used"
    );
    anyhow::ensure!(
        !forwarded.contains("1.2.3.4"),
        "spoofed IP 1.2.3.4 found in Forwarded header {forwarded:?} — \
         client spoof was not stripped before proxy-generated value was inserted (issue #409)"
    );

    Ok(())
}

/// A `RequestHeaderModifier` that attempts to `set` a proxy-owned forwarding header
/// must be silently ignored (#410). The strip-before-filters step (#409) removes any
/// client-supplied value; the modifier must not re-add it.
///
/// Also asserts no over-blocking: a custom header (`X-Team-Header`) in the same
/// modifier reaches the backend unchanged.
#[tokio::test]
async fn request_header_modifier_cannot_inject_blocked_forwarding_header() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sec-hdr-deny").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::FILTERS, FixtureVars::new(&ns.name)).await?;
    let gw = h.gateway_http(&ns.name).await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&gw, &host, "/filter/probe", Duration::from_secs(60)).await?;

    // `get` fails on non-2xx, so receiving an EchoResponse confirms the backend replied 200.
    let echo = gw.get(&host, "/filter/blocked-header").await?;

    // X-Forwarded-For injected by the RequestHeaderModifier must be absent —
    // the proxy denies operator-set forwarding headers to prevent trust-signal spoofing.
    anyhow::ensure!(
        !echo.headers.contains_key("X-Forwarded-For"),
        "X-Forwarded-For (value 10.0.0.1) leaked through to the backend — \
         RequestHeaderModifier must not be able to inject proxy-owned headers (#410)"
    );

    // X-Team-Header is a non-blocked custom header set in the same modifier;
    // it must reach the backend to prove the deny-list does not over-block.
    let team = echo
        .headers
        .get("X-Team-Header")
        .and_then(|v| v[0].as_str())
        .unwrap_or("");
    anyhow::ensure!(
        team == "keep-me",
        "X-Team-Header must survive RequestHeaderModifier (no over-blocking): \
         expected \"keep-me\", got {team:?} (#410)"
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
