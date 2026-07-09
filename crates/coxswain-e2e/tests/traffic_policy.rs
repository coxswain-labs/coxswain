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
//! limit-connections, mirror-target, drain-timeout, retries
//! (#263/#266/#270/#274/#275/#276/#277/#281/#282/#283/#360/#445) — each landing with
//! its feature. Retries: the `retry-attempts`/`retry-codes`/`retry-backoff` Ingress
//! annotations and the `RetryPolicy` ExtensionRef (HTTP + gRPC). Routing-shape
//! behavior lives in `routing.rs`; TLS in `tls.rs`.

use coxswain_e2e::{
    FixtureVars, Harness, IngressClassGuard, NamespaceGuard,
    fixtures::{self, backends, gateway_api as gwa, ingress},
    harness::wait,
};
use reqwest::Method;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

// ── Circuit-breaker helpers ───────────────────────────────────────────────────
//
// go-httpbin's `/status/:code` responses may carry a non-echo-format body.
// The shared `HttpClient` tries to deserialise 200 responses as `EchoResponse`
// JSON, which would fail for go-httpbin. These helpers use a plain `reqwest`
// client so callers receive just the status code without body parsing.

/// Make a raw HTTP GET to the proxy and return the status code only.
///
/// Does not attempt JSON body parsing — safe to call with go-httpbin backends
/// whose `/status/:code` endpoints return plain-text or empty bodies.
async fn raw_status(proxy_addr: SocketAddr, host: &str, path: &str) -> u16 {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let c = CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|e| panic!("build reqwest client: {e}"))
    });
    let url = format!("http://{proxy_addr}{path}");
    c.get(&url)
        .header("Host", host)
        .send()
        .await
        .map(|r| r.status().as_u16())
        .unwrap_or(0)
}

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
    let ns = NamespaceGuard::create(&h.client, "tp-ing-retry").await?;

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

/// Ingress `retry-codes` + `retry-backoff` effect (#445): with `retry-attempts: 2`,
/// `retry-codes: 503`, `retry-backoff: 200ms`, the always-503 go-httpbin backend is
/// retried. The client sees the final 503 (budget exhausted), but the retry loop
/// fired (retry metric) and each retried attempt waited the backoff (elapsed time).
#[tokio::test]
async fn annotation_retry_codes_retries_retriable_status_with_backoff() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tp-ing-retry-codes").await?;

    fixtures::apply_fixture(backends::GO_HTTPBIN, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["go-httpbin"]).await?;
    fixtures::apply_fixture(ingress::ANNOTATION_RETRY_CODES, FixtureVars::new(&ns.name)).await?;

    let host = format!("ingretry.{}.local", ns.name);
    // The shared proxy serves Ingress on its default HTTP listener. Use `raw_status`
    // (plain reqwest, no JSON parse) — the shared `HttpClient` deserializes 2xx bodies
    // as `EchoResponse`, which fails on go-httpbin's non-echo `/status/:code` body.
    let proxy = h.http.proxy_addr;

    // Readiness: /status/200 is not retriable, so a 200 confirms the route is live.
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async { format!("{host} route live (go-httpbin 200)") },
        || async { (raw_status(proxy, &host, "/status/200").await == 200).then_some(()) },
    )
    .await?;

    let before = retry_count(&h, &ns.name, "http-code").await;
    let start = std::time::Instant::now();
    let status = raw_status(proxy, &host, "/status/503").await;
    let elapsed = start.elapsed();

    assert_eq!(
        status, 503,
        "budget-exhausted retry returns the upstream 503"
    );
    assert!(
        elapsed >= Duration::from_millis(300),
        "each retried attempt must wait the 200ms backoff (elapsed {elapsed:?})"
    );
    let after = retry_count(&h, &ns.name, "http-code").await;
    assert!(
        after > before,
        "retry-codes:503 must retry the 503 \
         (upstream_retries_total{{condition=http-code}}: {before} -> {after})"
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
    let ns = NamespaceGuard::create(&h.client, "tp-ing-connect-timeout").await?;

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
    let ns = NamespaceGuard::create(&h.client, "tp-ing-read-timeout").await?;

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
    let ns = NamespaceGuard::create(&h.client, "tp-ing-cls-timeout").await?;

    // Cluster-scoped IngressClass — guard deletes it on drop. Name matches the
    // fixture's `coxswain-clstimeout-${TESTNS}`.
    let ic_name = format!("coxswain-clstimeout-{}", ns.name);
    let _ic_guard = IngressClassGuard::new(&ic_name);

    fixtures::apply_fixture(ingress::CLASS_DEFAULT_TIMEOUT, FixtureVars::new(&ns.name)).await?;

    let host = format!("clstimeout.{}.local", ns.name);

    // 502 doubles as the readiness signal: once the route is installed every
    // request black-holes on connect and returns 502 within the 500ms deadline
    // supplied by the class default.
    wait::wait_for_route_status(&h.http, &host, "/", 502, Duration::from_secs(60)).await?;

    Ok(())
}

/// Verifies that a `CoxswainBackendPolicy` with `spec.timeouts.connect: 500ms`
/// attached to a backend `Service` bounds the upstream TCP-connect for a
/// Gateway-API route (#354).
///
/// The backend's only EndpointSlice address is `192.0.2.1` (RFC 5737 TEST-NET-1),
/// so the SYN is black-holed and `connect()` hangs. With the policy the proxy
/// abandons the connect after 500ms and returns 502 (ConnectTimedout). The proof
/// is the prompt 502 within the 60s budget: without the policy the connect would
/// hang past it and the route would never return a clean 502 — i.e. the 502 IS
/// the proof the per-backend connect timeout reached the Gateway-API upstream.
#[tokio::test]
async fn backend_policy_connect_timeout_returns_502() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tp-cbp-connect").await?;

    fixtures::apply_fixture(
        gwa::BACKEND_POLICY_CONNECT_TIMEOUT,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("backend-policy-connect.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;

    // 502 doubles as the readiness signal: once the route + policy are installed
    // every request black-holes on connect and returns 502 within the 500ms
    // deadline supplied by the policy.
    wait::wait_for_route_status(&gw, &host, "/", 502, Duration::from_secs(60)).await?;

    Ok(())
}

/// Verifies that an unparseable `CoxswainBackendPolicy` `spec.timeouts.connect`
/// value WARNs and falls back to the default connection behaviour rather than
/// erroring the connection (#354).
///
/// The policy targets the reachable `echo-a` Service with a bad duration string.
/// The route must still return 200 — proving the bad value degraded to the
/// default (no connection-level error). Without fail-open the connection would
/// break and the route would never serve a clean 200.
#[tokio::test]
async fn backend_policy_invalid_timeout_falls_back() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tp-cbp-fallback").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        gwa::BACKEND_POLICY_INVALID_TIMEOUT,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("backend-policy-fallback.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;

    // The bad value must not break the connection — the reachable echo backend
    // serves a clean 200, proving fallback to default connect behaviour.
    wait::wait_for_route(&gw, &host, "/", Duration::from_secs(60)).await?;

    Ok(())
}

// ── CoxswainBackendPolicy: load-balancer algorithm (#389) ─────────────────────
//
// Gateway-API parity for the Ingress `load-balance` annotation. The policy's
// `spec.loadBalancer.algorithm` mirrors the annotation vocabulary 1:1; a bad value
// WARNs and falls back to round-robin (no apiserver rejection).

/// Happy path (#389): a `CoxswainBackendPolicy` with
/// `spec.loadBalancer.algorithm: least_conn` on the backend `Service` makes the
/// proxy route a Gateway-API HTTPRoute's traffic by fewest-active-connections.
///
/// The `lb-pool` Service is backed by `lb-fast` (echo-basic, instant) and
/// `lb-slow` (go-httpbin, holds `/delay/1` for 1s). Under least_conn the slow
/// endpoint accumulates active connections and new selections prefer the fast
/// one. Asserts `fast_count > slow_count` and `slow_count >= 1` — the same proof
/// as the Ingress annotation test, here via the policy on the Gateway-API surface.
#[tokio::test]
async fn backend_policy_least_conn_routes_more_to_fast_upstream() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tp-cbp-leastconn").await?;

    fixtures::apply_fixture(backends::LB_MIXED, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["lb-fast", "lb-slow"]).await?;
    fixtures::apply_fixture(gwa::BACKEND_POLICY_LEAST_CONN, FixtureVars::new(&ns.name)).await?;

    let host = format!("backend-policy-lb.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;

    // Readiness: both backends return 200 for /delay/1 (echo instantly, httpbin after 1s).
    wait::wait_for_route_status(&gw, &host, "/delay/1", 200, Duration::from_secs(90)).await?;
    // BOTH lb-pool endpoints must be compiled before the burst, else the
    // distribution assertions are decided by whichever endpoint landed first.
    wait::wait_for_route_endpoints(
        &h.shared_proxy_routes_url().await?,
        &host,
        2,
        Duration::from_secs(60),
    )
    .await?;

    // Pipelined burst: 20 requests, up to 4 in-flight. lb-slow holds each for 1s,
    // so new selections see its active count ≥ 1 and route to lb-fast.
    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?,
    );
    let sem = Arc::new(tokio::sync::Semaphore::new(4));
    let proxy_addr = gw.proxy_addr;

    let handles: Vec<_> = (0..20u32)
        .map(|_| {
            let client = Arc::clone(&client);
            let sem = Arc::clone(&sem);
            let url = format!("http://{proxy_addr}/delay/1");
            let host = host.clone();
            tokio::spawn(async move {
                let _permit = sem
                    .acquire_owned()
                    .await
                    .map_err(|e| anyhow::anyhow!("semaphore closed: {e}"))?;
                let resp =
                    coxswain_e2e::harness::http::get_with_transient_retry(&client, &url, &host, 3)
                        .await
                        .map_err(|e| anyhow::anyhow!("send: {e}"))?;
                let status = resp.status().as_u16();
                anyhow::ensure!(status == 200, "expected 200, got {status}");
                let body = resp
                    .json::<serde_json::Value>()
                    .await
                    .map_err(|e| anyhow::anyhow!("parse body: {e}"))?;
                Ok::<Option<String>, anyhow::Error>(body["pod"].as_str().map(String::from))
            })
        })
        .collect();

    let mut fast_count = 0usize;
    let mut slow_count = 0usize;
    for handle in handles {
        let pod_opt = handle.await.map_err(|e| anyhow::anyhow!("task: {e}"))??;
        if pod_opt
            .as_deref()
            .is_some_and(|p| p.starts_with("lb-fast-"))
        {
            fast_count += 1;
        } else {
            slow_count += 1;
        }
    }

    assert!(
        fast_count > slow_count,
        "policy least_conn must route more requests to the fast upstream; \
         fast_count={fast_count}, slow_count={slow_count}"
    );
    assert!(
        slow_count >= 1,
        "policy least_conn must route at least one request to the slow upstream \
         (both endpoints reachable); fast_count={fast_count}, slow_count={slow_count}"
    );

    Ok(())
}

/// Sad path (#389): a `CoxswainBackendPolicy` with an unrecognised
/// `spec.loadBalancer.algorithm` WARNs and falls back to round-robin rather than
/// dropping the route.
///
/// The policy targets the reachable `echo-a` Service with a bogus algorithm. The
/// route must still return 200 — proving the bad value degraded to the default
/// (no routing break). Without fail-open the route would never serve a clean 200.
#[tokio::test]
async fn backend_policy_invalid_load_balance_falls_back_to_round_robin() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tp-cbp-lbfallback").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        gwa::BACKEND_POLICY_INVALID_LOAD_BALANCE,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("backend-policy-lb-fallback.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;

    // The bad algorithm must not drop the route — the reachable echo backend
    // serves a clean 200, proving fallback to default round-robin.
    wait::wait_for_route(&gw, &host, "/", Duration::from_secs(60)).await?;

    Ok(())
}

// ── CoxswainBackendPolicy: circuit breaker (#478) ─────────────────────────────
//
// Gateway-API parity for the Ingress `circuit-breaker-*` annotation family. The
// policy's `spec.circuitBreaker` carries the same knobs; an out-of-range threshold
// disables the breaker. The fixture uses threshold=50%, min-requests=4,
// window=500ms (sub-second, so failsafe's EWMA time gate is always satisfied),
// open-duration=2s. go-httpbin's /status/:code drives upstream codes.

/// Happy path (#478): once enough upstream 500s drop the EWMA success rate below
/// `threshold`, the policy-driven breaker opens and subsequent requests fail fast
/// with 503 without reaching the upstream.
///
/// Asserts the negative first: a baseline error is a real upstream 500 (breaker
/// still closed). After the trip batch, requests are fail-fast 503.
#[tokio::test]
async fn backend_policy_breaker_opens_when_upstream_errors() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tp-cbp-cb-open").await?;

    fixtures::apply_fixture(backends::GO_HTTPBIN, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["go-httpbin"]).await?;
    fixtures::apply_fixture(
        gwa::BACKEND_POLICY_CIRCUIT_BREAKER,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("backend-policy-breaker.{}.local", ns.name);
    let proxy = h.gateway_http_addr(&ns.name).await?;

    // Route readiness: poll /status/200 until the proxy forwards it to go-httpbin.
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async { format!("{host} / route to return 200 from go-httpbin") },
        || async {
            if raw_status(proxy, &host, "/status/200").await == 200 {
                Some(())
            } else {
                None
            }
        },
    )
    .await?;

    // Negative baseline: the breaker is still closed — the first error must reach
    // the upstream (500), not be rejected by the breaker (503).
    let pre = raw_status(proxy, &host, "/status/500").await;
    assert_eq!(
        pre, 500,
        "before the trip sequence the upstream 500 must reach the client (not a breaker 503)"
    );

    // Trip sequence: over-shoot min-requests to guarantee the breaker opens
    // regardless of how many readiness requests remain in the 500ms window.
    for _ in 0..8u32 {
        raw_status(proxy, &host, "/status/500").await;
    }

    let open_status = raw_status(proxy, &host, "/status/500").await;
    assert_eq!(
        open_status, 503,
        "after the trip sequence the policy circuit breaker must fail-fast with 503 \
         (circuitBreaker.threshold=50, minRequests=4)"
    );

    Ok(())
}

/// Recovery path (#478): after the breaker opens and `openDuration` elapses, the
/// breaker half-opens; a successful probe (upstream 200) closes it and traffic is
/// served normally again.
#[tokio::test]
async fn backend_policy_breaker_closes_after_open_duration_when_upstream_recovers()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tp-cbp-cb-recover").await?;

    fixtures::apply_fixture(backends::GO_HTTPBIN, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["go-httpbin"]).await?;
    fixtures::apply_fixture(
        gwa::BACKEND_POLICY_CIRCUIT_BREAKER,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("backend-policy-breaker.{}.local", ns.name);
    let proxy = h.gateway_http_addr(&ns.name).await?;

    // Route readiness.
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async { format!("{host} / route to return 200 from go-httpbin") },
        || async {
            if raw_status(proxy, &host, "/status/200").await == 200 {
                Some(())
            } else {
                None
            }
        },
    )
    .await?;

    // Trip the breaker.
    for _ in 0..8u32 {
        raw_status(proxy, &host, "/status/500").await;
    }
    let open_status = raw_status(proxy, &host, "/status/500").await;
    assert_eq!(
        open_status, 503,
        "breaker must be open (503) before the recovery window; \
         if 500, the trip sequence did not open the policy breaker"
    );

    // Recovery: after openDuration (2s) the breaker half-opens; a /status/200 probe
    // closes it. No bare sleep — poll the real observable (200 response).
    wait::poll_until(
        Duration::from_secs(15),
        wait::POLL_FAST,
        || async { "policy circuit breaker to close (expecting 200 from /status/200)".to_string() },
        || async {
            if raw_status(proxy, &host, "/status/200").await == 200 {
                Some(())
            } else {
                None
            }
        },
    )
    .await?;

    Ok(())
}

/// Sad path (#478): a `CoxswainBackendPolicy` with an out-of-range
/// `spec.circuitBreaker.threshold: 0` (the disabled gate) WARNs and installs no
/// breaker — upstream 500s pass through and never become a fail-fast 503.
///
/// Drives the same error stream as the open test against a policy that should be
/// disabled; the breaker never trips, so the route keeps returning the real
/// upstream 500. Proves the bad value disabled the breaker rather than rejecting
/// the resource.
#[tokio::test]
async fn backend_policy_invalid_circuit_breaker_threshold_stays_disabled() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tp-cbp-cb-disabled").await?;

    fixtures::apply_fixture(backends::GO_HTTPBIN, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["go-httpbin"]).await?;
    fixtures::apply_fixture(
        gwa::BACKEND_POLICY_INVALID_CIRCUIT_BREAKER,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("backend-policy-breaker-disabled.{}.local", ns.name);
    let proxy = h.gateway_http_addr(&ns.name).await?;

    // Readiness.
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async { format!("{host} / route to return 200 from go-httpbin") },
        || async {
            if raw_status(proxy, &host, "/status/200").await == 200 {
                Some(())
            } else {
                None
            }
        },
    )
    .await?;

    // Drive a stream of errors that WOULD trip a 50%-threshold breaker, then assert
    // the upstream 500 still passes through — the disabled gate installed no breaker.
    for _ in 0..8u32 {
        raw_status(proxy, &host, "/status/500").await;
    }
    let status = raw_status(proxy, &host, "/status/500").await;
    assert_eq!(
        status, 500,
        "with threshold=0 (disabled) the breaker must never trip — upstream 500 must pass \
         through, never a fail-fast 503; got {status}"
    );

    Ok(())
}

/// Verifies that `ingress.coxswain-labs.dev/max-body-size: "1k"` (#263) caps the
/// request body. One route, the full happy/sad matrix:
/// - under-limit POST (200 B, Content-Length) → 200, served by `echo-a`;
/// - over-limit POST (4 KiB, Content-Length) → 413, rejected up front before the
///   upstream is contacted (no echo body);
/// - over-limit chunked POST (8×512 B, no Content-Length) → 413, proving the
///   mid-stream `request_body_filter` cap fires without buffering the whole body.
///
/// A bodyless GET carries nothing to cap, so its 200 is the route-ready signal.
#[tokio::test]
async fn max_body_size_enforces_limit() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tp-ing-maxbody").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_MAX_BODY_SIZE,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("maxbody.{}.local", ns.name);

    // Readiness: a bodyless GET is always under the limit, so a 200 proves the route
    // is installed before we exercise the body-size cases.
    wait::wait_for_route_status(&h.http, &host, "/", 200, Duration::from_secs(60)).await?;

    // Happy path: 200 B < 1 KiB → served, and specifically by echo-a (backend identity).
    let (status, body) = h
        .http
        .request_with_body(reqwest::Method::POST, &host, "/", vec![b'x'; 200])
        .await?;
    assert_eq!(status, 200, "under-limit POST must be served");
    body.expect("under-limit POST must return an echo body")
        .assert_backend("echo-a");

    // Sad path (up-front): 4 KiB with Content-Length > 1 KiB → 413 before any upstream.
    let (status, body) = h
        .http
        .request_with_body(reqwest::Method::POST, &host, "/", vec![b'x'; 4096])
        .await?;
    assert_eq!(
        status, 413,
        "over-limit POST (Content-Length) must be rejected with 413"
    );
    assert!(
        body.is_none(),
        "rejected POST must not reach the echo backend"
    );

    // Sad path (mid-stream): chunked body (no Content-Length) totalling 4 KiB across
    // 8×512 B chunks crosses the 1 KiB cap → 413 from request_body_filter.
    let chunks = vec![vec![b'x'; 512]; 8];
    let (status, body) = h
        .http
        .request_with_streamed_body(reqwest::Method::POST, &host, "/", chunks)
        .await?;
    assert_eq!(
        status, 413,
        "over-limit chunked POST must be rejected with 413"
    );
    assert!(
        body.is_none(),
        "rejected chunked POST must not reach the echo backend"
    );

    Ok(())
}

/// Verifies that an unparseable `max-body-size` value is rejected by the VAP at
/// admission time (#263, #29 VAP). Fail-open proxy semantics remain the backstop for
/// VAP-disabled installs, covered by the `parse_max_body_size_invalid` unit test.
#[tokio::test]
async fn max_body_size_invalid_value_rejected_by_vap() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tp-ing-maxbody-bad").await?;

    let msg = fixtures::apply_fixture_expect_rejected(
        ingress::ANNOTATION_MAX_BODY_SIZE_INVALID,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("max-body-size"),
        "VAP rejection message must name the offending annotation, got: {msg}"
    );

    Ok(())
}

// ── RequestSizeLimit ExtensionRef (Gateway API, #443) ─────────────────────────

/// `RequestSizeLimit` CR via `ExtensionRef` on an HTTPRoute: under-limit bodies
/// are served (backend identity, 2xx); over-limit bodies are rejected with 413
/// — both up-front (`Content-Length`) and mid-stream (chunked, no
/// `Content-Length`) (#443 happy + sad path — also proves the ExtensionRef is
/// accepted on HTTPRoute).
#[tokio::test]
async fn gateway_request_size_limit_enforces_cap() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-maxbody").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        gwa::REQUEST_SIZE_LIMIT_EXTENSIONREF,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwmaxbody.{}.local", ns.name);

    // Readiness: a bodyless GET is always under the limit, so a 200 proves the
    // route is installed before we exercise the body-size cases.
    wait::wait_for_route_status(&gw, &host, "/", 200, Duration::from_secs(60)).await?;

    // Happy path: 200 B < 1 KiB → served, and specifically by echo-a.
    let (status, body) = gw
        .request_with_body(Method::POST, &host, "/", vec![b'x'; 200])
        .await?;
    assert_eq!(status, 200, "under-limit POST must be served");
    body.expect("under-limit POST must return an echo body")
        .assert_backend("echo-a");

    // Sad path (up-front): 4 KiB with Content-Length > 1 KiB → 413.
    let (status, body) = gw
        .request_with_body(Method::POST, &host, "/", vec![b'x'; 4096])
        .await?;
    assert_eq!(
        status, 413,
        "over-limit POST (Content-Length) must be rejected with 413"
    );
    assert!(
        body.is_none(),
        "rejected POST must not reach the echo backend"
    );

    // Sad path (mid-stream): chunked body (no Content-Length) totalling 4 KiB
    // across 8x512 B chunks crosses the 1 KiB cap → 413.
    let chunks = vec![vec![b'x'; 512]; 8];
    let (status, body) = gw
        .request_with_streamed_body(Method::POST, &host, "/", chunks)
        .await?;
    assert_eq!(
        status, 413,
        "over-limit chunked POST must be rejected with 413"
    );
    assert!(
        body.is_none(),
        "rejected chunked POST must not reach the echo backend"
    );

    Ok(())
}

// Minimal `grpcecho` proto (hand-derived from grpcecho.proto to avoid a
// prost-build dependency) for the GRPCRoute RequestSizeLimit parity test (#443).
// Service: gateway_api_conformance.echo_basic.grpcecho.GrpcEcho
mod grpcecho {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct EchoRequest {}

    /// A padded request used only to exceed the RequestSizeLimit byte cap.
    /// The proxy's byte-size guard fires on raw body bytes before the backend
    /// ever deserializes the message, so a real grpcecho.proto field is not
    /// needed — proto3's wire format tolerates the extra unknown tag.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct PaddedEchoRequest {
        #[prost(bytes = "vec", tag = "99")]
        pub padding: Vec<u8>,
    }

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

/// Issue one `GrpcEcho/Echo` unary call through the Gateway VIP for `host`,
/// with an arbitrary request message type. Connect/transport failures are
/// folded into `Status::unavailable` so callers can match on `tonic::Code`
/// uniformly. Bounded to 20s total (`Status::deadline_exceeded` on expiry) as a
/// general safety net so a stuck call fails the test instead of hanging the suite.
async fn grpc_echo_call<Req: prost::Message + Default + 'static>(
    gw_addr: SocketAddr,
    host: &str,
    req: Req,
) -> Result<grpcecho::EchoResponse, tonic::Status> {
    match tokio::time::timeout(
        Duration::from_secs(20),
        grpc_echo_call_inner(gw_addr, host, req),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(tonic::Status::deadline_exceeded(
            "grpc_echo_call did not complete within 20s",
        )),
    }
}

async fn grpc_echo_call_inner<Req: prost::Message + Default + 'static>(
    gw_addr: SocketAddr,
    host: &str,
    req: Req,
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
    let codec = tonic_prost::ProstCodec::<Req, grpcecho::EchoResponse>::default();
    client
        .unary(tonic::Request::new(req), path, codec)
        .await
        .map(tonic::Response::into_inner)
}

/// Issue a unary call to an arbitrary `method_path` (full `/service/method`) on the
/// `GrpcEcho` backend. Used to drive a non-existent method, which yields a
/// trailers-only `UNIMPLEMENTED` — the retriable outcome exercised by the gRPC retry
/// tests. Returns the resulting [`tonic::Status`] (`Ok` is folded to an `Ok` status so
/// callers can match uniformly on the code).
async fn grpc_call_to(gw_addr: SocketAddr, host: &str, method_path: &str) -> tonic::Status {
    let attempt = async {
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
        let path = method_path
            .parse::<tonic::codegen::http::uri::PathAndQuery>()
            .map_err(|e| tonic::Status::unavailable(format!("path: {e}")))?;
        let codec =
            tonic_prost::ProstCodec::<grpcecho::EchoRequest, grpcecho::EchoResponse>::default();
        client
            .unary(tonic::Request::new(grpcecho::EchoRequest {}), path, codec)
            .await
            .map(|_| tonic::Status::ok(""))
    };
    match tokio::time::timeout(Duration::from_secs(20), attempt).await {
        Ok(Ok(status)) => status,
        Ok(Err(status)) => status,
        Err(_) => tonic::Status::deadline_exceeded("grpc_call_to did not complete within 20s"),
    }
}

/// `RequestSizeLimit` is deliberately **not enforced** on GRPCRoute (#443 scope
/// decision, coxswain-labs/coxswain#509). A mid-stream body cap over HTTP/2 deadlocks
/// the client under pingora (its h2 proxy loop swallows a `request_body_filter`
/// rejection instead of responding), and gRPC never sends `Content-Length` for the
/// up-front check to use — so coxswain leaves gRPC message sizing to the backend's own
/// `max_recv_msg_size` until pingora ships request-body buffering (pingora #816/#780).
/// The reconciler skips the `RequestSizeLimit` ExtensionRef on GRPCRoute (logged as
/// unsupported, like `BasicAuth`/`Compression`), so an over-cap message routes through
/// untouched.
///
/// Asserts non-enforcement: with a 1 KiB `RequestSizeLimit` attached, both a small call
/// and a 2 KiB over-cap call succeed promptly — the backend echoes them, no rejection
/// and (critically) no hang.
#[tokio::test]
async fn gateway_request_size_limit_not_enforced_on_grpcroute() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-grpc-maxbody").await?;
    fixtures::apply_fixture(backends::GRPC_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["grpc-echo"]).await?;
    fixtures::apply_fixture(
        gwa::REQUEST_SIZE_LIMIT_GRPCROUTE,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("grpc-maxbody.{}.local", ns.name);
    let gw_addr = h.gateway_http_addr(&ns.name).await?;

    // Wait until a small call succeeds — confirms the route is live.
    wait::poll_until(
        Duration::from_secs(60),
        Duration::from_millis(500),
        || async { format!("gRPC Echo via {host} to succeed") },
        || async {
            grpc_echo_call(gw_addr, &host, grpcecho::EchoRequest {})
                .await
                .ok()
        },
    )
    .await?;

    // A 2 KiB message far exceeds the CR's 1 KiB cap. Because RequestSizeLimit is not
    // enforced on GRPCRoute, it must route through to grpc-echo and succeed — proving
    // the edge does not cap gRPC bodies, and that a rejected body no longer hangs the
    // client (#509). The route is confirmed live above, so this is a single atomic call.
    let oversized = grpcecho::PaddedEchoRequest {
        padding: vec![0u8; 2048],
    };
    grpc_echo_call(gw_addr, &host, oversized).await.map_err(|s| {
        anyhow::anyhow!(
            "over-cap gRPC call must succeed (RequestSizeLimit is not enforced on gRPC), got {s:?}"
        )
    })?;

    Ok(())
}

// ── RetryPolicy ExtensionRef (#445) ─────────────────────────────────────────────
//
// Retrying is black-box: e2e cannot observe individual attempts except through the
// per-condition metric `coxswain_proxy_upstream_retries_total{condition=...}`, which
// the proxy increments once per retry. Each test drives an always-failing upstream
// (go-httpbin /status/503, or an unimplemented gRPC method) and asserts on that metric,
// scoped to the test's own namespace (which appears in the route/upstream labels on the
// shared proxy). The happy path proves the retry loop fires; the sad path proves the
// code-list gates it.

/// Sum `coxswain_proxy_upstream_retries_total` series for `condition` whose labels
/// mention `ns_marker` (the test namespace, present in the `route`/`upstream` labels).
async fn retry_count(h: &Harness, ns_marker: &str, condition: &str) -> u64 {
    let Ok(resp) = reqwest::get(h.admin_url("/metrics")).await else {
        return 0;
    };
    let Ok(body) = resp.text().await else {
        return 0;
    };
    body.lines()
        .filter(|l| l.starts_with("coxswain_proxy_upstream_retries_total{"))
        .filter(|l| l.contains(&format!("condition=\"{condition}\"")))
        .filter(|l| l.contains(ns_marker))
        .filter_map(|l| l.rsplit(' ').next().and_then(|v| v.parse::<f64>().ok()))
        .map(|v| v as u64)
        .sum()
}

/// HTTP happy path: a `RetryPolicy` with `codes: [503]` retries the always-503
/// go-httpbin backend. The client sees the final 503 (budget exhausted), but the retry
/// loop fired — proven by the retry metric — and the `200ms` backoff delayed each
/// retried attempt (proven by elapsed time).
#[tokio::test]
async fn retry_fires_on_retriable_http_status_and_applies_backoff() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-retry-http").await?;
    fixtures::apply_fixture(backends::GO_HTTPBIN, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["go-httpbin"]).await?;
    fixtures::apply_fixture(gwa::RETRY_HTTP, FixtureVars::new(&ns.name)).await?;

    let host = format!("gwretry.{}.local", ns.name);
    let proxy = h.gateway_http_addr(&ns.name).await?;

    // Readiness: /status/200 is not in the retry code set, so a 200 confirms the route
    // is live without firing retries.
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async { format!("{host} route live (go-httpbin 200)") },
        || async { (raw_status(proxy, &host, "/status/200").await == 200).then_some(()) },
    )
    .await?;

    let before = retry_count(&h, &ns.name, "http-code").await;
    let start = std::time::Instant::now();
    let status = raw_status(proxy, &host, "/status/503").await;
    let elapsed = start.elapsed();

    assert_eq!(
        status, 503,
        "with the retry budget exhausted the upstream 503 reaches the client"
    );
    // attempts=2 ⇒ two retried attempts, each preceded by the 200ms backoff (>= 400ms);
    // allow slack for scheduling/clock granularity.
    assert!(
        elapsed >= Duration::from_millis(300),
        "each retried attempt must wait the 200ms backoff (elapsed {elapsed:?})"
    );
    let after = retry_count(&h, &ns.name, "http-code").await;
    assert!(
        after > before,
        "the retry loop must fire for a 503 in codes=[503] \
         (upstream_retries_total{{condition=http-code}}: {before} -> {after})"
    );

    Ok(())
}

/// HTTP sad path: a `RetryPolicy` with `codes: [500]` must NOT retry the go-httpbin
/// 503 — 503 is outside the code set, so it passes straight through and the retry
/// metric never increments.
#[tokio::test]
async fn retry_not_attempted_for_non_retriable_http_status() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-retry-http-nr").await?;
    fixtures::apply_fixture(backends::GO_HTTPBIN, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["go-httpbin"]).await?;
    fixtures::apply_fixture(gwa::RETRY_HTTP_NON_RETRIABLE, FixtureVars::new(&ns.name)).await?;

    let host = format!("gwretrynr.{}.local", ns.name);
    let proxy = h.gateway_http_addr(&ns.name).await?;

    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async { format!("{host} route live (go-httpbin 200)") },
        || async { (raw_status(proxy, &host, "/status/200").await == 200).then_some(()) },
    )
    .await?;

    let before = retry_count(&h, &ns.name, "http-code").await;
    let status = raw_status(proxy, &host, "/status/503").await;
    assert_eq!(
        status, 503,
        "503 is not in codes=[500]; it must pass through without a retry"
    );
    let after = retry_count(&h, &ns.name, "http-code").await;
    assert_eq!(
        after, before,
        "no retry may fire for a status outside the configured code set"
    );

    Ok(())
}

/// gRPC happy path: a `RetryPolicy` with `grpcCodes: [12]` retries a trailers-only
/// `UNIMPLEMENTED` from a non-existent method. The RPC still fails `UNIMPLEMENTED`
/// (budget exhausted), but the gRPC-aware retry loop fired — proven by the metric.
#[tokio::test]
async fn grpc_retry_fires_on_retriable_grpc_status() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-retry-grpc").await?;
    fixtures::apply_fixture(backends::GRPC_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["grpc-echo"]).await?;
    fixtures::apply_fixture(gwa::RETRY_GRPC, FixtureVars::new(&ns.name)).await?;

    let host = format!("grpc-retry.{}.local", ns.name);
    let gw_addr = h.gateway_http_addr(&ns.name).await?;

    // Readiness via a real Echo call (matches all methods on this route), which
    // succeeds and does not fire retries.
    wait::poll_until(
        Duration::from_secs(60),
        Duration::from_millis(500),
        || async { format!("gRPC Echo via {host} to succeed") },
        || async {
            grpc_echo_call(gw_addr, &host, grpcecho::EchoRequest {})
                .await
                .ok()
        },
    )
    .await?;

    let before = retry_count(&h, &ns.name, "grpc-code").await;
    let method = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/DoesNotExist";
    let st = grpc_call_to(gw_addr, &host, method).await;
    assert_eq!(
        st.code(),
        tonic::Code::Unimplemented,
        "a non-existent method must yield UNIMPLEMENTED, got {st:?}"
    );
    let after = retry_count(&h, &ns.name, "grpc-code").await;
    assert!(
        after > before,
        "the retry loop must fire for grpc-status 12 in grpcCodes=[12] \
         (upstream_retries_total{{condition=grpc-code}}: {before} -> {after})"
    );

    Ok(())
}

/// gRPC sad path: a `RetryPolicy` with `grpcCodes: [14]` must NOT retry an
/// `UNIMPLEMENTED` (12) — it is outside the set, so no retry fires.
#[tokio::test]
async fn grpc_retry_not_attempted_for_non_retriable_grpc_status() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-retry-grpc-nr").await?;
    fixtures::apply_fixture(backends::GRPC_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["grpc-echo"]).await?;
    fixtures::apply_fixture(gwa::RETRY_GRPC_NON_RETRIABLE, FixtureVars::new(&ns.name)).await?;

    let host = format!("grpc-retrynr.{}.local", ns.name);
    let gw_addr = h.gateway_http_addr(&ns.name).await?;

    wait::poll_until(
        Duration::from_secs(60),
        Duration::from_millis(500),
        || async { format!("gRPC Echo via {host} to succeed") },
        || async {
            grpc_echo_call(gw_addr, &host, grpcecho::EchoRequest {})
                .await
                .ok()
        },
    )
    .await?;

    let before = retry_count(&h, &ns.name, "grpc-code").await;
    let method = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/DoesNotExist";
    let st = grpc_call_to(gw_addr, &host, method).await;
    assert_eq!(
        st.code(),
        tonic::Code::Unimplemented,
        "a non-existent method must yield UNIMPLEMENTED, got {st:?}"
    );
    let after = retry_count(&h, &ns.name, "grpc-code").await;
    assert_eq!(
        after, before,
        "no retry may fire for grpc-status 12 when grpcCodes=[14]"
    );

    Ok(())
}

// ── Session affinity (#15) ─────────────────────────────────────────────────────
//
// One `echo-aff` Service with three pods backs each test, so a backend group holds
// three endpoints: weighted round-robin spreads across them and affinity pins to
// one. Pod identity comes from the echo body's `pod` field (Downward API).

/// Extract the `name=value` pair for cookie `name` from the response's `Set-Cookie`
/// headers, ready to replay as a `Cookie` request header. `None` if absent.
fn set_cookie_pair(hdrs: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    for v in hdrs.get_all(reqwest::header::SET_COOKIE).iter() {
        let Ok(s) = v.to_str() else { continue };
        let Some(pair) = s.split(';').next().map(str::trim) else {
            continue;
        };
        if pair.split_once('=').is_some_and(|(k, _)| k == name) {
            return Some(pair.to_string());
        }
    }
    None
}

/// Cookie-mode affinity (happy path): the proxy injects a `SESSIONID` cookie on the
/// first response, and every subsequent request replaying that cookie pins to the
/// same pod. A valid pin is not re-issued. Also proves the custom
/// `session-cookie-name` is honored.
#[tokio::test]
async fn session_affinity_cookie_pins_client_to_same_backend_when_cookie_replayed()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "aff-cookie").await?;

    fixtures::apply_fixture(
        ingress::ANNOTATION_SESSION_AFFINITY_COOKIE,
        FixtureVars::new(&ns.name),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-aff"]).await?;
    let host = format!("affinity.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    // All 3 endpoints must be propagated before establishing the cookie pin:
    // the cookie encodes the chosen endpoint, and a set that grows afterwards
    // shifts that mapping. Un-keyed requests round-robin to confirm the full set.
    wait::wait_for_distinct_backends(&h.http, &host, "/", 3, Duration::from_secs(60)).await?;

    // First request carries no cookie → the proxy round-robins to a pod and pins it
    // by injecting the (custom-named) SESSIONID cookie.
    let (status, hdrs, body) = h.http.get_full(&host, "/").await?;
    assert_eq!(status, 200, "first affinity request must succeed");
    let first_pod = body
        .and_then(|b| b.pod)
        .expect("echo body must report the serving pod");
    let cookie = set_cookie_pair(&hdrs, "SESSIONID").expect(
        "cookie mode must inject a SESSIONID Set-Cookie (custom session-cookie-name) \
         on the first response",
    );

    // Replaying the cookie pins every request to the original pod and does not
    // re-issue the cookie.
    for i in 0..10 {
        let (status, hdrs, body) = h
            .http
            .get_full_with_headers(&host, "/", &[("Cookie", cookie.as_str())])
            .await?;
        assert_eq!(status, 200, "cookie replay {i} must succeed");
        let pod = body.and_then(|b| b.pod).unwrap_or_default();
        assert_eq!(
            pod, first_pod,
            "cookie replay {i} must pin to the original pod (got {pod}, want {first_pod})"
        );
        assert!(
            set_cookie_pair(&hdrs, "SESSIONID").is_none(),
            "cookie replay {i}: an already-valid pin must not re-issue the cookie"
        );
    }
    Ok(())
}

/// Cookie-mode affinity (sad path): a cookie whose token matches no live endpoint
/// (e.g. the pinned pod was removed) must not error — the proxy falls back to
/// round-robin and re-establishes affinity by issuing a fresh, different cookie.
#[tokio::test]
async fn session_affinity_cookie_reestablishes_when_cookie_token_is_stale() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "aff-stale").await?;

    fixtures::apply_fixture(
        ingress::ANNOTATION_SESSION_AFFINITY_COOKIE,
        FixtureVars::new(&ns.name),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-aff"]).await?;
    let host = format!("affinity.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // u64::MAX is never a real endpoint token (those are FNV-1a of addr+port), so it
    // models a pin to a pod that has been removed/scaled away.
    let stale = "SESSIONID=ffffffffffffffff";
    let (status, hdrs, body) = h
        .http
        .get_full_with_headers(&host, "/", &[("Cookie", stale)])
        .await?;
    assert_eq!(
        status, 200,
        "a stale affinity cookie must still serve a healthy pod"
    );
    assert!(
        body.and_then(|b| b.pod).is_some(),
        "the request must reach a live backend pod"
    );
    let fresh = set_cookie_pair(&hdrs, "SESSIONID")
        .expect("a stale cookie must re-establish affinity with a fresh Set-Cookie");
    assert_ne!(
        fresh, stale,
        "the re-established cookie must differ from the stale one"
    );
    Ok(())
}

/// Header-mode affinity (happy path): the value of `X-Session-Id` is rendezvous-hashed
/// to a single pod, so a fixed value pins consistently; distinct values spread across
/// pods; and no cookie is ever set.
#[tokio::test]
async fn session_affinity_header_pins_same_header_value_to_same_backend() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "aff-header").await?;

    fixtures::apply_fixture(
        ingress::ANNOTATION_SESSION_AFFINITY_HEADER,
        FixtureVars::new(&ns.name),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-aff"]).await?;
    let host = format!("affinity.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    // All 3 endpoints must be propagated before pinning a session: adding an
    // endpoint mid-test rebalances the affinity hash and moves the pinned pod.
    // Un-keyed requests round-robin, so this confirms the full set is live.
    wait::wait_for_distinct_backends(&h.http, &host, "/", 3, Duration::from_secs(60)).await?;

    // A fixed header value pins to one pod and never sets a cookie.
    let (_, _, body) = h
        .http
        .get_full_with_headers(&host, "/", &[("X-Session-Id", "user-42")])
        .await?;
    let pinned = body
        .and_then(|b| b.pod)
        .expect("echo body must report the serving pod");
    for i in 0..10 {
        let (status, hdrs, body) = h
            .http
            .get_full_with_headers(&host, "/", &[("X-Session-Id", "user-42")])
            .await?;
        assert_eq!(status, 200, "header request {i} must succeed");
        assert_eq!(
            body.and_then(|b| b.pod).unwrap_or_default(),
            pinned,
            "request {i}: a fixed header value must pin to one pod"
        );
        assert!(
            hdrs.get(reqwest::header::SET_COOKIE).is_none(),
            "request {i}: header mode must never set a cookie"
        );
    }

    // Distinct header values spread across more than one pod.
    // Poll until ≥2 pods are visible: EndpointSlice propagation to the proxy can
    // lag behind the Deployment Available condition under load, so a single pass
    // may see only one endpoint. Retry until all endpoints are visible or time out.
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async { "≥2 of 3 echo-aff pods to appear in the proxy routing table".to_string() },
        || async {
            let mut seen = std::collections::HashSet::new();
            for k in 0..50u32 {
                let value = format!("user-{k}");
                if let Ok((_, _, Some(body))) = h
                    .http
                    .get_full_with_headers(&host, "/", &[("X-Session-Id", value.as_str())])
                    .await
                    && let Some(p) = body.pod
                {
                    seen.insert(p);
                }
            }
            (seen.len() >= 2).then_some(seen)
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e} — distinct session ids must spread across multiple pods"))?;
    Ok(())
}

/// Header-mode affinity (sad path): with no `X-Session-Id` header, requests fall back
/// to round-robin across pods, and header mode still never sets a cookie.
#[tokio::test]
async fn session_affinity_header_falls_back_to_round_robin_when_header_absent() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "aff-hdr-rr").await?;

    fixtures::apply_fixture(
        ingress::ANNOTATION_SESSION_AFFINITY_HEADER,
        FixtureVars::new(&ns.name),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-aff"]).await?;
    let host = format!("affinity.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // EndpointSlice propagation to the proxy can lag behind the Deployment
    // Available condition — more so now that routing flows controller→discovery→
    // proxy — so a single sampling pass may see only one endpoint. Poll batches of
    // requests until ≥2 distinct pods appear, asserting the header-mode no-cookie
    // invariant on every successful response along the way.
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            "≥2 echo-aff pods to round-robin requests sent without the affinity header".to_string()
        },
        || async {
            let mut pods = std::collections::HashSet::new();
            for i in 0..30 {
                if let Ok((status, hdrs, body)) = h.http.get_full(&host, "/").await {
                    assert_eq!(status, 200, "request {i} must succeed");
                    assert!(
                        hdrs.get(reqwest::header::SET_COOKIE).is_none(),
                        "request {i}: header mode must not set a cookie even without the header"
                    );
                    if let Some(p) = body.and_then(|b| b.pod) {
                        pods.insert(p);
                    }
                }
            }
            (pods.len() >= 2).then_some(())
        },
    )
    .await
    .map_err(|e| {
        anyhow::anyhow!("{e} — without the affinity header, requests must round-robin across pods")
    })?;
    Ok(())
}

/// Verifies that `ingress.coxswain-labs.dev/mirror-target` fires a fire-and-forget
/// copy of each request to the named secondary backend (#283).
///
/// - Primary traffic (`echo-a`) must return 200 with the primary backend identity;
///   the client never sees the mirror response.
/// - An access-log row with `mirror = true` and `host = mirror.<ns>.local` must
///   appear within 30 s of the driven request — the sole observable that proves the
///   mirror dispatch fired without any response from the echo backend being visible.
///
/// The fixture sets `max-body-size: 1k` so body-buffering mode is active; the POST
/// body exercises the buffer-then-send path in `request_body_filter`.
#[tokio::test]
async fn request_mirrored_to_secondary_backend_when_mirror_target_set() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tp-ing-mirror").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_MIRROR_TARGET,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("mirror.{}.local", ns.name);
    let route = wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    route.assert_backend("echo-a");

    // POST a small body to exercise the body-buffering mirror path (max-body-size
    // is set in the fixture, so chunks are teed to mirror_body then dispatched
    // on end_of_stream).
    let (status, body) = h
        .http
        .request_with_body(Method::POST, &host, "/", b"hello mirror".to_vec())
        .await?;
    assert_eq!(status, 200, "primary POST must succeed; host={host}");
    body.expect("primary response must carry echo JSON")
        .assert_backend("echo-a");

    // Mirror dispatch is fire-and-forget and best-effort: a single request's mirror
    // copy can be lost if the mirror backend's endpoints are still propagating into
    // the proxy snapshot or under parallel load. Re-drive a POST on every poll
    // iteration so the mirror has repeated chances to fire; the test passes as soon
    // as one mirror=true access-log row for this host appears.
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async { format!("a mirror=true access-log row to appear for host={host}") },
        || async {
            // Re-drive the mirrored request, then look for its access-log row.
            let _ = h
                .http
                .request_with_body(Method::POST, &host, "/", b"hello mirror".to_vec())
                .await;
            let logs = h.controller.shared_proxy_access_logs().await.ok()?;
            logs.into_iter().find(|row| {
                row.get("mirror").and_then(|v| v.as_bool()) == Some(true)
                    && row.get("host").and_then(|v| v.as_str()) == Some(host.as_str())
            })
        },
    )
    .await?; // poll_until returns Ok(row) when found, or Err on timeout

    Ok(())
}

/// Verifies that the primary route succeeds when the `mirror-target` Service has no
/// ready endpoints (sad path for `ingress.coxswain-labs.dev/mirror-target`, #283).
///
/// The fixture points `mirror-target` at port 9999 of `echo-b`, which has no
/// EndpointSlices; the reflector warns and disables the mirror filter entirely.
/// The primary route must still serve normally — mirror misconfiguration must
/// never degrade the primary path.
#[tokio::test]
async fn primary_succeeds_when_mirror_backend_unreachable() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tp-ing-mirror-bad").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_MIRROR_TARGET_UNREACHABLE,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("mirrorbad.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60))
        .await?
        .assert_backend("echo-a");

    // Primary must return 200 with no mirror failure visible to the client.
    let (status, body) = h.http.request(Method::GET, &host, "/", &[]).await?;
    assert_eq!(
        status, 200,
        "primary GET must succeed even when mirror backend is unreachable; host={host}"
    );
    body.expect("primary response must carry echo JSON")
        .assert_backend("echo-a");

    // Mirror was disabled at reconcile time (no ready endpoints on port 9999),
    // so no mirror=true access-log row should appear for this host.
    let logs = h.controller.shared_proxy_access_logs().await?;
    let mirror_fired = logs.iter().any(|row| {
        row.get("mirror").and_then(|v| v.as_bool()) == Some(true)
            && row.get("host").and_then(|v| v.as_str()) == Some(host.as_str())
    });
    assert!(
        !mirror_fired,
        "mirror was disabled at reconcile time (no ready endpoints on port 9999); \
         no mirror=true access-log row must appear for host={host}"
    );

    Ok(())
}

/// Verifies stream-concurrent mirroring works without `max-body-size` (#360).
///
/// The fixture has `mirror-target` set but no `max-body-size`.  The proxy must
/// stream the request body to the mirror backend as chunks arrive (no buffering),
/// producing an access-log `mirror = true` row for the host.  This confirms that
/// body mirroring no longer requires a body-size cap annotation.
#[tokio::test]
async fn mirror_body_forwarded_without_max_body_size() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tp-ing-mirror-nombs").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_MIRROR_TARGET_NO_MAX_BODY,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("mirrornombs.{}.local", ns.name);
    let route = wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    route.assert_backend("echo-a");

    // POST with a body to exercise the streaming mirror path.  No max-body-size
    // is set, so the proxy must forward body chunks directly to the mirror channel.
    let (status, body) = h
        .http
        .request_with_body(Method::POST, &host, "/", b"hello stream mirror".to_vec())
        .await?;
    assert_eq!(status, 200, "primary POST must succeed; host={host}");
    body.expect("primary response must carry echo JSON")
        .assert_backend("echo-a");

    // Re-drive the POST on every poll iteration (mirror is fire-and-forget; a
    // single copy can be lost during endpoint propagation) until a mirror=true
    // access-log row appears for this host.
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async { format!("a mirror=true access-log row to appear for host={host}") },
        || async {
            let _ = h
                .http
                .request_with_body(Method::POST, &host, "/", b"hello stream mirror".to_vec())
                .await;
            let logs = h.controller.shared_proxy_access_logs().await.ok()?;
            logs.into_iter().find(|row| {
                row.get("mirror").and_then(|v| v.as_bool()) == Some(true)
                    && row.get("host").and_then(|v| v.as_str()) == Some(host.as_str())
            })
        },
    )
    .await?;

    Ok(())
}

/// Baseline (sad/negative): a backend with no session-affinity annotation keeps plain
/// round-robin and never injects an affinity cookie.
#[tokio::test]
async fn requests_round_robin_across_backends_when_no_affinity_annotation() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "aff-none").await?;

    fixtures::apply_fixture(ingress::SESSION_AFFINITY_NONE, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["echo-aff"]).await?;
    let host = format!("affinity.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    // All 3 echo-aff endpoints must be live in the proxy before asserting
    // distribution — EndpointSlice propagation lags the Deployment Available
    // condition, so a single pass right after route-live can see only one pod.
    wait::wait_for_distinct_backends(&h.http, &host, "/", 3, Duration::from_secs(60)).await?;

    let mut pods = std::collections::HashSet::new();
    for i in 0..30 {
        let (status, hdrs, body) = h.http.get_full(&host, "/").await?;
        assert_eq!(status, 200, "request {i} must succeed");
        assert!(
            hdrs.get(reqwest::header::SET_COOKIE).is_none(),
            "request {i}: a backend without affinity must not inject any cookie"
        );
        if let Some(p) = body.and_then(|b| b.pod) {
            pods.insert(p);
        }
    }
    assert!(
        pods.len() >= 2,
        "a no-affinity backend must round-robin across pods, saw {pods:?}"
    );
    Ok(())
}

/// Happy path (#266): `ingress.coxswain-labs.dev/upstream-keepalive-timeout: 60s`
/// causes Pingora to keep idle upstream connections alive for 60 s.
///
/// After the route is installed, 20 sequential requests are fired on a single
/// keep-alive client connection. At least one of those requests must reuse an
/// existing upstream connection — asserted via
/// `coxswain_proxy_upstream_connections_total{state="reused"}` on the admin
/// /metrics endpoint.
///
/// Determinism: all requests go to the same single-backend route; a 60-second
/// idle window exceeds any CI scheduling jitter between sequential HTTP requests.
/// No bare sleeps — the metric assert is polled via `poll_until`.
#[tokio::test]
async fn upstream_keepalive_reuses_connections() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "kp-reuse").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_KEEPALIVE_TIMEOUT,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("keepalive.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // Fire 20 sequential requests — the keepalive pool is warm after the first,
    // so every subsequent request reuses the existing upstream connection.
    for i in 0..20u32 {
        let (status, _, _) = h.http.get_full(&host, "/").await?;
        assert_eq!(status, 200, "sequential request {i} must return 200");
    }

    // Poll the admin metrics endpoint until the reused counter appears and is > 0.
    wait::poll_until(
        Duration::from_secs(10),
        wait::POLL,
        || async {
            "coxswain_proxy_upstream_connections_total{state=\"reused\"} to be > 0".to_string()
        },
        || async {
            let metrics = reqwest::get(h.admin_url("/metrics"))
                .await
                .ok()?
                .text()
                .await
                .ok()?;
            // The Prometheus text format line looks like:
            //   coxswain_proxy_upstream_connections_total{state="reused"} N
            // We parse the N and check it is > 0.
            metrics.lines().find_map(|line| {
                if line.starts_with("coxswain_proxy_upstream_connections_total{")
                    && line.contains("state=\"reused\"")
                {
                    let count: u64 = line.split_whitespace().last()?.parse().ok()?;
                    if count > 0 { Some(count) } else { None }
                } else {
                    None
                }
            })
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("reused connection counter never climbed above 0: {e}"))?;

    Ok(())
}

// ── Compression (#270, converged to a CR reference in #550) ──────────────────

/// Happy path (#270, #550): a route annotated with
/// `compression: "ns/name"` referencing a `Compression` CR (`gzip: true`,
/// `minSize: 1`) returns a gzip-compressed body when the client sends
/// `Accept-Encoding: gzip`. Both the Ingress annotation and the HTTPRoute
/// `ExtensionRef` filter (see the `gateway_compression_*` tests below)
/// resolve the same CR through the identical spec→config translation, so
/// this also proves cross-surface parity.
///
/// Asserts:
/// - Status 200.
/// - `Content-Encoding: gzip` is set on the response.
/// - `Vary` contains `Accept-Encoding`.
/// - `Content-Length` is absent (body is chunked after compression).
/// - The gzip-decompressed body is valid JSON (the echo response).
#[tokio::test]
async fn compression_gzip_compresses_eligible_response() -> anyhow::Result<()> {
    use flate2::read::GzDecoder;
    use std::io::Read as _;

    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "comp-gzip").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_COMPRESSION_GZIP,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("compression-gzip.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    let (status, resp_headers, body) = h
        .http
        .get_full_raw(&host, "/", &[("Accept-Encoding", "gzip")])
        .await?;

    assert_eq!(
        status, 200,
        "compression-gzip route must return 200; got {status}"
    );
    assert_eq!(
        resp_headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok()),
        Some("gzip"),
        "proxy must set Content-Encoding: gzip on the response"
    );
    let vary = resp_headers
        .get("vary")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        vary.to_ascii_lowercase().contains("accept-encoding"),
        "Vary must include Accept-Encoding (got: {vary:?})"
    );
    assert!(
        resp_headers.get("content-length").is_none(),
        "Content-Length must be absent after compression (body is now chunked)"
    );

    // Decompress and check that the body is valid JSON.
    let mut decoder = GzDecoder::new(body.as_ref());
    let mut decompressed = String::new();
    decoder
        .read_to_string(&mut decompressed)
        .map_err(|e| anyhow::anyhow!("failed to gzip-decompress response: {e}"))?;
    serde_json::from_str::<serde_json::Value>(&decompressed).map_err(|e| {
        anyhow::anyhow!("decompressed body is not valid JSON: {e}; body: {decompressed}")
    })?;

    Ok(())
}

/// Behaviour test (#270, #550): when a `compression`-referenced `Compression`
/// CR enables both `gzip` and `brotli`, brotli is preferred when the client
/// advertises `br` in `Accept-Encoding`.
///
/// Asserts `Content-Encoding: br` when the client sends `Accept-Encoding: br, gzip`.
#[tokio::test]
async fn compression_prefers_brotli_when_client_supports_br() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "comp-brotli").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_COMPRESSION_BROTLI,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("compression-brotli.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    let (status, resp_headers, _) = h
        .http
        .get_full_raw(&host, "/", &[("Accept-Encoding", "br, gzip")])
        .await?;

    assert_eq!(
        status, 200,
        "compression-brotli route must return 200; got {status}"
    );
    assert_eq!(
        resp_headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok()),
        Some("br"),
        "brotli must be preferred over gzip when both enabled and br offered"
    );

    Ok(())
}

/// Sad path (#270, #550): the proxy passes a response through uncompressed
/// when its `Content-Length` is below the referenced CR's `minSize`
/// threshold (1 MiB here).
///
/// The echo backend's JSON response is always well under 1 MiB, so the proxy
/// must skip compression entirely. Asserts no `Content-Encoding` header.
#[tokio::test]
async fn compression_skips_response_below_min_size() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "comp-minsize").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_COMPRESSION_MIN_SIZE,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("compression-minsize.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    let (status, resp_headers, _) = h
        .http
        .get_full_raw(&host, "/", &[("Accept-Encoding", "gzip")])
        .await?;

    assert_eq!(
        status, 200,
        "route must still return 200 when response is below min-size"
    );
    assert!(
        resp_headers.get("content-encoding").is_none(),
        "proxy must NOT compress responses below compression-min-size"
    );

    Ok(())
}

/// Sad path (#270, #550): the proxy passes a response through uncompressed
/// when its `Content-Type` is not in the referenced CR's `types` allow-list.
///
/// The fixture allows only `text/plain`; the echo backend responds with
/// `application/json`. Asserts no `Content-Encoding` header.
#[tokio::test]
async fn compression_skips_disallowed_content_type() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "comp-types").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_COMPRESSION_TYPES,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("compression-types.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    let (status, resp_headers, _) = h
        .http
        .get_full_raw(&host, "/", &[("Accept-Encoding", "gzip")])
        .await?;

    assert_eq!(
        status, 200,
        "route must still return 200 when content-type is not in compression-types"
    );
    assert!(
        resp_headers.get("content-encoding").is_none(),
        "proxy must NOT compress application/json when only text/plain is in compression-types"
    );

    Ok(())
}

/// Sad path (#550): `compression` references a `Compression` CR that does not
/// exist. Unlike the auth annotation family (`ext-auth`/`auth-basic-secret`/
/// `auth-jwt`), which fails **closed** (503) on a missing CR, compression
/// fails **open** — the route still serves 200, uncompressed.
#[tokio::test]
async fn ingress_compression_passthrough_when_cr_missing() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "comp-missing").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_COMPRESSION_MISSING,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("compression-missing.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    let (status, resp_headers, _) = h
        .http
        .get_full_raw(&host, "/", &[("Accept-Encoding", "gzip")])
        .await?;

    assert_eq!(
        status, 200,
        "route must still return 200 when the Compression CR reference is missing (fail-open)"
    );
    assert!(
        resp_headers.get("content-encoding").is_none(),
        "proxy must NOT compress when the referenced Compression CR does not exist"
    );

    Ok(())
}

// ── Compression ExtensionRef (Gateway API, #446) ──────────────────────────────
//
// The `application/grpc*` passthrough guard (never compress a gRPC-over-HTTPRoute
// response, regardless of `types` config) is covered by the proxy unit tests in
// `crates/coxswain-proxy/src/policy/compression.rs` — constructing a real
// gRPC-content-type HTTPRoute response end-to-end adds no additional coverage
// over the deterministic unit tests and isn't exercised here.

/// `Compression` CR via `ExtensionRef`: with gzip enabled and `minSize: 1`, a
/// request advertising `Accept-Encoding: gzip` gets a gzip-compressed response
/// (#446 happy path — also proves the ExtensionRef is accepted on HTTPRoute).
#[tokio::test]
async fn gateway_compression_gzip_compresses_eligible_response() -> anyhow::Result<()> {
    use flate2::read::GzDecoder;
    use std::io::Read as _;

    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-comp-gzip").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::COMPRESSION_EXTENSIONREF, FixtureVars::new(&ns.name)).await?;

    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwcompression.{}.local", ns.name);
    wait::wait_for_route(&gw, &host, "/", Duration::from_secs(60)).await?;

    let (status, resp_headers, body) = gw
        .get_full_raw(&host, "/", &[("Accept-Encoding", "gzip")])
        .await?;

    assert_eq!(status, 200, "gateway compression route must return 200");
    assert_eq!(
        resp_headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok()),
        Some("gzip"),
        "proxy must set Content-Encoding: gzip on the response"
    );
    let vary = resp_headers
        .get("vary")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        vary.to_ascii_lowercase().contains("accept-encoding"),
        "Vary must include Accept-Encoding (got: {vary:?})"
    );

    let mut decoder = GzDecoder::new(body.as_ref());
    let mut decompressed = String::new();
    decoder
        .read_to_string(&mut decompressed)
        .map_err(|e| anyhow::anyhow!("failed to gzip-decompress response: {e}"))?;
    serde_json::from_str::<serde_json::Value>(&decompressed).map_err(|e| {
        anyhow::anyhow!("decompressed body is not valid JSON: {e}; body: {decompressed}")
    })?;

    Ok(())
}

/// `Compression` CR via `ExtensionRef`: with both gzip and brotli enabled,
/// brotli is preferred when the client advertises `br` in `Accept-Encoding`
/// (#446 behaviour).
#[tokio::test]
async fn gateway_compression_prefers_brotli_when_client_supports_br() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-comp-brotli").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::COMPRESSION_EXTENSIONREF, FixtureVars::new(&ns.name)).await?;

    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwcompression.{}.local", ns.name);
    wait::wait_for_route(&gw, &host, "/", Duration::from_secs(60)).await?;

    let (status, resp_headers, _) = gw
        .get_full_raw(&host, "/", &[("Accept-Encoding", "br, gzip")])
        .await?;

    assert_eq!(status, 200, "gateway compression route must return 200");
    assert_eq!(
        resp_headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok()),
        Some("br"),
        "brotli must be preferred over gzip when both enabled and br offered"
    );

    Ok(())
}

/// `Compression` CR via `ExtensionRef`: a client that sends no `Accept-Encoding`
/// gets the response uncompressed — the proxy never forces an encoding the
/// client didn't advertise (#446 sad path).
#[tokio::test]
async fn gateway_compression_passthrough_without_accept_encoding() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-comp-passthrough").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::COMPRESSION_EXTENSIONREF, FixtureVars::new(&ns.name)).await?;

    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("gwcompression.{}.local", ns.name);
    wait::wait_for_route(&gw, &host, "/", Duration::from_secs(60)).await?;

    let (status, resp_headers, _) = gw.get_full_raw(&host, "/", &[]).await?;

    assert_eq!(status, 200, "gateway compression route must return 200");
    assert!(
        resp_headers.get("content-encoding").is_none(),
        "proxy must NOT compress when the client sends no Accept-Encoding"
    );

    Ok(())
}

/// Sad path (#266, #29 VAP): an unparseable `upstream-keepalive-timeout` value is
/// rejected by the VAP at admission time. Fail-open proxy semantics remain the
/// backstop for VAP-disabled installs, verified by the reflector unit tests.
#[tokio::test]
async fn upstream_keepalive_invalid_timeout_rejected_by_vap() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "kp-bad").await?;

    let msg = fixtures::apply_fixture_expect_rejected(
        ingress::ANNOTATION_KEEPALIVE_TIMEOUT_INVALID,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("upstream-keepalive-timeout"),
        "VAP rejection message must name the offending annotation, got: {msg}"
    );

    Ok(())
}

// ── Load-balance algorithms (#275) ────────────────────────────────────────────

/// Happy path (#275): with `load-balance: least_conn`, the proxy accumulates
/// in-flight counts per endpoint and routes new requests to whichever endpoint
/// has the fewest active connections.
///
/// The fixture routes to `lb-pool`, a Service backed by two pods:
/// - `lb-fast` (echo-basic) — responds in < 1 ms.
/// - `lb-slow` (go-httpbin) — holds the connection for 1 second via `/delay/1`.
///
/// 20 requests are issued with a concurrency of 4. Once `lb-slow` holds a slot
/// for 1 second, all subsequent selections prefer `lb-fast` (active=0 vs active≥1).
/// Asserts `fast_count > slow_count` and `slow_count ≥ 1` (both endpoints reachable).
#[tokio::test]
async fn least_conn_sends_more_requests_to_the_fast_upstream() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "lb-leastconn").await?;

    fixtures::apply_fixture(backends::LB_MIXED, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["lb-fast", "lb-slow"]).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_LOAD_BALANCE_LEAST_CONN,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("lb.{}.local", ns.name);
    // Route readiness: both backends return 200 for /delay/1 (echo instantly, httpbin after 1s).
    wait::wait_for_route_status(&h.http, &host, "/delay/1", 200, Duration::from_secs(90)).await?;
    // BOTH lb-pool endpoints (lb-fast + lb-slow) must be compiled into the route
    // before the burst: if only one is propagated, the distribution assertions
    // (fast > slow, slow >= 1) are decided by which endpoint happened to land
    // first. lb-slow (go-httpbin) sets no POD_NAME, so count endpoints via the
    // admin route table rather than by sampling distinct pod names.
    wait::wait_for_route_endpoints(
        &h.shared_proxy_routes_url().await?,
        &host,
        2,
        Duration::from_secs(60),
    )
    .await?;

    // Pipelined concurrency: 20 requests with up to 4 in-flight at a time.
    // `lb-slow` holds each connection for 1 s; new selections see lb-slow.active ≥ 1
    // and route to lb-fast instead. A standalone reqwest client (10 s timeout — the
    // slow backend needs headroom under load) is spawned per task; each send routes
    // through `get_with_transient_retry` so a one-off connection blip under the
    // parallel profile is retried rather than failing the distribution count.
    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?,
    );
    let sem = Arc::new(tokio::sync::Semaphore::new(4));
    let proxy_addr = h.http.proxy_addr;

    let handles: Vec<_> = (0..20u32)
        .map(|_| {
            let client = Arc::clone(&client);
            let sem = Arc::clone(&sem);
            let url = format!("http://{proxy_addr}/delay/1");
            let host = host.clone();
            tokio::spawn(async move {
                let _permit = sem
                    .acquire_owned()
                    .await
                    .map_err(|e| anyhow::anyhow!("semaphore closed: {e}"))?;
                let resp =
                    coxswain_e2e::harness::http::get_with_transient_retry(&client, &url, &host, 3)
                        .await
                        .map_err(|e| anyhow::anyhow!("send: {e}"))?;
                let status = resp.status().as_u16();
                anyhow::ensure!(status == 200, "expected 200, got {status}");
                let body = resp
                    .json::<serde_json::Value>()
                    .await
                    .map_err(|e| anyhow::anyhow!("parse body: {e}"))?;
                Ok::<Option<String>, anyhow::Error>(body["pod"].as_str().map(String::from))
            })
        })
        .collect();

    let mut fast_count = 0usize;
    let mut slow_count = 0usize;
    for handle in handles {
        let pod_opt = handle.await.map_err(|e| anyhow::anyhow!("task: {e}"))??;
        // lb-fast (echo-basic) sets POD_NAME; lb-slow (go-httpbin) does not.
        if pod_opt
            .as_deref()
            .is_some_and(|p| p.starts_with("lb-fast-"))
        {
            fast_count += 1;
        } else {
            slow_count += 1;
        }
    }

    assert!(
        fast_count > slow_count,
        "least_conn must route more requests to the fast upstream; \
         fast_count={fast_count}, slow_count={slow_count}"
    );
    assert!(
        slow_count >= 1,
        "least_conn must route at least one request to the slow upstream \
         (both endpoints reachable); fast_count={fast_count}, slow_count={slow_count}"
    );

    Ok(())
}

/// Happy path (#275): with `load-balance: ip_hash`, all requests from the same
/// source IP must hash to the same endpoint, pinning the client to one pod for
/// the lifetime of the route.
///
/// The fixture routes to `echo-two-replicas` (2 pods). The test runner's source
/// IP is `127.0.0.1` (port-forwarded loopback), which hashes to a fixed slot.
/// All 10 sequential GETs must return the same `pod` name.
#[tokio::test]
async fn ip_hash_pins_a_client_to_one_upstream() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "lb-iphash").await?;

    fixtures::apply_fixture(backends::ECHO_TWO_REPLICAS, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["echo-two-replicas"]).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_LOAD_BALANCE_IP_HASH,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("lb.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    // Consistent-hash pins a single key (client IP / URI) to one pod; an endpoint
    // set that grows after the baseline rebalances the ring and moves the pin.
    // A single hash key can't sample the whole set, so confirm both endpoints are
    // compiled into the proxy route table before pinning the baseline.
    wait::wait_for_route_endpoints(
        &h.shared_proxy_routes_url().await?,
        &host,
        2,
        Duration::from_secs(60),
    )
    .await?;
    let pinned_pod = h
        .http
        .get(&host, "/")
        .await?
        .pod
        .expect("echo body must report the serving pod on first request");

    // All subsequent requests from the same source IP must land on the same pod.
    for i in 0..10u32 {
        let body = h.http.get(&host, "/").await?;
        let pod = body.pod.unwrap_or_default();
        assert_eq!(
            pod, pinned_pod,
            "ip_hash must pin the client to one pod (request {i}: got '{pod}', want '{pinned_pod}')"
        );
    }

    Ok(())
}

/// Sad path (#275, #29 VAP): an unknown `load-balance` value must be rejected
/// by the VAP at admission time with a message naming the offending annotation.
#[tokio::test]
async fn unknown_load_balance_value_rejected_by_vap() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "lb-unknown").await?;

    let msg = fixtures::apply_fixture_expect_rejected(
        ingress::ANNOTATION_LOAD_BALANCE_UNKNOWN,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("load-balance"),
        "VAP rejection message must name the offending annotation, got: {msg}"
    );

    Ok(())
}

/// Happy path (#276): with `load-balance: hash:uri`, every request to the same
/// URI must consistently hash (HRW) to the same upstream pod.
///
/// The fixture routes to `echo-two-replicas` (2 pods). The test fires 10 sequential
/// GETs to `/` and asserts they all reach the same pod (URI is stable, so the hash
/// key is stable). It then fires requests to a different path (`/other`) and asserts
/// those too are stable (possibly a different pod, but deterministic).
#[tokio::test]
async fn same_uri_always_reaches_the_same_upstream() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "lb-hash-uri").await?;

    fixtures::apply_fixture(backends::ECHO_TWO_REPLICAS, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["echo-two-replicas"]).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_LOAD_BALANCE_HASH_URI,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("lb.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    // Consistent-hash pins a single key (client IP / URI) to one pod; an endpoint
    // set that grows after the baseline rebalances the ring and moves the pin.
    // A single hash key can't sample the whole set, so confirm both endpoints are
    // compiled into the proxy route table before pinning the baseline.
    wait::wait_for_route_endpoints(
        &h.shared_proxy_routes_url().await?,
        &host,
        2,
        Duration::from_secs(60),
    )
    .await?;
    let pinned_pod = h
        .http
        .get(&host, "/")
        .await?
        .pod
        .expect("echo body must report the serving pod on first request");

    for i in 0..10u32 {
        let body = h.http.get(&host, "/").await?;
        let pod = body.pod.unwrap_or_default();
        assert_eq!(
            pod, pinned_pod,
            "hash:uri must pin '/' to one pod (request {i}: got '{pod}', want '{pinned_pod}')"
        );
    }

    // A different path may or may not land on a different pod, but must be stable.
    let first_other = h.http.get(&host, "/other").await?;
    let pinned_other = first_other.pod.unwrap_or_default();
    for i in 0..10u32 {
        let body = h.http.get(&host, "/other").await?;
        let pod = body.pod.unwrap_or_default();
        assert_eq!(
            pod, pinned_other,
            "hash:uri must pin '/other' to one pod (request {i}: got '{pod}', want '{pinned_other}')"
        );
    }

    Ok(())
}

/// Happy path (#276): with `load-balance: hash:header=x-hash-key`, every request
/// carrying the same `X-Hash-Key` header value must consistently reach the same pod.
///
/// The fixture routes to `echo-two-replicas` (2 pods). The test sends 10 sequential
/// GETs with `X-Hash-Key: alpha` and asserts they all land on one pod. It also sends
/// GETs with `X-Hash-Key: beta` and asserts those are stable (may differ from alpha).
#[tokio::test]
async fn same_hash_header_value_pins_the_upstream() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "lb-hash-hdr").await?;

    fixtures::apply_fixture(backends::ECHO_TWO_REPLICAS, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["echo-two-replicas"]).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_LOAD_BALANCE_HASH_HEADER,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("lb.{}.local", ns.name);

    // Wait until the route is live before sending the first header request —
    // wait_for_route polls with a plain GET; only after 200 do we know the
    // route is installed and pods are ready.
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    // Both endpoints must be propagated before we pin a hash key: adding an
    // endpoint mid-test rebalances the hash ring and moves the pinned pod.
    // Un-keyed requests fall back to round-robin, so this sees the full set.
    wait::wait_for_distinct_backends(&h.http, &host, "/", 2, Duration::from_secs(60)).await?;

    let (_, _, first_body) = h
        .http
        .get_full_with_headers(&host, "/", &[("x-hash-key", "alpha")])
        .await?;
    let pinned_alpha = first_body.and_then(|b| b.pod).unwrap_or_default();

    for i in 0..10u32 {
        let (status, _, body) = h
            .http
            .get_full_with_headers(&host, "/", &[("x-hash-key", "alpha")])
            .await?;
        assert_eq!(
            status, 200,
            "hash:header=x-hash-key must route successfully (request {i} returned {status})"
        );
        let pod = body.and_then(|b| b.pod).unwrap_or_default();
        assert_eq!(
            pod, pinned_alpha,
            "X-Hash-Key: alpha must always reach the same pod \
             (request {i}: got '{pod}', want '{pinned_alpha}')"
        );
    }

    // A different header value may hash to a different pod, but must itself be stable.
    let (_, _, first_beta) = h
        .http
        .get_full_with_headers(&host, "/", &[("x-hash-key", "beta")])
        .await?;
    let pinned_beta = first_beta.and_then(|b| b.pod).unwrap_or_default();
    for i in 0..10u32 {
        let (status, _, body) = h
            .http
            .get_full_with_headers(&host, "/", &[("x-hash-key", "beta")])
            .await?;
        assert_eq!(
            status, 200,
            "X-Hash-Key: beta must route successfully (request {i})"
        );
        let pod = body.and_then(|b| b.pod).unwrap_or_default();
        assert_eq!(
            pod, pinned_beta,
            "X-Hash-Key: beta must always reach the same pod \
             (request {i}: got '{pod}', want '{pinned_beta}')"
        );
    }

    Ok(())
}

/// Sad path (#276): with `load-balance: hash:header=x-hash-key`, requests that
/// omit the header must fall back to round-robin. The test fires 30 requests
/// without `X-Hash-Key` and asserts that both pods are reached, proving the
/// fallback distributes traffic rather than pinning to one upstream.
#[tokio::test]
async fn missing_hash_attribute_falls_back_to_round_robin() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "lb-hash-fb").await?;

    fixtures::apply_fixture(backends::ECHO_TWO_REPLICAS, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["echo-two-replicas"]).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_LOAD_BALANCE_HASH_HEADER,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("lb.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    // Both endpoints must be live before asserting the fallback distributes —
    // an un-keyed request round-robins, so this also confirms full propagation.
    wait::wait_for_distinct_backends(&h.http, &host, "/", 2, Duration::from_secs(60)).await?;

    let mut pods = std::collections::HashSet::new();
    for i in 0..30u32 {
        let (status, _, body) = h.http.get_full(&host, "/").await?;
        assert_eq!(
            status, 200,
            "hash:header fallback must not break routing (request {i} returned {status})"
        );
        if let Some(p) = body.and_then(|b| b.pod) {
            pods.insert(p);
        }
    }
    assert!(
        pods.len() >= 2,
        "missing hash attribute must fall back to round_robin and spread across \
         both pods; saw only {pods:?}"
    );

    Ok(())
}

// ── Circuit breaker (#282) ────────────────────────────────────────────────────
//
// Annotations exercised (satisfies check-annotation-coverage.sh rubric #11):
//   ingress.coxswain-labs.dev/circuit-breaker-threshold
//   ingress.coxswain-labs.dev/circuit-breaker-window
//   ingress.coxswain-labs.dev/circuit-breaker-open-duration
//   ingress.coxswain-labs.dev/circuit-breaker-min-requests
//   ingress.coxswain-labs.dev/circuit-breaker-max-open-duration
//
// The fixture sets threshold=50%, min-requests=4, window=500ms, open-duration=2s.
// window=500ms is sub-second: failsafe's EWMA time gate (elapsed >= window_millis)
// is always satisfied because 500ms.as_secs()*1000 == 0. This lets the breaker trip
// as soon as min-requests is met without sleeping in the test body.
// go-httpbin's /status/:code lets tests drive configurable upstream status codes.

/// Happy path (#282): after enough upstream 500s the EWMA success rate falls
/// below `threshold`, the circuit breaker opens, and subsequent requests are
/// fail-fast 503 (never reaching the upstream).
///
/// Asserts the negative: a single baseline error is a real upstream 500 (breaker
/// still closed). After the trip batch, requests fail-fast as 503.
/// Also asserts the `coxswain_proxy_circuit_breaker_state` gauge reads `1`
/// (open) and `coxswain_proxy_circuit_breaker_rejected_total` is > 0.
#[tokio::test]
async fn breaker_opens_and_fails_fast_when_upstream_errors() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tp-cb-open").await?;

    fixtures::apply_fixture(backends::GO_HTTPBIN, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["go-httpbin"]).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_CIRCUIT_BREAKER,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("breaker.{}.local", ns.name);
    let proxy = h.http.proxy_addr;

    // Route readiness: poll /status/200 until the proxy forwards it to go-httpbin.
    // (Uses raw_status to avoid EchoResponse JSON-parse failure on go-httpbin's body.)
    // Note: readiness requests go through the circuit breaker and contribute to its
    // rolling request counter — we send enough errors below to guarantee the trip
    // threshold is reached regardless of how many readiness requests are still in
    // the 500ms window.
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            format!(
                "breaker.{}.local / route to return 200 from go-httpbin",
                ns.name
            )
        },
        || async {
            if raw_status(proxy, &host, "/status/200").await == 200 {
                Some(())
            } else {
                None
            }
        },
    )
    .await?;

    // Negative baseline: the circuit breaker is still closed — the first error
    // must reach the upstream (500), not be rejected by the breaker (503).
    let pre = raw_status(proxy, &host, "/status/500").await;
    assert_eq!(
        pre, 500,
        "before the trip sequence the upstream 500 must reach the client (not a breaker 503)"
    );

    // Trip sequence: send enough errors to guarantee the breaker opens, regardless
    // of how many readiness /status/200 requests are still in the rolling window.
    // Individual responses may be 500 (breaker still closing) or 503 (just opened);
    // we assert only the final state below.
    for _ in 0..8u32 {
        raw_status(proxy, &host, "/status/500").await;
    }

    // The breaker is now open. The next request must be fail-fast 503.
    let open_status = raw_status(proxy, &host, "/status/500").await;
    assert_eq!(
        open_status, 503,
        "after the trip sequence the circuit breaker must fail-fast with 503 \
         (circuit-breaker-threshold=50%, circuit-breaker-min-requests=4)"
    );

    // Metric: coxswain_proxy_circuit_breaker_state for this route must be 1 (open).
    // Filter by ns.name to avoid matching entries from other concurrent tests.
    let metrics = reqwest::get(h.admin_url("/metrics")).await?.text().await?;
    let ns_route = format!("route=\"ingress/{}/", ns.name);
    assert!(
        metrics.lines().any(|line| {
            line.starts_with("coxswain_proxy_circuit_breaker_state{")
                && line.contains(&ns_route)
                && line.split_whitespace().last().is_some_and(|v| v == "1")
        }),
        "coxswain_proxy_circuit_breaker_state must equal 1 (open) for route in ns {}; \
         metrics:\n{metrics}",
        ns.name
    );

    // Metric: coxswain_proxy_circuit_breaker_rejected_total > 0 for this route.
    assert!(
        metrics.lines().any(|line| {
            line.starts_with("coxswain_proxy_circuit_breaker_rejected_total{")
                && line.contains(&ns_route)
                && line
                    .split_whitespace()
                    .last()
                    .and_then(|v| v.parse::<u64>().ok())
                    .is_some_and(|n| n > 0)
        }),
        "coxswain_proxy_circuit_breaker_rejected_total must be > 0 for route in ns {}; \
         metrics:\n{metrics}",
        ns.name
    );

    Ok(())
}

/// Sad / recovery path (#282): after the breaker opens, `circuit-breaker-open-duration`
/// expires and the breaker transitions to HalfOpen, allowing a probe request
/// through. When the probe succeeds (upstream returns 200), the breaker closes
/// and subsequent requests are served normally.
///
/// Also checks that `coxswain_proxy_circuit_breaker_state` is no longer `1`
/// (open) and that `coxswain_proxy_circuit_breaker_transitions_total{to="closed"}`
/// is > 0 after recovery.
#[tokio::test]
async fn breaker_closes_after_open_duration_when_upstream_recovers() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tp-cb-recover").await?;

    fixtures::apply_fixture(backends::GO_HTTPBIN, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["go-httpbin"]).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_CIRCUIT_BREAKER,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("breaker.{}.local", ns.name);
    let proxy = h.http.proxy_addr;

    // Route readiness.
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            format!(
                "breaker.{}.local / route to return 200 from go-httpbin",
                ns.name
            )
        },
        || async {
            if raw_status(proxy, &host, "/status/200").await == 200 {
                Some(())
            } else {
                None
            }
        },
    )
    .await?;

    // Trip sequence: send enough errors to guarantee the breaker opens.
    // (Readiness requests may already be in the window counter; we over-shoot
    // min-requests to be robust to that.)
    for _ in 0..8u32 {
        raw_status(proxy, &host, "/status/500").await;
    }

    // Verify the breaker is open before testing recovery.
    let open_status = raw_status(proxy, &host, "/status/500").await;
    assert_eq!(
        open_status, 503,
        "breaker must be open (503) before the recovery window; \
         if 500, the trip sequence did not open the breaker"
    );

    // Recovery: poll /status/200 until the proxy forwards it (200).
    // After `circuit-breaker-open-duration` (2s) the breaker transitions to
    // HalfOpen; the next permitted request goes to go-httpbin → 200 → closes.
    // No bare sleep: poll_until waits on the real observable (200 response).
    wait::poll_until(
        Duration::from_secs(15),
        wait::POLL_FAST,
        || async { "circuit breaker to close (expecting 200 from /status/200)".to_string() },
        || async {
            if raw_status(proxy, &host, "/status/200").await == 200 {
                Some(())
            } else {
                None
            }
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("circuit breaker did not close within 15 s: {e}"))?;

    // Metric: state gauge for this route must not be 1 (open) after recovery.
    // Filter by ns.name to avoid matching entries from other concurrent tests.
    let metrics = reqwest::get(h.admin_url("/metrics")).await?.text().await?;
    let ns_route = format!("route=\"ingress/{}/", ns.name);
    assert!(
        !metrics.lines().any(|line| {
            line.starts_with("coxswain_proxy_circuit_breaker_state{")
                && line.contains(&ns_route)
                && line.split_whitespace().last().is_some_and(|v| v == "1")
        }),
        "coxswain_proxy_circuit_breaker_state must not be 1 (open) for route in ns {} \
         after recovery; metrics:\n{metrics}",
        ns.name
    );

    // Metric: transitions_total{to="closed"} > 0 for this route proves the breaker closed.
    assert!(
        metrics.lines().any(|line| {
            line.starts_with("coxswain_proxy_circuit_breaker_transitions_total{")
                && line.contains(&ns_route)
                && line.contains("to=\"closed\"")
                && line
                    .split_whitespace()
                    .last()
                    .and_then(|v| v.parse::<u64>().ok())
                    .is_some_and(|n| n > 0)
        }),
        "coxswain_proxy_circuit_breaker_transitions_total{{to=\"closed\"}} must be > 0 \
         for route in ns {} after the breaker closes; metrics:\n{metrics}",
        ns.name
    );

    Ok(())
}
