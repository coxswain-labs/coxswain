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
    let _ic_guard = IngressClassGuard::new(&ic_name);

    fixtures::apply_fixture(ingress::CLASS_DEFAULT_TIMEOUT, FixtureVars::new(&ns.name)).await?;

    let host = format!("clstimeout.{}.local", ns.name);

    // 502 doubles as the readiness signal: once the route is installed every
    // request black-holes on connect and returns 502 within the 500ms deadline
    // supplied by the class default.
    wait::wait_for_route_status(&h.http, &host, "/", 502, Duration::from_secs(60)).await?;

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
    let ns = NamespaceGuard::create(&h.client, "ing-maxbody").await?;

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

/// Verifies that an unparseable `max-body-size` value fails open (#263): the limit is
/// ignored and an oversized 4 KiB POST still reaches the backend (200). Proves an
/// invalid size can never block traffic — the inverse of the enforced case above.
#[tokio::test]
async fn max_body_size_invalid_value_fails_open() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-maxbody-bad").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_MAX_BODY_SIZE_INVALID,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("maxbodybad.{}.local", ns.name);

    wait::wait_for_route_status(&h.http, &host, "/", 200, Duration::from_secs(60)).await?;

    let (status, body) = h
        .http
        .request_with_body(reqwest::Method::POST, &host, "/", vec![b'x'; 4096])
        .await?;
    assert_eq!(
        status, 200,
        "fail-open: oversized POST must still be served when the limit is invalid"
    );
    body.expect("served POST must return an echo body")
        .assert_backend("echo-a");

    Ok(())
}

/// `cache-enabled` happy path (#40): with caching opted in and the upstream
/// response made cacheable (`Cache-Control: max-age=300` injected via
/// `response-header-set`), a second identical GET is served from cache. Pingora
/// stamps an `Age` header only on cache hits, so its presence is the black-box
/// proof the response came from the cache rather than the upstream.
#[tokio::test]
async fn response_served_from_cache_when_cache_enabled_and_cacheable() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-cache-hit").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_CACHE_ENABLED,
        FixtureVars::new(&ns.name).with("CACHE_CONTROL", "max-age=300"),
    )
    .await?;

    let host = format!("cache.{}.local", ns.name);

    // Route install (a cache MISS that fills the entry); also pins backend identity.
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60))
        .await?
        .assert_backend("echo-a");

    // Poll an identical GET until it is served from cache (carries `Age`). Polling
    // absorbs the gap between install and the first cacheable fill without a sleep.
    let served = wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            match h.http.get_full(&host, "/").await {
                Ok((status, hdrs, _)) => format!(
                    "a cache hit; last status={status}, age_present={}",
                    hdrs.contains_key(reqwest::header::AGE)
                ),
                Err(e) => format!("a cache hit; last attempt failed: {e}"),
            }
        },
        || async {
            match h.http.get_full(&host, "/").await {
                Ok((200, hdrs, body)) if hdrs.contains_key(reqwest::header::AGE) => Some(body),
                _ => None,
            }
        },
    )
    .await?;
    served
        .expect("cache hit must carry the echo JSON body")
        .assert_backend("echo-a");

    Ok(())
}

/// `cache-enabled` sad path (#40): a response marked `Cache-Control: no-store`
/// is never admitted to the cache, so no identical follow-up GET is ever served
/// from cache (no `Age` header appears). Caching being *enabled* on the route
/// must not override the upstream's explicit no-store directive.
#[tokio::test]
async fn response_not_cached_when_response_is_no_store() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-cache-nostore").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_CACHE_ENABLED,
        FixtureVars::new(&ns.name).with("CACHE_CONTROL", "no-store"),
    )
    .await?;

    let host = format!("cache.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60))
        .await?
        .assert_backend("echo-a");

    // Once the route is live, no-store guarantees the entry is never stored, so
    // every subsequent identical GET is a fresh upstream hit (no `Age`).
    for i in 0..4 {
        let (status, hdrs, _) = h.http.get_full(&host, "/").await?;
        assert_eq!(status, 200, "request {i} must succeed");
        assert!(
            !hdrs.contains_key(reqwest::header::AGE),
            "request {i}: a no-store response must never be served from cache, \
             but an Age header appeared"
        );
    }

    Ok(())
}

/// `cache-enabled` sad path (#40): a request carrying `Authorization` bypasses
/// the cache even when the route opted in and a fresh entry is warm — per-user
/// credentials must never be answered from a shared cache. The authorized reply
/// therefore carries no `Age` header.
#[tokio::test]
async fn request_bypasses_cache_when_authorization_header_present() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-cache-auth").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_CACHE_ENABLED,
        FixtureVars::new(&ns.name).with("CACHE_CONTROL", "max-age=300"),
    )
    .await?;

    let host = format!("cache.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // Warm the cache with an unauthenticated GET (poll until the entry is hot).
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            match h.http.get_full(&host, "/").await {
                Ok((s, hdrs, _)) => {
                    format!(
                        "warm cache; status={s}, age={}",
                        hdrs.contains_key(reqwest::header::AGE)
                    )
                }
                Err(e) => format!("warm cache; failed: {e}"),
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

    // An identical GET carrying Authorization must bypass the warm cache and be
    // answered fresh by the upstream — no `Age` header.
    let (status, hdrs, body) = h
        .http
        .get_full_with_headers(&host, "/", &[("Authorization", "Bearer test-token")])
        .await?;
    assert_eq!(status, 200, "authorized request must be served");
    assert!(
        !hdrs.contains_key(reqwest::header::AGE),
        "a request with Authorization must bypass the cache (no Age header), \
         but the response was served from cache"
    );
    body.expect("bypassed request must return a fresh echo body")
        .assert_backend("echo-a");

    Ok(())
}

/// Cache purge (#40): `DELETE /cache/{host}/{path}` on the proxy admin port
/// evicts the warm entry, so the next identical GET is a fresh upstream miss
/// (no `Age`). Proves the admin purge endpoint reaches the live data-plane cache.
#[tokio::test]
async fn cache_entry_purged_when_admin_delete_called() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-cache-purge").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_CACHE_ENABLED,
        FixtureVars::new(&ns.name).with("CACHE_CONTROL", "max-age=300"),
    )
    .await?;

    let host = format!("cache.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // Warm the cache (poll until a hit is observable).
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            match h.http.get_full(&host, "/").await {
                Ok((s, hdrs, _)) => {
                    format!(
                        "warm cache; status={s}, age={}",
                        hdrs.contains_key(reqwest::header::AGE)
                    )
                }
                Err(e) => format!("warm cache; failed: {e}"),
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

    // Purge the entry via the proxy admin port. `admin_url` targets the
    // shared-proxy pod, where the cache lives.
    let purge_url = h.admin_url(&format!("/cache/{host}/"));
    let resp = reqwest::Client::new().delete(&purge_url).send().await?;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "DELETE {purge_url} must return 200"
    );
    let purged: serde_json::Value = resp.json().await?;
    assert_eq!(
        purged["purged"],
        serde_json::Value::Bool(true),
        "purge must report an entry was removed; body={purged}"
    );

    // The next identical GET is now a fresh miss — no `Age` header.
    let (status, hdrs, _) = h.http.get_full(&host, "/").await?;
    assert_eq!(status, 200, "post-purge request must succeed");
    assert!(
        !hdrs.contains_key(reqwest::header::AGE),
        "after purge the next GET must be a fresh upstream miss (no Age), \
         but the response still carried an Age header"
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
    let mut pods = std::collections::HashSet::new();
    for k in 0..50 {
        let value = format!("user-{k}");
        let (_, _, body) = h
            .http
            .get_full_with_headers(&host, "/", &[("X-Session-Id", value.as_str())])
            .await?;
        if let Some(p) = body.and_then(|b| b.pod) {
            pods.insert(p);
        }
    }
    assert!(
        pods.len() >= 2,
        "distinct session ids must spread across multiple pods, saw {pods:?}"
    );
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

    let mut pods = std::collections::HashSet::new();
    for i in 0..30 {
        let (status, hdrs, body) = h.http.get_full(&host, "/").await?;
        assert_eq!(status, 200, "request {i} must succeed");
        assert!(
            hdrs.get(reqwest::header::SET_COOKIE).is_none(),
            "request {i}: header mode must not set a cookie even without the header"
        );
        if let Some(p) = body.and_then(|b| b.pod) {
            pods.insert(p);
        }
    }
    assert!(
        pods.len() >= 2,
        "without the affinity header, requests must round-robin across pods, saw {pods:?}"
    );
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
