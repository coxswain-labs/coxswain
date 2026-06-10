#![allow(missing_docs)]
//! E2E tests for zero-drop in-flight requests during Gateway listener add/remove
//! (issue #231).
//!
//! Each scenario:
//! 1. Starts the `dev` role (controller + proxy in one process).
//! 2. Applies a Gateway with one HTTP listener; waits for it to serve traffic.
//! 3. Launches N concurrent reqwest clients each sending M sequential requests
//!    to the "survivor" listener — count-based and deterministic.
//! 4. Mid-flight, patches the Gateway spec to add or remove a second listener.
//! 5. Asserts: **every** response on the survivor was 2xx; zero connection errors.
//!
//! The load harness is purely in-process Rust (`reqwest`), count-based, so CI
//! timing variance cannot cause flakes.

use anyhow::Context as _;
use gateway_api::apis::standard::gateways::Gateway;
use kube::api::{Api, Patch, PatchParams};
use reqwest::Method;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time;

use coxswain_e2e::{
    FixtureVars, Harness, NamespaceGuard,
    fixtures::{backends, gateway_api as gwa},
    harness::wait,
};

mod common;

// ── Concurrency parameters ────────────────────────────────────────────────────

/// Number of concurrent client tasks.
const CLIENTS: usize = 10;
/// Requests per client (total = CLIENTS × REQUESTS_PER_CLIENT = 2000).
const REQUESTS_PER_CLIENT: usize = 200;
/// After this many requests have succeeded (globally), apply the mid-flight patch.
const PATCH_AFTER_REQUESTS: u64 = 500;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Wait up to `timeout` for a 2xx GET on `addr/` with `Host: drain.<ns>.local`.
async fn wait_for_listener(addr: SocketAddr, host: &str, timeout: Duration) -> anyhow::Result<()> {
    let deadline = time::Instant::now() + timeout;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("build reqwest client")?;
    loop {
        let url = format!("http://{addr}/");
        match client.get(&url).header("Host", host).send().await {
            Ok(r) if r.status().is_success() => return Ok(()),
            _ => {}
        }
        if time::Instant::now() >= deadline {
            anyhow::bail!("listener at {addr} did not become ready within {timeout:?}");
        }
        time::sleep(Duration::from_millis(200)).await;
    }
}

// ── Sustained load harness ────────────────────────────────────────────────────

/// Result collected across all concurrent load clients.
struct LoadResult {
    /// Total requests attempted.
    total: u64,
    /// Responses with a non-2xx status (correctness invariant: must be 0).
    non_2xx: u64,
    /// Transport/connection errors.
    errors: u64,
}

/// Drive `CLIENTS × REQUESTS_PER_CLIENT` requests against `addr`.
///
/// After `PATCH_AFTER_REQUESTS` successful responses (globally), calls
/// `patch_fn` exactly once.
async fn run_load_with_midpoint_patch<F, Fut>(
    addr: SocketAddr,
    host: String,
    patch_fn: F,
) -> anyhow::Result<LoadResult>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = anyhow::Result<()>> + Send,
{
    let ok_count = Arc::new(AtomicU64::new(0));
    let non_2xx = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let patch_applied = Arc::new(AtomicU64::new(0));
    let patch_fn = Arc::new(patch_fn);

    let url_base = format!("http://{addr}/");

    let mut handles = Vec::with_capacity(CLIENTS);
    for _ in 0..CLIENTS {
        let ok_count = Arc::clone(&ok_count);
        let non_2xx = Arc::clone(&non_2xx);
        let errors = Arc::clone(&errors);
        let patch_applied = Arc::clone(&patch_applied);
        let patch_fn = Arc::clone(&patch_fn);
        let url = url_base.clone();
        let host = host.clone();

        handles.push(tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());

            for _ in 0..REQUESTS_PER_CLIENT {
                match client
                    .request(Method::GET, &url)
                    .header("Host", &host)
                    .send()
                    .await
                {
                    Ok(r) => {
                        if r.status().is_success() {
                            let prev = ok_count.fetch_add(1, Ordering::Relaxed);
                            // Exactly one task fires the mid-flight patch.
                            if prev == PATCH_AFTER_REQUESTS
                                && patch_applied
                                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
                                    .is_ok()
                            {
                                let _ = patch_fn().await;
                            }
                        } else {
                            non_2xx.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    for h in handles {
        h.await.context("load client task panicked")?;
    }

    Ok(LoadResult {
        total: (CLIENTS * REQUESTS_PER_CLIENT) as u64,
        non_2xx: non_2xx.load(Ordering::Relaxed),
        errors: errors.load(Ordering::Relaxed),
    })
}

// ── Scenario 1: port-add during sustained load ────────────────────────────────

/// Start sustained load on port A, then mid-flight add port B to the Gateway.
/// Assert: every request on port A returned 2xx; zero connection errors.
#[tokio::test]
async fn listener_add_does_not_drop_requests_on_survivor() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "drain-add").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    // Apply one-listener Gateway.
    h.apply(gwa::LISTENER_DRAIN, FixtureVars::new(&ns.name))
        .await?;

    let addr_a = h.controller.gateway_http_addr;
    let port_b = h.controller.gateway_https_addr.port();
    let host = format!("drain.{}.local", ns.name);

    wait_for_listener(addr_a, &host, Duration::from_secs(30)).await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let port_a = addr_a.port();

    let result = run_load_with_midpoint_patch(addr_a, host, move || {
        let gw_api = gw_api.clone();
        async move {
            let patch = json!({
                "spec": {
                    "listeners": [
                        { "name": "http-a", "port": port_a, "protocol": "HTTP",
                          "allowedRoutes": { "namespaces": { "from": "Same" } } },
                        { "name": "http-b", "port": port_b, "protocol": "HTTP",
                          "allowedRoutes": { "namespaces": { "from": "Same" } } }
                    ]
                }
            });
            gw_api
                .patch(
                    "drain-gw",
                    &PatchParams::apply("e2e-test"),
                    &Patch::Merge(&patch),
                )
                .await
                .context("patch Gateway to add port B")?;
            Ok(())
        }
    })
    .await?;

    assert_eq!(
        result.non_2xx, 0,
        "expected 0 non-2xx on port A during listener add (got {}); \
         total={}, errors={}",
        result.non_2xx, result.total, result.errors
    );
    assert_eq!(
        result.errors, 0,
        "expected 0 connection errors on port A during listener add (got {}); \
         total={}, non_2xx={}",
        result.errors, result.total, result.non_2xx
    );

    // Verify port B is reachable after the transition.
    let addr_b = SocketAddr::new(addr_a.ip(), port_b);
    let host_b = format!("drain.{}.local", ns.name);
    wait_for_listener(addr_b, &host_b, Duration::from_secs(15))
        .await
        .context("port B should be reachable after listener add")?;

    Ok(())
}

// ── Scenario 2: port-remove during sustained load ─────────────────────────────

/// Start sustained load on port A alongside port B; then mid-flight remove port B.
/// Assert: port A traffic is completely unaffected.
#[tokio::test]
async fn listener_remove_does_not_drop_requests_on_survivor() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "drain-rem").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let addr_a = h.controller.gateway_http_addr;
    let port_a = addr_a.port();
    let port_b = h.controller.gateway_https_addr.port();
    let host = format!("drain.{}.local", ns.name);

    // Start with TWO listeners.
    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let patch_two = json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": "drain-gw", "namespace": &ns.name },
        "spec": {
            "gatewayClassName": "coxswain",
            "listeners": [
                { "name": "http-a", "port": port_a, "protocol": "HTTP",
                  "allowedRoutes": { "namespaces": { "from": "Same" } } },
                { "name": "http-b", "port": port_b, "protocol": "HTTP",
                  "allowedRoutes": { "namespaces": { "from": "Same" } } }
            ]
        }
    });
    gw_api
        .patch(
            "drain-gw",
            &PatchParams::apply("e2e-test"),
            &Patch::Apply(&patch_two),
        )
        .await
        .context("create two-listener Gateway")?;

    // Apply the HTTPRoute (reuse the LISTENER_DRAIN fixture for the route; the
    // Gateway already exists, so kubectl apply is idempotent for the Gateway part).
    h.apply(gwa::LISTENER_DRAIN, FixtureVars::new(&ns.name))
        .await?;

    wait_for_listener(addr_a, &host, Duration::from_secs(30)).await?;

    // Run load on A; mid-flight remove B.
    let result = run_load_with_midpoint_patch(addr_a, host, move || {
        let gw_api = gw_api.clone();
        async move {
            let patch = json!({
                "spec": {
                    "listeners": [
                        { "name": "http-a", "port": port_a, "protocol": "HTTP",
                          "allowedRoutes": { "namespaces": { "from": "Same" } } }
                    ]
                }
            });
            gw_api
                .patch(
                    "drain-gw",
                    &PatchParams::apply("e2e-test"),
                    &Patch::Merge(&patch),
                )
                .await
                .context("patch Gateway to remove port B")?;
            Ok(())
        }
    })
    .await?;

    assert_eq!(
        result.non_2xx, 0,
        "expected 0 non-2xx on port A during listener remove (got {}); \
         total={}, errors={}",
        result.non_2xx, result.total, result.errors
    );
    assert_eq!(
        result.errors, 0,
        "expected 0 connection errors on port A during listener remove (got {}); \
         total={}, non_2xx={}",
        result.errors, result.total, result.non_2xx
    );

    Ok(())
}
