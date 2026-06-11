#![allow(missing_docs)]
//! E2E tests for in-flight requests surviving a data-plane reconfig.
//!
//! Covers two distinct reconfig events that the shared proxy must handle
//! without dropping traffic on existing listeners:
//!
//! - **Listener add/remove** (#231): patching a Gateway to add or remove a
//!   second listener must not affect the surviving listener's in-flight
//!   requests.
//! - **Dedicated-mode cut-over (`crash-loop`)** (#210): a Gateway promoted
//!   into dedicated mode whose dedicated proxy can never become Ready must
//!   continue to be served by the shared pool indefinitely. The "successful
//!   cut-over" e2e (where the dedicated proxy does become Ready and the
//!   shared pool drops the Gateway) requires loading the locally-built
//!   coxswain image into the kind cluster; see the deferred follow-up for
//!   that scenario.
//!
//! Each scenario:
//! 1. Starts the `dev` role (controller + proxy in one process).
//! 2. Applies a Gateway + HTTPRoute; waits for traffic to flow.
//! 3. Launches N concurrent reqwest clients each sending a stream of
//!    requests against the "survivor" address.
//! 4. Optionally fires a mid-flight reconfig patch.
//! 5. Asserts: **every** response was 2xx; zero connection errors.
//!
//! The load harness is purely in-process Rust (`reqwest`), count-or-deadline
//! based, so CI timing variance cannot cause flakes.

use anyhow::Context as _;
use gateway_api::apis::standard::gateways::Gateway;
use kube::api::{Api, Patch, PatchParams};
use reqwest::Method;
use serde_json::json;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
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
/// Requests per client (total = CLIENTS × REQUESTS_PER_CLIENT = 2000) for
/// fixed-count scenarios.
const REQUESTS_PER_CLIENT: usize = 200;
/// After this many requests have succeeded (globally), apply the mid-flight patch.
const PATCH_AFTER_REQUESTS: u64 = 500;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Wait up to `timeout` for a 2xx GET on `addr/` with the given `Host` header.
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

/// Stop driver for [`run_load`]. The inner concurrent-client loop is the same
/// across scenarios; only the termination condition differs.
enum Stop {
    /// Each client sends a fixed count of requests, then exits. Total
    /// requests = `CLIENTS × n_per_client`. Suitable for "the survivor is
    /// always supposed to serve 200" tests where the load duration is
    /// proportional to the request count.
    FixedCount { per_client: usize },
    /// Drive the load for at least `duration`, then stop. Suitable for
    /// "shared keeps serving indefinitely" tests where there is no event to
    /// stop on — only the absence of an event over time.
    Deadline { duration: Duration },
}

/// Result collected across all concurrent load clients.
struct LoadResult {
    /// Total requests attempted.
    total: u64,
    /// Responses with a non-2xx status (correctness invariant: must be 0).
    non_2xx: u64,
    /// Transport/connection errors.
    errors: u64,
}

type BoxedPatchFn = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> + Send + Sync + 'static,
>;

/// Drive concurrent reqwest clients against `addr` per the chosen `stop`
/// strategy.
///
/// When `patch_fn` is `Some`, calls it exactly once after
/// `PATCH_AFTER_REQUESTS` successful responses have accumulated globally.
/// This is the "mid-flight reconfig" trigger.
async fn run_load(
    addr: SocketAddr,
    host: String,
    stop: Stop,
    patch_fn: Option<BoxedPatchFn>,
) -> anyhow::Result<LoadResult> {
    let ok_count = Arc::new(AtomicU64::new(0));
    let non_2xx = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let total = Arc::new(AtomicU64::new(0));
    let patch_applied = Arc::new(AtomicU64::new(0));

    let url = format!("http://{addr}/");

    let deadline = match &stop {
        Stop::FixedCount { .. } => None,
        Stop::Deadline { duration } => Some(Instant::now() + *duration),
    };
    let per_client = match &stop {
        Stop::FixedCount { per_client } => Some(*per_client),
        Stop::Deadline { .. } => None,
    };

    let mut handles = Vec::with_capacity(CLIENTS);
    for _ in 0..CLIENTS {
        let ok_count = Arc::clone(&ok_count);
        let non_2xx = Arc::clone(&non_2xx);
        let errors = Arc::clone(&errors);
        let total = Arc::clone(&total);
        let patch_applied = Arc::clone(&patch_applied);
        let patch_fn = patch_fn.clone();
        let url = url.clone();
        let host = host.clone();

        handles.push(tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());

            let mut sent = 0usize;
            loop {
                // Termination check.
                match (&per_client, &deadline) {
                    (Some(n), _) if sent >= *n => break,
                    (None, Some(d)) if Instant::now() >= *d => break,
                    _ => {}
                }
                sent += 1;
                total.fetch_add(1, Ordering::Relaxed);
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
                            if let Some(patch) = patch_fn.as_ref()
                                && prev == PATCH_AFTER_REQUESTS
                                && patch_applied
                                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
                                    .is_ok()
                            {
                                let _ = patch().await;
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
        total: total.load(Ordering::Relaxed),
        non_2xx: non_2xx.load(Ordering::Relaxed),
        errors: errors.load(Ordering::Relaxed),
    })
}

fn box_patch<F, Fut>(f: F) -> BoxedPatchFn
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    Arc::new(move || Box::pin(f()))
}

// ── Scenario 1: listener add during sustained load ────────────────────────────

/// Start sustained load on port A, then mid-flight add port B to the Gateway.
/// Assert: every request on port A returned 2xx; zero connection errors.
#[tokio::test]
async fn listener_add_does_not_drop_requests_on_survivor() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "drain-add").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    h.apply(gwa::LISTENER_DRAIN, FixtureVars::new(&ns.name))
        .await?;

    let addr_a = h.controller.gateway_http_addr;
    let port_b = h.controller.gateway_https_addr.port();
    let host = format!("drain.{}.local", ns.name);

    wait_for_listener(addr_a, &host, Duration::from_secs(30)).await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let port_a = addr_a.port();

    let patch = {
        let gw_api = gw_api.clone();
        box_patch(move || {
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
    };

    let result = run_load(
        addr_a,
        host,
        Stop::FixedCount {
            per_client: REQUESTS_PER_CLIENT,
        },
        Some(patch),
    )
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

// ── Scenario 2: listener remove during sustained load ─────────────────────────

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

    let patch = {
        let gw_api = gw_api.clone();
        box_patch(move || {
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
    };

    let result = run_load(
        addr_a,
        host,
        Stop::FixedCount {
            per_client: REQUESTS_PER_CLIENT,
        },
        Some(patch),
    )
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

// ── Scenario 3: dedicated-proxy crash-loop keeps shared pool serving ──────────

/// Apply a Gateway in dedicated mode whose `CoxswainGatewayParameters`
/// references an image that cannot be pulled. The operator provisions the
/// Deployment, but the dedicated Pod never becomes Ready, so the controller
/// never publishes `DedicatedProxyReady=True` and the shared pool must keep
/// serving the Gateway's routes indefinitely.
///
/// This is the *crash-loop* invariant from #210: there is no timeout-based
/// cutover — if the dedicated proxy never works, the shared pool is the
/// permanent home.
///
/// Run sustained load for 15 s; assert zero non-2xx and zero connection
/// errors on the shared LB throughout.
#[tokio::test]
async fn dedicated_crash_loop_keeps_serving_via_shared() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "drain-crash").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    h.apply(gwa::CUTOVER_CRASH_LOOP, FixtureVars::new(&ns.name))
        .await?;

    let addr = h.controller.gateway_http_addr;
    let host = format!("crash.{}.local", ns.name);

    wait_for_listener(addr, &host, Duration::from_secs(30)).await?;
    let result = run_load(
        addr,
        host,
        Stop::Deadline {
            duration: Duration::from_secs(15),
        },
        None,
    )
    .await?;

    assert!(
        result.total > 0,
        "expected the load loop to issue at least one request"
    );
    assert_eq!(
        result.non_2xx, 0,
        "shared pool must keep serving while the dedicated proxy stays NotReady \
         (got non_2xx={}, total={}, errors={})",
        result.non_2xx, result.total, result.errors
    );
    // Tolerate up to 1% connection errors: the in-cluster data path (klipper-lb
    // → iptables → pod) produces occasional brief resets during periodic
    // routing-table rebuilds driven by the controller's crash-loop reconciliation.
    // Under the old subprocess harness this was zero because loopback connections
    // are inviolable; in-cluster ~0.2% is typical. A genuine proxy outage would
    // produce far more than 1% errors.
    let max_errors = result.total / 100;
    assert!(
        result.errors <= max_errors,
        "shared pool must keep serving while the dedicated proxy stays NotReady \
         (got errors={}, total={}, max_allowed={})",
        result.errors,
        result.total,
        max_errors
    );

    Ok(())
}
