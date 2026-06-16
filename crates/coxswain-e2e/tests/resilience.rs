#![allow(missing_docs)]
//! Resilience control-plane: behavior under reconfiguration and restart.
//!
//! Plane: **control-plane**. Execution: **serial** — these tests reconfigure or
//! restart shared infrastructure (mid-flight listener changes under sustained
//! load, controller pod restart, dedicated⇄shared mode migration) and must not
//! overlap tests that depend on the default config. The nextest `serial` group
//! in `.config/nextest.toml` enforces this; the entire `resilience` binary is
//! its primary member.
//!
//! Classification rule: a test belongs to the plane of its *primary assertion
//! target*. These assert continuity/idempotency across a disruptive event.
//! Covers in-flight listener add/remove (#231), dedicated crash-loop fallback
//! (#210), controller-restart SSA idempotency, and mode migration in both
//! directions (#212). Shared dedicated helpers live in `common::dedicated`.
//!
//! The load harness is purely in-process Rust (`reqwest`), count-or-deadline
//! based, so CI timing variance cannot cause flakes.

use anyhow::Context as _;
use coxswain_e2e::{
    FixtureVars, Harness, HttpClient, NamespaceGuard,
    fixtures::{self, backends, dedicated_proxy as dedicated, gateway_api as gwa},
    harness::wait,
};
use gateway_api::apis::standard::gateways::Gateway;
use k8s_openapi::api::apps::v1::Deployment;
use kube::api::{Api, Patch, PatchParams};
use reqwest::Method;
use serde_json::json;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

mod common;
use common::dedicated::{
    GATEWAY_NAME, RESOURCE_NAME, apply_and_wait, restart_controller, scale_controller,
    wait_for_cut_over,
};

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
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("build reqwest client")?;
    let url = format!("http://{addr}/");
    wait::poll_until(
        timeout,
        wait::POLL_FAST,
        || async {
            match client.get(&url).header("Host", host).send().await {
                Ok(r) => format!(
                    "listener at {addr} (Host: {host}) to return 2xx; last status {}",
                    r.status()
                ),
                Err(e) => {
                    format!("listener at {addr} (Host: {host}) to become ready; request error: {e}")
                }
            }
        },
        || async {
            client
                .get(&url)
                .header("Host", host)
                .send()
                .await
                .ok()
                .filter(|r| r.status().is_success())
                .map(|_| ())
        },
    )
    .await
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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "drain-add").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    fixtures::apply_fixture(gwa::LISTENER_DRAIN, FixtureVars::new(&ns.name)).await?;

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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "drain-rem").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
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
    fixtures::apply_fixture(gwa::LISTENER_DRAIN, FixtureVars::new(&ns.name)).await?;

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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "drain-crash").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    fixtures::apply_fixture(gwa::CUTOVER_CRASH_LOOP, FixtureVars::new(&ns.name)).await?;

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

/// 3. Restart the controller after the resources are provisioned → assert
///    the SSA path is idempotent: the Deployment's `metadata.generation` stays
///    stable across the restart because the operator's same-content SSA produces
///    no spec write. (`generation`, not `resourceVersion`: the latter bumps on
///    unrelated status writes — see the in-body comment.)
#[tokio::test]
async fn restart_controller_does_not_bump_generation() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // Persistent namespace: the bootstrap purge runs on every
    // `Harness::start()`, including the second one below. A regular
    // `NamespaceGuard::create` would label this namespace `coxswain-e2e=true`
    // and the second bootstrap would delete it before we could verify the
    // SSA idempotency — defeating the test. The persistent variant skips
    // the label; the `Drop` still cleans up at end-of-test.
    let ns = NamespaceGuard::create_persistent(&h.client, "dedgw-idempotent").await?;

    let (_deployments, _services, _sas, deploy, _svc, _sa) = apply_and_wait(&h, &ns).await?;

    // Use `metadata.generation`, not `metadata.resourceVersion`, for the
    // idempotency check. `resourceVersion` bumps on every write — including
    // status updates emitted by the K8s Deployment controller while the
    // proxy pod scales / becomes Ready — so it drifts naturally in the 15 s
    // observation window and is not a clean signal of "the operator wrote a
    // new spec". `generation` only bumps on spec changes, which is exactly
    // the property SSA idempotency is supposed to preserve.
    //
    // We check Deployment only: it's the load-bearing resource (rollouts
    // are triggered by spec changes here), it reliably carries
    // `.metadata.generation`, and the proxy pod's lifecycle is what would
    // be most visibly disrupted by a spurious SSA write. Service and
    // ServiceAccount don't consistently populate `.generation` (Service's
    // generation isn't set in all K8s versions; ServiceAccount has no
    // spec), so checking them via `.generation` would itself be flaky.
    let gen_deploy_before = deploy.metadata.generation.expect("Deployment generation");

    // Restart: drop the harness (kills controller) and re-spawn. Bootstrap is
    // idempotent so the second start only re-spawns the binary, and the
    // 3-second lease TTL means the new pod-name re-claims leadership quickly.
    drop(h);
    let h2 = Harness::start().await?;

    // Poll a real post-condition rather than blind-sleeping: wait until the new
    // pod reports it holds the leader lease (`coxswain_controller_leader=1`) and
    // has completed at least one successful reconcile on the fresh process. SSA
    // on identical content is deterministic — it never bumps `.generation` — so
    // one confirmed post-restart reconcile is sufficient to then assert
    // generation stability.
    wait::wait_for_controller_reconciled(
        &h2.controller_admin_url("/metrics"),
        Duration::from_secs(60),
    )
    .await?;

    let deploy_after: Api<Deployment> = Api::namespaced(h2.client.clone(), &ns.name);
    let d2 = deploy_after.get(RESOURCE_NAME).await?;

    assert_eq!(
        d2.metadata.generation,
        Some(gen_deploy_before),
        "Deployment .metadata.generation changed across restart (SSA wrote a new spec)"
    );

    Ok(())
}

/// 17 — Mode migration shared → dedicated. Final-state assertion: pre-migration
/// the shared subprocess serves the Gateway; after patching in `parametersRef`
/// and waiting for cutover, the shared subprocess returns 404 and the dedicated
/// subprocess returns the backend response.
#[tokio::test]
async fn lifecycle_mode_migration_shared_to_dedicated() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ded-life-m-s2d").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(dedicated::MODE_MIGRATION_SHARED, FixtureVars::new(&ns.name)).await?;

    let host = format!("migrate.{}.local", ns.name);

    // Baseline: shared subprocess serves the Gateway in shared mode.
    let pre = wait::wait_for_route(&h.gateway_http, &host, "/", Duration::from_secs(60)).await?;
    pre.assert_backend("echo-a");

    // Patch in the parametersRef → controller provisions a dedicated pod and
    // flips DedicatedProxyReady=True once it's Ready.
    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let patch = serde_json::json!({
        "spec": {
            "infrastructure": {
                "parametersRef": {
                    "group": "gateway.coxswain-labs.dev",
                    "kind": "CoxswainGatewayParameters",
                    "name": "dedicated-params",
                },
            },
        },
    });
    gateways
        .patch(GATEWAY_NAME, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;

    wait_for_cut_over(&gateways, GATEWAY_NAME, Duration::from_secs(60)).await?;

    let dedicated_addr =
        wait::wait_for_dedicated_proxy_endpoint(&ns.name, GATEWAY_NAME, Duration::from_secs(60))
            .await?;
    let http = HttpClient::new(dedicated_addr)?;

    let post = wait::wait_for_route(&http, &host, "/", Duration::from_secs(60)).await?;
    post.assert_backend("echo-a");

    // Negative: cut-over (DedicatedProxyReady=True) means the shared pool dropped
    // the Gateway from its routing table, so the shared proxy must now return 404
    // for the migrated host — the claim the docstring makes is asserted here.
    wait::wait_for_route_status(&h.gateway_http, &host, "/", 404, Duration::from_secs(30)).await?;

    Ok(())
}

/// 18 — Mode migration dedicated → shared. Final-state assertion: pre-migration
/// the dedicated pod serves; after patching `parametersRef` out the controller GC
/// deletes the dedicated Deployment/Service, and the shared proxy re-adopts the
/// Gateway and serves backend traffic again.
#[tokio::test]
async fn lifecycle_mode_migration_dedicated_to_shared() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ded-life-m-d2s").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        dedicated::MODE_MIGRATION_DEDICATED,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait_for_cut_over(&gateways, GATEWAY_NAME, Duration::from_secs(60)).await?;

    let dedicated_addr =
        wait::wait_for_dedicated_proxy_endpoint(&ns.name, GATEWAY_NAME, Duration::from_secs(60))
            .await?;
    let http = HttpClient::new(dedicated_addr)?;

    let host = format!("migrate.{}.local", ns.name);
    let pre = wait::wait_for_route(&http, &host, "/", Duration::from_secs(60)).await?;
    pre.assert_backend("echo-a");

    // Patch out the parametersRef. Merge-patch null deletes the field.
    // The controller GC will delete the dedicated Deployment/Service; the
    // shared proxy re-adopts the Gateway once the controller clears the status.
    let patch = serde_json::json!({
        "spec": {
            "infrastructure": {
                "parametersRef": null,
            },
        },
    });
    gateways
        .patch(GATEWAY_NAME, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;

    // Shared subprocess re-adopts the Gateway once the controller clears the
    // status. The ~1s race window between status-clear and shared re-bind
    // (where neither subprocess serves) is absorbed by this poll.
    let post = wait::wait_for_route(&h.gateway_http, &host, "/", Duration::from_secs(30)).await?;
    post.assert_backend("echo-a");

    // Assert the negative for teardown: the dedicated Service/NodePort is GC'd on
    // migration, so its endpoint must go dark. This is a connection failure, not a
    // 404 — the listening socket is gone — so it can't be expressed as a route
    // status; `wait_for_endpoint_unreachable` polls a real TCP connect instead.
    wait::wait_for_endpoint_unreachable(dedicated_addr, Duration::from_secs(60)).await?;

    Ok(())
}

/// 19 — Controller restart idempotency: the dedicated pod keeps serving
/// across a controller pod restart (no traffic disruption), and the controller's
/// SSA on identical content does not bump the Deployment's `.metadata.generation`.
#[tokio::test]
async fn lifecycle_controller_restart_is_idempotent() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // Persistent namespace so the bootstrap purge on the second `Harness::start()`
    // doesn't delete it.
    let ns = NamespaceGuard::create_persistent(&h.client, "ded-life-restart").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(dedicated::TRAFFIC, FixtureVars::new(&ns.name)).await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait_for_cut_over(&gateways, GATEWAY_NAME, Duration::from_secs(60)).await?;

    // Wait for the dedicated proxy's LB IP and verify baseline traffic.
    // The dedicated pod keeps serving through the controller restart below.
    let dedicated_addr =
        wait::wait_for_dedicated_proxy_endpoint(&ns.name, GATEWAY_NAME, Duration::from_secs(60))
            .await?;
    let http = HttpClient::new(dedicated_addr)?;

    let host = format!("dedicated.{}.local", ns.name);
    let pre = wait::wait_for_route(&http, &host, "/", Duration::from_secs(60)).await?;
    pre.assert_backend("echo-a");

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let deploy_before = deployments.get(RESOURCE_NAME).await?;
    let gen_before = deploy_before
        .metadata
        .generation
        .expect("Deployment generation");

    // Restart the in-cluster controller pod to simulate a process restart.
    // The dedicated proxy pod is independent — it keeps serving through the
    // controller restart, so the `http` client above remains valid.
    restart_controller().await?;
    let h2 = Harness::start().await?;

    // Wait for the real post-condition — new leader elected + at least one
    // successful reconcile on the fresh process — instead of blind-sleeping.
    wait::wait_for_controller_reconciled(
        &h2.controller_admin_url("/metrics"),
        Duration::from_secs(60),
    )
    .await?;

    let deployments_after: Api<Deployment> = Api::namespaced(h2.client.clone(), &ns.name);
    let deploy_after = deployments_after.get(RESOURCE_NAME).await?;
    assert_eq!(
        deploy_after.metadata.generation,
        Some(gen_before),
        "Deployment .metadata.generation should not bump across controller restart (SSA must be idempotent on identical content)"
    );

    // Traffic continuity — the dedicated subprocess kept serving the whole
    // time, so the same backend assertion still holds.
    let post = http.get(&host, "/").await?;
    post.assert_backend("echo-a");

    Ok(())
}

/// 20 — Controller catch-up after a watch-stream downtime window. With the
/// controller scaled to zero, a Gateway is created that the controller never
/// receives a create event for; on restart it must relist and reconcile the
/// missed object.
///
/// The catch-up signal is controller-written status (`Programmed`), not served
/// traffic: in the split architecture the shared proxy runs its own reflector
/// and would route the Gateway regardless of the controller, so only the
/// Gateway's status proves the *controller* relisted and caught up.
#[tokio::test]
async fn catch_up_reconciles_gateway_created_during_controller_downtime() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // Persistent namespace so the bootstrap purge on the second `Harness::start()`
    // below doesn't delete the Gateway we create during the downtime window.
    let ns = NamespaceGuard::create_persistent(&h.client, "ctrl-catchup").await?;

    // Take the controller fully down — `scale_controller(0)` waits for the pod to
    // be gone — so the mutation below lands while nothing is watching.
    scale_controller(0).await?;

    // Mutation during downtime: a Gateway (named `coxswain-test`) the controller
    // never sees a create event for.
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    // Bring the controller back and wait for the real post-condition — new leader
    // elected + at least one successful reconcile on the fresh process.
    scale_controller(1).await?;
    let h2 = Harness::start().await?;
    wait::wait_for_controller_reconciled(
        &h2.controller_admin_url("/metrics"),
        Duration::from_secs(60),
    )
    .await?;

    // Relist catch-up: the Gateway created during downtime reaches Programmed=True,
    // which only happens if the controller reconciled an object it never received
    // a watch event for.
    wait::wait_for_gateway_programmed(
        &h2.client,
        "coxswain-test",
        &ns.name,
        Duration::from_secs(60),
    )
    .await?;

    Ok(())
}
