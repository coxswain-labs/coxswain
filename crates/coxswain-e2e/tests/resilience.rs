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
    ControllerOptions, FixtureVars, Harness, HttpClient, NamespaceGuard,
    fixtures::{self, backends, dedicated_proxy as dedicated, gateway_api as gwa, ingress as ing},
    harness::{leader, wait},
};
use gateway_api_types::apis::standard::gateways::Gateway;
use gateway_api_types::apis::standard::httproutes::HttpRoute;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Pod, Secret};
use k8s_openapi::api::networking::v1::Ingress;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams};
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

/// Establish a `kubectl port-forward` to the shared pool's Gateway HTTP listener
/// that is proven live, re-creating the forward until it serves a 2xx for `host`.
///
/// A forward to a port nothing is listening on yet dies *permanently* on its
/// first refused connection (`kubectl`: "lost connection to pod") — it never
/// recovers once the port later binds. So a forward set up before the shared
/// proxy has bound the dedicated-pre-cutover Gateway's listener (#210) is dead on
/// arrival, and every later probe through it fails. Recreate the forward each
/// poll; once the listener is bound the forward stays alive for the load run.
async fn wait_for_shared_gateway_forward(
    h: &Harness,
    host: &str,
    timeout: Duration,
) -> anyhow::Result<coxswain_e2e::harness::controller::GatewayPortForward> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("build reqwest client")?;
    wait::poll_until(
        timeout,
        wait::POLL,
        || async { format!("shared pool to bind and serve {host} on its Gateway HTTP listener") },
        || async {
            // A fresh forward each attempt: a forward that raced ahead of the
            // listener bind is already dead and cannot be reused.
            let pf = h.controller.gateway_http_forward().await.ok()?;
            let url = format!("http://{}/", pf.addr);
            match client.get(&url).header("Host", host).send().await {
                Ok(r) if r.status().is_success() => Some(pf),
                _ => None,
            }
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
                // A real client retries a transient connection blip; only a
                // SUSTAINED inability to reach the proxy is a routing gap. The
                // bounded transient-retry (with its backoff) lives in the harness
                // so the test body stays free of bare sleeps (e2e charter).
                let response =
                    coxswain_e2e::harness::http::get_with_transient_retry(&client, &url, &host, 3)
                        .await;
                match response {
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

    // Resolve THIS Gateway's own per-Gateway VIP (#472) now that the fixture is
    // applied; the fixed shared address no longer carries Gateway traffic.
    let gw_http = h.gateway_http_addr(&ns.name).await?;
    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    let addr_a = gw_http;
    let port_b = gw_tls.port();
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

    let host = format!("drain.{}.local", ns.name);
    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);

    // Create the single-listener Gateway (http-a on GATEWAY_HTTP_PORT) and its
    // HTTPRoute via the shared fixture, then resolve this Gateway's own VIP
    // (#472) — the fixed shared address no longer carries Gateway traffic.
    fixtures::apply_fixture(gwa::LISTENER_DRAIN, FixtureVars::new(&ns.name)).await?;

    let gw_http = h.gateway_http_addr(&ns.name).await?;
    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    let addr_a = gw_http;
    let port_a = gw_http.port();
    let port_b = gw_tls.port();

    // Add a second listener (http-b) so the baseline has TWO listeners; the
    // mid-flight patch below removes it under sustained load.
    let patch_two = json!({
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
            &Patch::Merge(&patch_two),
        )
        .await
        .context("add second listener to Gateway")?;

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

    // White-box: port-forward directly to the shared-proxy pod's Gateway HTTP
    // port, NOT the Gateway's own VIP (#472). The Gateway is dedicated-mode, so
    // no per-Gateway VIP exists; the dedicated Service selects the crash-looping
    // (ImagePullBackOff) pods. The invariant under test is that the SHARED pool
    // keeps serving the route until cut-over — only observable on the shared
    // pod's listener, hence the direct pod port-forward.
    //
    // The forward must be established *after* the shared proxy binds the
    // listener: a forward that races ahead of the bind dies permanently on the
    // first refused connection. `wait_for_shared_gateway_forward` recreates it
    // until a probe succeeds, then hands back a live forward for the load run.
    let host = format!("crash.{}.local", ns.name);
    let pf = wait_for_shared_gateway_forward(&h, &host, Duration::from_secs(60)).await?;
    let addr = pf.addr;

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
    let ns = NamespaceGuard::create_persistent(&h.client, "res-dedgw-idempotent").await?;

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
    // Scrape the LEADER specifically, not an arbitrary Service replica: after a
    // restart the HA standby reports leader=0 forever, so a Service-pinned scrape
    // races. `wait_for_leader_reconciled` re-resolves the Lease holder each tick.
    leader::wait_for_leader_reconciled(&h2.client, Duration::from_secs(60)).await?;

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
#[ignore = "dedicated-over-discovery clobbers shared routing cells under concurrent provisioning; unignore when per-proxy scope filtering lands (#426)"]
async fn lifecycle_mode_migration_shared_to_dedicated() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "res-ded-life-m-s2d").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(dedicated::MODE_MIGRATION_SHARED, FixtureVars::new(&ns.name)).await?;

    let host = format!("migrate.{}.local", ns.name);

    // Resolve this Gateway's own per-Gateway VIP (#472) while it is still shared.
    let gw = h.gateway_http(&ns.name).await?;

    // Baseline: shared subprocess serves the Gateway in shared mode.
    let pre = wait::wait_for_route(&gw, &host, "/", Duration::from_secs(60)).await?;
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
    wait::wait_for_route_status(&gw, &host, "/", 404, Duration::from_secs(30)).await?;

    Ok(())
}

/// 18 — Mode migration dedicated → shared. Final-state assertion: pre-migration
/// the dedicated pod serves; after patching `parametersRef` out the controller GC
/// deletes the dedicated Deployment/Service, and the shared proxy re-adopts the
/// Gateway and serves backend traffic again.
#[tokio::test]
#[ignore = "dedicated-over-discovery clobbers shared routing cells under concurrent provisioning; unignore when per-proxy scope filtering lands (#426)"]
async fn lifecycle_mode_migration_dedicated_to_shared() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "res-ded-life-m-d2s").await?;

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
    // (where neither subprocess serves) is absorbed by this poll. Re-resolve the
    // VIP post-migration: the Gateway's effective address moves dedicated→shared.
    let gw = h.gateway_http(&ns.name).await?;
    let post = wait::wait_for_route(&gw, &host, "/", Duration::from_secs(30)).await?;
    post.assert_backend("echo-a");

    // Assert the negative for teardown: the dedicated proxy is torn down on
    // migration. Owner-ref GC cannot reclaim it — the owning Gateway survives the
    // migration — so the controller deletes the dedicated Deployment/Service
    // explicitly, but only AFTER the shared pool is serving the migrated routes
    // (which the `post` assertion above just confirmed). We assert that
    // controller-owned, spec-driven observable directly via the K8s API: the
    // Service and Deployment are gone. This is deterministic and identical on
    // every cluster, unlike a NodePort TCP probe whose teardown timing is
    // kube-proxy/CNI-dependent and is not the controller's contract.
    wait::wait_for_dedicated_proxy_deleted(
        &h.client,
        &ns.name,
        GATEWAY_NAME,
        Duration::from_secs(60),
    )
    .await?;

    Ok(())
}

/// 19 — Controller restart idempotency: the dedicated pod keeps serving
/// across a controller pod restart (no traffic disruption), and the controller's
/// SSA on identical content does not bump the Deployment's `.metadata.generation`.
#[tokio::test]
#[ignore = "dedicated-over-discovery clobbers shared routing cells under concurrent provisioning; unignore when per-proxy scope filtering lands (#426)"]
async fn lifecycle_controller_restart_is_idempotent() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // Persistent namespace so the bootstrap purge on the second `Harness::start()`
    // doesn't delete it.
    let ns = NamespaceGuard::create_persistent(&h.client, "res-ded-life-restart").await?;

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
    // Scrape the LEADER specifically, not an arbitrary Service replica: after a
    // restart the HA standby reports leader=0 forever, so a Service-pinned scrape
    // races. `wait_for_leader_reconciled` re-resolves the Lease holder each tick.
    leader::wait_for_leader_reconciled(&h2.client, Duration::from_secs(60)).await?;

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
    // Scrape the LEADER specifically, not an arbitrary Service replica: after a
    // restart the HA standby reports leader=0 forever, so a Service-pinned scrape
    // races. `wait_for_leader_reconciled` re-resolves the Lease holder each tick.
    leader::wait_for_leader_reconciled(&h2.client, Duration::from_secs(60)).await?;

    // Catch-up: the Gateway created during downtime reaches Programmed=True,
    // which only happens if the controller reconciled an object it never received
    // a watch event for. On a cold restart that Gateway's InitApply is consumed
    // before its preconditions are met (the GatewayClass watch stream is an
    // independent race; leadership/readiness lag the first events), so the per-event
    // path alone can drop it until the next relist (minutes). The controller's
    // status-resync backstop re-drives the cached Gateway once the preconditions
    // hold, bounding recovery to the resync interval — comfortably inside 60s.
    wait::wait_for_gateway_programmed(
        &h2.client,
        "coxswain-test",
        &ns.name,
        Duration::from_secs(60),
    )
    .await?;

    Ok(())
}

/// 21 — Controller catch-up after a watch-stream downtime window: route
/// mutations and deletions committed to the API server while the controller is
/// at zero replicas must be reflected on the data plane after the controller
/// restarts and relists.
///
/// Two Ingresses are seeded and confirmed live on the data plane. With the
/// controller scaled to zero, one Ingress is mutated (backend repointed from
/// `echo-a` to `echo-b`) and the other is deleted. After the controller comes
/// back and the shared proxy relists, the data plane must show the mutation
/// (`echo-b` is the serving pod) and the deletion (404 — route removed from the
/// routing table) — proving that neither a missed update event nor a missed
/// delete event leaves a stale routing entry.
#[tokio::test]
async fn catch_up_reconciles_ingress_mutations_and_deletes_during_controller_downtime()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    // Persistent namespace: the second Harness::start() below runs bootstrap(),
    // which purges namespaces labelled coxswain-e2e=true. A persistent namespace
    // skips that label so the Ingresses we mutate during downtime survive the purge.
    let ns = NamespaceGuard::create_persistent(&h.client, "ctrl-mu-del").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host_a = format!("catchup-a.{}.local", ns.name);
    let host_b = format!("catchup-b.{}.local", ns.name);
    let ingresses: Api<Ingress> = Api::namespaced(h.client.clone(), &ns.name);
    let params = PatchParams::apply("e2e-test");

    // ── Seed two Ingresses ────────────────────────────────────────────────────

    // Ingress A: will be mutated (echo-a → echo-b) during downtime.
    let ing_a = json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": { "name": "catchup-mutate", "namespace": &ns.name },
        "spec": {
            "ingressClassName": "coxswain",
            "rules": [{ "host": &host_a, "http": { "paths": [{
                "path": "/", "pathType": "Prefix",
                "backend": { "service": { "name": "echo-a", "port": { "number": 3000 } } }
            }] } }]
        }
    });
    ingresses
        .patch("catchup-mutate", &params, &Patch::Apply(&ing_a))
        .await
        .context("apply catchup-mutate ingress")?;

    // Ingress B: will be deleted entirely during downtime.
    let ing_b = json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": { "name": "catchup-delete", "namespace": &ns.name },
        "spec": {
            "ingressClassName": "coxswain",
            "rules": [{ "host": &host_b, "http": { "paths": [{
                "path": "/", "pathType": "Prefix",
                "backend": { "service": { "name": "echo-a", "port": { "number": 3000 } } }
            }] } }]
        }
    });
    ingresses
        .patch("catchup-delete", &params, &Patch::Apply(&ing_b))
        .await
        .context("apply catchup-delete ingress")?;

    // Confirm data-plane baseline: both routes serve echo-a.
    wait::wait_for_backend(&h.http, &host_a, "/", "echo-a", Duration::from_secs(60)).await?;
    wait::wait_for_backend(&h.http, &host_b, "/", "echo-a", Duration::from_secs(60)).await?;

    // ── Downtime window ───────────────────────────────────────────────────────

    // Take the controller fully down; mutations below land while nothing is
    // writing status or potentially re-reconciling stale state.
    scale_controller(0).await?;

    // Mutation: repoint catchup-mutate from echo-a to echo-b.
    let ing_a_mutated = json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": { "name": "catchup-mutate", "namespace": &ns.name },
        "spec": {
            "ingressClassName": "coxswain",
            "rules": [{ "host": &host_a, "http": { "paths": [{
                "path": "/", "pathType": "Prefix",
                "backend": { "service": { "name": "echo-b", "port": { "number": 3000 } } }
            }] } }]
        }
    });
    ingresses
        .patch("catchup-mutate", &params, &Patch::Apply(&ing_a_mutated))
        .await
        .context("mutate catchup-mutate to echo-b during downtime")?;

    // Deletion: remove catchup-delete so the proxy must eventually return 404.
    ingresses
        .delete("catchup-delete", &DeleteParams::default())
        .await
        .context("delete catchup-delete ingress during downtime")?;

    // ── Controller restart + convergence assertions ───────────────────────────

    scale_controller(1).await?;
    let h2 = Harness::start().await?;
    // Poll the real post-condition: new leader elected + at least one successful
    // reconcile on the fresh process.
    // Scrape the LEADER specifically, not an arbitrary Service replica: after a
    // restart the HA standby reports leader=0 forever, so a Service-pinned scrape
    // races. `wait_for_leader_reconciled` re-resolves the Lease holder each tick.
    leader::wait_for_leader_reconciled(&h2.client, Duration::from_secs(60)).await?;

    // Mutated route: proxy must serve echo-b (not stale echo-a).
    wait::wait_for_backend(&h2.http, &host_a, "/", "echo-b", Duration::from_secs(60)).await?;

    // Deleted route: proxy must return 404 (route removed from routing table).
    wait::wait_for_route_status(&h2.http, &host_b, "/", 404, Duration::from_secs(60)).await?;

    Ok(())
}

// ── Scenario: terminating endpoint excluded from active pool (#281) ───────────

/// A terminating pod must receive no new requests while the proxy routing table
/// reflects the `terminating=true` EndpointSlice condition.
///
/// Setup: 2-replica `drain-echo` backend with a 20-second `preStop` hook so the
/// pod keeps serving during the drain window. One pod is deleted; the proxy must
/// stop routing to it BEFORE the pod exits.
///
/// This test is the Phase-0 empirical check as well as the happy-path assertion:
/// it FAILS before the reflector's `terminating` exclusion fix is applied
/// (confirming the bug) and PASSES after the fix lands.
#[tokio::test]
async fn no_requests_reach_terminating_endpoint_during_drain() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "drain-ep").await?;

    fixtures::apply_fixture(backends::DRAIN_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["drain-echo"]).await?;

    fixtures::apply_fixture(ing::DRAIN_INGRESS, FixtureVars::new(&ns.name)).await?;

    let host = format!("drain-ep.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(30)).await?;

    // Discover the two running pods.
    let pods_api: Api<Pod> = Api::namespaced(h.client.clone(), &ns.name);
    let pod_list = pods_api
        .list(&ListParams::default().labels("app=drain-echo"))
        .await
        .context("list drain-echo pods")?;
    anyhow::ensure!(
        pod_list.items.len() == 2,
        "expected 2 drain-echo pods, got {}",
        pod_list.items.len()
    );
    let target_pod = pod_list.items[0]
        .metadata
        .name
        .clone()
        .context("pod has no name")?;

    // Delete the first pod with the default grace period (preStop hook runs).
    pods_api
        .delete(&target_pod, &DeleteParams::default())
        .await
        .context("delete target pod")?;

    // Poll until the pod has a deletionTimestamp (K8s acknowledged the delete;
    // the preStop hook is now running — pod keeps serving for ~20 s).
    {
        let pods_api = pods_api.clone();
        let target_pod = target_pod.clone();
        wait::poll_until(
            Duration::from_secs(10),
            wait::POLL_FAST,
            || async { format!("pod {target_pod} to have deletionTimestamp") },
            || async {
                pods_api
                    .get(&target_pod)
                    .await
                    .ok()
                    .filter(|p| p.metadata.deletion_timestamp.is_some())
                    .map(|_| ())
            },
        )
        .await
        .context("pod deletion not acknowledged")?;
    }

    // Poll until N consecutive requests all land on the surviving pod.
    // - Happy path (fix applied): the reflector stops routing to the terminating
    //   endpoint within ~2 s; this loop exits quickly.
    // - Sad path (bug present): the terminating pod keeps receiving traffic
    //   indefinitely; this loop times out → test fails, confirming the bug.
    //
    // Timeout (15 s) is well within the preStop window (20 s), so the assertion
    // fires while the pod is still alive and capable of serving.
    const BURST: usize = 20;
    wait::poll_until(
        Duration::from_secs(15),
        wait::POLL,
        || async {
            format!("all {BURST} consecutive requests to avoid terminating pod {target_pod}")
        },
        || async {
            let mut all_avoided = true;
            for _ in 0..BURST {
                match h.http.get(&host, "/").await {
                    Ok(resp) if resp.pod.as_deref() == Some(target_pod.as_str()) => {
                        all_avoided = false;
                        break;
                    }
                    _ => {}
                }
            }
            if all_avoided { Some(()) } else { None }
        },
    )
    .await
    .context("terminating endpoint still received new requests during drain window")?;

    Ok(())
}

// ── SVID rotation continuity (#423) ───────────────────────────────────────────

/// A short SVID TTL drives the proxy bootstrap loop to refresh its SVID and
/// force a clean discovery-Stream reconnect several times during the window.
/// The proxy's routing cells are never zeroed across a reconnect (last-good is
/// served throughout), so sustained traffic must never see a 5xx/404 gap.
///
/// Serial by construction: it reconfigures the shared Helm release's
/// `discovery.svidTtl`, then restores the default before returning.
#[tokio::test]
async fn svid_rotation_before_expiry_keeps_routing() -> anyhow::Result<()> {
    // 20s TTL → the bootstrap loop refreshes at ~10s; a 50s load window spans
    // ≥4 rotation cycles with comfortable margin before any issued SVID expires.
    let h = Harness::start_with_options(ControllerOptions {
        discovery_svid_ttl: Some("20s".to_string()),
        ..Default::default()
    })
    .await?;
    let ns = NamespaceGuard::create(&h.client, "res-svid-rotation").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    // Rules-less default backend serves every host+path, so the bare `GET /`
    // the load generator issues always has a live route.
    fixtures::apply_fixture(ing::DEFAULT_BACKEND_ONLY, FixtureVars::new(&ns.name)).await?;

    let host = "rotation.example".to_string();
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // Sustain traffic across ≥4 SVID rotation cycles; assert zero gaps.
    let result = run_load(
        h.controller.proxy_addr,
        host,
        Stop::Deadline {
            duration: Duration::from_secs(50),
        },
        None,
    )
    .await?;

    assert!(result.total > 0, "load generated no requests");
    assert_eq!(
        result.non_2xx, 0,
        "SVID rotation caused {} non-2xx responses out of {} — routing gapped across a reconnect",
        result.non_2xx, result.total
    );
    assert_eq!(
        result.errors, 0,
        "SVID rotation caused {} connection errors out of {}",
        result.errors, result.total
    );

    // No manual restore: leaving `discovery.svidTtl` set (even to the chart
    // default) would register as a leaked override forever after. The next
    // default-options `Harness::start` self-heals via `ensure_default_release`,
    // which clears ALL user-supplied values back to chart defaults.

    Ok(())
}

// ── Scenario 5: shared-Gateway churn recycles internal ports cleanly ──────────

/// Deleting a shared-mode Gateway frees its allocated internal accept port; a
/// Gateway created afterwards recycles that first-free port. This exercises the
/// two halves of the #529 hardening together: the proxy releases a removed VIP
/// listener's socket the instant it stops accepting (so the recycled port is
/// not left dark by a bind race), and the controller reads existing
/// internal-port assignments authoritatively from the apiserver each pass (so a
/// survivor Gateway's port is never remapped when the allocation landscape
/// shifts under it).
///
/// Sad-path note: a genuine bind conflict (the `bind_failed` metric / dark
/// port) requires a second process contending for the port, which the harness
/// cannot stage in-cluster; it is covered by the metric + the reasoning in
/// `edge/accept.rs`, not here.
#[tokio::test]
async fn shared_gateway_port_recycle_keeps_survivor_and_newcomer_routing() -> anyhow::Result<()> {
    let h = Harness::start().await?;

    // Two independent shared Gateways, each with its own VIP + internal port.
    let ns_a = NamespaceGuard::create(&h.client, "recycle-a").await?;
    let ns_b = NamespaceGuard::create(&h.client, "recycle-b").await?;
    for ns in [&ns_a.name, &ns_b.name] {
        fixtures::apply_fixture(backends::ECHO, FixtureVars::new(ns)).await?;
        wait::wait_for_backends(ns).await?;
        fixtures::apply_fixture(gwa::LISTENER_DRAIN, FixtureVars::new(ns)).await?;
    }
    let host_a = format!("drain.{}.local", ns_a.name);
    let host_b = format!("drain.{}.local", ns_b.name);
    let gw_a = h.gateway_http_addr(&ns_a.name).await?;
    let gw_b = h.gateway_http_addr(&ns_b.name).await?;
    wait_for_listener(gw_a, &host_a, Duration::from_secs(60)).await?;
    wait_for_listener(gw_b, &host_b, Duration::from_secs(60)).await?;

    // Delete Gateway A: its VIP is pruned and its internal port freed. Wait for
    // the Gateway object to be gone so the free has been triggered.
    let gw_api_a: Api<Gateway> = Api::namespaced(h.client.clone(), &ns_a.name);
    gw_api_a
        .delete("drain-gw", &DeleteParams::default())
        .await
        .context("delete Gateway A")?;
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL_FAST,
        || async { "Gateway A to be deleted".to_string() },
        || async {
            match gw_api_a.get_opt("drain-gw").await {
                Ok(None) => Some(()),
                _ => None,
            }
        },
    )
    .await?;

    // A newcomer Gateway C recycles A's freed first-free internal port. If that
    // port were left dark (bind race) or the survivor B were remapped onto it,
    // one of these probes would fail.
    let ns_c = NamespaceGuard::create(&h.client, "recycle-c").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns_c.name)).await?;
    wait::wait_for_backends(&ns_c.name).await?;
    fixtures::apply_fixture(gwa::LISTENER_DRAIN, FixtureVars::new(&ns_c.name)).await?;
    let host_c = format!("drain.{}.local", ns_c.name);
    let gw_c = h.gateway_http_addr(&ns_c.name).await?;
    wait_for_listener(gw_c, &host_c, Duration::from_secs(60)).await?;

    // Survivor B still routes on its own host after the churn — a remap would
    // have sent B's VIP traffic into another Gateway's listener (404/503 on
    // B's host) or darkened B's port.
    wait_for_listener(gw_b, &host_b, Duration::from_secs(30))
        .await
        .context("survivor Gateway B still routes after peer churn")?;

    Ok(())
}

/// #531 HA rider: a Gateway created in the leaderless window between killing
/// the live leader and the warm standby's promotion must be reconciled by the
/// promotion re-drive — the standby ingested it with writes gated off, and
/// without the re-drive it would sit unprogrammed until the next watch event
/// or periodic relist. The generous bound guards the regression class
/// ("stuck until relist"), not a latency SLO.
#[tokio::test]
async fn promotion_redrives_gateway_created_before_leadership_acquired() -> anyhow::Result<()> {
    use coxswain_e2e::harness::leader;

    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "res-promotion-redrive").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let old_leader = leader::leader_pod_name(&h.client).await?;
    let pods_api: Api<Pod> = Api::namespaced(h.client.clone(), leader::SYSTEM_NAMESPACE);
    pods_api
        .delete(&old_leader, &DeleteParams::default())
        .await
        .context("delete the live leader pod")?;

    // Apply the Gateway IMMEDIATELY — before waiting for the new leader — so
    // its creation lands while no replica is writing status.
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let new_leader =
        leader::wait_for_new_leader(&h.client, &old_leader, Duration::from_secs(90)).await?;
    anyhow::ensure!(
        new_leader != old_leader,
        "sanity: takeover must elect a different pod"
    );

    // The promotion re-drive (leadership_txs + operator/VIP notify) must
    // program the Gateway promptly — end to end through VIP provisioning and
    // the pool-bind readiness gate on the NEW leader's registry.
    wait::wait_for_gateway_programmed(
        &h.client,
        "coxswain-test",
        &ns.name,
        Duration::from_secs(60),
    )
    .await?;

    // And the data plane serves it (the reconnected proxy received the new
    // Gateway's snapshot from the new leader).
    let host = format!("echo.{}.local", ns.name);
    let gw_http = h.gateway_http(&ns.name).await?;
    wait::wait_for_backend(&gw_http, &host, "/a", "echo-a", Duration::from_secs(30)).await?;
    Ok(())
}

// ── #573: shared-store relist wedge under churn ───────────────────────────────

/// Number of apply+delete HTTPRoute cycles in a churn burst. Each cycle drives
/// two events (apply + delete) through the controller's shared HTTPRoute store,
/// exercising the lossy fan-out (`shared_stream`) that replaced kube's
/// back-pressuring `store_shared` dispatcher (#573).
const ROUTE_CHURN_CYCLES: usize = 60;

/// Apply then immediately delete `cycles` distinct HTTPRoutes, driving sustained
/// apply/delete churn through the controller's shared HTTPRoute store. The
/// routes parent onto `coxswain-test`; they need not become Accepted (they may
/// be deleted before reconcile) — the point is the volume of store events.
async fn churn_httproutes(client: &kube::Client, ns: &str, cycles: usize) -> anyhow::Result<()> {
    let routes: Api<HttpRoute> = Api::namespaced(client.clone(), ns);
    let params = PatchParams::apply("e2e-churn");
    for i in 0..cycles {
        let name = format!("churn-{i}");
        let body = json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": &name, "namespace": ns },
            "spec": {
                "parentRefs": [{ "name": "coxswain-test" }],
                "rules": [{ "backendRefs": [{ "name": "echo-a", "port": 3000 }] }]
            }
        });
        routes
            .patch(&name, &params, &Patch::Apply(&body))
            .await
            .with_context(|| format!("apply churn route {name}"))?;
        routes
            .delete(&name, &DeleteParams::default())
            .await
            .with_context(|| format!("delete churn route {name}"))?;
    }
    Ok(())
}

/// #573 happy path: a route created *after* a sustained churn burst still
/// converges. Before the fix, enough churn against a lagging shared-store
/// subscriber wedged the root reflector — relists stopped completing and the
/// store froze on a stale/empty snapshot, so nothing created afterwards ever
/// reconciled. This asserts the store keeps processing across the burst: the
/// `coxswain-test` Gateway is Programmed, a churn burst runs, and a fresh
/// HTTPRoute created afterwards reaches Programmed=True.
#[tokio::test]
async fn fresh_route_converges_after_churn_burst() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "churn-fresh").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_gateway_programmed(
        &h.client,
        "coxswain-test",
        &ns.name,
        Duration::from_secs(60),
    )
    .await?;

    // Sustained churn through the shared HTTPRoute store.
    churn_httproutes(&h.client, &ns.name, ROUTE_CHURN_CYCLES).await?;

    // A route created AFTER the burst must still converge — the store did not
    // wedge on a stale relist.
    let routes: Api<HttpRoute> = Api::namespaced(h.client.clone(), &ns.name);
    let fresh = json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "post-churn", "namespace": &ns.name },
        "spec": {
            "parentRefs": [{ "name": "coxswain-test" }],
            "hostnames": ["post-churn.local"],
            "rules": [{ "backendRefs": [{ "name": "echo-a", "port": 3000 }] }]
        }
    });
    routes
        .patch(
            "post-churn",
            &PatchParams::apply("e2e-test"),
            &Patch::Apply(&fresh),
        )
        .await
        .context("apply post-churn route")?;
    wait::wait_for_httproute_programmed(&h.client, "post-churn", &ns.name, Duration::from_secs(60))
        .await?;

    // And the wedge signature is absent: every relist completed.
    wait::wait_for_relists_settled(&h.controller_admin_url("/metrics"), Duration::from_secs(30))
        .await?;
    Ok(())
}

/// #573 failure-mode guard: a churn burst must not leave a stuck relist, and the
/// existing Gateway's status must not go stale/zombie. This asserts the wedge
/// *signature* directly — `coxswain_controller_watch_relists_pending` settles to
/// 0 (a relist that began but never finished would pin it above 0) — and that
/// the live `coxswain-test` Gateway is still Programmed at its current
/// generation after the burst (a wedged store would freeze its status).
#[tokio::test]
async fn route_churn_burst_leaves_no_stuck_relist() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "churn-nostuck").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_gateway_programmed(
        &h.client,
        "coxswain-test",
        &ns.name,
        Duration::from_secs(60),
    )
    .await?;

    // Churn the shared HTTPRoute store while the Gateway is live.
    churn_httproutes(&h.client, &ns.name, ROUTE_CHURN_CYCLES).await?;

    // Primary assertion: no reflector is stuck mid-relist (the #573 signature).
    wait::wait_for_relists_settled(&h.controller_admin_url("/metrics"), Duration::from_secs(30))
        .await?;

    // No zombie: the existing Gateway's status is still maintained (re-confirmed
    // Programmed at current generation), not frozen behind a wedged store.
    wait::wait_for_gateway_programmed(
        &h.client,
        "coxswain-test",
        &ns.name,
        Duration::from_secs(30),
    )
    .await?;
    Ok(())
}

// ── #511 partitioned incremental rebuild ────────────────────────────────────
//
// `build_gateway_routes` caches one compiled `Arc<HostRouter>` per `(port,
// host)` partition, keyed by a fingerprint folding each bound route's
// content, its endpoint dependencies, and a `global_epoch` covering inputs a
// per-route static scan can't precisely attribute (targetRef-based policy
// attachment, a `BasicAuth` CR's own `secretRef`). Two properties to prove
// black-box: (a) endpoint churn on one service re-resolves only that
// service's partition, leaving a sibling host undisturbed; (b) a
// global-epoch-only change (an auth Secret rotated without touching the
// BasicAuth CR or the HTTPRoute that reference it) still gets picked up on
// the next rebuild — the safe fallback, not a silently stale partition.

/// Scaling `echo-a` from 1 to 2 replicas must resolve the new pod on
/// `host-a`'s route; `host-b` (a separate HTTPRoute, disjoint partition,
/// distinct backend) must keep serving throughout, undisturbed by host-a's
/// endpoint churn.
#[tokio::test]
async fn endpoint_churn_reresolves_only_affected_service() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "resil-endpoint-churn").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::TWO_HOSTS, FixtureVars::new(&ns.name)).await?;

    let gw = h.gateway_http(&ns.name).await?;
    let host_a = format!("host-a.{}.local", ns.name);
    let host_b = format!("host-b.{}.local", ns.name);

    wait::wait_for_backend(&gw, &host_a, "/", "echo-a", Duration::from_secs(60)).await?;
    wait::wait_for_backend(&gw, &host_b, "/", "echo-b", Duration::from_secs(15)).await?;

    // Scale echo-a only. echo-b, host-b's backend, is never touched.
    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    deployments
        .patch(
            "echo-a",
            &PatchParams::default(),
            &Patch::Merge(&json!({"spec": {"replicas": 2}})),
        )
        .await
        .context("scale echo-a to 2 replicas")?;

    // host-a's partition re-resolves the new endpoint: both pods answer.
    wait::wait_for_distinct_backends(&gw, &host_a, "/", 2, Duration::from_secs(60)).await?;
    // host-b's disjoint partition was never recompiled by host-a's endpoint
    // churn — it keeps serving its own single backend throughout.
    wait::wait_for_backend(&gw, &host_b, "/", "echo-b", Duration::from_secs(15)).await?;

    Ok(())
}

/// A `BasicAuth` CR's own htpasswd Secret is not precisely tracked per-route
/// by `route_fingerprint` — it folds into `compute_global_epoch` instead, so
/// a change to it must fall back to recompiling the BasicAuth route's
/// partition rather than risk it wrongly believing itself unaffected.
/// Rotating the Secret alone (the BasicAuth CR and the HTTPRoute are both
/// untouched) must invalidate the previously-valid credentials on the next
/// rebuild. A sibling host in a wholly separate namespace (and therefore
/// partition, and therefore Gateway) stays up throughout, proving the
/// fallback doesn't degrade into a stop-the-world full-table replace either.
#[tokio::test]
async fn unmappable_change_falls_back_to_full_rebuild() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let auth_ns = NamespaceGuard::create(&h.client, "resil-epoch-auth").await?;
    let sibling_ns = NamespaceGuard::create(&h.client, "resil-epoch-sibling").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&auth_ns.name)).await?;
    wait::wait_for_backends(&auth_ns.name).await?;
    fixtures::apply_fixture(
        gwa::BASIC_AUTH_EXTENSIONREF,
        FixtureVars::new(&auth_ns.name),
    )
    .await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&sibling_ns.name)).await?;
    wait::wait_for_backends(&sibling_ns.name).await?;
    fixtures::apply_fixture(gwa::TWO_HOSTS, FixtureVars::new(&sibling_ns.name)).await?;

    let auth_gw = h.gateway_http(&auth_ns.name).await?;
    let sibling_gw = h.gateway_http(&sibling_ns.name).await?;
    let auth_host = format!("gwbasicauth.{}.local", auth_ns.name);
    let host_a = format!("host-a.{}.local", sibling_ns.name);
    let host_b = format!("host-b.{}.local", sibling_ns.name);

    // Baseline: alice:secret (bcrypt) is admitted; sibling hosts serve normally.
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async { format!("gateway BasicAuth route to admit alice:secret at {auth_host}") },
        || async {
            match auth_gw
                .get_full_with_headers(
                    &auth_host,
                    "/",
                    &[("authorization", "Basic YWxpY2U6c2VjcmV0")],
                )
                .await
            {
                Ok((200, _, Some(body))) => Some(body),
                _ => None,
            }
        },
    )
    .await?
    .assert_backend("echo-a");
    wait::wait_for_backend(&sibling_gw, &host_a, "/", "echo-a", Duration::from_secs(60)).await?;
    wait::wait_for_backend(&sibling_gw, &host_b, "/", "echo-b", Duration::from_secs(15)).await?;

    // Rotate the htpasswd Secret to a different (still valid) credential —
    // bob replaces alice. The BasicAuth CR and the HTTPRoute are both
    // untouched — a pure `auth_secrets`-store change, the exact
    // untracked-by-route-fingerprint dependency the global_epoch fold exists
    // to catch. A still-parseable htpasswd keeps `IngressAuthConfig::Basic`
    // resolved (proving the rotation was actually picked up) rather than
    // degrading to `Unavailable`/503 (an empty-credentials broken-config
    // case, not a credential-rejection case).
    let secrets: Api<Secret> = Api::namespaced(h.client.clone(), &auth_ns.name);
    secrets
        .patch(
            "gw-auth-htpasswd",
            &PatchParams::default(),
            &Patch::Merge(&json!({
                "data": {
                    "auth": "Ym9iOiQyeSQwNCR3clJGUVNDQmV6WUxUeVdYSktXZXV1T2h0RnVrckFqN1B6UFl0UXNPTkVoOHJPT2pqSUxhSwo="
                }
            })),
        )
        .await
        .context("rotate gw-auth-htpasswd to a different credential (bob)")?;

    // Previously-valid credentials are now rejected — the rotation was picked
    // up despite not being precisely tracked per-route.
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            format!("alice:secret to be rejected (401) at {auth_host} after Secret rotation")
        },
        || async {
            match auth_gw
                .get_full_with_headers(
                    &auth_host,
                    "/",
                    &[("authorization", "Basic YWxpY2U6c2VjcmV0")],
                )
                .await
            {
                Ok((401, _, _)) => Some(()),
                _ => None,
            }
        },
    )
    .await?;

    // The sibling namespace's hosts, sharing nothing with the BasicAuth
    // route's Gateway or partition, were never disrupted.
    wait::wait_for_backend(&sibling_gw, &host_a, "/", "echo-a", Duration::from_secs(15)).await?;
    wait::wait_for_backend(&sibling_gw, &host_b, "/", "echo-b", Duration::from_secs(15)).await?;

    Ok(())
}

// ── UDP listener drain (#618) ─────────────────────────────────────────────────

/// Sum every sample of `metric` in a Prometheus exposition, ignoring labels.
///
/// The `listener` label on a shared-mode Gateway is the controller-allocated
/// internal accept port, not the advertised one, so a test cannot predict it.
/// Summing sidesteps that; this suite is serial, so the total is attributable.
fn metric_sum(exposition: &str, metric: &str) -> f64 {
    exposition
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter(|l| {
            l.split(&[' ', '{'][..])
                .next()
                .is_some_and(|name| name == metric)
        })
        .filter_map(|l| {
            let after = match l.rsplit_once('}') {
                Some((_, rest)) => rest,
                None => l.split_once(' ').map(|(_, rest)| rest)?,
            };
            after.split_whitespace().next()?.parse::<f64>().ok()
        })
        .sum()
}

async fn proxy_metric_sum(h: &Harness, metric: &str) -> anyhow::Result<f64> {
    let body = reqwest::get(h.admin_url("/metrics"))
        .await
        .context("scrape proxy /metrics")?
        .text()
        .await?;
    Ok(metric_sum(&body, metric))
}

/// Removing a UDP listener must return its session and listener gauges to
/// baseline (#618).
///
/// UDP drain calls `JoinSet::abort_all`, which cancels each reply pump exactly
/// where it is parked — inside `recv()`. Cleanup written as straight-line code
/// after the pump loop therefore never runs, so `udp_sessions_active` kept every
/// session it ever opened. The gauge is keyed by listener port, so a listener
/// re-added on that port inherits the drift: it compounds per reconcile and
/// never self-heals. `listeners_active{draining}` had the same shape — the
/// reconcile increments it for both protocols, but only the TCP path ever
/// decremented it, so every UDP add/remove cycle inflated it permanently and an
/// operator alerting on stuck drains got a false positive forever.
///
/// Both assertions are baseline-relative: this suite is serial, but the proxy is
/// shared, so absolute values are not the test's to own.
#[tokio::test]
async fn udp_listener_removal_does_not_leak_session_gauge() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "res-udp-drain").await?;

    let sessions_baseline = proxy_metric_sum(&h, "coxswain_proxy_udp_sessions_active").await?;
    let draining_baseline = proxy_metric_sum(&h, "coxswain_proxy_listeners_active").await?;

    fixtures::apply_fixture(backends::UDP_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["udp-echo-a"]).await?;
    fixtures::apply_fixture(
        gwa::UDP_ROUTE,
        FixtureVars::new(&ns.name).with(
            "GATEWAY_UDP_PROXY_PORT",
            coxswain_e2e::harness::GATEWAY_UDP_PROXY_PORT.to_string(),
        ),
    )
    .await?;
    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-udp-gw",
        &ns.name,
        "Programmed",
        "True",
        Duration::from_secs(60),
    )
    .await?;

    // Each probe binds a fresh client socket, so each opens a distinct session.
    // Hold them open: the sessions must still be live when the listener is
    // removed, or the drain has nothing to leak.
    let udp_addr = h.gateway_udp_addr(&ns.name).await?;
    let mut clients = Vec::new();
    for _ in 0..3u8 {
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .context("bind UDP client")?;
        sock.connect(&udp_addr)
            .await
            .context("connect UDP client")?;
        clients.push(sock);
    }

    // Poll rather than assume the route is live: the first datagram of a session
    // is what establishes it.
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async { "UDP sessions to establish on the proxy".to_string() },
        || async {
            for sock in &clients {
                sock.send(b"hello-udp").await.ok()?;
            }
            let live = proxy_metric_sum(&h, "coxswain_proxy_udp_sessions_active")
                .await
                .ok()?;
            (live > sessions_baseline).then_some(live)
        },
    )
    .await?;

    // Remove the listener: this is the drain that used to leak.
    Api::<Gateway>::namespaced(h.client.clone(), &ns.name)
        .delete("coxswain-udp-gw", &DeleteParams::default())
        .await
        .context("delete the UDP Gateway")?;

    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async {
            let live = proxy_metric_sum(&h, "coxswain_proxy_udp_sessions_active")
                .await
                .unwrap_or(-1.0);
            format!(
                "udp_sessions_active to fall back to its {sessions_baseline} baseline \
                 after the UDP listener drained (currently {live}); a stuck value is \
                 the abort_all() leak — every session the listener ever opened, \
                 counted forever"
            )
        },
        || async {
            let live = proxy_metric_sum(&h, "coxswain_proxy_udp_sessions_active")
                .await
                .ok()?;
            (live <= sessions_baseline).then_some(())
        },
    )
    .await?;

    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            let live = proxy_metric_sum(&h, "coxswain_proxy_listeners_active")
                .await
                .unwrap_or(-1.0);
            format!(
                "listeners_active to fall back to its {draining_baseline} baseline \
                 after the UDP listener drained (currently {live}); a stuck value \
                 means the drained listener never released its slot, so every UDP \
                 add/remove cycle inflates the gauge permanently"
            )
        },
        || async {
            let live = proxy_metric_sum(&h, "coxswain_proxy_listeners_active")
                .await
                .ok()?;
            (live <= draining_baseline).then_some(())
        },
    )
    .await?;

    Ok(())
}
