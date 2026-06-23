#![allow(missing_docs)]
//! Discovery control-plane behaviour plane.
//!
//! Plane: **discovery**. Execution: **serial** — Group 3 scales the shared
//! controller to zero, so the full binary is placed in the serial pass to
//! prevent interference with concurrent routing/status tests.
//!
//! Classification rule: a test belongs to the plane of its *primary assertion
//! target*. Tests here assert discovery-channel behaviour (SPIFFE SAN rejection,
//! convergence lifecycle, proxy health state, NodeRegistry), **not** routing
//! outcomes. Routing-outcome assertions appear in `routing.rs`; this plane
//! treats an established route as a pre-condition or ancillary continuity check.
//!
//! ## Scenario groups
//!
//! **Group 1 — Auth rejection (SPIFFE trust-domain mismatch)**
//! The proxy binary always bootstraps its SVID from the controller; there is no
//! static-cert injection path. The config-reachable path that exercises the
//! SPIFFE `SpiffeMatcher` is `COXSWAIN_DISCOVERY_TRUST_DOMAIN`: a wrong value
//! makes the proxy reject the controller's real `spiffe://cluster.local/...` SAN
//! at the bootstrap TLS handshake. The observable end-states (NotReady / Ready)
//! are identical to the stream-level SAN mismatch the issue describes.
//!
//! **Group 2 — Convergence / readiness lifecycle**
//! A fresh proxy pod starts cold (NotReady), bootstraps, applies the first
//! snapshot, and reaches Ready. The transient NotReady window is proven
//! structurally by Group 1 (a wrong-config proxy never exits it); direct
//! observation of the window is skipped here to avoid a flake-prone race.
//! The convergence is cross-validated against the topology API.
//!
//! **Group 3 — Reconnect after controller restart**
//! Covers the proxy-health + NodeRegistry side of a controller outage
//! (`lifecycle_controller_restart_is_idempotent` in `resilience.rs` covers
//! the controller-SSA idempotency side). The shared proxy must transition to
//! `Degraded` (still serving last-good snapshot) while the controller is down,
//! then return to `Ready` and show `in_sync=true` in the topology after the
//! controller comes back.

use anyhow::Context as _;
use k8s_openapi::api::apps::v1::Deployment;
use kube::api::{Api, PostParams};
use std::time::Duration;

use coxswain_e2e::{
    FixtureVars, Harness, NamespaceGuard,
    fixtures::{self, backends, ingress},
    harness::wait,
};

mod common;
use common::dedicated::scale_controller;
use common::discovery::{
    assert_pod_stays_not_ready, copy_trust_bundle, fetch_topology, find_node, proxy_health_state,
    shared_proxy_deployment, wait_for_pod_ready,
};

// ── Group 1 — Auth rejection (SPIFFE trust-domain mismatch) ──────────────────

/// Sad path: a proxy configured with `COXSWAIN_DISCOVERY_TRUST_DOMAIN=wrong.example`
/// derives the wrong expected controller SAN
/// (`spiffe://wrong.example/ns/coxswain-system/sa/coxswain-controller`). The
/// real controller's bootstrap TLS certificate carries
/// `spiffe://cluster.local/ns/coxswain-system/sa/coxswain-controller`, which
/// doesn't match the proxy's expected SAN → the proxy rejects the TLS handshake
/// → no SVID is issued → `routing_table_loaded` stays `Pending` → the
/// readinessProbe fails → pod stays `Ready=False` for the entire observation window.
///
/// This exercises the `SpiffeMatcher::Exact` verifier on the proxy/client side
/// of the mTLS exchange (the closest config-reachable analogue to a stream-level
/// SPIFFE SAN mismatch; the bootstrap endpoint drives the same SAN-matching code).
#[tokio::test]
async fn wrong_trust_domain_keeps_proxy_not_ready() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "disc-auth-bad").await?;

    // Copy the controller's trust bundle into the test namespace so the rogue
    // pod can mount it (cross-namespace ConfigMap volume mounts are disallowed).
    copy_trust_bundle(&h.client, &ns.name).await?;

    // Build the Deployment with the wrong trust domain.
    let deploy = shared_proxy_deployment(&ns.name, "disc-bad-trust", "wrong.example")?;
    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    deployments
        .create(&PostParams::default(), &deploy)
        .await
        .context("create disc-bad-trust Deployment")?;

    // Assert the pod stays NotReady for at least 30 s. The readinessProbe polls
    // every 2 s with failureThreshold=30, so 30 s of NotReady means the probe
    // fired ~15 times — well past a scheduling or container-startup blip.
    // (The bootstrap loop retries with jittered backoff 250 ms → 30 s; within
    // 30 s it will have tried at least twice and failed both times.)
    assert_pod_stays_not_ready(
        &h.client,
        &ns.name,
        "app=disc-bad-trust",
        Duration::from_secs(30),
    )
    .await?;

    Ok(())
}

/// Happy path / recovery: the same proxy configuration with the correct
/// `COXSWAIN_DISCOVERY_TRUST_DOMAIN=cluster.local` bootstraps its SVID,
/// applies the first routing snapshot, and reaches `Ready=True`.
///
/// This is the issue's "correct SAN after rotation → proxy reconnects and
/// becomes Ready" modelled as a fresh correctly-configured deploy: same
/// SAN-matching code path, controlled configuration rather than a flaky
/// mid-run cert rotation window.
#[tokio::test]
async fn corrected_trust_domain_lets_proxy_become_ready() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "disc-auth-good").await?;

    copy_trust_bundle(&h.client, &ns.name).await?;

    // Deploy with the correct trust domain.
    let deploy = shared_proxy_deployment(&ns.name, "disc-good-trust", "cluster.local")?;
    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    deployments
        .create(&PostParams::default(), &deploy)
        .await
        .context("create disc-good-trust Deployment")?;

    // Wait for the pod to reach Ready=True (proves bootstrap + first snapshot
    // + Ack all succeeded). 90 s is generous; on a warm OrbStack cluster the
    // full bootstrap chain typically completes in under 10 s.
    wait_for_pod_ready(
        &h.client,
        &ns.name,
        "app=disc-good-trust",
        Duration::from_secs(90),
    )
    .await?;

    Ok(())
}

// ── Group 2 — Convergence / readiness lifecycle ───────────────────────────────

/// A fresh shared proxy pod bootstraps its SVID, applies the first routing
/// snapshot, transitions from `NotReady` to `Ready`, and registers in the
/// controller's NodeRegistry. The topology API reflects the converged state:
/// `in_sync=true`, `last_acked_version` non-null, and scope `SharedPool`.
///
/// The transient `NotReady`-before-snapshot window is proven structurally by
/// `wrong_trust_domain_keeps_proxy_not_ready` (a wrong-config proxy never
/// exits it) rather than by a racy direct observation here.
#[tokio::test]
async fn fresh_proxy_converges_and_registers_in_node_registry() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "disc-converge").await?;

    copy_trust_bundle(&h.client, &ns.name).await?;

    let deploy = shared_proxy_deployment(&ns.name, "disc-converge", "cluster.local")?;
    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    deployments
        .create(&PostParams::default(), &deploy)
        .await
        .context("create disc-converge Deployment")?;

    // Wait for the proxy pod's readinessProbe to flip Ready=True (proves the
    // full bootstrap → snapshot → Ack chain completed).
    wait_for_pod_ready(
        &h.client,
        &ns.name,
        "app=disc-converge",
        Duration::from_secs(90),
    )
    .await?;

    // Cross-validate against the topology API: the NodeRegistry must contain an
    // entry for this proxy with in_sync=true and a non-null last_acked_version.
    // The node_id is the pod name (POD_NAME downward API = metadata.name), which
    // for a Deployment called "disc-converge" is "disc-converge-<rs>-<pod>".
    let topology_url = h.controller_admin_url("/api/v1/topology");
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || {
            let url = topology_url.clone();
            async move {
                format!("topology at '{url}' to contain a 'disc-converge-*' node with in_sync=true")
            }
        },
        || {
            let url = topology_url.clone();
            async move {
                let topology = fetch_topology(&url).await.ok()?;
                let node = find_node(&topology, "disc-converge-")?;
                node.get("in_sync")
                    .and_then(|v| v.as_bool())
                    .filter(|&b| b)
                    .map(|_| node.clone())
            }
        },
    )
    .await
    .context("topology did not converge for disc-converge-* node")?;

    // Re-fetch to run the full set of assertions now that we know the node exists.
    let topology = fetch_topology(&topology_url).await?;
    let node = find_node(&topology, "disc-converge-").ok_or_else(|| {
        anyhow::anyhow!(
            "topology node for 'disc-converge-*' absent after convergence poll passed; \
             topology: {topology}"
        )
    })?;

    assert_eq!(
        topology.get("discovery_active").and_then(|v| v.as_bool()),
        Some(true),
        "topology discovery_active must be true; topology: {topology}"
    );
    assert_eq!(
        node.pointer("/scope/kind").and_then(|v| v.as_str()),
        Some("SharedPool"),
        "node scope must be SharedPool; node: {node}"
    );
    assert!(
        node.get("last_acked_version").is_some_and(|v| !v.is_null()),
        "node last_acked_version must be non-null after convergence; node: {node}"
    );
    assert_eq!(
        node.get("in_sync").and_then(|v| v.as_bool()),
        Some(true),
        "node must be in_sync after convergence; node: {node}"
    );

    Ok(())
}

// ── Group 3 — Reconnect after controller restart ──────────────────────────────

/// Stop the controller, observe the shared proxy transition to `Degraded`
/// (still serving traffic from last-good snapshot), then bring the controller
/// back and assert the proxy returns to `Ready` with the NodeRegistry
/// `in_sync=true`.
///
/// Serial: this test scales the shared controller to zero, which affects every
/// test that relies on the controller being up. The `discovery` binary is
/// serialised in the nextest config.
///
/// The controller-SSA idempotency side of a restart is covered by
/// `lifecycle_controller_restart_is_idempotent` in `resilience.rs`.
/// This test covers the proxy-health and NodeRegistry convergence side.
#[tokio::test]
async fn proxy_degrades_during_controller_outage_then_recovers() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "disc-restart").await?;

    // Establish a live route so we can assert traffic continuity during
    // controller downtime.
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("ingress.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;

    // ── Phase 1: take the controller down ────────────────────────────────────

    scale_controller(0).await?;

    // The proxy detects the dropped TCP connection within seconds of the
    // controller pod terminating (OS-side RST/FIN). Poll until the shared proxy
    // health shows `Degraded` (still serving; /readyz stays 200).
    let proxy_health_url = h.admin_url("/api/v1/health");
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || {
            let url = proxy_health_url.clone();
            async move {
                let state = proxy_health_state(&url).await;
                format!(
                    "shared proxy subsystems.proxy.state to be 'degraded'; \
                     currently: {state:?}; health URL: {url}"
                )
            }
        },
        || {
            let url = proxy_health_url.clone();
            async move {
                let state = proxy_health_state(&url).await?;
                (state == "degraded").then_some(())
            }
        },
    )
    .await
    .context("shared proxy did not transition to Degraded during controller downtime")?;

    // With the discovery stream down the data plane must still serve routes
    // from the last-good snapshot.
    let continuity = h.http.get(&host, "/a").await?;
    continuity.assert_backend("echo-a");

    // ── Phase 2: bring the controller back ───────────────────────────────────

    scale_controller(1).await?;

    // Re-create the harness to get fresh port-forwards to the new controller
    // pod. The proxy is unchanged so its port-forward stays implicitly valid,
    // but Harness::start() re-establishes it correctly.
    let h2 = Harness::start().await?;

    // Poll until the topology shows the shared proxy (any SharedPool node)
    // back in_sync — proves reconnect + re-Ack completed.
    let topology_url = h2.controller_admin_url("/api/v1/topology");
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || {
            let url = topology_url.clone();
            async move {
                format!(
                    "topology at '{url}' to contain a SharedPool node with in_sync=true \
                     after controller restart"
                )
            }
        },
        || {
            let url = topology_url.clone();
            async move {
                let topology = fetch_topology(&url).await.ok()?;
                topology
                    .get("nodes")?
                    .as_array()?
                    .iter()
                    .find(|n| {
                        n.pointer("/scope/kind").and_then(|v| v.as_str()) == Some("SharedPool")
                            && n.get("in_sync").and_then(|v| v.as_bool()).unwrap_or(false)
                    })
                    .map(|_| ())
            }
        },
    )
    .await
    .context(
        "shared proxy did not re-register as in_sync in the NodeRegistry after controller restart",
    )?;

    // After reconnect the proxy health must return to Ready.
    let proxy_health_url2 = h2.admin_url("/api/v1/health");
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || {
            let url = proxy_health_url2.clone();
            async move {
                let state = proxy_health_state(&url).await;
                format!(
                    "shared proxy subsystems.proxy.state to return to 'ready'; \
                     currently: {state:?}"
                )
            }
        },
        || {
            let url = proxy_health_url2.clone();
            async move {
                let state = proxy_health_state(&url).await?;
                (state == "ready").then_some(())
            }
        },
    )
    .await
    .context("shared proxy did not return to Ready after controller restart")?;

    // Traffic must still serve after the reconnect.
    let post = h2.http.get(&host, "/a").await?;
    post.assert_backend("echo-a");

    Ok(())
}
