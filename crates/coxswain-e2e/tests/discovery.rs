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
//!
//! **Group 4 — Bootstrap credential (ServiceAccount token, #423)**
//! The shared proxy ships zero pre-provisioned cert material; it acquires its
//! SVID at runtime by presenting its projected `coxswain-discovery`-audience
//! ServiceAccount token to the controller's bootstrap listener. Happy path: a
//! zero-cert proxy bootstraps and serves a route (end-to-end proof of
//! controller-as-CA + SA-token TokenReview + SVID-over-channel). Sad path: a
//! token minted for the WRONG audience is rejected, the rogue proxy never
//! reaches Ready, and the controller — the sole diagnostic emitter — records a
//! `BootstrapRejected` Warning Event and increments the rejection metric.
//!
//! **Group 5 — Read-only-proxy ServiceAccount audit (#424)**
//! The shared proxy is a pure discovery client: its SA exists only as a pod
//! identity for SVID bootstrap and carries no ClusterRole/RoleBinding. A
//! structural `kubectl auth can-i --list` audit guards that the SA holds zero
//! coxswain-granted resource verbs (only Kubernetes baseline grants may appear).

use anyhow::Context as _;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use k8s_openapi::api::events::v1::Event;
use k8s_openapi::api::networking::v1::Ingress;
use kube::api::{Api, ListParams, ObjectMeta, Patch, PatchParams, PostParams};
use serde_json::json;
use std::collections::HashSet;
use std::process::Command;
use std::time::Duration;

use coxswain_e2e::{
    FixtureVars, Harness, NamespaceGuard,
    fixtures::{self, backends, gateway_api as gwa, ingress},
    harness::wait,
};

mod common;
use common::dedicated::scale_controller;
use common::discovery::{
    assert_pod_stays_not_ready, copy_trust_bundle, fetch_topology, find_node, proxy_health_state,
    scrape_metric, scrape_metric_label_sum, shared_proxy_deployment, wait_for_pod_ready,
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
/// (still serving traffic from its last-good snapshot), then bring the
/// controller back and assert the proxy reconnects and reconverges.
///
/// Recovery is asserted from the **proxy and data plane**, not the controller's
/// NodeRegistry: the proxy health returns to `Ready`, the pre-existing route
/// keeps serving, and — the strongest signal — a route created *after* the
/// restart is compiled by the new controller and pushed to the reconnected
/// proxy. That fresh-snapshot delivery proves the discovery stream is live again
/// end-to-end; the controller-side `in_sync` view is already covered in
/// [`fresh_proxy_converges_and_registers_in_node_registry`], so re-asserting it
/// here would only duplicate that and couple this test to registry repopulation
/// timing.
///
/// Serial: this test scales the shared controller to zero, which affects every
/// test that relies on the controller being up. The `discovery` binary is
/// serialised in the nextest config.
///
/// The controller-SSA idempotency side of a restart is covered by
/// `restart_controller_does_not_bump_generation` in `resilience.rs`. This test
/// covers the proxy-health + data-plane recovery side.
#[tokio::test]
async fn proxy_degrades_during_controller_outage_then_recovers() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // Persistent namespace: the second Harness::start() below runs bootstrap(),
    // which purges coxswain-e2e=true namespaces. Persistent skips that label so
    // the route we assert on after the restart survives the purge.
    let ns = NamespaceGuard::create_persistent(&h.client, "disc-restart").await?;

    // Establish a live route so we can assert traffic continuity during
    // controller downtime.
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("ingress.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;

    // ── Phase 1: take the controller down → proxy degrades, keeps serving ─────

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

    // ── Phase 2: bring the controller back → proxy reconnects, reconverges ────

    scale_controller(1).await?;

    // Re-create the harness for fresh port-forwards to the new controller pod,
    // then gate on the real post-condition — new leader elected + at least one
    // successful reconcile on the fresh process — before asserting proxy
    // recovery. wait_for_controller_reconciled polls until it sees leader=1, so
    // the port-forward is confirmed to target the new leader pod (not an old
    // replica lingering mid-rollout), which the metric assertion below relies on.
    let h2 = Harness::start().await?;
    wait::wait_for_controller_reconciled(
        &h2.controller_admin_url("/metrics"),
        Duration::from_secs(60),
    )
    .await?;

    // Gate on the proxy actually reconnecting BEFORE creating the post-restart
    // route: poll until shared-proxy health clears Degraded and returns to
    // `ready`, which happens only once the discovery client has reconnected and
    // applied a post-reconnect snapshot. The proxy's reconnect backoff can sit at
    // its 30 s full-jitter cap when the controller returns (it climbed during the
    // downtime), so this window is generous. Sequencing recovery first — rather
    // than racing it against a freshly-applied route — keeps the route assertion
    // below on the same apply→serve path every steady-state routing test uses,
    // instead of coupling two independent async convergences (reconnect + push)
    // into one bounded wait.
    let proxy_health_url2 = h2.admin_url("/api/v1/health");
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || {
            let url = proxy_health_url2.clone();
            async move {
                let state = proxy_health_state(&url).await;
                format!(
                    "shared proxy subsystems.proxy.state to return to 'ready' \
                     (discovery client reconnected); currently: {state:?}"
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

    // With the stream provably live, create a brand-new route and confirm it
    // serves end-to-end. `echo-b` answering on a host that never existed before
    // the restart proves the reconnected discovery stream delivers fresh
    // snapshots — the data-plane half of recovery. Mirrors the controller-restart
    // catch-up assertions in `resilience.rs`.
    let fresh_host = format!("disc-restart-fresh.{}.local", ns.name);
    let fresh_ingress = json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": { "name": "disc-restart-fresh", "namespace": &ns.name },
        "spec": {
            "ingressClassName": "coxswain",
            "rules": [{ "host": &fresh_host, "http": { "paths": [{
                "path": "/", "pathType": "Prefix",
                "backend": { "service": { "name": "echo-b", "port": { "number": 3000 } } }
            }] } }]
        }
    });
    let ingresses: Api<Ingress> = Api::namespaced(h2.client.clone(), &ns.name);
    ingresses
        .patch(
            "disc-restart-fresh",
            &PatchParams::apply("e2e-test"),
            &Patch::Apply(&fresh_ingress),
        )
        .await
        .context("apply post-restart route")?;

    wait::wait_for_backend(
        &h2.http,
        &fresh_host,
        "/",
        "echo-b",
        Duration::from_secs(120),
    )
    .await?;

    // The pre-existing route still serves too.
    wait::wait_for_backend(&h2.http, &host, "/a", "echo-a", Duration::from_secs(30)).await?;

    // Final confirmation of the server-side discovery metric: now that the data
    // plane has proven the stream is live, the controller's gauge must report the
    // reconnected proxy. This runs last (not as a gate) precisely because the
    // gauge is lazily registered on first connect and is process-local — asserting
    // it before reconnection is proven would race both registration and a
    // mid-rollout port-forward. After the proof above, it is guaranteed present
    // and >= 1 on the confirmed-leader port-forward.
    let controller_metrics_url = h2.controller_admin_url("/metrics");
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || {
            let url = controller_metrics_url.clone();
            async move {
                let v = scrape_metric(&url, "coxswain_discovery_connected_proxies").await;
                format!(
                    "controller coxswain_discovery_connected_proxies >= 1 after restart; \
                     currently: {v:?}"
                )
            }
        },
        || {
            let url = controller_metrics_url.clone();
            async move {
                let v = scrape_metric(&url, "coxswain_discovery_connected_proxies").await?;
                (v >= 1.0).then_some(())
            }
        },
    )
    .await
    .context("controller did not report the reconnected proxy stream in coxswain_discovery_connected_proxies")?;

    Ok(())
}

// ===========================================================================
// Group 4 — Discovery control-plane bootstrap (#423).
//
// The shared proxy ships with ZERO pre-provisioned cert material: it acquires
// its SVID at runtime by presenting its projected ServiceAccount token to the
// controller's bootstrap listener (server-auth-only TLS), receiving a CA-signed
// SVID, then opening the mandatory-mTLS Stream to receive routing snapshots.
//
// Because the e2e harness installs via `helm --wait`, the shared-proxy pod only
// reaches Ready once that whole bootstrap chain has succeeded — so a served
// route is end-to-end proof that controller-as-CA + SA-token bootstrap +
// SVID-over-channel all work. The first test asserts the CA artifacts exist and
// that routing flows; the read-only audit below confirms the bootstrap volumes
// added no write verbs to the proxy SA.
// ===========================================================================

/// The discovery control-plane namespace (matches the harness Helm install and
/// `deploy/manifests`). CA Secret + trust ConfigMap live here.
const DISCOVERY_NAMESPACE: &str = "coxswain-system";

/// Happy path: a proxy with no pre-provisioned cert bootstraps its SVID, opens
/// the mTLS Stream, and serves a route — and the controller-as-CA artifacts
/// (CA Secret + published trust-bundle ConfigMap) exist.
#[tokio::test]
async fn zero_cert_proxy_bootstraps_and_serves_routes() -> anyhow::Result<()> {
    let h = Harness::start().await?;

    // The controller self-generated (mode=auto) the CA Secret and published the
    // public trust bundle ConfigMap proxies mount. Assert both exist with the
    // expected keys — these are the controller-as-CA artifacts the bootstrap
    // chain depends on.
    let secrets: Api<Secret> = Api::namespaced(h.client.clone(), DISCOVERY_NAMESPACE);
    let ca = secrets.get("coxswain-discovery-ca").await.map_err(|e| {
        anyhow::anyhow!("CA Secret coxswain-discovery-ca must exist in {DISCOVERY_NAMESPACE}: {e}")
    })?;
    let ca_data = ca.data.unwrap_or_default();
    assert!(
        ca_data.contains_key("tls.crt") && ca_data.contains_key("tls.key"),
        "CA Secret must carry tls.crt + tls.key, got keys: {:?}",
        ca_data.keys().collect::<Vec<_>>()
    );

    let cms: Api<ConfigMap> = Api::namespaced(h.client.clone(), DISCOVERY_NAMESPACE);
    let trust = cms.get("coxswain-discovery-trust").await.map_err(|e| {
        anyhow::anyhow!(
            "trust-bundle ConfigMap coxswain-discovery-trust must be published in \
             {DISCOVERY_NAMESPACE} (the controller publisher writes it): {e}"
        )
    })?;
    let trust_data = trust.data.unwrap_or_default();
    let bundle = trust_data.get("ca.crt").ok_or_else(|| {
        anyhow::anyhow!(
            "trust ConfigMap must carry the ca.crt key, got: {:?}",
            trust_data.keys().collect::<Vec<_>>()
        )
    })?;
    assert!(
        bundle.contains("BEGIN CERTIFICATE"),
        "trust bundle ca.crt must be PEM, got {} bytes without a PEM header",
        bundle.len()
    );

    // End-to-end proof: the bootstrapped proxy serves a route over the mTLS
    // stream it could only have opened with a valid SVID.
    let ns = NamespaceGuard::create(&h.client, "boot-serves").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("ingress.{}.local", ns.name);
    let resp = wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    Ok(())
}

/// Sum the *occurrences* of `BootstrapRejected` Warning Events in the discovery
/// namespace.
///
/// The kube `Recorder` coalesces every same-key event into ONE Event object: its
/// key is `(type, action, reason, reportingController, reportingInstance,
/// regarding)` — the note is NOT part of the key. Every bootstrap rejection
/// shares that key (regarding is always the controller Pod, reason is always
/// `BootstrapRejected`), so the first rejection in the controller's lifetime
/// creates the object and every later one only PATCHes its `series.count`.
/// Counting event *objects* therefore stays pinned at 1 no matter how many
/// proxies are rejected — and in a shared suite another test's dedicated proxy
/// routinely emits the first `BootstrapRejected` before this test runs, so an
/// object-count delta never moves.
///
/// Summing `series.count` (an Event with no series == 1 occurrence) yields a
/// total that increments on EVERY rejection, so the before/after delta reliably
/// captures the rogue proxy's reject regardless of coalescing. Coalescing is the
/// correct production behaviour (it prevents event spam from a proxy retrying on
/// a backoff loop), so the robustness lives here in the test, not the controller.
async fn count_bootstrap_rejected(events: &Api<Event>) -> anyhow::Result<usize> {
    let list = events.list(&ListParams::default()).await?;
    Ok(list
        .items
        .iter()
        .filter(|e| e.reason.as_deref() == Some("BootstrapRejected"))
        .map(|e| {
            e.series
                .as_ref()
                .and_then(|s| usize::try_from(s.count).ok())
                .unwrap_or(1)
        })
        .sum())
}

/// Sad path: a proxy that presents a ServiceAccount token minted for the WRONG
/// audience is rejected at bootstrap. TokenReview (which the controller scopes
/// to the `coxswain-discovery` audience) fails, so no SVID is issued, the rogue
/// proxy never reaches Ready, and the controller — the sole diagnostic emitter —
/// records a `BootstrapRejected` Warning Event.
#[tokio::test]
async fn invalid_sa_token_is_rejected_with_event() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "boot-reject").await?;

    // The rogue proxy must verify the controller's server cert before it can
    // send its (bad) token, so it needs the public trust bundle. Copy the
    // controller-published ConfigMap into the rogue namespace (cross-namespace
    // ConfigMap mounts are not allowed).
    let src_cms: Api<ConfigMap> = Api::namespaced(h.client.clone(), DISCOVERY_NAMESPACE);
    let trust = src_cms.get("coxswain-discovery-trust").await.map_err(|e| {
        anyhow::anyhow!("trust ConfigMap must exist before the sad-path test can run: {e}")
    })?;
    let dst_cms: Api<ConfigMap> = Api::namespaced(h.client.clone(), &ns.name);
    dst_cms
        .create(
            &PostParams::default(),
            &ConfigMap {
                metadata: ObjectMeta {
                    name: Some("coxswain-discovery-trust".to_owned()),
                    namespace: Some(ns.name.clone()),
                    ..Default::default()
                },
                data: trust.data.clone(),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("copy trust bundle into {}: {e}", ns.name))?;

    let events: Api<Event> = Api::namespaced(h.client.clone(), DISCOVERY_NAMESPACE);
    let before = count_bootstrap_rejected(&events).await?;

    // Baseline the controller's rejection counter so we can prove this rogue's
    // rejects (not some earlier test's) drive the metric up.
    let metrics_url = h.controller_admin_url("/metrics");
    let rejected_before = scrape_metric_label_sum(
        &metrics_url,
        "coxswain_discovery_bootstrap_total",
        "result=\"rejected\"",
    )
    .await
    .unwrap_or(0.0);

    // A rogue proxy whose projected token is minted for the WRONG audience.
    // Everything else mirrors a normal shared proxy.
    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let rogue: Deployment = serde_json::from_value(json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": { "name": "rogue-proxy", "namespace": ns.name },
        "spec": {
            "replicas": 1,
            "selector": { "matchLabels": { "app": "rogue-proxy" } },
            "template": {
                "metadata": { "labels": { "app": "rogue-proxy" } },
                "spec": {
                    "containers": [{
                        "name": "coxswain",
                        "image": "coxswain:e2e",
                        "imagePullPolicy": "Never",
                        "args": ["serve", "proxy", "--shared"],
                        "env": [
                            { "name": "POD_NAME", "valueFrom": { "fieldRef": { "fieldPath": "metadata.name" } } },
                            { "name": "POD_NAMESPACE", "valueFrom": { "fieldRef": { "fieldPath": "metadata.namespace" } } },
                            { "name": "COXSWAIN_DISCOVERY_ENDPOINT", "value": "https://coxswain-controller-discovery.coxswain-system.svc:50051" },
                            { "name": "COXSWAIN_DISCOVERY_BOOTSTRAP_ENDPOINT", "value": "https://coxswain-controller-discovery-bootstrap.coxswain-system.svc:50052" },
                            { "name": "COXSWAIN_DISCOVERY_SA_TOKEN_PATH", "value": "/var/run/secrets/coxswain/discovery-token/token" },
                            { "name": "COXSWAIN_DISCOVERY_CA_BUNDLE_PATH", "value": "/var/run/secrets/coxswain/trust-bundle/ca.crt" },
                            { "name": "COXSWAIN_DISCOVERY_TRUST_DOMAIN", "value": "cluster.local" }
                        ],
                        "volumeMounts": [
                            { "name": "discovery-token", "mountPath": "/var/run/secrets/coxswain/discovery-token", "readOnly": true },
                            { "name": "trust-bundle", "mountPath": "/var/run/secrets/coxswain/trust-bundle", "readOnly": true }
                        ]
                    }],
                    "volumes": [
                        {
                            "name": "discovery-token",
                            "projected": {
                                "sources": [{
                                    "serviceAccountToken": {
                                        "path": "token",
                                        // Deliberately WRONG: the controller requires `coxswain-discovery`.
                                        "audience": "wrong-audience",
                                        "expirationSeconds": 3600
                                    }
                                }]
                            }
                        },
                        {
                            "name": "trust-bundle",
                            "configMap": { "name": "coxswain-discovery-trust", "optional": false }
                        }
                    ]
                }
            }
        }
    }))?;
    deployments.create(&PostParams::default(), &rogue).await?;

    // The bootstrap loop retries with backoff, so a rejection event appears
    // shortly after the rogue pod schedules.
    wait::poll_until(
        Duration::from_secs(120),
        wait::POLL,
        || async {
            "controller to emit a BootstrapRejected Warning Event for the wrong-audience token"
                .to_string()
        },
        || async {
            let now = count_bootstrap_rejected(&events).await.unwrap_or(before);
            (now > before).then_some(())
        },
    )
    .await?;

    // The same rejection must also increment the controller's Prometheus counter,
    // not just the K8s Event — operators alert on the metric. Poll because the
    // port-forwarded scrape and the reject path are independently timed.
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            let now = scrape_metric_label_sum(
                &metrics_url,
                "coxswain_discovery_bootstrap_total",
                "result=\"rejected\"",
            )
            .await;
            format!(
                "controller coxswain_discovery_bootstrap_total{{result=\"rejected\"}} to exceed \
                 the {rejected_before} baseline; currently: {now:?}"
            )
        },
        || async {
            let now = scrape_metric_label_sum(
                &metrics_url,
                "coxswain_discovery_bootstrap_total",
                "result=\"rejected\"",
            )
            .await?;
            (now > rejected_before).then_some(())
        },
    )
    .await?;

    Ok(())
}

// ===========================================================================
// Group 5 — Shared-proxy ServiceAccount RBAC audit.
//
// The shared proxy is a pure gRPC discovery client (post-#424); its runtime
// never touches the Kubernetes API. The SA exists only as a pod identity
// for SVID bootstrap (projected coxswain-discovery-audience token); no
// ClusterRole or RoleBinding is bound to it. This test guards that invariant:
// the SA must hold zero coxswain-granted resource verbs — only Kubernetes
// baseline grants (selfsubject* resources and non-resource URLs from
// system:basic-user and system:public-info-viewer) may appear.
//
// Two baseline-grant carve-outs:
// - `selfsubjectaccessreviews` / `selfsubjectrulesreviews` (api group
//   `authorization.k8s.io`) — every authenticated user holds `create` on
//   these via the cluster-default `system:basic-user` ClusterRoleBinding;
//   that's not the proxy's RBAC, it's Kubernetes plumbing.
// - Non-resource URLs (`/healthz`, `/version`, `/.well-known/*`) — same
//   reason, `system:public-info-viewer` grants `get` on these to every
//   authenticated user.
//
// The test skips when no cluster is reachable (kubectl unavailable, no
// kubeconfig context) so it remains runnable locally without infrastructure.
// In CI it runs against the same cluster the rest of the e2e suite targets.
// ===========================================================================

/// The ServiceAccount under audit. Matches the name rendered by both the
/// raw manifests in `deploy/manifests/shared-proxy-rbac.yaml` and the Helm
/// chart's default release-name convention (`<release>-coxswain-shared-proxy`).
const PROXY_SA_CANDIDATES: &[&str] = &[
    "coxswain-shared-proxy",
    "release-name-coxswain-shared-proxy",
];

/// Resource prefixes whose verbs come from baseline cluster grants
/// (`system:basic-user`, `system:public-info-viewer`), not from any
/// coxswain-bound ClusterRole. Excluded from the audit.
///
/// Every `selfsubject*` resource (under both `authorization.k8s.io` and
/// `authentication.k8s.io`) grants `create` to every authenticated principal
/// via cluster-default bindings; that's K8s plumbing, not coxswain.
const BASELINE_RESOURCE_PREFIXES: &[&str] = &["selfsubject"];

#[test]
fn shared_proxy_sa_has_no_kubernetes_rbac() {
    let Some(output) = try_auth_can_i_list() else {
        eprintln!(
            "shared_proxy_sa_has_no_kubernetes_rbac: no reachable cluster — skipping. \
             Run against a cluster with coxswain installed (helm or manifests) to enforce \
             the invariant."
        );
        return;
    };

    let rows = parse_auth_can_i(&output);
    assert!(
        !rows.is_empty(),
        "auth can-i --list returned no rows — is the ServiceAccount present? \
         Output was:\n{output}"
    );

    // Every non-baseline row is a coxswain-granted resource verb — there must
    // be none. Baseline grants (selfsubject* resources and non-resource URLs)
    // are K8s plumbing that exists for every authenticated principal and are
    // not the proxy's RBAC.
    let violations: Vec<String> = rows
        .iter()
        .filter(|r| !is_baseline_grant(r))
        .map(|r| format!("resource={}, verbs={:?}", r.resource, r.verbs))
        .collect();

    assert!(
        violations.is_empty(),
        "shared-proxy ServiceAccount holds coxswain-granted resource rows — \
         the SA must have zero K8s RBAC (discovery client, identity-only SA):\n\
         {}\n\
         full kubectl output:\n{output}",
        violations.join("\n")
    );
}

/// Try each candidate SA name; return the first kubectl output that succeeded.
/// Returns `None` when no cluster is reachable or no candidate SA exists.
fn try_auth_can_i_list() -> Option<String> {
    let namespace =
        std::env::var("COXSWAIN_E2E_NAMESPACE").unwrap_or_else(|_| "coxswain-system".to_string());

    for sa in PROXY_SA_CANDIDATES {
        let principal = format!("system:serviceaccount:{namespace}:{sa}");
        let output = Command::new("kubectl")
            .args(["auth", "can-i", "--list", "--as", &principal])
            .output()
            .ok()?;
        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("rbac_read_only_proxy: candidate `{sa}` failed: {stderr}");
    }
    None
}

/// One parsed row of `kubectl auth can-i --list` output.
#[derive(Debug, Default)]
struct AuthRow {
    /// Resource cell (first column). Empty when the row is a non-resource URL.
    resource: String,
    /// Verbs from the rightmost bracketed segment.
    verbs: Vec<String>,
    /// True when the row's non-resource URL column is non-empty.
    is_non_resource_url: bool,
}

/// Parse the kubectl table into [`AuthRow`]s. The output is column-aligned
/// whitespace; columns are: Resources, Non-Resource URLs, Resource Names,
/// Verbs. We split on whitespace runs, then re-assemble: the last bracketed
/// segment is verbs; segments preceding it are the first three columns.
fn parse_auth_can_i(output: &str) -> Vec<AuthRow> {
    let mut rows = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Resources") {
            continue;
        }
        let Some(open) = trimmed.rfind('[') else {
            continue;
        };
        let Some(close) = trimmed.rfind(']') else {
            continue;
        };
        if close <= open {
            continue;
        }

        // Verbs.
        let mut verbs = Vec::new();
        for verb in trimmed[open + 1..close].split(|c: char| c.is_whitespace() || c == ',') {
            let v = verb.trim();
            if !v.is_empty() {
                verbs.push(v.to_string());
            }
        }

        // Everything before the verbs bracket is the first three columns.
        let prefix = trimmed[..open].trim_end();
        let first_col = prefix.split_whitespace().next().unwrap_or("").to_string();

        let is_non_resource_url = first_col.starts_with('[') || first_col.is_empty();

        rows.push(AuthRow {
            resource: if is_non_resource_url {
                String::new()
            } else {
                first_col
            },
            verbs,
            is_non_resource_url,
        });
    }
    rows
}

fn is_baseline_grant(row: &AuthRow) -> bool {
    if row.is_non_resource_url {
        return true;
    }
    BASELINE_RESOURCE_PREFIXES
        .iter()
        .any(|p| row.resource == *p || row.resource.starts_with(p))
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    const SAMPLE_READ_ONLY: &str = "\
Resources                          Non-Resource URLs   Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []   []   [create]
selfsubjectrulesreviews.authorization.k8s.io    []   []   [create]
services                                        []   []   [get list watch]
secrets                                         []   []   [get,list,watch]
gateways.gateway.networking.k8s.io              []   []   [get list watch]
                                                [/.well-known/openid-configuration]   []   [get]
                                                [/.well-known/openid/v1/jwks]         []   [get]
";

    const SAMPLE_HAS_WRITE: &str = "\
Resources                          Non-Resource URLs   Resource Names   Verbs
services                                        []   []   [get list watch]
gateways/status.gateway.networking.k8s.io       []   []   [patch update]
";

    const ALLOWED_VERBS: &[&str] = &["get", "list", "watch"];

    #[test]
    fn read_only_sample_passes_audit() {
        let rows = parse_auth_can_i(SAMPLE_READ_ONLY);
        let allowed: HashSet<&str> = ALLOWED_VERBS.iter().copied().collect();
        for row in &rows {
            if is_baseline_grant(row) {
                continue;
            }
            for verb in &row.verbs {
                assert!(
                    allowed.contains(verb.as_str()),
                    "real read-only sample should not yield disallowed verbs; got {verb} on {}",
                    row.resource
                );
            }
        }
    }

    #[test]
    fn write_sample_yields_violation() {
        let rows = parse_auth_can_i(SAMPLE_HAS_WRITE);
        let allowed: HashSet<&str> = ALLOWED_VERBS.iter().copied().collect();
        let mut violations = 0;
        for row in &rows {
            if is_baseline_grant(row) {
                continue;
            }
            for verb in &row.verbs {
                if !allowed.contains(verb.as_str()) {
                    violations += 1;
                }
            }
        }
        assert!(
            violations >= 2,
            "write sample must produce at least two violations (patch + update); got {violations}"
        );
    }

    #[test]
    fn parse_ignores_header() {
        let rows = parse_auth_can_i("Resources Non-Resource URLs Resource Names Verbs\n");
        assert!(rows.is_empty(), "header line must not produce rows");
    }

    #[test]
    fn parse_handles_empty_output() {
        let rows = parse_auth_can_i("");
        assert!(rows.is_empty());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Group 6 — Leader-gated discovery stream (#531)
//
// The Stream RPC is served only by the lease holder: the leader labels its own
// pod (`discovery.coxswain-labs.dev/leader=true`) so the stream Service routes
// dials to it, and standbys reject stray streams with FAILED_PRECONDITION (the
// code-level rejection is unit-tested in coxswain-discovery). Readiness reports
// therefore always land in the status-writing leader's registry.
// ─────────────────────────────────────────────────────────────────────────────

/// The stream Service's endpoints and the per-pod `connected_proxies` gauge
/// must both single out the lease holder: standbys serve no streams.
#[tokio::test]
async fn only_lease_holder_reports_connected_proxy_streams() -> anyhow::Result<()> {
    use coxswain_e2e::harness::leader;
    use k8s_openapi::api::core::v1::{Endpoints, Pod};

    let h = Harness::start().await?;

    let leader_pod = leader::leader_pod_name(&h.client).await?;

    // The always-running shared proxy must hold a stream to the leader.
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || {
            let leader_pod = leader_pod.clone();
            async move {
                format!(
                    "leader pod {leader_pod} to report connected_proxies >= 1; observed {:?}",
                    leader::pod_metric_value(&leader_pod, "coxswain_discovery_connected_proxies")
                        .await
                )
            }
        },
        || {
            let leader_pod = leader_pod.clone();
            async move {
                let v =
                    leader::pod_metric_value(&leader_pod, "coxswain_discovery_connected_proxies")
                        .await
                        .ok()??;
                (v >= 1.0).then_some(())
            }
        },
    )
    .await?;

    // Every OTHER Ready controller replica must hold zero streams (absent
    // series reads as 0 — the gauge is touched only when a stream lands).
    let pods_api: Api<Pod> = Api::namespaced(h.client.clone(), leader::SYSTEM_NAMESPACE);
    let controller_pods = pods_api
        .list(&ListParams::default().labels("app.kubernetes.io/component=controller"))
        .await?;
    let mut standbys_checked = 0;
    for pod in &controller_pods {
        let name = pod.metadata.name.as_deref().unwrap_or_default();
        if name == leader_pod || name.is_empty() {
            continue;
        }
        let v = leader::pod_metric_value(name, "coxswain_discovery_connected_proxies").await?;
        assert!(
            v.unwrap_or(0.0) == 0.0,
            "standby {name} must serve zero discovery streams, reports {v:?}"
        );
        standbys_checked += 1;
    }
    assert!(
        standbys_checked >= 1,
        "HA default runs >= 2 controller replicas; found none besides the leader — \
         the standby assertion never ran"
    );

    // Deterministic routing: the stream Service's endpoints are exactly the
    // leader pod (the leader label selector at work).
    let ep_api: Api<Endpoints> = Api::namespaced(h.client.clone(), leader::SYSTEM_NAMESPACE);
    let ep = ep_api.get("coxswain-controller-discovery").await?;
    let targets: Vec<String> = ep
        .subsets
        .unwrap_or_default()
        .into_iter()
        .flat_map(|s| s.addresses.unwrap_or_default())
        .filter_map(|a| a.target_ref.and_then(|r| r.name))
        .collect();
    assert_eq!(
        targets,
        vec![leader_pod.clone()],
        "the discovery stream Service must route to exactly the leader pod"
    );
    Ok(())
}

/// Kill the live leader while a warm standby holds: the data plane keeps
/// serving last-good routing at every poll tick, the standby takes the lease
/// and the proxy's stream re-lands on it, and a Gateway created *after* the
/// failover still reaches `Programmed=True` — proof the new leader's readiness
/// registry rebuilt from the reconnecting proxy's NodeStatus, with no
/// cross-replica state ever synced.
#[tokio::test]
async fn proxies_reconnect_to_new_leader_after_leader_pod_kill() -> anyhow::Result<()> {
    use coxswain_e2e::harness::leader;
    use k8s_openapi::api::core::v1::Pod;

    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "disc-leader-kill").await?;

    // Baseline route through the Ingress data plane (Service-level LB to the
    // proxy pod — independent of which controller replica leads).
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;
    let host = format!("ingress.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;

    let old_leader = leader::leader_pod_name(&h.client).await?;
    let pods_api: Api<Pod> = Api::namespaced(h.client.clone(), leader::SYSTEM_NAMESPACE);
    pods_api
        .delete(&old_leader, &Default::default())
        .await
        .context("delete the live leader pod")?;

    // Take-over, with per-tick data-plane continuity: the proxy serves its
    // last-good snapshot throughout the leaderless window.
    let new_leader = wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || {
            let client = h.client.clone();
            let old = old_leader.clone();
            async move {
                format!(
                    "a new Ready leader (not {old}); current holder {:?}",
                    leader::leader_pod_name(&client).await
                )
            }
        },
        || {
            let client = h.client.clone();
            let old = old_leader.clone();
            let http = &h.http;
            let host = host.clone();
            async move {
                // Continuity invariant on EVERY tick — a failed probe is a
                // hard failure, not a retry: routing must never blink.
                let resp = http
                    .get(&host, "/a")
                    .await
                    .expect("data plane must keep serving during the leaderless window");
                resp.assert_backend("echo-a");

                let holder = leader::leader_pod_name(&client).await.ok()?;
                if holder == old {
                    return None;
                }
                let pod = Api::<Pod>::namespaced(client, leader::SYSTEM_NAMESPACE)
                    .get(&holder)
                    .await
                    .ok()?;
                leader::pod_is_ready(&pod).then_some(holder)
            }
        },
    )
    .await?;

    // The proxy's stream must re-land on the new leader (fast-retry through
    // the re-labelled Service), observable as its gauge + leadership metrics.
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || {
            let new_leader = new_leader.clone();
            async move {
                format!(
                    "new leader {new_leader} to show leader=1, >=1 connected proxy, and a \
                     recorded leadership transition; observed leader={:?} connected={:?} transitions={:?}",
                    leader::pod_metric_value(&new_leader, "coxswain_controller_leader").await,
                    leader::pod_metric_value(&new_leader, "coxswain_discovery_connected_proxies")
                        .await,
                    leader::pod_metric_value(&new_leader, "coxswain_controller_leader_transitions_total")
                        .await,
                )
            }
        },
        || {
            let new_leader = new_leader.clone();
            async move {
                let leading = leader::pod_metric_value(&new_leader, "coxswain_controller_leader")
                    .await
                    .ok()??;
                let connected = leader::pod_metric_value(
                    &new_leader,
                    "coxswain_discovery_connected_proxies",
                )
                .await
                .ok()??;
                let transitions = leader::pod_metric_value(
                    &new_leader,
                    "coxswain_controller_leader_transitions_total",
                )
                .await
                .ok()??;
                (leading == 1.0 && connected >= 1.0 && transitions >= 1.0).then_some(())
            }
        },
    )
    .await?;

    // Registry-rebuild proof: a Gateway created AFTER the failover reaches
    // Programmed=True — only possible if the reconnected proxy's NodeStatus
    // repopulated the NEW leader's readiness view.
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_gateway_programmed(
        &h.client,
        "coxswain-test",
        &ns.name,
        Duration::from_secs(120),
    )
    .await?;
    Ok(())
}
