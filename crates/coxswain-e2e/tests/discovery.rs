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
use kube::api::{Api, DeleteParams, ListParams, ObjectMeta, Patch, PatchParams, PostParams};
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
use common::dedicated::{controller_replicas, scale_controller};
use common::discovery::{
    apply_host_ingress, assert_pod_stays_not_ready, copy_trust_bundle, counter, counter_kind,
    fetch_topology, find_node, leader_discovery_metrics, proxy_health_state,
    scrape_metric_label_sum, set_deployment_replicas, shared_proxy_deployment, wait_for_pod_ready,
};
use common::relay::{
    self, assert_pod_stays_ready, create_relay_service_account, leaf_deployment, relay_deployment,
    relay_service,
};
use common::rollout::rollout_restart_deployment;
use k8s_openapi::api::core::v1::Service;

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

    // Capture the HA replica count so phase 2 restores it exactly (the install
    // runs two replicas; leader-election tests in this pass assert a standby).
    let ha_replicas = controller_replicas().await?.max(1);
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

    scale_controller(ha_replicas).await?;

    // Re-create the harness for fresh port-forwards, then gate on the real
    // post-condition — new leader elected + at least one successful reconcile —
    // on the LEADER pod specifically. With the HA replica count restored, an
    // arbitrary port-forward has even odds of landing on the standby, which
    // reports leader=0 forever; resolve the leader via the Lease (the stale
    // pre-outage holder is filtered by the pod-Ready check) and scrape it.
    let h2 = Harness::start().await?;
    use coxswain_e2e::harness::leader;
    leader::wait_for_leader_reconciled(&h.client, Duration::from_secs(60)).await?;

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
    // mid-rollout port-forward. The gauge lives only on the LEADER (streams are
    // leader-gated, #531), and with the HA replica count restored the harness's
    // Service-level forward can pin the standby — so resolve the leader per tick
    // and scrape it directly, mirroring the lease-holder test's pattern.
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || {
            let client = h2.client.clone();
            async move {
                let observed = match leader::leader_pod_name(&client).await {
                    Ok(pod) => {
                        let v = leader::pod_metric_value(
                            &pod,
                            "coxswain_discovery_connected_proxies",
                        )
                        .await
                        .ok()
                        .flatten();
                        format!("leader {pod}: {v:?}")
                    }
                    Err(e) => format!("no leader resolvable: {e}"),
                };
                format!(
                    "leader coxswain_discovery_connected_proxies >= 1 after restart; \
                     currently: {observed}"
                )
            }
        },
        || {
            let client = h2.client.clone();
            async move {
                let pod = leader::leader_pod_name(&client).await.ok()?;
                let v = leader::pod_metric_value(&pod, "coxswain_discovery_connected_proxies")
                    .await
                    .ok()??;
                (v >= 1.0).then_some(())
            }
        },
    )
    .await
    .context("leader did not report the reconnected proxy stream in coxswain_discovery_connected_proxies")?;

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
    // the re-labelled Service), observable as its leadership gauge plus a
    // connected proxy. Deliberately NO transitions-counter assertion: the
    // Deployment replaces the killed pod, and the replacement can win the
    // lease over the warm standby — a fresh pod's initial acquisition is not
    // a "transition", so the counter is legitimately absent on that path.
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || {
            let new_leader = new_leader.clone();
            async move {
                format!(
                    "new leader {new_leader} to show leader=1 and >=1 connected proxy; \
                     observed leader={:?} connected={:?}",
                    leader::pod_metric_value(&new_leader, "coxswain_controller_leader").await,
                    leader::pod_metric_value(&new_leader, "coxswain_discovery_connected_proxies")
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
                let connected =
                    leader::pod_metric_value(&new_leader, "coxswain_discovery_connected_proxies")
                        .await
                        .ok()??;
                (leading == 1.0 && connected >= 1.0).then_some(())
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

// ─────────────────────────────────────────────────────────────────────────────
// Group 7 — Delta snapshot streaming (#383, wire v2)
//
// The controller's discovery server ships an initial full snapshot then
// per-resource deltas: EDS-style endpoint resources (keyed by
// `(namespace, service, port)`) travel independently of route resources, and the
// proxy's client recompiles only the route partitions the delta actually dirties,
// splicing the live `Arc<HostRouter>` for every partition it doesn't. The wire is
// not black-box observable, so these tests assert the protocol behaviour through
// the two ends' Prometheus counters (proxy `/metrics` for the client side,
// leader controller `/metrics` for the server side) while pinning the data-plane
// outcome (backend identity, status code) that the delta must have produced.
//
// Counter discipline. Every assertion is a *delta* of a cumulative counter across
// this test's own single action, captured after gating on a real data-plane
// post-condition — the client increments the counter in the same apply that
// publishes the routing change, so once the proxy serves the new world the
// counter has already moved. Client-side counters come from the one always-on
// shared-proxy pod and are therefore exact for this test's stream regardless of
// any other stream; server-side per-stream counters are asserted with `>=`
// (own-effect lower bound) because a second connected proxy would add its own
// sends. The `discovery` binary runs in the serial pass (`test-threads = 1`), so
// no concurrent test mutates the shared proxy's routing while a window is open —
// which is what makes a `{kind="full"}`-stays-static assertion meaningful.
//
// Route type. These use Ingress hosts, not HTTPRoute, deliberately: the client's
// partitioned recompile keys on `RoutePartitionKey{table, port, host}` and the
// splice/dirty machinery is route-type-agnostic, so Ingress hosts exercise the
// exact same delta apply path without the per-Gateway VIP provisioning that would
// add unrelated flake surface to a discovery-plane test.
// ─────────────────────────────────────────────────────────────────────────────

/// Cumulative snapshots the client applied, split by kind.
const M_CLIENT_APPLIED: &str = "coxswain_discovery_client_snapshots_applied_total";
/// Cumulative route partitions the client recompiled on the apply path.
const M_CLIENT_RECOMPILED: &str = "coxswain_discovery_client_partitions_recompiled_total";
/// Cumulative route partitions the client reused (spliced) on the apply path.
const M_CLIENT_REUSED: &str = "coxswain_discovery_client_partitions_reused_total";
/// Cumulative snapshot messages the server pushed, split by kind.
const M_SERVER_MESSAGES: &str = "coxswain_discovery_snapshot_messages_total";
/// Cumulative resource upserts the server placed in pushed snapshots.
const M_SERVER_SENT: &str = "coxswain_discovery_snapshot_resources_sent_total";
/// Cumulative resource tombstones the server placed in delta snapshots.
const M_SERVER_REMOVED: &str = "coxswain_discovery_snapshot_resources_removed_total";

/// The four client-side apply counters, sampled together so a test can compare a
/// before/after pair.
#[derive(Debug, Clone, Copy)]
struct ClientCounters {
    /// `client_snapshots_applied_total{kind="full"}` — bumps only on connect /
    /// reconnect / Nack-resync.
    full: f64,
    /// `client_snapshots_applied_total{kind="delta"}` — every steady-state change.
    delta: f64,
    /// `client_partitions_recompiled_total`.
    recompiled: f64,
    /// `client_partitions_reused_total`.
    reused: f64,
}

/// Sample the shared proxy's four apply counters from its admin `/metrics`.
async fn read_client_counters(metrics_url: &str) -> ClientCounters {
    ClientCounters {
        full: counter_kind(metrics_url, M_CLIENT_APPLIED, "full").await,
        delta: counter_kind(metrics_url, M_CLIENT_APPLIED, "delta").await,
        recompiled: counter(metrics_url, M_CLIENT_RECOMPILED).await,
        reused: counter(metrics_url, M_CLIENT_REUSED).await,
    }
}

/// Rollout-restarting a backend re-IPs its pods but leaves every route DTO byte
/// identical: the change is a single EDS endpoint resource. Traffic must converge
/// to the new pod, the churn must ride `{kind="delta"}` (never a `{kind="full"}`
/// resync), and — the negative — the client must recompile only the one partition
/// referencing the restarted Service while *splicing* (reusing) every sibling
/// partition, proving an endpoint change does not fan out into an unrelated
/// route's compile.
#[tokio::test]
async fn rolling_deploy_sends_only_endpoint_deltas() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "disc-roll").await?;

    // Three independent host partitions, each on its own backend, so an echo-a
    // rollout touches exactly one and leaves two as splice candidates.
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    let host_a = format!("a.{}.local", ns.name);
    let host_b = format!("b.{}.local", ns.name);
    let host_c = format!("c.{}.local", ns.name);
    apply_host_ingress(&h.client, &ns.name, "ing-a", &host_a, "echo-a", 3000).await?;
    apply_host_ingress(&h.client, &ns.name, "ing-b", &host_b, "echo-b", 3000).await?;
    apply_host_ingress(&h.client, &ns.name, "ing-c", &host_c, "echo-c", 3000).await?;

    let baseline = wait::wait_for_backend(&h.http, &host_a, "/", "echo-a", Duration::from_secs(60))
        .await?
        .pod
        .ok_or_else(|| anyhow::anyhow!("echo-a response carried no pod name"))?;
    wait::wait_for_backend(&h.http, &host_b, "/", "echo-b", Duration::from_secs(60)).await?;
    wait::wait_for_backend(&h.http, &host_c, "/", "echo-c", Duration::from_secs(60)).await?;

    let metrics_url = h.admin_url("/metrics");
    let before = read_client_counters(&metrics_url).await;

    // Re-IP echo-a's pod. The rollout waits for the new ReplicaSet to be Ready.
    rollout_restart_deployment(&ns.name, "echo-a").await?;

    // Gate on the data-plane effect: host a served by a *new* echo-a pod. Once
    // this passes the client has necessarily applied the endpoint delta.
    let new_pod = wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || {
            let (http, host, baseline) = (&h.http, host_a.clone(), baseline.clone());
            async move {
                let observed = http.get(&host, "/").await.ok().and_then(|r| r.pod);
                format!(
                    "host {host} to be served by a NEW echo-a pod (baseline {baseline}); \
                     observed {observed:?}"
                )
            }
        },
        || {
            let (http, host, baseline) = (&h.http, host_a.clone(), baseline.clone());
            async move {
                let pod = http.get(&host, "/").await.ok()?.pod?;
                (pod.starts_with("echo-a-") && pod != baseline).then_some(pod)
            }
        },
    )
    .await?;
    assert_ne!(
        new_pod, baseline,
        "rollout must move host a to a fresh echo-a pod"
    );

    let after = read_client_counters(&metrics_url).await;

    // Endpoint churn is a delta, never a full resync.
    assert_eq!(
        after.full, before.full,
        "endpoint re-IP must not trigger a full resync; \
         client {M_CLIENT_APPLIED}{{kind=\"full\"}} moved {} -> {}",
        before.full, after.full
    );
    assert!(
        after.delta > before.delta,
        "endpoint re-IP must apply at least one delta; \
         client {M_CLIENT_APPLIED}{{kind=\"delta\"}} moved {} -> {}",
        before.delta,
        after.delta
    );

    // Negative: only host a's partition recompiled; hosts b and c were spliced.
    let recompiled = after.recompiled - before.recompiled;
    let reused = after.reused - before.reused;
    assert!(
        recompiled >= 1.0,
        "the restarted Service's partition (host a) must recompile; \
         {M_CLIENT_RECOMPILED} moved +{recompiled}"
    );
    if reused <= recompiled {
        // Self-diagnosing failure: pull the delta/full split and the server's
        // send-side counters so a CI-only trip tells us WHAT was resent
        // (route resources vs endpoint resources) without a rerun.
        let server = match leader_discovery_metrics(&h.client).await {
            Ok((_pf, url)) => {
                let sent = counter(&url, "coxswain_discovery_snapshot_resources_sent_total").await;
                let removed =
                    counter(&url, "coxswain_discovery_snapshot_resources_removed_total").await;
                format!("server resources_sent_total={sent}, resources_removed_total={removed}")
            }
            Err(e) => format!("server counters unavailable: {e}"),
        };
        panic!(
            "unrelated partitions (hosts b, c reference echo-b/echo-c, untouched by an \
             echo-a rollout) must be spliced, not recompiled; {M_CLIENT_REUSED} moved \
             +{reused} vs {M_CLIENT_RECOMPILED} +{recompiled}; client applied \
             full {} -> {}, delta {} -> {}; {server}",
            before.full, after.full, before.delta, after.delta
        );
    }

    // Siblings still serve their own backends unchanged.
    wait::wait_for_backend(&h.http, &host_b, "/", "echo-b", Duration::from_secs(30)).await?;
    wait::wait_for_backend(&h.http, &host_c, "/", "echo-c", Duration::from_secs(30)).await?;

    Ok(())
}

/// Adding one route host among N pre-existing ones is a single route-resource
/// upsert. The client must compile exactly the new partition and reuse the N
/// existing ones — recompiled ~= 1, reused ~= N — and never resync. The negative
/// (unrelated partitions untouched) is embedded in `reused > recompiled`.
#[tokio::test]
async fn structural_change_recompiles_only_affected_partition() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "disc-struct").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    let host_a = format!("a.{}.local", ns.name);
    let host_b = format!("b.{}.local", ns.name);
    let host_c = format!("c.{}.local", ns.name);
    apply_host_ingress(&h.client, &ns.name, "ing-a", &host_a, "echo-a", 3000).await?;
    apply_host_ingress(&h.client, &ns.name, "ing-b", &host_b, "echo-b", 3000).await?;
    apply_host_ingress(&h.client, &ns.name, "ing-c", &host_c, "echo-c", 3000).await?;
    wait::wait_for_backend(&h.http, &host_a, "/", "echo-a", Duration::from_secs(60)).await?;
    wait::wait_for_backend(&h.http, &host_b, "/", "echo-b", Duration::from_secs(60)).await?;
    wait::wait_for_backend(&h.http, &host_c, "/", "echo-c", Duration::from_secs(60)).await?;

    let metrics_url = h.admin_url("/metrics");
    let before = read_client_counters(&metrics_url).await;

    // A fourth host, reusing an existing Service so the delta carries only the new
    // route_host resource (echo-a's endpoint resource is already in the pool — no
    // endpoint churn to muddy the partition attribution).
    let host_d = format!("d.{}.local", ns.name);
    apply_host_ingress(&h.client, &ns.name, "ing-d", &host_d, "echo-a", 3000).await?;
    wait::wait_for_backend(&h.http, &host_d, "/", "echo-a", Duration::from_secs(60)).await?;

    let after = read_client_counters(&metrics_url).await;

    assert_eq!(
        after.full, before.full,
        "adding a host must be a delta, not a full resync; \
         client {M_CLIENT_APPLIED}{{kind=\"full\"}} moved {} -> {}",
        before.full, after.full
    );
    assert!(
        after.delta > before.delta,
        "adding a host must apply at least one delta; \
         client {M_CLIENT_APPLIED}{{kind=\"delta\"}} moved {} -> {}",
        before.delta,
        after.delta
    );

    let recompiled = after.recompiled - before.recompiled;
    let reused = after.reused - before.reused;
    assert!(
        recompiled >= 1.0,
        "the new host d partition must compile; {M_CLIENT_RECOMPILED} moved +{recompiled}"
    );
    assert!(
        reused >= 3.0,
        "the three pre-existing host partitions (a, b, c) must be spliced; \
         {M_CLIENT_REUSED} moved +{reused}"
    );
    assert!(
        reused > recompiled,
        "only the added partition may recompile — every pre-existing partition is \
         reused; {M_CLIENT_REUSED} +{reused} must exceed {M_CLIENT_RECOMPILED} +{recompiled}"
    );

    // The pre-existing hosts are unchanged; the new one routes.
    wait::wait_for_backend(&h.http, &host_a, "/", "echo-a", Duration::from_secs(30)).await?;
    wait::wait_for_backend(&h.http, &host_b, "/", "echo-b", Duration::from_secs(30)).await?;
    wait::wait_for_backend(&h.http, &host_c, "/", "echo-c", Duration::from_secs(30)).await?;

    Ok(())
}

/// Deleting a route tombstones its partition: the host stops serving (404 — the
/// negative), the server records a resource removal, and — the no-Nack proof —
/// the deletion rides a clean delta with no `{kind="full"}` self-healing resync,
/// while sibling hosts keep serving.
#[tokio::test]
async fn route_delete_tombstones_partition() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "disc-tomb").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    let host_a = format!("a.{}.local", ns.name);
    let host_b = format!("b.{}.local", ns.name);
    apply_host_ingress(&h.client, &ns.name, "ing-a", &host_a, "echo-a", 3000).await?;
    apply_host_ingress(&h.client, &ns.name, "ing-b", &host_b, "echo-b", 3000).await?;
    wait::wait_for_backend(&h.http, &host_a, "/", "echo-a", Duration::from_secs(60)).await?;
    wait::wait_for_backend(&h.http, &host_b, "/", "echo-b", Duration::from_secs(60)).await?;

    // Server-side removal counter is scraped from the leader (it serves the
    // stream); hold the forward across the poll.
    let (_leader_pf, server_url) = leader_discovery_metrics(&h.client).await?;
    let removed_before = counter(&server_url, M_SERVER_REMOVED).await;

    let client_url = h.admin_url("/metrics");
    let before = read_client_counters(&client_url).await;

    // Delete host a's route.
    let ingresses: Api<Ingress> = Api::namespaced(h.client.clone(), &ns.name);
    ingresses
        .delete("ing-a", &DeleteParams::default())
        .await
        .context("delete ing-a")?;

    // Negative: host a stops serving (tombstone applied → no compiled partition →
    // 404). Gating on this proves the client applied the removal.
    wait::wait_for_route_status(&h.http, &host_a, "/", 404, Duration::from_secs(60)).await?;

    // Sibling host b is untouched.
    wait::wait_for_backend(&h.http, &host_b, "/", "echo-b", Duration::from_secs(30)).await?;

    let after = read_client_counters(&client_url).await;

    // No-Nack proof: a Nack would force a `{kind="full"}` resync. The delete must
    // instead ride a clean delta. (There is no dedicated Nack counter; a static
    // full counter across a change that landed via a delta is the observable
    // signal that the client accepted the message rather than rejecting it.)
    assert_eq!(
        after.full, before.full,
        "a route delete must ride a clean delta with no Nack-driven full resync; \
         client {M_CLIENT_APPLIED}{{kind=\"full\"}} moved {} -> {}",
        before.full, after.full
    );
    assert!(
        after.delta > before.delta,
        "the tombstone must apply as a delta; \
         client {M_CLIENT_APPLIED}{{kind=\"delta\"}} moved {} -> {}",
        before.delta,
        after.delta
    );

    // Server recorded the tombstone. `>=` because a concurrently-connected proxy
    // (e.g. a prior test's still-terminating pod) would receive — and be counted
    // for — the same removal; this test's own stream contributes at least one.
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || {
            let url = server_url.clone();
            async move {
                let now = counter(&url, M_SERVER_REMOVED).await;
                format!(
                    "leader {M_SERVER_REMOVED} to advance past {removed_before} \
                     (route tombstone); currently {now}"
                )
            }
        },
        || {
            let url = server_url.clone();
            async move { (counter(&url, M_SERVER_REMOVED).await > removed_before).then_some(()) }
        },
    )
    .await
    .context("leader never recorded the route tombstone in snapshot_resources_removed_total")?;

    Ok(())
}

/// Draining a backend to zero endpoints (Service intact) must surface a
/// client-derived 503 — the `valid-but-empty` status, never the 500 a *missing*
/// Service gives — carried by a single EDS endpoint resource. Route resources are
/// not re-sent: the client recompiles only the drained partition (to bake the
/// 503) and splices the siblings, and no full resync occurs. Scaling back up
/// restores 200s.
#[tokio::test]
async fn endpoint_drain_yields_503_without_route_resend() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "disc-drain").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    let host_a = format!("a.{}.local", ns.name);
    let host_b = format!("b.{}.local", ns.name);
    let host_c = format!("c.{}.local", ns.name);
    apply_host_ingress(&h.client, &ns.name, "ing-a", &host_a, "echo-a", 3000).await?;
    apply_host_ingress(&h.client, &ns.name, "ing-b", &host_b, "echo-b", 3000).await?;
    apply_host_ingress(&h.client, &ns.name, "ing-c", &host_c, "echo-c", 3000).await?;
    wait::wait_for_backend(&h.http, &host_a, "/", "echo-a", Duration::from_secs(60)).await?;
    wait::wait_for_backend(&h.http, &host_b, "/", "echo-b", Duration::from_secs(60)).await?;
    wait::wait_for_backend(&h.http, &host_c, "/", "echo-c", Duration::from_secs(60)).await?;

    let (_leader_pf, server_url) = leader_discovery_metrics(&h.client).await?;
    let sent_before = counter(&server_url, M_SERVER_SENT).await;

    let client_url = h.admin_url("/metrics");
    let before = read_client_counters(&client_url).await;

    // Drain echo-a: endpoints empty, Service survives.
    set_deployment_replicas(&h.client, &ns.name, "echo-a", 0).await?;

    // Client-derived status parity: 503 (valid-but-empty), NOT 500 (missing
    // Service). wait_for_route_status keeps polling on any other code, so a 500
    // would fail here rather than pass.
    wait::wait_for_route_status(&h.http, &host_a, "/", 503, Duration::from_secs(90)).await?;
    let status = h.http.get_status(&host_a, "/").await?;
    assert_eq!(
        status, 503,
        "a drained-but-present Service must yield the valid-but-empty 503, not 500 \
         (missing Service) or any other code; observed {status}"
    );

    // Siblings unaffected.
    wait::wait_for_backend(&h.http, &host_b, "/", "echo-b", Duration::from_secs(30)).await?;
    wait::wait_for_backend(&h.http, &host_c, "/", "echo-c", Duration::from_secs(30)).await?;

    let after = read_client_counters(&client_url).await;

    // The drain rode a delta, not a full resync.
    assert_eq!(
        after.full, before.full,
        "endpoint drain must not trigger a full resync; \
         client {M_CLIENT_APPLIED}{{kind=\"full\"}} moved {} -> {}",
        before.full, after.full
    );
    assert!(
        after.delta > before.delta,
        "endpoint drain must apply at least one delta; \
         client {M_CLIENT_APPLIED}{{kind=\"delta\"}} moved {} -> {}",
        before.delta,
        after.delta
    );

    // Route resources were NOT re-sent: only host a's partition recompiled (to
    // bake the 503), and the sibling partitions were spliced. Had the routes been
    // re-sent, the siblings would recompile instead of reuse.
    let recompiled = after.recompiled - before.recompiled;
    let reused = after.reused - before.reused;
    assert!(
        recompiled >= 1.0,
        "the drained Service's partition (host a) must recompile to bake the 503; \
         {M_CLIENT_RECOMPILED} moved +{recompiled}"
    );
    assert!(
        reused > recompiled,
        "sibling route partitions (hosts b, c) must be spliced, not rebuilt from \
         re-sent routes; {M_CLIENT_REUSED} +{reused} must exceed {M_CLIENT_RECOMPILED} \
         +{recompiled}"
    );

    // Server sent the endpoint resource (with empty addrs). `>=` for the same
    // multi-stream reason as the removal counter above; the drain contributes at
    // least one upsert on this test's stream.
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || {
            let url = server_url.clone();
            async move {
                let now = counter(&url, M_SERVER_SENT).await;
                format!(
                    "leader {M_SERVER_SENT} to advance past {sent_before} \
                     (drained endpoint resource); currently {now}"
                )
            }
        },
        || {
            let url = server_url.clone();
            async move { (counter(&url, M_SERVER_SENT).await > sent_before).then_some(()) }
        },
    )
    .await
    .context(
        "leader never re-sent the drained endpoint resource in snapshot_resources_sent_total",
    )?;

    // Scale back up → 200s return, still via deltas.
    set_deployment_replicas(&h.client, &ns.name, "echo-a", 1).await?;
    wait::wait_for_backend(&h.http, &host_a, "/", "echo-a", Duration::from_secs(90)).await?;
    let restored = read_client_counters(&client_url).await;
    assert_eq!(
        restored.full, before.full,
        "recovery must ride a delta too; client {M_CLIENT_APPLIED}{{kind=\"full\"}} \
         moved {} -> {}",
        before.full, restored.full
    );
    assert!(
        restored.delta > after.delta,
        "scaling the backend back up must apply a further delta; \
         client {M_CLIENT_APPLIED}{{kind=\"delta\"}} moved {} -> {}",
        after.delta,
        restored.delta
    );

    Ok(())
}

/// Killing the controller forces the proxy's stream to drop; the data plane keeps
/// serving its last-good snapshot throughout, and on reconnect the fresh
/// controller sends a *full* resync (protocol invariant: first message per stream
/// is `full=true`). Both ends must record exactly that: the client's
/// `{kind="full"}` counter advances and the new leader's `{kind="full"}`
/// server counter is non-zero — while traffic never drops.
///
/// Serial: scales the shared controller to zero (crib of
/// `proxy_degrades_during_controller_outage_then_recovers`). This test's distinct
/// assertion target is the full-resync *counter parity* on both ends, not the
/// health-state transition that test already covers.
#[tokio::test]
async fn controller_restart_full_resync_reconverges() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // Persistent: the second Harness::start() below runs bootstrap(), which purges
    // coxswain-e2e=true namespaces; persistent skips that label so the route
    // survives the restart window.
    let ns = NamespaceGuard::create_persistent(&h.client, "disc-resync").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    let host = format!("resync.{}.local", ns.name);
    apply_host_ingress(&h.client, &ns.name, "resync-a", &host, "echo-a", 3000).await?;
    wait::wait_for_backend(&h.http, &host, "/", "echo-a", Duration::from_secs(60)).await?;

    // Baseline the client full counter BEFORE the outage. The proxy pod is not
    // restarted (only the controller is), so this counter is monotonic across the
    // whole test and a post-reconnect read is directly comparable.
    let client_full_before = counter_kind(&h.admin_url("/metrics"), M_CLIENT_APPLIED, "full").await;

    // ── Phase 1: controller down → proxy degrades, keeps serving last-good ─────
    // Capture the HA replica count so phase 2 restores it exactly: the install
    // runs two replicas and `only_lease_holder_reports_connected_proxy_streams`
    // (later in this serial pass) asserts a standby exists.
    let ha_replicas = controller_replicas().await?.max(1);
    scale_controller(0).await?;
    let proxy_health_url = h.admin_url("/api/v1/health");
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || {
            let url = proxy_health_url.clone();
            async move {
                let state = proxy_health_state(&url).await;
                format!("shared proxy to report 'degraded' during outage; currently {state:?}")
            }
        },
        || {
            let url = proxy_health_url.clone();
            async move { (proxy_health_state(&url).await? == "degraded").then_some(()) }
        },
    )
    .await
    .context("shared proxy did not degrade during controller downtime")?;
    // Continuity: last-good snapshot still serves with the discovery stream down.
    h.http
        .get(&host, "/")
        .await
        .context("data plane must keep serving during controller downtime")?
        .assert_backend("echo-a");

    // ── Phase 2: controller back → proxy reconnects with a full resync ─────────
    // Restore the captured count (rollout-status inside waits for ALL replicas,
    // so the standby is back before this test returns).
    scale_controller(ha_replicas).await?;
    let h2 = Harness::start().await?;
    // Gate the reconcile wait on the LEADER: with HA replicas restored, an
    // arbitrary port-forward can land on the standby (leader=0 forever), and a
    // held forward can wedge if it dials the admin port before it serves.
    use coxswain_e2e::harness::leader;
    leader::wait_for_leader_reconciled(&h.client, Duration::from_secs(60)).await?;

    // Wait for the proxy to clear Degraded, asserting per-tick that traffic never
    // drops throughout the reconnect window.
    let proxy_health_url2 = h2.admin_url("/api/v1/health");
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || {
            let url = proxy_health_url2.clone();
            async move {
                let state = proxy_health_state(&url).await;
                format!("shared proxy to return to 'ready' after reconnect; currently {state:?}")
            }
        },
        || {
            let (url, http, host) = (proxy_health_url2.clone(), &h.http, host.clone());
            async move {
                // A failed probe on any tick is a hard continuity failure.
                http.get(&host, "/")
                    .await
                    .expect("data plane must keep serving during reconnect")
                    .assert_backend("echo-a");
                (proxy_health_state(&url).await? == "ready").then_some(())
            }
        },
    )
    .await
    .context("shared proxy did not return to Ready after controller restart")?;

    // Client end: the reconnect applied a full resync.
    let client_full_after = counter_kind(&h2.admin_url("/metrics"), M_CLIENT_APPLIED, "full").await;
    assert!(
        client_full_after > client_full_before,
        "reconnect must apply a full resync (protocol invariant: first message per \
         stream is full=true); client {M_CLIENT_APPLIED}{{kind=\"full\"}} moved {} -> {}",
        client_full_before,
        client_full_after
    );

    // Server end: the fresh controller process sent a full to the reconnected
    // proxy. Its counters start at zero on restart, so `>= 1` on the new leader
    // is the full-resync signal. Scrape the leader specifically (leader-gated
    // stream), and poll — the leader-metric port-forward and the reconnect are
    // independently timed.
    let (_leader_pf, server_url) = leader_discovery_metrics(&h2.client).await?;
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || {
            let url = server_url.clone();
            async move {
                let n = counter_kind(&url, M_SERVER_MESSAGES, "full").await;
                format!(
                    "new leader {M_SERVER_MESSAGES}{{kind=\"full\"}} to report >= 1 \
                     (full resync sent to the reconnected proxy); currently {n}"
                )
            }
        },
        || {
            let url = server_url.clone();
            async move { (counter_kind(&url, M_SERVER_MESSAGES, "full").await >= 1.0).then_some(()) }
        },
    )
    .await
    .context("new leader never recorded a full snapshot to the reconnected proxy")?;

    // A route created AFTER the restart serves end-to-end — proof the reconnected
    // stream delivers fresh snapshots, not just the pre-restart last-good.
    let fresh_host = format!("resync-fresh.{}.local", ns.name);
    apply_host_ingress(
        &h2.client,
        &ns.name,
        "resync-fresh",
        &fresh_host,
        "echo-b",
        3000,
    )
    .await?;
    wait::wait_for_backend(
        &h2.http,
        &fresh_host,
        "/",
        "echo-b",
        Duration::from_secs(120),
    )
    .await?;
    // The original route still serves.
    wait::wait_for_backend(&h2.http, &host, "/", "echo-a", Duration::from_secs(30)).await?;

    Ok(())
}

// ── Group 4 — Relay tier (#583) ───────────────────────────────────────────────
//
// A relay is `serve relay --shared`: an upstream discovery client (to the
// controller) + a downstream discovery server (to leaf proxies), caching
// last-good and re-serving. The relay + leaf run in a throwaway test namespace
// and reach the controller's discovery/bootstrap Services by cross-namespace DNS
// (`…​.coxswain-system.svc`); the leaf's upstream is the RELAY. All three tests
// assert from the Pod `Ready` condition (readinessProbe on `/readyz`), which for
// the relay gates on `routing_table_loaded` (upstream) AND `downstream_serving`,
// and for the leaf gates on `routing_table_loaded` fed by the relay.
//
// The namespace-relay (`--namespace`) data-plane path is deny-authorized upstream
// until the provenance authorizer + provisioning land in #584, so its live e2e
// ships there; the demux itself is unit-covered in `coxswain-discovery`.

/// Happy path: a relay bootstraps its SVID, converges upstream against the
/// controller (visible as an in-sync `SharedPool` node in the controller
/// topology), serves downstream, and a leaf proxy pointed at the relay converges
/// **through** the relay to `Ready` — proving the relay re-served a
/// self-consistent routing world (a mismatched world would Nack forever and
/// never let the leaf go Ready).
///
/// Serial: co-located in the `discovery` binary with the controller-scaling
/// tests (see the nextest config).
#[tokio::test]
async fn relay_fronted_proxy_converges_through_relay() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "relay-converge").await?;

    copy_trust_bundle(&h.client, &ns.name).await?;
    create_relay_service_account(&h.client, &ns.name, relay::RELAY_SA).await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);

    // Relay + its downstream discovery Service.
    deployments
        .create(
            &PostParams::default(),
            &relay_deployment(&ns.name, "relay", relay::RELAY_SA)?,
        )
        .await
        .context("create relay Deployment")?;
    services
        .create(&PostParams::default(), &relay_service(&ns.name, "relay")?)
        .await
        .context("create relay Service")?;

    // Relay Ready ⟹ upstream converged AND downstream server bound.
    wait_for_pod_ready(&h.client, &ns.name, "app=relay", Duration::from_secs(120))
        .await
        .context("relay pod did not become Ready (upstream converge + downstream serve)")?;

    // Cross-validate from the controller's view: the relay is an ordinary
    // `SharedPool` subscriber, so it appears in-sync in the NodeRegistry.
    let topology_url = h.controller_admin_url("/api/v1/topology");
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || {
            let url = topology_url.clone();
            async move { format!("controller topology at '{url}' to show relay-* in_sync") }
        },
        || {
            let url = topology_url.clone();
            async move {
                let topology = fetch_topology(&url).await.ok()?;
                let node = find_node(&topology, "relay-")?;
                (node.pointer("/scope/kind").and_then(|v| v.as_str()) == Some("SharedPool"))
                    .then_some(())?;
                node.get("in_sync")
                    .and_then(|v| v.as_bool())
                    .filter(|&b| b)
                    .map(|_| ())
            }
        },
    )
    .await
    .context("relay did not register as an in-sync SharedPool node on the controller")?;

    // Leaf pointed at the relay (endpoint = relay Service; expected-server SA =
    // the relay's SA; bootstrap still targets the controller).
    deployments
        .create(
            &PostParams::default(),
            &leaf_deployment(&ns.name, "leaf", "relay", relay::RELAY_SA)?,
        )
        .await
        .context("create relay-fronted leaf Deployment")?;

    // Leaf Ready ⟹ it received a self-consistent full world THROUGH the relay.
    wait_for_pod_ready(&h.client, &ns.name, "app=leaf", Duration::from_secs(120))
        .await
        .context("relay-fronted leaf did not converge to Ready through the relay")?;

    Ok(())
}

/// Sad path — controller outage: with the relay + leaf converged, scaling the
/// controller to zero must leave BOTH serving their last-good world (the relay
/// degrades but keeps `/readyz` 200; the leaf's upstream — the relay — never
/// drops), and both must reconverge when the controller returns. The leaf never
/// disconnects.
///
/// Serial: scales the shared controller to zero.
#[tokio::test]
async fn relay_and_leaf_serve_last_good_during_controller_outage() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "relay-outage").await?;

    copy_trust_bundle(&h.client, &ns.name).await?;
    create_relay_service_account(&h.client, &ns.name, relay::RELAY_SA).await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    deployments
        .create(
            &PostParams::default(),
            &relay_deployment(&ns.name, "relay", relay::RELAY_SA)?,
        )
        .await
        .context("create relay Deployment")?;
    services
        .create(&PostParams::default(), &relay_service(&ns.name, "relay")?)
        .await
        .context("create relay Service")?;
    wait_for_pod_ready(&h.client, &ns.name, "app=relay", Duration::from_secs(120)).await?;
    deployments
        .create(
            &PostParams::default(),
            &leaf_deployment(&ns.name, "leaf", "relay", relay::RELAY_SA)?,
        )
        .await
        .context("create leaf Deployment")?;
    wait_for_pod_ready(&h.client, &ns.name, "app=leaf", Duration::from_secs(120)).await?;

    // ── Controller down → both keep serving last-good ─────────────────────────
    let ha_replicas = controller_replicas().await?.max(1);
    scale_controller(0).await?;

    // Both the relay and its leaf must hold Ready (last-good) across the outage.
    assert_pod_stays_ready(&h.client, &ns.name, "app=relay", Duration::from_secs(20))
        .await
        .context("relay dropped Ready during controller outage (last-good violated)")?;
    assert_pod_stays_ready(&h.client, &ns.name, "app=leaf", Duration::from_secs(20))
        .await
        .context("relay-fronted leaf dropped Ready during controller outage (leaf disconnected)")?;

    // ── Controller back → both reconverge ─────────────────────────────────────
    scale_controller(ha_replicas).await?;
    wait_for_pod_ready(&h.client, &ns.name, "app=relay", Duration::from_secs(120))
        .await
        .context("relay did not reconverge after the controller returned")?;
    wait_for_pod_ready(&h.client, &ns.name, "app=leaf", Duration::from_secs(120))
        .await
        .context("leaf did not reconverge after the controller returned")?;

    Ok(())
}

/// Sad path — relay restart: with the leaf converged through the relay,
/// restarting the relay Deployment must leave the leaf serving its last-good
/// world (it never drops Ready), and the leaf must reconverge when the relay
/// returns (a reconnecting leaf gets a fresh full via `expect_full`).
///
/// Serial: co-located in the `discovery` binary.
#[tokio::test]
async fn leaf_serves_last_good_when_relay_restarts() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "relay-restart").await?;

    copy_trust_bundle(&h.client, &ns.name).await?;
    create_relay_service_account(&h.client, &ns.name, relay::RELAY_SA).await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    deployments
        .create(
            &PostParams::default(),
            &relay_deployment(&ns.name, "relay", relay::RELAY_SA)?,
        )
        .await
        .context("create relay Deployment")?;
    services
        .create(&PostParams::default(), &relay_service(&ns.name, "relay")?)
        .await
        .context("create relay Service")?;
    wait_for_pod_ready(&h.client, &ns.name, "app=relay", Duration::from_secs(120)).await?;
    deployments
        .create(
            &PostParams::default(),
            &leaf_deployment(&ns.name, "leaf", "relay", relay::RELAY_SA)?,
        )
        .await
        .context("create leaf Deployment")?;
    wait_for_pod_ready(&h.client, &ns.name, "app=leaf", Duration::from_secs(120)).await?;

    // ── Restart the relay → the leaf serves last-good across the gap ──────────
    rollout_restart_deployment(&ns.name, "relay").await?;

    // The leaf's upstream is briefly gone, but it never drops Ready (Degraded
    // keeps `/readyz` 200), serving its last-good world through the relay gap.
    assert_pod_stays_ready(&h.client, &ns.name, "app=leaf", Duration::from_secs(20))
        .await
        .context("leaf dropped Ready while the relay restarted (last-good violated)")?;

    // ── Relay back → leaf reconverges (still Ready) ───────────────────────────
    wait_for_pod_ready(&h.client, &ns.name, "app=relay", Duration::from_secs(120))
        .await
        .context("relay did not come back Ready after restart")?;
    wait_for_pod_ready(&h.client, &ns.name, "app=leaf", Duration::from_secs(120))
        .await
        .context("leaf did not reconverge after the relay returned")?;

    Ok(())
}

// ── Group 5 — Relay leaf-roster telemetry (#585) ──────────────────────────────
//
// A relay reports its downstream leaves upstream as a `RosterReport`; the
// controller folds each leaf into its NodeRegistry tagged with the relay as
// `parent`, marks the relay `is_relay`, and evicts the subtree when the relay's
// stream drops. Asserted from the controller's `/api/v1/topology`, the same
// view the operator UI and the #531 gate read.

/// Poll the controller topology until the relay-fronted leaf is folded under the
/// relay: the relay row carries `is_relay = true`, and the leaf row's `parent`
/// is the relay's `node_id`. Returns the relay's `node_id`.
async fn wait_for_folded_leaf(topology_url: &str) -> anyhow::Result<String> {
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || {
            let url = topology_url.to_owned();
            async move { format!("controller topology at '{url}' to fold leaf-* under relay-* (is_relay + parent)") }
        },
        || {
            let url = topology_url.to_owned();
            async move {
                let topology = fetch_topology(&url).await.ok()?;
                let relay = find_node(&topology, "relay-")?;
                relay.get("is_relay").and_then(|v| v.as_bool()).filter(|&b| b)?;
                let relay_id = relay.get("node_id").and_then(|v| v.as_str())?.to_owned();
                let leaf = find_node(&topology, "leaf-")?;
                (leaf.get("parent").and_then(|v| v.as_str()) == Some(relay_id.as_str()))
                    .then_some(relay_id)
            }
        },
    )
    .await
    .context("relay-fronted leaf was not folded under its relay in the controller topology")
}

/// Happy path: a leaf behind a relay is folded into the controller's registry as
/// a child of the relay (#585) — the controller sees real leaf state through the
/// tier, not just the relay's own row.
#[tokio::test]
async fn relay_folds_leaf_roster_into_controller_topology() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "relay-roster-fold").await?;

    copy_trust_bundle(&h.client, &ns.name).await?;
    create_relay_service_account(&h.client, &ns.name, relay::RELAY_SA).await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    deployments
        .create(
            &PostParams::default(),
            &relay_deployment(&ns.name, "relay", relay::RELAY_SA)?,
        )
        .await
        .context("create relay Deployment")?;
    services
        .create(&PostParams::default(), &relay_service(&ns.name, "relay")?)
        .await
        .context("create relay Service")?;
    wait_for_pod_ready(&h.client, &ns.name, "app=relay", Duration::from_secs(120))
        .await
        .context("relay pod did not become Ready")?;

    deployments
        .create(
            &PostParams::default(),
            &leaf_deployment(&ns.name, "leaf", "relay", relay::RELAY_SA)?,
        )
        .await
        .context("create relay-fronted leaf Deployment")?;
    wait_for_pod_ready(&h.client, &ns.name, "app=leaf", Duration::from_secs(120))
        .await
        .context("relay-fronted leaf did not converge to Ready")?;

    // The leaf reaches the controller only via the relay's RosterReport.
    let topology_url = h.controller_admin_url("/api/v1/topology");
    wait_for_folded_leaf(&topology_url).await?;

    Ok(())
}

/// Sad path — relay outage: deleting the relay drops its upstream stream, so the
/// controller evicts the whole subtree (#585). The leaf keeps serving last-good,
/// but it must vanish from the controller's view — a new publish must not gate on
/// a blind spot.
#[tokio::test]
async fn relay_outage_evicts_leaf_subtree_from_topology() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "relay-roster-evict").await?;

    copy_trust_bundle(&h.client, &ns.name).await?;
    create_relay_service_account(&h.client, &ns.name, relay::RELAY_SA).await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    deployments
        .create(
            &PostParams::default(),
            &relay_deployment(&ns.name, "relay", relay::RELAY_SA)?,
        )
        .await
        .context("create relay Deployment")?;
    services
        .create(&PostParams::default(), &relay_service(&ns.name, "relay")?)
        .await
        .context("create relay Service")?;
    wait_for_pod_ready(&h.client, &ns.name, "app=relay", Duration::from_secs(120)).await?;
    deployments
        .create(
            &PostParams::default(),
            &leaf_deployment(&ns.name, "leaf", "relay", relay::RELAY_SA)?,
        )
        .await
        .context("create relay-fronted leaf Deployment")?;
    wait_for_pod_ready(&h.client, &ns.name, "app=leaf", Duration::from_secs(120)).await?;

    let topology_url = h.controller_admin_url("/api/v1/topology");
    wait_for_folded_leaf(&topology_url).await?;

    // ── Relay down → the controller evicts the subtree ────────────────────────
    deployments
        .delete("relay", &DeleteParams::default())
        .await
        .context("delete relay Deployment")?;

    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || {
            let url = topology_url.clone();
            async move {
                format!(
                    "controller topology at '{url}' to evict the leaf subtree after relay outage"
                )
            }
        },
        || {
            let url = topology_url.clone();
            async move {
                let topology = fetch_topology(&url).await.ok()?;
                // Both the relay row and its folded leaf must be gone.
                (find_node(&topology, "relay-").is_none()
                    && find_node(&topology, "leaf-").is_none())
                .then_some(())
            }
        },
    )
    .await
    .context("controller did not evict the leaf subtree after the relay's stream dropped")?;

    Ok(())
}
