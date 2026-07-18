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
    ControllerOptions, FixtureVars, Harness, NamespaceGuard,
    fixtures::{self, backends, dedicated_proxy as dedicated, gateway_api as gwa, ingress},
    harness::{HttpClient, wait},
};

mod common;
use common::dedicated::{
    GATEWAY_NAME, RESOURCE_NAME, controller_replicas, scale_controller, wait_for_cut_over,
};
use common::discovery::{
    apply_host_ingress, assert_pod_stays_not_ready, copy_trust_bundle, counter, counter_kind,
    fetch_topology, find_node, leader_discovery_metrics, proxy_health_state,
    scrape_metric_label_sum, set_deployment_replicas, shared_proxy_deployment, wait_for_pod_ready,
};
use common::relay::assert_pod_stays_ready;
use common::rollout::rollout_restart_deployment;
use gateway_api_types::apis::standard::gateways::Gateway;
use k8s_openapi::api::core::v1::{Pod, Service};

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
    let node = wait::poll_until(
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

    // Assert on the node captured BY the convergence poll — the snapshot in which
    // it was in_sync. Re-fetching and re-asserting `in_sync` would be a TOCTOU
    // flake: a churn-driven snapshot (e.g. the serial pass's controller rollout)
    // can transiently flip a converged node to in_sync=false until it re-Acks, and
    // reaching in_sync once is the convergence proof this test needs.
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

    // `discovery_active` is a stable top-level flag (true whenever any proxy is
    // connected), so a fresh fetch for it carries no TOCTOU risk.
    let topology = fetch_topology(&topology_url).await?;
    assert_eq!(
        topology.get("discovery_active").and_then(|v| v.as_bool()),
        Some(true),
        "topology discovery_active must be true; topology: {topology}"
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

// ── Relay tier (#583, #585) over the runtime-repoint model (#601) ─────────────
//
// Since #601 a leaf is no longer hand-pinned at a relay via a static
// `--discovery-endpoint`; the controller delivers each proxy's routing upstream
// at bootstrap and repoints it live. These tests therefore drive the **real**
// controller-provisioned namespace-relay path: relay tiering on with a threshold
// of 1, so a single servable dedicated Gateway both provisions a namespace relay
// AND has its dedicated proxy repointed onto that relay — with the data plane
// never recycled. All assert from the dedicated proxy's Pod `Ready` condition,
// live traffic through its VIP, and the controller `/api/v1/topology` fold view.
//
// Execution: these use `start_with_options` (a `relay.dedicated.*` Helm mutator);
// the `discovery` binary is always-serial, so the mutator-serialization invariant
// (scripts/check-e2e-mutators-serialized.sh) is satisfied by the binary itself.

/// Fixed name of every controller-provisioned namespace relay
/// (`render_relay::RELAY_NAME`).
const RELAY_NAME: &str = "coxswain-relay";
/// GEP-1762 label every dedicated-proxy pod carries; selects the leaf pod.
const GATEWAY_NAME_LABEL: &str = "gateway.networking.k8s.io/gateway-name";
/// Selects the namespace-relay pod (`render_relay::RELAY_COMPONENT`).
const RELAY_POD_SELECTOR: &str = "app.kubernetes.io/component=relay-namespace";

/// Controller options that provision a namespace relay for any namespace with a
/// single servable dedicated Gateway (threshold 1).
fn relay_tiering_threshold_1() -> ControllerOptions {
    ControllerOptions {
        relay_enabled: true,
        relay_min_proxy_replicas: Some(1),
        ..Default::default()
    }
}

/// The dedicated proxy's container `restartCount` (0 when it has never restarted).
fn restart_count(pod: &Pod) -> i32 {
    pod.status
        .as_ref()
        .and_then(|s| s.container_statuses.as_ref())
        .and_then(|cs| cs.first())
        .map(|c| c.restart_count)
        .unwrap_or(0)
}

/// The single dedicated-proxy pod for `GATEWAY_NAME` in `ns`.
async fn dedicated_proxy_pod(client: &kube::Client, ns: &str) -> anyhow::Result<Pod> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), ns);
    let sel = format!("{GATEWAY_NAME_LABEL}={GATEWAY_NAME}");
    let list = pods
        .list(&ListParams::default().labels(&sel))
        .await
        .with_context(|| format!("listing dedicated-proxy pods '{sel}' in '{ns}'"))?;
    list.items
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no dedicated-proxy pod matching '{sel}' in '{ns}'"))
}

/// Wait until the namespace relay's Deployment reports at least one ready replica.
async fn wait_for_relay_ready(deployments: &Api<Deployment>) -> anyhow::Result<()> {
    wait::wait_for_resource(deployments, RELAY_NAME, Duration::from_secs(60)).await?;
    wait::poll_until(
        Duration::from_secs(150),
        wait::POLL,
        || async { format!("namespace relay '{RELAY_NAME}' to report a ready replica") },
        || async {
            let ready = deployments
                .get(RELAY_NAME)
                .await
                .ok()
                .and_then(|d| d.status)
                .and_then(|s| s.ready_replicas)
                .unwrap_or(0);
            (ready >= 1).then_some(())
        },
    )
    .await
}

/// The `node_id`s of every `is_relay` Namespace-relay node in `ns`. There may be
/// more than one (`--relay-replicas` defaults to 2), and a repointed leaf's
/// `parent` is whichever replica its stream landed on — so a fold assertion must
/// accept ANY of them, not the lexicographically-first. Namespace-scoped so a
/// serial test never matches another namespace's identically-named relay.
fn relay_ids_in(topology: &serde_json::Value, ns: &str) -> Vec<String> {
    topology
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes
                .iter()
                .filter(|n| {
                    n.pointer("/scope/kind").and_then(|v| v.as_str()) == Some("Namespace")
                        && n.pointer("/scope/namespace").and_then(|v| v.as_str()) == Some(ns)
                        && n.get("is_relay").and_then(|v| v.as_bool()) == Some(true)
                })
                .filter_map(|n| n.get("node_id").and_then(|v| v.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// The dedicated-proxy node for `ns` (scope `Gateway` in `ns`, `dedicated-gw`).
/// Namespace-scoped: every test uses the same Gateway name, so a bare node-id
/// prefix match would collide across the serial suite's namespaces.
fn dedicated_proxy_node<'a>(
    topology: &'a serde_json::Value,
    ns: &str,
) -> Option<&'a serde_json::Value> {
    topology.get("nodes")?.as_array()?.iter().find(|n| {
        n.pointer("/scope/kind").and_then(|v| v.as_str()) == Some("Gateway")
            && n.pointer("/scope/namespace").and_then(|v| v.as_str()) == Some(ns)
            && n.get("node_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id.starts_with(RESOURCE_NAME))
    })
}

/// Poll the controller topology until the `ns` dedicated proxy is folded UNDER a
/// relay: the proxy row's `parent` is one of the namespace's `is_relay` relay
/// nodes. This is the observable proof the proxy repointed from the controller
/// onto the relay.
async fn wait_for_proxy_under_relay(topology_url: &str, ns: &str) -> anyhow::Result<()> {
    wait::poll_until(
        Duration::from_secs(150),
        wait::POLL,
        || {
            let url = topology_url.to_owned();
            async move {
                format!(
                    "controller topology at '{url}' to fold the dedicated proxy under its relay"
                )
            }
        },
        || {
            let url = topology_url.to_owned();
            let ns = ns.to_owned();
            async move {
                let topology = fetch_topology(&url).await.ok()?;
                let relay_ids = relay_ids_in(&topology, &ns);
                if relay_ids.is_empty() {
                    return None;
                }
                let proxy = dedicated_proxy_node(&topology, &ns)?;
                let parent = proxy.get("parent").and_then(|v| v.as_str())?;
                relay_ids.iter().any(|r| r == parent).then_some(())
            }
        },
    )
    .await
    .context("dedicated proxy was never folded under its relay in the controller topology")
}

/// Provision a servable dedicated Gateway in `ns` (echo backend + HTTPRoute),
/// wait for cut-over, and confirm traffic flows through the dedicated proxy.
/// Returns the traffic client, the route host, and the proxy pod's UID (to prove
/// later that a repoint never recreates the pod).
async fn converge_dedicated_proxy(
    h: &Harness,
    ns: &str,
) -> anyhow::Result<(HttpClient, String, Option<String>)> {
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(ns)).await?;
    wait::wait_for_backends(ns).await?;
    fixtures::apply_fixture(dedicated::TRAFFIC, FixtureVars::new(ns)).await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), ns);
    wait_for_cut_over(&gateways, GATEWAY_NAME, Duration::from_secs(120)).await?;

    let host = format!("dedicated.{ns}.local");
    let addr =
        wait::wait_for_dedicated_proxy_endpoint(ns, GATEWAY_NAME, Duration::from_secs(60)).await?;
    let http = HttpClient::new(addr)?;
    wait::wait_for_route(&http, &host, "/", Duration::from_secs(90))
        .await?
        .assert_backend("echo-a");

    let uid = dedicated_proxy_pod(&h.client, ns).await?.metadata.uid;
    Ok((http, host, uid))
}

/// Happy path (#601): with relay tiering on, a servable dedicated Gateway
/// provisions a namespace relay AND its dedicated proxy is repointed from the
/// controller onto the relay — **live, without a pod restart**. Traffic keeps
/// flowing throughout, and the proxy is folded under the relay in the controller
/// topology (proving it now streams through the relay, not the controller).
///
/// Serial: `relay.dedicated.enabled` Helm mutator, in the always-serial
/// `discovery` binary.
#[tokio::test]
async fn dedicated_proxy_repoints_to_relay_without_dropping_traffic() -> anyhow::Result<()> {
    let h = Harness::start_with_options(relay_tiering_threshold_1()).await?;
    let ns = NamespaceGuard::create(&h.client, "relay-repoint").await?;

    // Dedicated proxy converged and serving traffic (initially from the controller).
    let (http, host, proxy_uid) = converge_dedicated_proxy(&h, &ns.name).await?;

    // The relay is provisioned (threshold 1) and becomes Ready.
    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    wait_for_relay_ready(&deployments).await?;

    // The dedicated proxy repoints onto the relay: it appears folded under the
    // relay in the controller topology.
    let topology_url = h.controller_admin_url("/api/v1/topology");
    wait_for_proxy_under_relay(&topology_url, &ns.name).await?;

    // Data plane untouched by the repoint: traffic still flows to the same backend,
    // the proxy pod was never recreated, and its container never restarted.
    wait::wait_for_route(&http, &host, "/", Duration::from_secs(30))
        .await
        .context("dedicated proxy stopped serving traffic across the relay repoint")?
        .assert_backend("echo-a");

    let after = dedicated_proxy_pod(&h.client, &ns.name).await?;
    assert_eq!(
        after.metadata.uid, proxy_uid,
        "the relay repoint must NOT recreate the dedicated-proxy pod (the upstream \
         swap is an in-process control-stream reconnect, not a rollout)"
    );
    assert_eq!(
        restart_count(&after),
        0,
        "the dedicated-proxy container must not restart across the relay repoint"
    );

    Ok(())
}

/// Sad path — controller outage: with the dedicated proxy converged **through**
/// the relay, scaling the controller to zero must leave both the relay and the
/// proxy serving their last-good world (neither drops Ready), and the proxy must
/// keep serving live traffic throughout. Both reconverge when the controller
/// returns.
///
/// Serial: scales the shared controller to zero + `relay.dedicated.*` mutator.
#[tokio::test]
async fn relay_and_dedicated_proxy_serve_last_good_during_controller_outage() -> anyhow::Result<()>
{
    let h = Harness::start_with_options(relay_tiering_threshold_1()).await?;
    let ns = NamespaceGuard::create(&h.client, "relay-outage").await?;

    let (http, host, _uid) = converge_dedicated_proxy(&h, &ns.name).await?;
    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    wait_for_relay_ready(&deployments).await?;
    let topology_url = h.controller_admin_url("/api/v1/topology");
    wait_for_proxy_under_relay(&topology_url, &ns.name).await?;

    // ── Controller down → relay + proxy hold last-good, traffic uninterrupted ──
    let ha_replicas = controller_replicas().await?.max(1);
    scale_controller(0).await?;

    assert_pod_stays_ready(
        &h.client,
        &ns.name,
        RELAY_POD_SELECTOR,
        Duration::from_secs(20),
    )
    .await
    .context("relay dropped Ready during controller outage (last-good violated)")?;
    assert_pod_stays_ready(
        &h.client,
        &ns.name,
        &format!("{GATEWAY_NAME_LABEL}={GATEWAY_NAME}"),
        Duration::from_secs(20),
    )
    .await
    .context("relay-fronted dedicated proxy dropped Ready during controller outage")?;
    wait::wait_for_route(&http, &host, "/", Duration::from_secs(20))
        .await
        .context("dedicated proxy stopped serving last-good traffic during controller outage")?
        .assert_backend("echo-a");

    // ── Controller back → both reconverge ─────────────────────────────────────
    scale_controller(ha_replicas).await?;
    wait_for_relay_ready(&deployments).await?;
    wait::wait_for_route(&http, &host, "/", Duration::from_secs(90))
        .await?
        .assert_backend("echo-a");

    Ok(())
}

/// Sad path — relay restart: with the dedicated proxy converged through the
/// relay, rolling-restarting the relay Deployment must leave the proxy serving
/// its last-good world (it never drops Ready) and keeping live traffic flowing,
/// then reconverge onto the fresh relay pod.
///
/// Serial: `relay.dedicated.*` mutator, always-serial binary.
#[tokio::test]
async fn dedicated_proxy_serves_last_good_while_relay_restarts() -> anyhow::Result<()> {
    let h = Harness::start_with_options(relay_tiering_threshold_1()).await?;
    let ns = NamespaceGuard::create(&h.client, "relay-restart").await?;

    let (http, host, proxy_uid) = converge_dedicated_proxy(&h, &ns.name).await?;
    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    wait_for_relay_ready(&deployments).await?;
    let topology_url = h.controller_admin_url("/api/v1/topology");
    wait_for_proxy_under_relay(&topology_url, &ns.name).await?;

    // ── Restart the relay → proxy holds last-good across the gap ──────────────
    rollout_restart_deployment(&ns.name, RELAY_NAME).await?;
    assert_pod_stays_ready(
        &h.client,
        &ns.name,
        &format!("{GATEWAY_NAME_LABEL}={GATEWAY_NAME}"),
        Duration::from_secs(20),
    )
    .await
    .context("dedicated proxy dropped Ready while its relay restarted (last-good violated)")?;
    wait::wait_for_route(&http, &host, "/", Duration::from_secs(20))
        .await
        .context("dedicated proxy stopped serving last-good traffic during the relay restart")?
        .assert_backend("echo-a");

    // ── Relay back → proxy reconverges onto the fresh relay pod, same proxy pod ─
    wait_for_relay_ready(&deployments).await?;
    wait_for_proxy_under_relay(&topology_url, &ns.name).await?;
    assert_eq!(
        dedicated_proxy_pod(&h.client, &ns.name).await?.metadata.uid,
        proxy_uid,
        "the dedicated-proxy pod must survive a relay restart untouched (only its \
         control stream reconnected)"
    );

    Ok(())
}

/// Sad path — relay deprovisioned: with the dedicated proxy converged through the
/// relay, a `CoxswainRelayPolicy{enabled:false}` vetoes the relay and the
/// controller garbage-collects it. The proxy must fall back to the controller —
/// re-bootstrapping to the always-up anchor once its relay stream drops — while
/// serving its last-good world uninterrupted (same pod, live traffic), and the
/// controller topology must show the relay gone and the proxy no longer folded
/// under it (the subtree is evicted and the proxy re-attaches directly).
///
/// Serial: `relay.dedicated.*` mutator, always-serial binary.
#[tokio::test]
async fn dedicated_proxy_falls_back_to_controller_when_relay_deprovisioned() -> anyhow::Result<()> {
    let h = Harness::start_with_options(relay_tiering_threshold_1()).await?;
    let ns = NamespaceGuard::create(&h.client, "relay-deprovision").await?;

    let (http, host, proxy_uid) = converge_dedicated_proxy(&h, &ns.name).await?;
    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    wait_for_relay_ready(&deployments).await?;
    let topology_url = h.controller_admin_url("/api/v1/topology");
    wait_for_proxy_under_relay(&topology_url, &ns.name).await?;

    // ── Veto the relay → the controller GCs it ────────────────────────────────
    fixtures::apply_fixture(
        dedicated::RELAY_POLICY_FORCE_OFF,
        FixtureVars::new(&ns.name),
    )
    .await?;
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async { format!("relay '{RELAY_NAME}' garbage-collected after enabled:false policy") },
        || async {
            let gone = deployments.get(RELAY_NAME).await.is_err()
                && services.get(RELAY_NAME).await.is_err();
            gone.then_some(())
        },
    )
    .await?;

    // ── Proxy falls back to the controller, uninterrupted ─────────────────────
    // The proxy re-attaches directly: the relay row is gone from topology and the
    // proxy no longer has a relay parent.
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || {
            let url = topology_url.clone();
            async move {
                format!("topology at '{url}' to drop the relay and re-attach the proxy directly")
            }
        },
        || {
            let url = topology_url.clone();
            let ns = ns.name.clone();
            async move {
                let topology = fetch_topology(&url).await.ok()?;
                // This namespace's relay is gone AND its proxy re-attached directly.
                if !relay_ids_in(&topology, &ns).is_empty() {
                    return None;
                }
                let proxy = dedicated_proxy_node(&topology, &ns)?;
                let reattached = proxy
                    .get("parent")
                    .and_then(|v| v.as_str())
                    .is_none_or(str::is_empty);
                reattached.then_some(())
            }
        },
    )
    .await
    .context(
        "dedicated proxy did not fall back to the controller after the relay was deprovisioned",
    )?;

    // The data plane never noticed: live traffic still flows to the same backend,
    // and the proxy pod was never recreated.
    wait::wait_for_route(&http, &host, "/", Duration::from_secs(30))
        .await
        .context("dedicated proxy stopped serving traffic across the relay deprovision")?
        .assert_backend("echo-a");
    assert_eq!(
        dedicated_proxy_pod(&h.client, &ns.name).await?.metadata.uid,
        proxy_uid,
        "the fallback to the controller must NOT recreate the dedicated-proxy pod"
    );

    Ok(())
}

/// Merge-patch the dedicated Gateway's `CoxswainGatewayParameters.spec.replicas`,
/// changing how many dedicated-proxy subscribers the namespace has — the relay
/// control loop's live signal (#602). `DynamicObject` because the CRD has no
/// generated typed Rust struct in the e2e crate.
async fn patch_dedicated_params_replicas(
    client: &kube::Client,
    namespace: &str,
    replicas: i32,
) -> anyhow::Result<()> {
    use kube::api::{ApiResource, DynamicObject};
    let ar = ApiResource {
        group: "gateway.coxswain-labs.dev".into(),
        version: "v1alpha1".into(),
        api_version: "gateway.coxswain-labs.dev/v1alpha1".into(),
        kind: "CoxswainGatewayParameters".into(),
        plural: "coxswaingatewayparameters".into(),
    };
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
    api.patch(
        "dedicated-params",
        &PatchParams::default(),
        &Patch::Merge(json!({ "spec": { "replicas": replicas } })),
    )
    .await
    .context("patch dedicated-params replicas")?;
    Ok(())
}

/// Happy path — the #602 make-before-break TEARDOWN traffic invariant: when a
/// namespace drops **below** break-even at a **nonzero** subscriber count, the
/// control loop tears the relay down after the cooldown, but sequences it safely —
/// the still-connected proxy is repointed back to the controller (a live
/// control-stream reconnect) *before* the relay is deleted, so live traffic is
/// never dropped. This exercises the risky case the force-off veto does not: a
/// proxy actively streaming through the relay at teardown time.
///
/// Serial: `relay.dedicated.*` mutator, always-serial binary.
#[tokio::test]
async fn relay_repoint_keeps_serving_during_teardown() -> anyhow::Result<()> {
    let h = Harness::start_with_options(ControllerOptions {
        relay_enabled: true,
        // Break-even 2: two subscribers provision the relay; dropping to one (below
        // break-even, but nonzero) drives the cooldown teardown.
        relay_min_proxy_replicas: Some(2),
        relay_cooldown: Some("5s".to_string()),
        ..Default::default()
    })
    .await?;
    let ns = NamespaceGuard::create(&h.client, "relay-teardown").await?;

    // Converge the dedicated proxy (serves from the controller; 1 replica < 2 so no
    // relay yet), then scale to 2 subscribers to cross break-even and provision the
    // relay, folding both proxies under it.
    let (http, host, _uid) = converge_dedicated_proxy(&h, &ns.name).await?;
    patch_dedicated_params_replicas(&h.client, &ns.name, 2).await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    wait_for_relay_ready(&deployments).await?;
    let topology_url = h.controller_admin_url("/api/v1/topology");
    wait_for_proxy_under_relay(&topology_url, &ns.name).await?;

    // Drop to a single subscriber: below break-even (2) but NONZERO. After the
    // cooldown the loop tears the relay down — repointing the surviving proxy back
    // to the controller FIRST (make-before-break), so traffic never drops.
    patch_dedicated_params_replicas(&h.client, &ns.name, 1).await?;

    // The relay is deleted and the surviving proxy re-attaches directly to the
    // controller (relay row gone, proxy has no relay parent).
    wait::poll_until(
        Duration::from_secs(120),
        wait::POLL,
        || {
            let url = topology_url.clone();
            async move {
                format!("relay torn down after cooldown and proxy re-attached directly at '{url}'")
            }
        },
        || {
            let url = topology_url.clone();
            let ns = ns.name.clone();
            let deployments = deployments.clone();
            async move {
                if deployments.get(RELAY_NAME).await.is_ok() {
                    return None;
                }
                let topology = fetch_topology(&url).await.ok()?;
                if !relay_ids_in(&topology, &ns).is_empty() {
                    return None;
                }
                let proxy = dedicated_proxy_node(&topology, &ns)?;
                proxy
                    .get("parent")
                    .and_then(|v| v.as_str())
                    .is_none_or(str::is_empty)
                    .then_some(())
            }
        },
    )
    .await
    .context(
        "relay was not torn down / proxy did not re-attach after the below-break-even cooldown",
    )?;

    // The service Deployment is gone too, and the data plane never noticed: traffic
    // still flows to the same backend through the (repointed) surviving proxy.
    anyhow::ensure!(
        services.get(RELAY_NAME).await.is_err(),
        "relay Service must be GC'd alongside its Deployment at teardown"
    );
    wait::wait_for_route(&http, &host, "/", Duration::from_secs(30))
        .await
        .context("traffic dropped across the below-break-even relay teardown")?
        .assert_backend("echo-a");

    Ok(())
}
