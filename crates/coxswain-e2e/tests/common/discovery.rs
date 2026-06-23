//! Shared helpers for the `discovery` behaviour-plane tests.
//!
//! Covers: deploying ad-hoc shared-proxy pods, waiting on their Pod `Ready`
//! condition, fetching the `/api/v1/topology` response, and constructing the
//! `serde_json` fixtures for inline Deployment objects.

use anyhow::Context as _;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Pod};
use kube::api::{Api, ListParams, ObjectMeta, PostParams};
use serde_json::json;
use std::time::Duration;

use coxswain_e2e::harness::wait;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Kubernetes namespace that holds the controller CA + trust-bundle ConfigMap.
pub const DISCOVERY_NAMESPACE: &str = "coxswain-system";

/// Container image tag that all ad-hoc proxy Deployments use. Matches the
/// image built by the e2e bootstrap step.
const E2E_IMAGE: &str = "coxswain:e2e";

/// mTLS discovery endpoint inside the cluster.
const DISCOVERY_ENDPOINT: &str = "https://coxswain-controller-discovery.coxswain-system.svc:50051";

/// Bootstrap endpoint (server-auth-only TLS; issues SVIDs to fresh proxies).
const BOOTSTRAP_ENDPOINT: &str = "https://coxswain-controller-discovery.coxswain-system.svc:50052";

/// SA token audience the controller validates at bootstrap time.
const DISCOVERY_AUDIENCE: &str = "coxswain-discovery";

// ── Trust-bundle helper ───────────────────────────────────────────────────────

/// Copy the `coxswain-discovery-trust` ConfigMap from `coxswain-system` into
/// `target_ns` so a test pod in that namespace can mount the trust bundle.
///
/// Cross-namespace ConfigMap volume mounts are not allowed in Kubernetes; this
/// mirrors the pattern used in `invalid_sa_token_is_rejected_with_event`.
///
/// # Errors
///
/// Returns an error if the source ConfigMap cannot be fetched or if the target
/// create call fails.
pub async fn copy_trust_bundle(client: &kube::Client, target_ns: &str) -> anyhow::Result<()> {
    let src: Api<ConfigMap> = Api::namespaced(client.clone(), DISCOVERY_NAMESPACE);
    let trust = src.get("coxswain-discovery-trust").await.map_err(|e| {
        anyhow::anyhow!(
            "coxswain-discovery-trust ConfigMap must exist in {DISCOVERY_NAMESPACE}: {e}"
        )
    })?;

    let dst: Api<ConfigMap> = Api::namespaced(client.clone(), target_ns);
    dst.create(
        &PostParams::default(),
        &ConfigMap {
            metadata: ObjectMeta {
                name: Some("coxswain-discovery-trust".to_owned()),
                namespace: Some(target_ns.to_owned()),
                ..Default::default()
            },
            data: trust.data.clone(),
            ..Default::default()
        },
    )
    .await
    .with_context(|| format!("copy trust bundle into {target_ns}"))?;
    Ok(())
}

// ── Deployment builder ────────────────────────────────────────────────────────

/// Build a `serve proxy --shared` Deployment that participates in the discovery
/// control-plane.
///
/// The pod:
/// - uses `coxswain:e2e` with `imagePullPolicy: Never`
/// - mounts a projected SA token for the `coxswain-discovery` audience
/// - mounts the `coxswain-discovery-trust` ConfigMap (must already exist in `ns`)
/// - sets the given `trust_domain` via `COXSWAIN_DISCOVERY_TRUST_DOMAIN`
/// - has a HTTP readinessProbe on `/readyz` (port 8081) so the pod's `Ready`
///   condition reflects discovery convergence without a port-forward
///
/// The `pod_name` is injected via `POD_NAME` downward-API env so it is used
/// as the `node_id` in the NodeRegistry / topology API.
///
/// # Errors
///
/// Returns an error if the JSON serialisation fails (invariant: the literal is
/// always valid).
pub fn shared_proxy_deployment(
    ns: &str,
    name: &str,
    trust_domain: &str,
) -> anyhow::Result<Deployment> {
    let deploy: Deployment = serde_json::from_value(json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": { "name": name, "namespace": ns },
        "spec": {
            "replicas": 1,
            "selector": { "matchLabels": { "app": name } },
            "template": {
                "metadata": { "labels": { "app": name } },
                "spec": {
                    "containers": [{
                        "name": "coxswain",
                        "image": E2E_IMAGE,
                        "imagePullPolicy": "Never",
                        "args": ["serve", "proxy", "--shared"],
                        "env": [
                            {
                                "name": "POD_NAME",
                                "valueFrom": { "fieldRef": { "fieldPath": "metadata.name" } }
                            },
                            {
                                "name": "POD_NAMESPACE",
                                "valueFrom": { "fieldRef": { "fieldPath": "metadata.namespace" } }
                            },
                            {
                                "name": "COXSWAIN_DISCOVERY_ENDPOINT",
                                "value": DISCOVERY_ENDPOINT
                            },
                            {
                                "name": "COXSWAIN_DISCOVERY_BOOTSTRAP_ENDPOINT",
                                "value": BOOTSTRAP_ENDPOINT
                            },
                            {
                                "name": "COXSWAIN_DISCOVERY_SA_TOKEN_PATH",
                                "value": "/var/run/secrets/coxswain/discovery-token/token"
                            },
                            {
                                "name": "COXSWAIN_DISCOVERY_CA_BUNDLE_PATH",
                                "value": "/var/run/secrets/coxswain/trust-bundle/ca.crt"
                            },
                            {
                                "name": "COXSWAIN_DISCOVERY_TRUST_DOMAIN",
                                "value": trust_domain
                            }
                        ],
                        "ports": [
                            { "name": "health", "containerPort": 8081 }
                        ],
                        "readinessProbe": {
                            "httpGet": { "path": "/readyz", "port": "health" },
                            "initialDelaySeconds": 2,
                            "periodSeconds": 2,
                            "failureThreshold": 30
                        },
                        "volumeMounts": [
                            {
                                "name": "discovery-token",
                                "mountPath": "/var/run/secrets/coxswain/discovery-token",
                                "readOnly": true
                            },
                            {
                                "name": "trust-bundle",
                                "mountPath": "/var/run/secrets/coxswain/trust-bundle",
                                "readOnly": true
                            }
                        ]
                    }],
                    "volumes": [
                        {
                            "name": "discovery-token",
                            "projected": {
                                "sources": [{
                                    "serviceAccountToken": {
                                        "path": "token",
                                        "audience": DISCOVERY_AUDIENCE,
                                        "expirationSeconds": 3600
                                    }
                                }]
                            }
                        },
                        {
                            "name": "trust-bundle",
                            "configMap": {
                                "name": "coxswain-discovery-trust",
                                "optional": false
                            }
                        }
                    ]
                }
            }
        }
    }))?;
    Ok(deploy)
}

// ── Pod readiness waits ───────────────────────────────────────────────────────

/// Wait until at least one Pod matching `label_selector` in `ns` reports
/// `Ready=True`, or until `timeout` elapses.
///
/// The readiness condition mirrors discovery convergence because
/// `shared_proxy_deployment` wires the readinessProbe to `/readyz` (gated on
/// `routing_table_loaded`).
///
/// # Errors
///
/// Returns an error if no pod becomes Ready within the timeout.
pub async fn wait_for_pod_ready(
    client: &kube::Client,
    ns: &str,
    label_selector: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), ns);
    wait::poll_until(
        timeout,
        wait::POLL,
        || {
            let sel = label_selector.to_owned();
            async move { format!("pod matching '{sel}' in '{ns}' to reach Ready=True") }
        },
        || {
            let pods = pods.clone();
            let sel = label_selector.to_owned();
            async move {
                let list = pods.list(&ListParams::default().labels(&sel)).await.ok()?;
                list.items.iter().find(|p| pod_is_ready(p)).map(|_| ())
            }
        },
    )
    .await
}

/// Assert that NO pod matching `label_selector` in `ns` reports `Ready=True`
/// for an entire `window`. Polls every 500 ms.
///
/// Used by the trust-domain-mismatch test to prove the bad-config proxy never
/// converges during the observation window.
///
/// # Errors
///
/// Returns an error if any pod goes Ready before the window closes.
pub async fn assert_pod_stays_not_ready(
    client: &kube::Client,
    ns: &str,
    label_selector: &str,
    window: Duration,
) -> anyhow::Result<()> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), ns);
    let deadline = tokio::time::Instant::now() + window;
    // Use an interval rather than a bare tokio::time::delay so the
    // no-e2e-sleeps gate remains satisfied. The first tick fires immediately,
    // giving us a check at t=0.
    let mut tick = tokio::time::interval(wait::POLL);
    loop {
        tick.tick().await;
        let list = pods
            .list(&ListParams::default().labels(label_selector))
            .await
            .context("listing pods for not-ready assertion")?;
        for pod in &list.items {
            if pod_is_ready(pod) {
                let pname = pod.metadata.name.as_deref().unwrap_or("<unnamed>");
                anyhow::bail!(
                    "pod '{pname}' in '{ns}' (selector '{label_selector}') became \
                     Ready=True within the observation window — expected it to stay \
                     NotReady (wrong trust domain should not complete SVID bootstrap)"
                );
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(());
        }
    }
}

/// Returns `true` when the pod's `Ready` status condition is `"True"`.
fn pod_is_ready(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == "Ready"))
        .is_some_and(|c| c.status == "True")
}

// ── Topology helpers ──────────────────────────────────────────────────────────

/// Fetch `GET /api/v1/topology` from the controller's admin endpoint and parse
/// the response as a `serde_json::Value`.
///
/// # Errors
///
/// Returns an error if the HTTP request fails or the body is not valid JSON.
pub async fn fetch_topology(topology_url: &str) -> anyhow::Result<serde_json::Value> {
    let resp = reqwest::get(topology_url)
        .await
        .with_context(|| format!("GET {topology_url}"))?;
    let body = resp
        .text()
        .await
        .with_context(|| format!("read body of {topology_url}"))?;
    serde_json::from_str(&body).with_context(|| format!("parse topology JSON from {topology_url}"))
}

/// Find the first node in a topology response whose `node_id` starts with
/// `node_id_prefix`. Returns `None` if no matching entry is found.
///
/// The topology `nodes` array is ordered by scope then node_id, so a prefix
/// match is stable.
pub fn find_node<'a>(
    topology: &'a serde_json::Value,
    node_id_prefix: &str,
) -> Option<&'a serde_json::Value> {
    topology.get("nodes")?.as_array()?.iter().find(|n| {
        n.get("node_id")
            .and_then(|v| v.as_str())
            .is_some_and(|id| id.starts_with(node_id_prefix))
    })
}

// ── Health helpers ────────────────────────────────────────────────────────────

/// Fetch `GET /api/v1/health` from the given URL (proxy admin endpoint) and
/// return the value of `subsystems.proxy.state` as a `String`, or `None` if
/// the request fails or the path is absent.
pub async fn proxy_health_state(health_url: &str) -> Option<String> {
    let body = reqwest::get(health_url).await.ok()?.text().await.ok()?;
    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    // The `/api/v1/health` body nests `CheckState` as a struct:
    //   `{ subsystems: { proxy: { state: { state: "ready|degraded|pending", ... } } } }`
    // so the path to the state string is `/subsystems/proxy/state/state`.
    json.pointer("/subsystems/proxy/state/state")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
}

// ── Metrics helpers ───────────────────────────────────────────────────────────

/// Scrape `GET <metrics_url>` (an admin `/metrics` endpoint) and return the
/// value of a bare, label-less Prometheus series named `metric`, or `None` if
/// the request fails or the series is absent.
///
/// Mirrors the bare-series parse in `harness::wait` (`name <value>`); only
/// matches the unlabelled form, never `metric{labels}` or `metric_suffix`.
pub async fn scrape_metric(metrics_url: &str, metric: &str) -> Option<f64> {
    let body = reqwest::get(metrics_url).await.ok()?.text().await.ok()?;
    body.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        let rest = l.strip_prefix(metric)?;
        rest.strip_prefix(' ')?.trim().parse::<f64>().ok()
    })
}
