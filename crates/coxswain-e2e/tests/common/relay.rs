#![allow(missing_docs)]
//! Relay-tier (#583) discovery-plane fixture helpers.
//!
//! A relay is a zero-RBAC discovery cache: `serve relay --shared` subscribes
//! upstream to the controller and re-serves the snapshot stream downstream to
//! leaf proxies. These builders stand up an ad-hoc relay + a leaf shared-proxy
//! pointed at it — the chart templates for a relay land in #584, so slice B's
//! e2e owns the manifests directly (modelled on `common::discovery`'s
//! ad-hoc-proxy builder).
//!
//! The relay runs under a dedicated **zero-verb** ServiceAccount so the leaf can
//! pin its `--discovery-expected-server-sa` to a non-default identity (proving
//! the configurable expected-server matcher) and so the read-only-relay RBAC
//! invariant is auditable.

use std::time::Duration;

use anyhow::Context as _;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Pod, Service, ServiceAccount};
use kube::api::{Api, ListParams, ObjectMeta, PostParams};
use serde_json::json;

use coxswain_e2e::harness::wait;

/// Dedicated zero-verb ServiceAccount the relay pod runs under. The leaf pins
/// its expected-server SA to this name.
pub const RELAY_SA: &str = "coxswain-relay-e2e";

/// Downstream discovery port the relay binds for leaf proxies (mirrors the
/// controller's `--discovery-port`).
pub const RELAY_DISCOVERY_PORT: i32 = 50051;

const E2E_IMAGE: &str = "coxswain:e2e";
const CONTROLLER_DISCOVERY_ENDPOINT: &str =
    "https://coxswain-controller-discovery.coxswain-system.svc:50051";
const CONTROLLER_BOOTSTRAP_ENDPOINT: &str =
    "https://coxswain-controller-discovery-bootstrap.coxswain-system.svc:50052";
const DISCOVERY_AUDIENCE: &str = "coxswain-discovery";

/// In-cluster discovery endpoint for the relay Service `name` in namespace `ns`
/// (the address a leaf's `--discovery-endpoint` targets). The leaf derives the
/// relay's expected-server namespace from this DNS, so it must name the relay's
/// actual namespace.
#[must_use]
pub fn relay_discovery_endpoint(ns: &str, name: &str) -> String {
    format!("https://{name}.{ns}.svc:{RELAY_DISCOVERY_PORT}")
}

/// A zero-verb ServiceAccount for the relay pod (no RoleBinding is created, so
/// the SA holds no Kubernetes verbs — the read-only-relay invariant).
///
/// # Errors
///
/// Never fails to build; returns `anyhow::Result` for call-site uniformity.
pub async fn create_relay_service_account(
    client: &kube::Client,
    ns: &str,
    sa: &str,
) -> anyhow::Result<()> {
    let api: Api<ServiceAccount> = Api::namespaced(client.clone(), ns);
    let obj = ServiceAccount {
        metadata: ObjectMeta {
            name: Some(sa.to_owned()),
            namespace: Some(ns.to_owned()),
            ..Default::default()
        },
        ..Default::default()
    };
    api.create(&PostParams::default(), &obj)
        .await
        .with_context(|| format!("create relay ServiceAccount {ns}/{sa}"))?;
    Ok(())
}

/// A `serve relay --shared` Deployment: a discovery client upstream (to the
/// controller) + a discovery server downstream (its own SVID as serving cert,
/// the mounted trust bundle as client-CA). Readiness (`/readyz`) gates on both
/// `routing_table_loaded` and `downstream_serving`.
///
/// # Errors
///
/// Returns an error if the literal fails to deserialize (invariant: it does not).
pub fn relay_deployment(ns: &str, name: &str, sa: &str) -> anyhow::Result<Deployment> {
    let deploy: Deployment = serde_json::from_value(json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": { "name": name, "namespace": ns },
        "spec": {
            "replicas": 1,
            "selector": { "matchLabels": { "app": name } },
            "template": {
                "metadata": {
                    "labels": { "app": name, "app.kubernetes.io/component": "relay" }
                },
                "spec": {
                    "serviceAccountName": sa,
                    "automountServiceAccountToken": false,
                    "containers": [{
                        "name": "coxswain",
                        "image": E2E_IMAGE,
                        "imagePullPolicy": "Never",
                        "args": ["serve", "relay", "--shared"],
                        "env": [
                            { "name": "POD_NAME", "valueFrom": { "fieldRef": { "fieldPath": "metadata.name" } } },
                            { "name": "POD_NAMESPACE", "valueFrom": { "fieldRef": { "fieldPath": "metadata.namespace" } } },
                            { "name": "COXSWAIN_DISCOVERY_ENDPOINT", "value": CONTROLLER_DISCOVERY_ENDPOINT },
                            { "name": "COXSWAIN_DISCOVERY_BOOTSTRAP_ENDPOINT", "value": CONTROLLER_BOOTSTRAP_ENDPOINT },
                            { "name": "COXSWAIN_DISCOVERY_SA_TOKEN_PATH", "value": "/var/run/secrets/coxswain/discovery-token/token" },
                            { "name": "COXSWAIN_DISCOVERY_CA_BUNDLE_PATH", "value": "/var/run/secrets/coxswain/trust-bundle/ca.crt" },
                            // The relay binds its downstream discovery server here.
                            { "name": "COXSWAIN_DISCOVERY_PORT", "value": RELAY_DISCOVERY_PORT.to_string() }
                        ],
                        "ports": [
                            { "name": "health", "containerPort": 8081 },
                            { "name": "discovery", "containerPort": RELAY_DISCOVERY_PORT }
                        ],
                        "readinessProbe": {
                            "httpGet": { "path": "/readyz", "port": "health" },
                            "initialDelaySeconds": 2,
                            "periodSeconds": 2,
                            "failureThreshold": 30
                        },
                        "volumeMounts": [
                            { "name": "discovery-token", "mountPath": "/var/run/secrets/coxswain/discovery-token", "readOnly": true },
                            { "name": "trust-bundle", "mountPath": "/var/run/secrets/coxswain/trust-bundle", "readOnly": true }
                        ]
                    }],
                    "volumes": [
                        {
                            "name": "discovery-token",
                            "projected": { "sources": [{
                                "serviceAccountToken": { "path": "token", "audience": DISCOVERY_AUDIENCE, "expirationSeconds": 3600 }
                            }] }
                        },
                        { "name": "trust-bundle", "configMap": { "name": "coxswain-discovery-trust", "optional": false } }
                    ]
                }
            }
        }
    }))?;
    Ok(deploy)
}

/// The relay's downstream discovery `Service`: leaves target
/// `https://<name>.<ns>.svc:<RELAY_DISCOVERY_PORT>`.
///
/// # Errors
///
/// Returns an error if the literal fails to deserialize (invariant: it does not).
pub fn relay_service(ns: &str, name: &str) -> anyhow::Result<Service> {
    let svc: Service = serde_json::from_value(json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": name, "namespace": ns },
        "spec": {
            "selector": { "app": name },
            "ports": [{
                "name": "discovery",
                "port": RELAY_DISCOVERY_PORT,
                "targetPort": "discovery",
                "protocol": "TCP"
            }]
        }
    }))?;
    Ok(svc)
}

/// A `serve proxy --shared` leaf Deployment pointed at the relay: its discovery
/// endpoint is the relay Service and its expected-server SA is the relay's SA;
/// bootstrap still targets the controller (bootstrap is never tiered).
///
/// # Errors
///
/// Returns an error if the literal fails to deserialize (invariant: it does not).
pub fn leaf_deployment(
    ns: &str,
    name: &str,
    relay_service_name: &str,
    expected_server_sa: &str,
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
                            { "name": "POD_NAME", "valueFrom": { "fieldRef": { "fieldPath": "metadata.name" } } },
                            { "name": "POD_NAMESPACE", "valueFrom": { "fieldRef": { "fieldPath": "metadata.namespace" } } },
                            // Upstream is the RELAY (in this test namespace), not the controller.
                            { "name": "COXSWAIN_DISCOVERY_ENDPOINT", "value": relay_discovery_endpoint(ns, relay_service_name) },
                            // Bootstrap is never tiered — still the controller.
                            { "name": "COXSWAIN_DISCOVERY_BOOTSTRAP_ENDPOINT", "value": CONTROLLER_BOOTSTRAP_ENDPOINT },
                            { "name": "COXSWAIN_DISCOVERY_SA_TOKEN_PATH", "value": "/var/run/secrets/coxswain/discovery-token/token" },
                            { "name": "COXSWAIN_DISCOVERY_CA_BUNDLE_PATH", "value": "/var/run/secrets/coxswain/trust-bundle/ca.crt" },
                            // Verify the relay's identity, not the controller's.
                            { "name": "COXSWAIN_DISCOVERY_EXPECTED_SERVER_SA", "value": expected_server_sa }
                        ],
                        "ports": [{ "name": "health", "containerPort": 8081 }],
                        "readinessProbe": {
                            "httpGet": { "path": "/readyz", "port": "health" },
                            "initialDelaySeconds": 2,
                            "periodSeconds": 2,
                            "failureThreshold": 30
                        },
                        "volumeMounts": [
                            { "name": "discovery-token", "mountPath": "/var/run/secrets/coxswain/discovery-token", "readOnly": true },
                            { "name": "trust-bundle", "mountPath": "/var/run/secrets/coxswain/trust-bundle", "readOnly": true }
                        ]
                    }],
                    "volumes": [
                        {
                            "name": "discovery-token",
                            "projected": { "sources": [{
                                "serviceAccountToken": { "path": "token", "audience": DISCOVERY_AUDIENCE, "expirationSeconds": 3600 }
                            }] }
                        },
                        { "name": "trust-bundle", "configMap": { "name": "coxswain-discovery-trust", "optional": false } }
                    ]
                }
            }
        }
    }))?;
    Ok(deploy)
}

/// Assert that at least one pod matching `label_selector` in `ns` **stays**
/// `Ready=True` for the whole `window` — the last-good invariant under an
/// upstream outage. Polls every [`wait::POLL`]; the first check fires at t=0.
///
/// # Errors
///
/// Returns an error if no matching pod is Ready at any poll during the window
/// (a flip to NotReady, or the pod vanishing).
pub async fn assert_pod_stays_ready(
    client: &kube::Client,
    ns: &str,
    label_selector: &str,
    window: Duration,
) -> anyhow::Result<()> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), ns);
    let deadline = tokio::time::Instant::now() + window;
    let mut tick = tokio::time::interval(wait::POLL);
    loop {
        tick.tick().await;
        let list = pods
            .list(&ListParams::default().labels(label_selector))
            .await
            .with_context(|| format!("listing pods '{label_selector}' in '{ns}'"))?;
        let ready = list.items.iter().any(pod_is_ready);
        anyhow::ensure!(
            ready,
            "expected a pod matching '{label_selector}' in '{ns}' to stay Ready=True \
             for the whole last-good window, but none was Ready at this poll"
        );
        if tokio::time::Instant::now() >= deadline {
            return Ok(());
        }
    }
}

/// Whether the pod's `Ready` status condition is `"True"`.
fn pod_is_ready(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == "Ready"))
        .is_some_and(|c| c.status == "True")
}
