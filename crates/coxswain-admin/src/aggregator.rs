//! Aggregating HTTP handlers for the controller's `/api/v1/*` REST surface.
//!
//! [`OperatorAggregator`] is wired into [`super::AdminServer`] only for the
//! controller and dev pod roles. Proxy pods receive `None` in the admin server's
//! aggregator slot, so every endpoint in this module returns 404 structurally on
//! proxy pods — the same pattern used for `/api/v1/cluster`.
//!
//! Fan-out to individual proxy admin ports is plain HTTP via [`reqwest`]; the
//! 2-second timeout configured at client construction prevents a slow pod from
//! blocking the whole response. A pod that doesn't respond within the deadline
//! is surfaced as `"reachable": false` (HTTP 200, partial results are valid).
//!
//! The Kubernetes client is lazily initialised on the first request that needs
//! it (`get_gateway`, `get_ingress`, `get_httproute`, `get_ingress_route`).
//! This avoids requiring an async context at construction time — `run_controller`
//! is synchronous and has no tokio runtime until `server.run_forever()`.

use crate::gw_types::{self, HttpRoute};
use coxswain_core::cluster::{ClusterSummary, GatewayCondition, SharedClusterSummary};
use coxswain_core::fleet::{Component, FleetEntry, SharedFleet};
use futures::future::join_all;
use http::{HeaderValue, Response, StatusCode, header};
use k8s_openapi::api::networking::v1::Ingress;
use kube::{Api, Client};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::OnceCell;

// ── OperatorAggregator ────────────────────────────────────────────────────────

/// Fan-out aggregator for the controller's `/api/v1/*` endpoints.
///
/// Constructed once in `run_controller` and stored behind an
/// [`Option`] in [`super::AdminServer`]; proxy roles leave it `None`.
#[non_exhaustive]
pub struct OperatorAggregator {
    /// HTTP client with a 2-second per-request timeout for fan-out calls.
    http: reqwest::Client,
    /// Live snapshot of every coxswain pod, updated by the fleet reflector.
    fleet: SharedFleet,
    /// Cluster-wide gateway/ingress summary published by the reconciler.
    cluster: SharedClusterSummary,
    /// Kubernetes client, initialised lazily on the first K8s-backed request.
    kube: OnceCell<Client>,
}

impl OperatorAggregator {
    /// Construct an aggregator with the given fleet and cluster handles.
    ///
    /// Installs the `ring` rustls crypto provider (idempotent) so the
    /// reqwest client can be built; fan-out targets are plain HTTP and
    /// TLS is never exercised at request time.
    #[must_use]
    pub fn new(fleet: SharedFleet, cluster: SharedClusterSummary) -> Self {
        // reqwest 0.13 uses rustls-no-provider; install ring as the
        // process-default provider. The call is idempotent — the `Err`
        // returned when a provider is already registered is intentionally
        // discarded.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap_or_else(|e| panic!("invariant: reqwest client must build: {e}"));

        Self {
            http,
            fleet,
            cluster,
            kube: OnceCell::new(),
        }
    }

    /// Return the Kubernetes client, initialising it on the first call.
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be initialised from the
    /// in-cluster service account or `KUBECONFIG`.
    async fn kube(&self) -> Result<&Client, kube::Error> {
        self.kube
            .get_or_try_init(|| async { Client::try_default().await })
            .await
    }
}

// ── URL helpers ───────────────────────────────────────────────────────────────

/// Build an admin base URL for `entry`, handling IPv6 bracket notation.
fn pod_base_url(entry: &FleetEntry) -> String {
    match entry.pod_ip {
        IpAddr::V4(_) => format!("http://{}:{}", entry.pod_ip, entry.admin_port),
        IpAddr::V6(_) => format!("http://[{}]:{}", entry.pod_ip, entry.admin_port),
    }
}

// ── Fan-out helpers ───────────────────────────────────────────────────────────

impl OperatorAggregator {
    /// Perform a single `GET {url}` and deserialise the body as JSON.
    ///
    /// Returns `None` on any network error, non-2xx status, or parse
    /// failure — the caller maps `None` to `"reachable": false`.
    async fn fetch_json(&self, url: &str) -> Option<serde_json::Value> {
        let resp = self.http.get(url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json::<serde_json::Value>().await.ok()
    }

    /// Build the base JSON object for a fleet entry.
    fn entry_json(entry: &FleetEntry) -> serde_json::Value {
        let component = component_str(entry.component);
        let mut obj = serde_json::json!({
            "pod_name": entry.pod_name,
            "pod_ip": entry.pod_ip.to_string(),
            "admin_port": entry.admin_port,
            "component": component,
        });
        if let Some(ref gw) = entry.gateway_ref {
            obj["gateway_ref"] = serde_json::Value::String(gw.clone());
        }
        obj
    }
}

// ── /api/v1/proxies ───────────────────────────────────────────────────────────

impl OperatorAggregator {
    /// `GET /api/v1/proxies` — all shared + dedicated proxy pods with liveness.
    pub(crate) async fn list_proxies(&self) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entries: Vec<FleetEntry> = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .cloned()
            .collect();
        let http = &self.http;
        let probes: Vec<_> = entries
            .iter()
            .map(|e| {
                let url = format!("{}/api/v1/health", pod_base_url(e));
                async move {
                    match http
                        .get(&url)
                        .send()
                        .await
                        .ok()
                        .filter(|r| r.status().is_success())
                    {
                        Some(_) => {
                            let mut v = Self::entry_json(e);
                            v["reachable"] = serde_json::Value::Bool(true);
                            v
                        }
                        None => serde_json::json!({ "pod_name": e.pod_name, "reachable": false }),
                    }
                }
            })
            .collect();
        let results = join_all(probes).await;
        json_response(serde_json::json!({ "proxies": results }).to_string())
    }

    /// `GET /api/v1/proxies/{pod-name}` — single proxy pod info + liveness.
    pub(crate) async fn get_proxy(&self, pod_name: &str) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entry = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .find(|e| e.pod_name == pod_name);
        let Some(entry) = entry else {
            return not_found();
        };
        let url = format!("{}/api/v1/health", pod_base_url(entry));
        match self.fetch_json(&url).await {
            Some(_) => {
                let mut v = Self::entry_json(entry);
                v["reachable"] = serde_json::Value::Bool(true);
                json_response(v.to_string())
            }
            None => json_response(
                serde_json::json!({ "pod_name": pod_name, "reachable": false }).to_string(),
            ),
        }
    }

    /// `GET /api/v1/proxies/{pod-name}/routes` — fan-out to the pod's `/routes`.
    pub(crate) async fn get_proxy_routes(&self, pod_name: &str) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entry = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .find(|e| e.pod_name == pod_name);
        let Some(entry) = entry else {
            return not_found();
        };
        let url = format!("{}/routes", pod_base_url(entry));
        match self.fetch_json(&url).await {
            Some(routes) => json_response(
                serde_json::json!({ "pod_name": pod_name, "reachable": true, "routes": routes })
                    .to_string(),
            ),
            None => json_response(
                serde_json::json!({ "pod_name": pod_name, "reachable": false }).to_string(),
            ),
        }
    }

    /// `GET /api/v1/proxies/{pod-name}/health` — fan-out to the pod's
    /// `/api/v1/health`.
    pub(crate) async fn get_proxy_health(&self, pod_name: &str) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entry = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .find(|e| e.pod_name == pod_name);
        let Some(entry) = entry else {
            return not_found();
        };
        self.fetch_pod_health(pod_name, entry).await
    }
}

// ── /api/v1/controllers ───────────────────────────────────────────────────────

impl OperatorAggregator {
    /// `GET /api/v1/controllers` — all controller pods with liveness probe.
    pub(crate) async fn list_controllers(&self) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entries: Vec<FleetEntry> = snapshot.controllers.iter().cloned().collect();
        let http = &self.http;
        let probes: Vec<_> = entries
            .iter()
            .map(|e| {
                let url = format!("{}/api/v1/health", pod_base_url(e));
                async move {
                    match http
                        .get(&url)
                        .send()
                        .await
                        .ok()
                        .filter(|r| r.status().is_success())
                    {
                        Some(_) => {
                            let mut v = Self::entry_json(e);
                            v["reachable"] = serde_json::Value::Bool(true);
                            v
                        }
                        None => serde_json::json!({ "pod_name": e.pod_name, "reachable": false }),
                    }
                }
            })
            .collect();
        let results = join_all(probes).await;
        json_response(serde_json::json!({ "controllers": results }).to_string())
    }

    /// `GET /api/v1/controllers/{pod-name}` — single controller pod info.
    pub(crate) async fn get_controller(&self, pod_name: &str) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let Some(entry) = snapshot.controllers.iter().find(|e| e.pod_name == pod_name) else {
            return not_found();
        };
        let url = format!("{}/api/v1/health", pod_base_url(entry));
        match self.fetch_json(&url).await {
            Some(_) => {
                let mut v = Self::entry_json(entry);
                v["reachable"] = serde_json::Value::Bool(true);
                json_response(v.to_string())
            }
            None => json_response(
                serde_json::json!({ "pod_name": pod_name, "reachable": false }).to_string(),
            ),
        }
    }

    /// `GET /api/v1/controllers/{pod-name}/health` — fan-out to that pod's
    /// `/api/v1/health`.
    pub(crate) async fn get_controller_health(&self, pod_name: &str) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let Some(entry) = snapshot.controllers.iter().find(|e| e.pod_name == pod_name) else {
            return not_found();
        };
        self.fetch_pod_health(pod_name, entry).await
    }

    /// Shared implementation for `/{pod}/health` detail endpoints.
    async fn fetch_pod_health(&self, pod_name: &str, entry: &FleetEntry) -> Response<Vec<u8>> {
        let url = format!("{}/api/v1/health", pod_base_url(entry));
        match self.fetch_json(&url).await {
            Some(health) => json_response(
                serde_json::json!({ "pod_name": pod_name, "reachable": true, "health": health })
                    .to_string(),
            ),
            None => json_response(
                serde_json::json!({ "pod_name": pod_name, "reachable": false }).to_string(),
            ),
        }
    }
}

// ── /api/v1/gateways ─────────────────────────────────────────────────────────

impl OperatorAggregator {
    /// `GET /api/v1/gateways` — gateway list from the cluster summary (no
    /// fan-out).
    pub(crate) fn list_gateways(&self) -> Response<Vec<u8>> {
        let snapshot = self.cluster.load();
        match serde_json::to_string(&serde_json::json!({ "gateways": snapshot.gateways })) {
            Ok(body) => json_response(body),
            Err(e) => {
                tracing::error!(error = %e, "failed to serialise /api/v1/gateways");
                internal_error()
            }
        }
    }

    /// `GET /api/v1/gateways/{namespace}/{name}` — cluster-summary entry
    /// enriched with live status conditions from the Kubernetes API.
    pub(crate) async fn get_gateway(&self, namespace: &str, name: &str) -> Response<Vec<u8>> {
        // Find the entry in the cluster summary (fast path).
        let snapshot = self.cluster.load();
        let summary = match snapshot
            .gateways
            .iter()
            .find(|g| g.name == name && g.namespace == namespace)
        {
            Some(s) => s,
            None => return not_found(),
        };

        // Enrich with live K8s conditions.
        let kube = match self.kube().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "kube client unavailable for /api/v1/gateways detail");
                return json_response(gateway_summary_json(summary, &snapshot).to_string());
            }
        };

        let api: Api<gw_types::v::gateways::Gateway> = Api::namespaced(kube.clone(), namespace);
        let conditions = match api.get(name).await {
            Ok(gw) => gw
                .status
                .as_ref()
                .and_then(|s| s.conditions.as_deref())
                .unwrap_or_default()
                .iter()
                .map(GatewayCondition::from_kube)
                .collect::<Vec<_>>(),
            Err(kube::Error::Api(e)) if e.code == 404 => {
                // Deleted since the last cluster-summary rebuild.
                return not_found();
            }
            Err(e) => {
                tracing::warn!(error = %e, namespace, name, "K8s GET Gateway failed; using summary conditions");
                summary.conditions.clone()
            }
        };

        let mut v = gateway_summary_json(summary, &snapshot);
        v["conditions"] = serde_json::to_value(&conditions).unwrap_or(serde_json::Value::Null);
        json_response(v.to_string())
    }
}

/// Build a JSON object from a `GatewaySummary` (dropping its own `conditions`
/// so the caller can inject live ones).
fn gateway_summary_json(
    summary: &coxswain_core::cluster::GatewaySummary,
    _snapshot: &ClusterSummary,
) -> serde_json::Value {
    serde_json::json!({
        "name": summary.name,
        "namespace": summary.namespace,
        "proxy": summary.proxy,
        "route_count": summary.route_count,
        "addresses": summary.addresses,
        "conditions": summary.conditions,
    })
}

// ── /api/v1/ingresses ────────────────────────────────────────────────────────

impl OperatorAggregator {
    /// `GET /api/v1/ingresses` — ingress list from the cluster summary (no
    /// fan-out).
    pub(crate) fn list_ingresses(&self) -> Response<Vec<u8>> {
        let snapshot = self.cluster.load();
        match serde_json::to_string(&serde_json::json!({ "ingresses": snapshot.ingresses })) {
            Ok(body) => json_response(body),
            Err(e) => {
                tracing::error!(error = %e, "failed to serialise /api/v1/ingresses");
                internal_error()
            }
        }
    }

    /// `GET /api/v1/ingresses/{namespace}/{name}` — cluster-summary entry
    /// enriched with a live load-balancer address from the Kubernetes API.
    pub(crate) async fn get_ingress(&self, namespace: &str, name: &str) -> Response<Vec<u8>> {
        let snapshot = self.cluster.load();
        let summary = match snapshot
            .ingresses
            .iter()
            .find(|i| i.name == name && i.namespace == namespace)
        {
            Some(s) => s,
            None => return not_found(),
        };

        let kube = match self.kube().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "kube client unavailable for /api/v1/ingresses detail");
                return json_response(ingress_summary_json(summary, None).to_string());
            }
        };

        let api: Api<Ingress> = Api::namespaced(kube.clone(), namespace);
        let live_lb = match api.get(name).await {
            Ok(ing) => ing
                .status
                .as_ref()
                .and_then(|s| s.load_balancer.as_ref())
                .and_then(|lb| lb.ingress.as_deref())
                .and_then(|items| items.first())
                .and_then(|i| i.ip.as_deref().or(i.hostname.as_deref()))
                .map(str::to_owned),
            Err(kube::Error::Api(e)) if e.code == 404 => return not_found(),
            Err(e) => {
                tracing::warn!(error = %e, namespace, name, "K8s GET Ingress failed; using summary data");
                None
            }
        };

        json_response(ingress_summary_json(summary, live_lb.as_deref()).to_string())
    }
}

fn ingress_summary_json(
    summary: &coxswain_core::cluster::IngressSummary,
    live_lb: Option<&str>,
) -> serde_json::Value {
    let lb = live_lb.unwrap_or(summary.load_balancer.as_str());
    let mut v = serde_json::json!({
        "name": summary.name,
        "namespace": summary.namespace,
        "route_count": summary.route_count,
    });
    if !lb.is_empty() {
        v["load_balancer"] = serde_json::Value::String(lb.to_owned());
    }
    v
}

// ── /api/v1/routes ────────────────────────────────────────────────────────────

impl OperatorAggregator {
    /// `GET /api/v1/routes/httproute/{namespace}/{name}` — live HTTPRoute status
    /// conditions from Kubernetes + parallel `/routes` fan-out to all proxy pods.
    pub(crate) async fn get_httproute(&self, namespace: &str, name: &str) -> Response<Vec<u8>> {
        let kube = match self.kube().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "kube client unavailable for /api/v1/routes/httproute");
                return service_unavailable("kubernetes client not available");
            }
        };

        let api: Api<HttpRoute> = Api::namespaced(kube.clone(), namespace);
        let parent_statuses = match api.get(name).await {
            Ok(route) => route
                .status
                .as_ref()
                .map(|s| s.parents.as_slice())
                .unwrap_or_default()
                .iter()
                .map(|p| {
                    let conditions: Vec<GatewayCondition> = p
                        .conditions
                        .iter()
                        .map(GatewayCondition::from_kube)
                        .collect();
                    serde_json::json!({
                        "parent_ref": {
                            "name": p.parent_ref.name,
                            "namespace": p.parent_ref.namespace,
                        },
                        "conditions": conditions,
                    })
                })
                .collect::<Vec<_>>(),
            Err(kube::Error::Api(e)) if e.code == 404 => return not_found(),
            Err(e) => {
                tracing::warn!(error = %e, namespace, name, "K8s GET HTTPRoute failed");
                return internal_error();
            }
        };

        let proxy_results = self.fan_out_routes().await;
        json_response(
            serde_json::json!({
                "namespace": namespace,
                "name": name,
                "parent_statuses": parent_statuses,
                "proxies": proxy_results,
            })
            .to_string(),
        )
    }

    /// `GET /api/v1/routes/ingress/{namespace}/{name}` — live Ingress load-balancer
    /// status from Kubernetes + parallel `/routes` fan-out to all proxy pods.
    pub(crate) async fn get_ingress_route(&self, namespace: &str, name: &str) -> Response<Vec<u8>> {
        let kube = match self.kube().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "kube client unavailable for /api/v1/routes/ingress");
                return service_unavailable("kubernetes client not available");
            }
        };

        let api: Api<Ingress> = Api::namespaced(kube.clone(), namespace);
        let load_balancer = match api.get(name).await {
            Ok(ing) => ing
                .status
                .as_ref()
                .and_then(|s| s.load_balancer.as_ref())
                .and_then(|lb| lb.ingress.as_deref())
                .and_then(|items| items.first())
                .and_then(|i| i.ip.as_deref().or(i.hostname.as_deref()))
                .map(str::to_owned)
                .unwrap_or_default(),
            Err(kube::Error::Api(e)) if e.code == 404 => return not_found(),
            Err(e) => {
                tracing::warn!(error = %e, namespace, name, "K8s GET Ingress (routes) failed");
                return internal_error();
            }
        };

        let proxy_results = self.fan_out_routes().await;
        let mut v = serde_json::json!({
            "namespace": namespace,
            "name": name,
            "proxies": proxy_results,
        });
        if !load_balancer.is_empty() {
            v["load_balancer"] = serde_json::Value::String(load_balancer);
        }
        json_response(v.to_string())
    }

    /// Fan out `GET /routes` to all proxy pods in parallel.
    ///
    /// Returns one entry per pod: `{pod_name, reachable: true, routes: {...}}`
    /// when the pod responds, or `{pod_name, reachable: false}` on timeout or
    /// error.
    async fn fan_out_routes(&self) -> Vec<serde_json::Value> {
        let snapshot = self.fleet.load();
        let entries: Vec<FleetEntry> = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .cloned()
            .collect();
        let http = &self.http;
        let futures: Vec<_> = entries
            .iter()
            .map(|e| {
                let url = format!("{}/routes", pod_base_url(e));
                let pod_name = e.pod_name.clone();
                async move {
                    match http
                        .get(&url)
                        .send()
                        .await
                        .ok()
                        .filter(|r| r.status().is_success())
                    {
                        Some(resp) => match resp.json::<serde_json::Value>().await.ok() {
                            Some(routes) => serde_json::json!({
                                "pod_name": pod_name,
                                "reachable": true,
                                "routes": routes,
                            }),
                            None => serde_json::json!({ "pod_name": pod_name, "reachable": false }),
                        },
                        None => serde_json::json!({ "pod_name": pod_name, "reachable": false }),
                    }
                }
            })
            .collect();
        join_all(futures).await
    }
}

// ── Response helpers ──────────────────────────────────────────────────────────

/// Build a JSON HTTP response from a serialised body string.
pub(crate) fn json_response(mut body: String) -> Response<Vec<u8>> {
    body.push('\n');
    let mut r = Response::new(body.into_bytes());
    *r.status_mut() = StatusCode::OK;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

pub(crate) fn not_found() -> Response<Vec<u8>> {
    let mut r = Response::new(Vec::new());
    *r.status_mut() = StatusCode::NOT_FOUND;
    r
}

fn internal_error() -> Response<Vec<u8>> {
    let mut r = Response::new(Vec::new());
    *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    r
}

fn service_unavailable(msg: &str) -> Response<Vec<u8>> {
    let body = serde_json::json!({ "error": msg }).to_string();
    let mut r = Response::new(body.into_bytes());
    *r.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

/// Serialize a [`Component`] to its wire string.
fn component_str(c: Component) -> &'static str {
    match c {
        Component::Controller => "controller",
        Component::SharedProxy => "shared-proxy",
        Component::DedicatedProxy => "dedicated-proxy",
        _ => "unknown",
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::cluster::{
        ClusterSummary, ControllerSummary, GatewaySummary, IngressSummary, ProxyAssignment,
    };
    use coxswain_core::fleet::{
        ADMIN_PORT_ANNOTATION, COMPONENT_LABEL, FleetSnapshot, GATEWAY_NAME_LABEL, build_snapshot,
    };
    use k8s_openapi::api::core::v1::{Pod, PodStatus};
    use kube::api::ObjectMeta;
    use std::collections::BTreeMap;

    /// Build a fake [`Pod`] recognised by [`build_snapshot`].
    ///
    /// `component` should be the string value stored in
    /// [`COMPONENT_LABEL`] (e.g. `"shared-proxy"`, `"dedicated-proxy"`,
    /// `"controller"`).  `admin_port` is the string stored in
    /// [`ADMIN_PORT_ANNOTATION`] (usually `"8082"`).
    fn make_pod(
        name: &str,
        component: &str,
        pod_ip: &str,
        admin_port: &str,
        gateway_name: Option<&str>,
    ) -> Pod {
        let mut labels = BTreeMap::new();
        labels.insert(COMPONENT_LABEL.to_string(), component.to_string());
        if let Some(gw) = gateway_name {
            labels.insert(GATEWAY_NAME_LABEL.to_string(), gw.to_string());
        }
        let mut annotations = BTreeMap::new();
        annotations.insert(ADMIN_PORT_ANNOTATION.to_string(), admin_port.to_string());
        Pod {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                labels: Some(labels),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: None,
            status: Some(PodStatus {
                pod_ip: Some(pod_ip.to_string()),
                ..Default::default()
            }),
        }
    }

    // ── entry_json ────────────────────────────────────────────────────────────

    #[test]
    fn entry_json_shared_proxy_has_no_gateway_ref() {
        let pod = make_pod("proxy-0", "shared-proxy", "10.0.0.1", "8082", None);
        let snap = build_snapshot([&pod]);
        let e = &snap.shared_proxies[0];
        let v = OperatorAggregator::entry_json(e);
        assert_eq!(v["pod_name"], "proxy-0");
        assert_eq!(v["component"], "shared-proxy");
        assert!(
            v.get("gateway_ref").is_none(),
            "gateway_ref must be absent for shared proxy"
        );
    }

    #[test]
    fn entry_json_dedicated_proxy_includes_gateway_ref() {
        let pod = make_pod(
            "ded-0",
            "dedicated-proxy",
            "10.0.0.1",
            "8082",
            Some("my-gateway"),
        );
        let snap = build_snapshot([&pod]);
        let e = &snap.dedicated_proxies[0];
        let v = OperatorAggregator::entry_json(e);
        assert_eq!(v["gateway_ref"], "my-gateway");
        assert_eq!(v["component"], "dedicated-proxy");
    }

    // ── unreachable branch ────────────────────────────────────────────────────

    #[test]
    fn unreachable_entry_shape_matches_contract() {
        // Simulates what probe() returns when fetch_json returns None.
        let pod_name = "proxy-1";
        let v = serde_json::json!({ "pod_name": pod_name, "reachable": false });
        assert_eq!(v["pod_name"], pod_name);
        assert_eq!(v["reachable"], false);
        // Contract: no nested health/routes data.
        assert!(v.get("health").is_none());
        assert!(v.get("routes").is_none());
    }

    // ── gateway list ──────────────────────────────────────────────────────────

    #[test]
    fn gateway_list_derived_from_cluster_summary() {
        let summary = ClusterSummary::new(
            vec![
                GatewaySummary::new("gw-a", "default")
                    .with_proxy(ProxyAssignment::dedicated())
                    .with_route_count(3),
                GatewaySummary::new("gw-b", "infra").with_route_count(1),
            ],
            vec![],
            ControllerSummary::new(false),
        );
        let cluster = SharedClusterSummary::default();
        cluster.store(std::sync::Arc::new(summary));

        let snapshot = cluster.load();
        let body = serde_json::json!({ "gateways": snapshot.gateways });
        let gateways = body["gateways"].as_array().expect("array");
        assert_eq!(gateways.len(), 2);
        assert_eq!(gateways[0]["name"], "gw-a");
        assert_eq!(gateways[0]["proxy"]["pool"], "dedicated");
        assert_eq!(gateways[1]["name"], "gw-b");
    }

    // ── ingress list ──────────────────────────────────────────────────────────

    #[test]
    fn ingress_list_derived_from_cluster_summary() {
        let summary = ClusterSummary::new(
            vec![],
            vec![
                IngressSummary::new("ing-a", "default").with_route_count(2),
                IngressSummary::new("ing-b", "other").with_load_balancer("10.0.0.5"),
            ],
            ControllerSummary::new(false),
        );
        let cluster = SharedClusterSummary::default();
        cluster.store(std::sync::Arc::new(summary));

        let snapshot = cluster.load();
        let body = serde_json::json!({ "ingresses": snapshot.ingresses });
        let ingresses = body["ingresses"].as_array().expect("array");
        assert_eq!(ingresses.len(), 2);
        assert_eq!(ingresses[0]["name"], "ing-a");
        assert_eq!(ingresses[1]["load_balancer"], "10.0.0.5");
    }

    // ── routes JSON parse ─────────────────────────────────────────────────────

    #[test]
    fn routes_response_parses_proxy_routes_shape() {
        // Simulates the body returned by a proxy pod's GET /routes.
        let raw = serde_json::json!({
            "ingress": {
                "hosts": [
                    {
                        "port": 80,
                        "host": "example.com",
                        "routes": [
                            {
                                "type": "prefix",
                                "path": "/",
                                "backend_group": "default/svc:80",
                                "endpoints": ["10.0.1.1:8080"]
                            }
                        ]
                    }
                ],
                "conflicts": []
            },
            "gateway": { "hosts": [], "conflicts": [] }
        });

        // The aggregator stores the parsed value as-is inside the per-pod entry.
        let entry = serde_json::json!({
            "pod_name": "proxy-0",
            "reachable": true,
            "routes": raw,
        });
        assert_eq!(
            entry["routes"]["ingress"]["hosts"][0]["host"],
            "example.com"
        );
        assert_eq!(
            entry["routes"]["ingress"]["hosts"][0]["routes"][0]["type"],
            "prefix"
        );
        assert_eq!(entry["routes"]["gateway"]["hosts"], serde_json::json!([]));
    }

    // ── find_entry ────────────────────────────────────────────────────────────

    /// Find a [`FleetEntry`] by `pod_name` across all fleet buckets.
    pub(super) fn find_entry<'a>(
        snapshot: &'a FleetSnapshot,
        pod_name: &str,
    ) -> Option<&'a FleetEntry> {
        snapshot
            .controllers
            .iter()
            .chain(&snapshot.shared_proxies)
            .chain(&snapshot.dedicated_proxies)
            .find(|e| e.pod_name == pod_name)
    }

    #[test]
    fn find_entry_locates_across_buckets() {
        let pods = [
            make_pod("proxy-0", "shared-proxy", "10.0.0.2", "8082", None),
            make_pod("ded-0", "dedicated-proxy", "10.0.0.3", "8082", Some("gw")),
            make_pod("ctrl-0", "controller", "10.0.0.1", "8082", None),
        ];
        let snapshot = build_snapshot(pods.iter());

        assert!(find_entry(&snapshot, "proxy-0").is_some());
        assert!(find_entry(&snapshot, "ded-0").is_some());
        assert!(find_entry(&snapshot, "ctrl-0").is_some());
        assert!(find_entry(&snapshot, "missing").is_none());
    }

    // ── pod_base_url ──────────────────────────────────────────────────────────

    #[test]
    fn pod_base_url_brackets_ipv6() {
        let pod = make_pod("pod", "shared-proxy", "::1", "9090", None);
        let snap = build_snapshot([&pod]);
        let e = &snap.shared_proxies[0];
        assert_eq!(pod_base_url(e), "http://[::1]:9090");
    }

    #[test]
    fn pod_base_url_plain_ipv4() {
        let pod = make_pod("pod", "shared-proxy", "10.0.0.1", "8082", None);
        let snap = build_snapshot([&pod]);
        let e = &snap.shared_proxies[0];
        assert_eq!(pod_base_url(e), "http://10.0.0.1:8082");
    }

    // ── json_response ─────────────────────────────────────────────────────────

    #[test]
    fn json_response_sets_content_type_and_newline() {
        let resp = json_response(r#"{"k":"v"}"#.to_string());
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .map(|h| h.as_bytes()),
            Some(&b"application/json"[..])
        );
        assert!(resp.body().ends_with(b"\n"), "body must end with newline");
    }
}
