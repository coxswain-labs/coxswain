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

use coxswain_core::fleet::{Component, FleetEntry, FleetSnapshot, SharedFleet};
use http::{HeaderValue, Response, StatusCode, header};
use kube::Client;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OnceCell, Semaphore};

use coxswain_core::cluster::SharedClusterSummary;
use coxswain_core::dedicated_registry::DedicatedRoutingRegistry;
use coxswain_core::node_registry::SharedNodeRegistry;
use coxswain_core::routing::{SharedGatewayRoutingTable, SharedIngressRoutingTable};

mod controllers;
mod gateways;
mod ingresses;
mod manifests;
mod pod_logs;
mod problems;
mod proxies;
mod routing;
mod topology;

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
    /// Connected proxy node registry, populated by the discovery server.
    /// `None` in dev and proxy roles (discovery not active).
    node_registry: Option<SharedNodeRegistry>,
    /// The controller's own shared-pool Ingress routing table — the same
    /// [`Shared`](coxswain_core::Shared) cell fed to the discovery server and
    /// pushed to every `SharedPool`-scoped proxy. Backs the local re-source of
    /// `fleet/proxies/{name}/routes|facets` (#537) for shared-pool pods,
    /// instead of an HTTP fan-out to the pod.
    ingress_routes: SharedIngressRoutingTable,
    /// The controller's own shared-pool Gateway-API routing table. See
    /// [`Self::ingress_routes`].
    gateway_routes: SharedGatewayRoutingTable,
    /// Per-Gateway dedicated routing snapshots, keyed by the owning Gateway's
    /// [`ObjectKey`](coxswain_core::ownership::ObjectKey). Backs the local
    /// re-source of `fleet/proxies/{name}/routes|facets` for dedicated-proxy
    /// pods. A Gateway absent from the registry (e.g. a cutover still in
    /// flight) reads as an empty routing table, not an error.
    dedicated_registry: DedicatedRoutingRegistry,
    /// Kubernetes client, initialised lazily on the first K8s-backed request.
    kube: OnceCell<Client>,
    /// Apiserver GitVersion (e.g. `v1.31.2`), fetched once from the `/version`
    /// endpoint and cached for the controller's lifetime — the server version
    /// is static between cluster upgrades, so it is never re-queried.
    k8s_version: OnceCell<String>,
    /// Bounds concurrent `/api/v1/pods/{name}/logs` streams. Each live stream
    /// holds one kube connection on the controller; the cap stops a few open
    /// tabs (or stuck clients) from piling them up.
    log_permits: Arc<Semaphore>,
}

/// Maximum number of concurrent pod-log streams the controller will relay.
const MAX_CONCURRENT_LOG_STREAMS: usize = 8;

impl OperatorAggregator {
    /// Construct an aggregator with the given fleet, cluster, node-registry,
    /// and routing-table handles.
    ///
    /// `node_registry` is `Some` on controller roles (discovery is active) and
    /// `None` on dev/proxy roles. `ingress_routes`/`gateway_routes`/
    /// `dedicated_registry` are the same cells the controller feeds to the
    /// discovery server (#537) — this aggregator never fans out to a proxy
    /// pod to answer "what does it serve", it reads its own copy of what it
    /// pushed. Installs the `ring` rustls crypto provider (idempotent) so the
    /// reqwest client can be built; the remaining fan-out targets (pod
    /// health/logs) are plain HTTP and TLS is never exercised at request time.
    #[must_use]
    pub fn new(
        fleet: SharedFleet,
        cluster: SharedClusterSummary,
        node_registry: Option<SharedNodeRegistry>,
        ingress_routes: SharedIngressRoutingTable,
        gateway_routes: SharedGatewayRoutingTable,
        dedicated_registry: DedicatedRoutingRegistry,
    ) -> Self {
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
            node_registry,
            ingress_routes,
            gateway_routes,
            dedicated_registry,
            kube: OnceCell::new(),
            k8s_version: OnceCell::new(),
            log_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_LOG_STREAMS)),
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

    /// Return the Kubernetes apiserver GitVersion (e.g. `v1.31.2`), fetched
    /// once from the `/version` endpoint and cached for the controller's
    /// lifetime.
    ///
    /// Returns `None` if the client can't be initialised or the apiserver is
    /// unreachable: the `/api/v1/cluster` handler omits the field rather than
    /// failing the whole response, and a later request retries (a failed
    /// fetch is not cached). The server version is static between cluster
    /// upgrades, so the cached value is never re-queried once obtained.
    pub(crate) async fn kubernetes_version(&self) -> Option<&str> {
        self.k8s_version
            .get_or_try_init(|| async {
                let info = self.kube().await?.apiserver_version().await?;
                Ok::<_, kube::Error>(info.git_version)
            })
            .await
            .map_err(|e| tracing::warn!(error = %e, "Failed to fetch Kubernetes apiserver version"))
            .ok()
            .map(String::as_str)
    }
}

// ── URL helpers ───────────────────────────────────────────────────────────────

/// Build an admin base URL for `entry`, handling IPv6 bracket notation.
pub(super) fn pod_base_url(entry: &FleetEntry) -> String {
    match entry.pod_ip {
        IpAddr::V4(_) => format!("http://{}:{}", entry.pod_ip, entry.admin_port),
        IpAddr::V6(_) => format!("http://[{}]:{}", entry.pod_ip, entry.admin_port),
    }
}

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

// ── Fan-out helpers ───────────────────────────────────────────────────────────

impl OperatorAggregator {
    /// Perform a single `GET {url}` and deserialise the body as JSON.
    ///
    /// Returns `None` on any network error, non-2xx status, or parse
    /// failure — the caller maps `None` to `"reachable": false`.
    pub(super) async fn fetch_json(&self, url: &str) -> Option<serde_json::Value> {
        let resp = self.http.get(url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json::<serde_json::Value>().await.ok()
    }

    /// Build the base JSON object for a fleet entry.
    pub(super) fn entry_json(entry: &FleetEntry) -> serde_json::Value {
        let component = component_str(entry.component);
        let mut obj = serde_json::json!({
            "pod_name": entry.pod_name,
            "pod_namespace": entry.pod_namespace,
            "pod_ip": entry.pod_ip.to_string(),
            "admin_port": entry.admin_port,
            "component": component,
        });
        if let Some(ref gw) = entry.gateway_ref {
            obj["gateway_ref"] = serde_json::Value::String(gw.clone());
        }
        // Pod runtime, straight off the fleet snapshot's Pod (present even when the
        // pod is unreachable — restart count is exactly what you want then).
        obj["restarts"] = serde_json::json!(entry.restarts);
        if let Some(ref node) = entry.node {
            obj["node"] = serde_json::Value::String(node.clone());
        }
        if let Some(ref phase) = entry.phase {
            obj["phase"] = serde_json::Value::String(phase.clone());
        }
        if let Some(ref created) = entry.created_at {
            obj["created_at"] = serde_json::Value::String(created.clone());
        }
        obj
    }
}

/// Attach a coarse health rollup to a fleet-entry JSON from that pod's
/// `/api/v1/health` body.
///
/// List endpoints already fetch each pod's `/api/v1/health` for liveness; rolling
/// it down here lets the browser render per-pod health (Fleet chips, Dashboard
/// "degraded pods") without a second fan-out. Sets `health` (`"ready"` or
/// `"degraded"`) and `degraded_checks` (the `"subsystem/check"` names that aren't
/// ready) on the entry.
pub(super) fn attach_health_rollup(entry: &mut serde_json::Value, health_body: &serde_json::Value) {
    let degraded = non_ready_checks(health_body);
    let state = if degraded.is_empty() {
        "ready"
    } else {
        "degraded"
    };
    entry["health"] = serde_json::Value::String(state.to_owned());
    entry["degraded_checks"] = serde_json::Value::from(degraded);
}

/// Collect the `"subsystem/check"` identifiers whose state is not `ready` from a
/// `/api/v1/health` body.
///
/// Anything other than the literal `"ready"` state (`degraded`, `pending`,
/// `failed`) counts as non-ready — the UI surfaces it amber and defers the
/// reason to the pod's own health view or logs. A subsystem with no checks
/// contributes its own name when its aggregate state isn't ready.
pub(super) fn non_ready_checks(health_body: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(subsystems) = health_body.get("subsystems").and_then(|v| v.as_object()) else {
        return out;
    };
    for (sub_name, sub) in subsystems {
        let mut had_check = false;
        if let Some(checks) = sub.get("checks").and_then(|v| v.as_object()) {
            for (check_name, check) in checks {
                had_check = true;
                if check.get("state").and_then(serde_json::Value::as_str) != Some("ready") {
                    out.push(format!("{sub_name}/{check_name}"));
                }
            }
        }
        let agg_ready = sub
            .get("state")
            .and_then(|s| s.get("state"))
            .and_then(serde_json::Value::as_str)
            == Some("ready");
        if !had_check && !agg_ready {
            out.push(sub_name.clone());
        }
    }
    out
}

// ── Response helpers ──────────────────────────────────────────────────────────

/// Build an HTML HTTP response from a static body string.
///
/// Used by `AdminServer::ui_response` to serve the embedded operator UI. The UI
/// is a single inlined document served from a stable path (`/`) but rebuilt on
/// every deploy, so it is sent `no-store` — a cached copy would silently mask a
/// new rollout. The bundle is tiny and same-origin, so there is no caching
/// benefit to trade away.
pub(crate) fn html_response(body: &'static str) -> Response<Vec<u8>> {
    let mut r = Response::new(body.as_bytes().to_vec());
    *r.status_mut() = StatusCode::OK;
    let headers = r.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    r
}

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

pub(super) fn internal_error() -> Response<Vec<u8>> {
    let mut r = Response::new(Vec::new());
    *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    r
}

pub(super) fn service_unavailable(msg: &str) -> Response<Vec<u8>> {
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
pub(super) fn component_str(c: Component) -> &'static str {
    match c {
        Component::Controller => "controller",
        Component::SharedProxy => "shared-proxy",
        Component::DedicatedProxy => "dedicated-proxy",
        _ => "unknown",
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use coxswain_core::fleet::{
        ADMIN_PORT_ANNOTATION, COMPONENT_LABEL, GATEWAY_NAME_LABEL, SharedFleet, build_snapshot,
    };
    use k8s_openapi::api::core::v1::{Pod, PodStatus};
    use kube::api::ObjectMeta;
    use std::collections::BTreeMap;
    use tokio::sync::OnceCell;

    /// Build a fake [`Pod`] recognised by [`build_snapshot`].
    ///
    /// `component` should be the string value stored in
    /// [`COMPONENT_LABEL`] (e.g. `"shared-proxy"`, `"dedicated-proxy"`,
    /// `"controller"`).  `admin_port` is the string stored in
    /// [`ADMIN_PORT_ANNOTATION`] (usually `"8082"`).
    pub(crate) fn make_pod(
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

    /// Build an [`OperatorAggregator`] with a short (200 ms) timeout for tests.
    ///
    /// Struct literal is allowed here because tests live inside the defining
    /// crate (`#[non_exhaustive]` only blocks external-crate construction).
    /// Routing tables/registry always default to empty.
    pub(crate) fn make_agg(
        fleet: SharedFleet,
        cluster: SharedClusterSummary,
    ) -> OperatorAggregator {
        make_agg_full(fleet, cluster, None)
    }

    /// Build an [`OperatorAggregator`] with a populated [`SharedNodeRegistry`]
    /// for topology unit tests.
    pub(crate) fn make_agg_with_registry(
        fleet: SharedFleet,
        cluster: SharedClusterSummary,
        node_registry: SharedNodeRegistry,
    ) -> OperatorAggregator {
        make_agg_full(fleet, cluster, Some(node_registry))
    }

    fn make_agg_full(
        fleet: SharedFleet,
        cluster: SharedClusterSummary,
        node_registry: Option<SharedNodeRegistry>,
    ) -> OperatorAggregator {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(200))
            .build()
            .unwrap_or_else(|e| panic!("invariant: {e}"));
        OperatorAggregator {
            http,
            fleet,
            cluster,
            node_registry,
            ingress_routes: SharedIngressRoutingTable::new(),
            gateway_routes: SharedGatewayRoutingTable::new(),
            dedicated_registry: DedicatedRoutingRegistry::new(),
            kube: OnceCell::new(),
            k8s_version: OnceCell::new(),
            log_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_LOG_STREAMS)),
        }
    }

    /// Build a [`SharedFleet`] pre-loaded with the given pods.
    pub(crate) fn fleet_with(pods: impl IntoIterator<Item = Pod>) -> SharedFleet {
        let pods: Vec<Pod> = pods.into_iter().collect();
        let snap = build_snapshot(pods.iter());
        let fleet = SharedFleet::default();
        fleet.store(std::sync::Arc::new(snap));
        fleet
    }

    /// Start a minimal HTTP/1.1 server on a random loopback port that always
    /// responds 200 with `body`. Returns the bound port.
    ///
    /// Each accepted connection is handled in its own task so concurrent
    /// fan-out probes from `list_proxies` work correctly.
    pub(crate) async fn start_mock_http(body: &'static str) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("invariant: {e}"));
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = stream.read(&mut buf).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body,
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        port
    }

    /// Bind an ephemeral port and immediately release it so the OS reclaims it.
    ///
    /// Any connection attempt after release receives ECONNREFUSED — the
    /// expected outcome for the `reachable: false` path.
    pub(crate) fn refused_port() -> u16 {
        let l =
            std::net::TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("invariant: {e}"));
        let port = l.local_addr().unwrap().port();
        drop(l);
        port
    }

    // ── find_entry ────────────────────────────────────────────────────────────

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

    #[test]
    fn entry_json_controller_component_field() {
        let pod = make_pod("ctrl-0", "controller", "10.0.0.1", "8082", None);
        let snap = build_snapshot([&pod]);
        let e = &snap.controllers[0];
        let v = OperatorAggregator::entry_json(e);
        assert_eq!(v["component"], "controller");
        assert_eq!(v["pod_name"], "ctrl-0");
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

    // ── health rollup ─────────────────────────────────────────────────────────

    #[test]
    fn health_rollup_ready_when_all_checks_ready() {
        let body = serde_json::json!({
            "version": "0.1.0",
            "subsystems": {
                "controller": { "state": { "state": "ready" },
                    "checks": { "ingress": { "state": "ready" }, "service": { "state": "ready" } } },
                "proxy": { "state": { "state": "ready" },
                    "checks": { "routing_table_loaded": { "state": "ready" } } }
            }
        });
        assert!(non_ready_checks(&body).is_empty());
        let mut entry = serde_json::json!({});
        attach_health_rollup(&mut entry, &body);
        assert_eq!(entry["health"], "ready");
        assert_eq!(entry["degraded_checks"], serde_json::json!([]));
    }

    #[test]
    fn health_rollup_names_non_ready_checks_as_subsystem_slash_check() {
        let body = serde_json::json!({
            "subsystems": {
                "controller": { "state": { "state": "failed" },
                    "checks": {
                        "ingress": { "state": "ready" },
                        "reflector": { "state": "failed", "reason": "watch desync" }
                    } }
            }
        });
        let degraded = non_ready_checks(&body);
        assert_eq!(degraded, vec!["controller/reflector".to_owned()]);
        let mut entry = serde_json::json!({});
        attach_health_rollup(&mut entry, &body);
        assert_eq!(entry["health"], "degraded");
        assert_eq!(
            entry["degraded_checks"],
            serde_json::json!(["controller/reflector"])
        );
    }

    #[test]
    fn health_rollup_falls_back_to_subsystem_name_when_no_checks() {
        let body = serde_json::json!({
            "subsystems": {
                "proxy": { "state": { "state": "pending" }, "checks": {} }
            }
        });
        assert_eq!(non_ready_checks(&body), vec!["proxy".to_owned()]);
    }

    // ── response helpers ──────────────────────────────────────────────────────

    #[test]
    fn html_response_sets_content_type_and_body() {
        let resp = html_response("<html><body>hi</body></html>");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .map(|h| h.as_bytes()),
            Some(&b"text/html; charset=utf-8"[..])
        );
        // The UI is rebuilt every deploy from a stable path, so it must never be
        // cached — a stale copy would silently mask a rollout.
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .map(|h| h.as_bytes()),
            Some(&b"no-store, no-cache, must-revalidate"[..])
        );
        assert_eq!(resp.body(), b"<html><body>hi</body></html>");
        // No trailing newline (unlike json_response).
        assert!(!resp.body().ends_with(b"\n"));
    }

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

    #[test]
    fn not_found_returns_404() {
        assert_eq!(not_found().status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn internal_error_returns_500() {
        assert_eq!(internal_error().status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn service_unavailable_returns_503_with_error_field() {
        let resp = service_unavailable("kube unavailable");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["error"], "kube unavailable");
    }
}
