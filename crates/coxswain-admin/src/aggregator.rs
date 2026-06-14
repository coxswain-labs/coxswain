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
use crate::logs::{self, LogQuery};
use coxswain_core::cluster::{ClusterSummary, GatewayCondition, SharedClusterSummary};
use coxswain_core::fleet::{Component, FleetEntry, FleetSnapshot, SharedFleet};
use futures::future::join_all;
use http::{HeaderValue, Response, StatusCode, header};
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::networking::v1::Ingress;
use kube::{Api, Client};
use pingora_core::protocols::http::ServerSession;
use pingora_core::server::ShutdownWatch;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OnceCell, Semaphore};

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
    /// Bounds concurrent `/api/v1/pods/{name}/logs` streams. Each live stream
    /// holds one kube connection on the controller; the cap stops a few open
    /// tabs (or stuck clients) from piling them up.
    log_permits: Arc<Semaphore>,
}

/// Maximum number of concurrent pod-log streams the controller will relay.
const MAX_CONCURRENT_LOG_STREAMS: usize = 8;

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
}

// ── URL helpers ───────────────────────────────────────────────────────────────

/// Build an admin base URL for `entry`, handling IPv6 bracket notation.
fn pod_base_url(entry: &FleetEntry) -> String {
    match entry.pod_ip {
        IpAddr::V4(_) => format!("http://{}:{}", entry.pod_ip, entry.admin_port),
        IpAddr::V6(_) => format!("http://[{}]:{}", entry.pod_ip, entry.admin_port),
    }
}

/// Find a [`FleetEntry`] by `pod_name` across all fleet buckets.
fn find_entry<'a>(snapshot: &'a FleetSnapshot, pod_name: &str) -> Option<&'a FleetEntry> {
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
fn attach_health_rollup(entry: &mut serde_json::Value, health_body: &serde_json::Value) {
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
fn non_ready_checks(health_body: &serde_json::Value) -> Vec<String> {
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
        let probes: Vec<_> = entries
            .iter()
            .map(|e| async move {
                // The liveness probe already returns the pod's full health body;
                // parse it (rather than discard it) so the entry carries a health
                // rollup without a second per-pod round-trip.
                let url = format!("{}/api/v1/health", pod_base_url(e));
                match self.fetch_json(&url).await {
                    Some(body) => {
                        let mut v = Self::entry_json(e);
                        v["reachable"] = serde_json::Value::Bool(true);
                        attach_health_rollup(&mut v, &body);
                        v
                    }
                    // Carry the full entry (component, namespace, …) even when
                    // unreachable so the UI can still bucket the pod by component
                    // and label it; "unreachable" is a probe outcome, not a loss
                    // of fleet-snapshot identity.
                    None => {
                        let mut v = Self::entry_json(e);
                        v["reachable"] = serde_json::Value::Bool(false);
                        v
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
    /// `GET /api/v1/controllers` — all controller pods with liveness + leadership.
    ///
    /// Probes each controller's `/api/v1/cluster` rather than `/api/v1/health`:
    /// it doubles as a liveness check (200 ⇒ reachable) and carries that pod's
    /// live `controller.leader` flag, so the response can report `is_leader` per
    /// pod. Without it the UI cannot tell who holds the lease and wrongly reads
    /// a healthy single-leader cluster as having no elected leader.
    pub(crate) async fn list_controllers(&self) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entries: Vec<FleetEntry> = snapshot.controllers.to_vec();
        let probes: Vec<_> = entries
            .iter()
            .map(|e| async move {
                let cluster_url = format!("{}/api/v1/cluster", pod_base_url(e));
                match self.fetch_json(&cluster_url).await {
                    Some(cluster) => {
                        let is_leader = cluster["controller"]["leader"].as_bool().unwrap_or(false);
                        let mut v = Self::entry_json(e);
                        v["reachable"] = serde_json::Value::Bool(true);
                        v["is_leader"] = serde_json::Value::Bool(is_leader);
                        // Second hop for subsystem health: the cluster summary
                        // carries leadership but not subsystem state. Controllers
                        // are few, so the extra fetch is cheap.
                        let health_url = format!("{}/api/v1/health", pod_base_url(e));
                        if let Some(body) = self.fetch_json(&health_url).await {
                            attach_health_rollup(&mut v, &body);
                        }
                        v
                    }
                    // Keep the full entry (namespace, …) on the unreachable
                    // path too, so the card still renders its identity.
                    None => {
                        let mut v = Self::entry_json(e);
                        v["reachable"] = serde_json::Value::Bool(false);
                        v
                    }
                }
            })
            .collect();
        let results = join_all(probes).await;
        json_response(serde_json::json!({ "controllers": results }).to_string())
    }

    /// `GET /api/v1/controllers/{pod-name}` — single controller pod info.
    ///
    /// Probes `/api/v1/cluster` (not `/health`): it doubles as a liveness check
    /// and carries this pod's live `controller.leader` flag, so the controller
    /// detail page can show leader/standby without a second call — mirroring
    /// [`Self::list_controllers`].
    pub(crate) async fn get_controller(&self, pod_name: &str) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let Some(entry) = snapshot.controllers.iter().find(|e| e.pod_name == pod_name) else {
            return not_found();
        };
        let url = format!("{}/api/v1/cluster", pod_base_url(entry));
        match self.fetch_json(&url).await {
            Some(cluster) => {
                let is_leader = cluster["controller"]["leader"].as_bool().unwrap_or(false);
                let mut v = Self::entry_json(entry);
                v["reachable"] = serde_json::Value::Bool(true);
                v["is_leader"] = serde_json::Value::Bool(is_leader);
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
        // Fetch the live Gateway object once; use it for both conditions and
        // listener detail so we only make one K8s call.
        let (conditions, listeners) = match api.get(name).await {
            Ok(gw) => {
                let conds = gw
                    .status
                    .as_ref()
                    .and_then(|s| s.conditions.as_deref())
                    .unwrap_or_default()
                    .iter()
                    .map(GatewayCondition::from_kube)
                    .collect::<Vec<_>>();

                // Join spec listeners with per-listener status (attached-route
                // count).  Status may be absent before the first reconcile.
                let status_attached: std::collections::HashMap<&str, i32> = gw
                    .status
                    .as_ref()
                    .and_then(|s| s.listeners.as_deref())
                    .unwrap_or_default()
                    .iter()
                    .map(|l| (l.name.as_str(), l.attached_routes))
                    .collect();

                let lsnrs: Vec<serde_json::Value> = gw
                    .spec
                    .listeners
                    .iter()
                    .map(|l| {
                        let attached = status_attached.get(l.name.as_str()).copied().unwrap_or(0);
                        serde_json::json!({
                            "name": l.name,
                            "port": l.port,
                            "protocol": l.protocol,
                            "tls_enabled": l.tls.is_some(),
                            "attached_routes": attached,
                        })
                    })
                    .collect();

                (conds, lsnrs)
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {
                // Deleted since the last cluster-summary rebuild.
                return not_found();
            }
            Err(e) => {
                tracing::warn!(error = %e, namespace, name, "K8s GET Gateway failed; using summary conditions");
                (summary.conditions.clone(), Vec::new())
            }
        };

        let attached_routes_list = self.list_attached_httproutes(kube, namespace, name).await;

        let mut v = gateway_summary_json(summary, &snapshot);
        v["conditions"] = serde_json::to_value(&conditions).unwrap_or(serde_json::Value::Null);
        v["listeners"] = serde_json::Value::Array(listeners);
        v["attached_routes_list"] = serde_json::Value::Array(attached_routes_list);
        json_response(v.to_string())
    }

    /// List all HTTPRoutes cluster-wide and return those whose `parentRefs`
    /// reference the given Gateway (`gw_namespace/gw_name`).
    ///
    /// A `parentRef` is considered to target the Gateway when its `name`
    /// matches `gw_name` and its effective namespace (the `namespace` field
    /// if present, otherwise the route's own namespace) matches `gw_namespace`.
    /// An absent `kind` or `group` is treated as `Gateway` /
    /// `gateway.networking.k8s.io` per the Gateway API spec.
    ///
    /// On any Kubernetes error the list degrades gracefully to an empty slice.
    async fn list_attached_httproutes(
        &self,
        kube: &Client,
        gw_namespace: &str,
        gw_name: &str,
    ) -> Vec<serde_json::Value> {
        let api: Api<gw_types::HttpRoute> = Api::all(kube.clone());
        let routes = match api.list(&kube::api::ListParams::default()).await {
            Ok(list) => list,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    gw_namespace,
                    gw_name,
                    "K8s list HTTPRoutes failed; attached_routes_list will be empty"
                );
                return Vec::new();
            }
        };

        // De-dup: a route can have multiple parentRefs targeting the same
        // Gateway (different sections); count the route once, not once per ref.
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();

        for route in &routes {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or_default();
            let route_name = match route.metadata.name.as_deref() {
                Some(n) => n,
                None => continue,
            };

            // Skip if we've already recorded this route (multiple matching parentRefs).
            if !seen.insert((route_ns, route_name)) {
                continue;
            }

            let refs = route.spec.parent_refs.as_deref().unwrap_or_default();

            let attaches = refs.iter().any(|p| {
                // Absent `kind` defaults to "Gateway"; absent `group` defaults to
                // "gateway.networking.k8s.io" — both are implicitly our target.
                let kind_ok = p.kind.as_deref().is_none_or(|k| k == "Gateway");
                let effective_ns = p.namespace.as_deref().unwrap_or(route_ns);
                kind_ok && p.name == gw_name && effective_ns == gw_namespace
            });

            if attaches {
                result.push(serde_json::json!({
                    "kind": "HTTPRoute",
                    "namespace": route_ns,
                    "name": route_name,
                }));
            }
        }

        result
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

// ── /api/v1/manifests ────────────────────────────────────────────────────────

impl OperatorAggregator {
    /// `GET /api/v1/manifests/{kind}/{namespace}/{name}` — raw Kubernetes
    /// manifest for the named resource, returned as JSON.
    ///
    /// `kind` ∈ `httproute` | `ingress` | `gateway` | `pod`.
    ///
    /// The response is the verbatim object returned by the Kubernetes API
    /// server, including `managedFields` and `status`. The operator UI
    /// converts it to YAML client-side for display in the manifest popup.
    ///
    /// # Errors
    ///
    /// Returns 400 for an unrecognised kind, 404 when the resource does not
    /// exist, 503 when the Kubernetes client cannot be initialised, and 500
    /// for other Kubernetes errors.
    pub(crate) async fn get_manifest(
        &self,
        kind: &str,
        namespace: &str,
        name: &str,
    ) -> Response<Vec<u8>> {
        let kube = match self.kube().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "kube client unavailable for /api/v1/manifests");
                return service_unavailable("kubernetes client not available");
            }
        };

        match kind {
            "httproute" => {
                let api: Api<gw_types::HttpRoute> = Api::namespaced(kube.clone(), namespace);
                match api.get(name).await {
                    Ok(obj) => match serde_json::to_string(&obj) {
                        Ok(body) => json_response(body),
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to serialise HTTPRoute manifest");
                            internal_error()
                        }
                    },
                    Err(kube::Error::Api(e)) if e.code == 404 => not_found(),
                    Err(e) => {
                        tracing::warn!(error = %e, namespace, name, "K8s GET HTTPRoute manifest failed");
                        internal_error()
                    }
                }
            }
            "gateway" => {
                let api: Api<gw_types::v::gateways::Gateway> =
                    Api::namespaced(kube.clone(), namespace);
                match api.get(name).await {
                    Ok(obj) => match serde_json::to_string(&obj) {
                        Ok(body) => json_response(body),
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to serialise Gateway manifest");
                            internal_error()
                        }
                    },
                    Err(kube::Error::Api(e)) if e.code == 404 => not_found(),
                    Err(e) => {
                        tracing::warn!(error = %e, namespace, name, "K8s GET Gateway manifest failed");
                        internal_error()
                    }
                }
            }
            "ingress" => {
                let api: Api<Ingress> = Api::namespaced(kube.clone(), namespace);
                match api.get(name).await {
                    Ok(obj) => match serde_json::to_string(&obj) {
                        Ok(body) => json_response(body),
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to serialise Ingress manifest");
                            internal_error()
                        }
                    },
                    Err(kube::Error::Api(e)) if e.code == 404 => not_found(),
                    Err(e) => {
                        tracing::warn!(error = %e, namespace, name, "K8s GET Ingress manifest failed");
                        internal_error()
                    }
                }
            }
            "pod" => {
                let api: Api<Pod> = Api::namespaced(kube.clone(), namespace);
                match api.get(name).await {
                    Ok(obj) => match serde_json::to_string(&obj) {
                        Ok(body) => json_response(body),
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to serialise Pod manifest");
                            internal_error()
                        }
                    },
                    Err(kube::Error::Api(e)) if e.code == 404 => not_found(),
                    Err(e) => {
                        tracing::warn!(error = %e, namespace, name, "K8s GET Pod manifest failed");
                        internal_error()
                    }
                }
            }
            _ => {
                let body =
                    serde_json::json!({ "error": format!("unknown kind: {kind}") }).to_string();
                let mut r = Response::new(body.into_bytes());
                *r.status_mut() = StatusCode::BAD_REQUEST;
                r.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                r
            }
        }
    }
}

// ── /api/v1/problems ──────────────────────────────────────────────────────────

impl OperatorAggregator {
    /// `GET /api/v1/problems` — cluster-wide routing problems derived from
    /// fan-out to all proxy `/routes` endpoints.
    ///
    /// Returns a single snapshot:
    /// ```json
    /// {
    ///   "conflicts": [{ "host", "path", "rejected_group", "kind", "pods": ["…"] }],
    ///   "dead_routes": [{ "host", "path", "backend_group", "kind", "pods": ["…"] }]
    /// }
    /// ```
    ///
    /// Conflicts are route-table collisions where a second claim for the same
    /// `(host, path)` was rejected. `dead_routes` are entries present in the
    /// routing table but with zero endpoints — the route is accepted but
    /// backends are unavailable (Service has no ready Pods). `kind`
    /// (`"ingress"`/`"gateway"`) tags which routing surface owns the problem so
    /// the UI can attribute it to the right resource.
    ///
    /// Shared proxies carry an identical table: the same conflict appears once
    /// per proxy. Results are de-duplicated by `(host, path, rejected_group)`
    /// and `(host, path, backend_group)` respectively, with `pods` listing
    /// which proxies reported that problem.
    pub(crate) async fn list_problems(&self) -> Response<Vec<u8>> {
        let raw = self.fan_out_routes().await;
        json_response(aggregate_problems(&raw).to_string())
    }
}

// ── /api/v1/pods/{name}/logs ──────────────────────────────────────────────────

impl OperatorAggregator {
    /// Relay a coxswain pod's logs to the client as a chunked NDJSON stream.
    ///
    /// Unlike the buffered endpoints, this writes its full response (header and
    /// body, including error statuses) directly on `session` — it is dispatched
    /// out of the streaming arm of `process_new_http`, past the buffered
    /// pipeline. The flow is: acquire a concurrency permit (→ 429 when the cap
    /// is saturated); resolve `pod_name` to its namespace from the trusted fleet
    /// snapshot (→ 404 when unknown — never the request URL, so an arbitrary
    /// cluster pod can't be tailed); obtain the kube client (→ 503 on failure);
    /// then delegate the byte pump to [`logs::run_until_shutdown`]. The permit is
    /// released by RAII when the stream ends.
    pub(crate) async fn stream_logs(
        &self,
        pod_name: &str,
        query: &str,
        session: &mut ServerSession,
        shutdown: &ShutdownWatch,
    ) {
        let Ok(_permit) = Arc::clone(&self.log_permits).try_acquire_owned() else {
            logs::write_status(
                session,
                StatusCode::TOO_MANY_REQUESTS,
                "too many concurrent log streams",
            )
            .await;
            return;
        };

        // Resolve namespace from the fleet, not the URL — this is what scopes
        // the endpoint to pods coxswain already tracks.
        let namespace = {
            let snapshot = self.fleet.load();
            match find_entry(&snapshot, pod_name) {
                Some(entry) => entry.pod_namespace.clone(),
                None => {
                    logs::write_status(session, StatusCode::NOT_FOUND, "pod not found").await;
                    return;
                }
            }
        };

        let kube = match self.kube().await {
            Ok(c) => c.clone(),
            Err(e) => {
                tracing::warn!(error = %e, "kube client unavailable for /api/v1/pods/.../logs");
                logs::write_status(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "kubernetes client not available",
                )
                .await;
                return;
            }
        };

        let query = LogQuery::parse(query);
        logs::run_until_shutdown(&kube, &namespace, pod_name, &query, session, shutdown).await;
    }
}

/// De-dupe and aggregate fanned-out proxy `/routes` results into the
/// `/api/v1/problems` payload. Split out from [`OperatorAggregator::list_problems`]
/// so it is unit-testable without a live fan-out.
///
/// Shared proxies carry an identical table, so each problem is keyed by
/// `(host, path, group, kind)` and de-duped across pods; `pods` lists which
/// proxies reported it. Each problem also carries `route: {kind, namespace, name}`
/// — the source Ingress/HTTPRoute identity — so the operator UI can deep-link the
/// card to that route in the Route Inspector. (For a conflict, this is the
/// rejected/shadowed route.)
fn aggregate_problems(raw: &[serde_json::Value]) -> serde_json::Value {
    // (host, path, group, kind) → (route_ns, route_name, pods). BTreeMap for
    // stable output ordering.
    type ProblemMap =
        std::collections::BTreeMap<(String, String, String, String), (String, String, Vec<String>)>;
    let mut conflicts: ProblemMap = std::collections::BTreeMap::new();
    let mut dead_routes: ProblemMap = std::collections::BTreeMap::new();

    for proxy in raw {
        let pod_name = proxy["pod_name"].as_str().unwrap_or("").to_owned();
        if !proxy["reachable"].as_bool().unwrap_or(false) {
            continue;
        }
        let routes = &proxy["routes"];

        for spec in ["ingress", "gateway"] {
            if let Some(conflict_arr) = routes[spec]["conflicts"].as_array() {
                for c in conflict_arr {
                    let key = (
                        c["host"].as_str().unwrap_or("").to_owned(),
                        c["path"].as_str().unwrap_or("").to_owned(),
                        c["rejected_group"].as_str().unwrap_or("").to_owned(),
                        spec.to_owned(),
                    );
                    let route_ns = c["namespace"].as_str().unwrap_or("").to_owned();
                    let route_name = c["name"].as_str().unwrap_or("").to_owned();
                    conflicts
                        .entry(key)
                        .or_insert_with(|| (route_ns, route_name, Vec::new()))
                        .2
                        .push(pod_name.clone());
                }
            }

            if let Some(hosts) = routes[spec]["hosts"].as_array() {
                for host_entry in hosts {
                    let host = host_entry["host"].as_str().unwrap_or("").to_owned();
                    if let Some(route_arr) = host_entry["routes"].as_array() {
                        for route in route_arr {
                            let is_dead =
                                route["endpoints"].as_array().is_some_and(|e| e.is_empty());
                            if is_dead {
                                let key = (
                                    host.clone(),
                                    route["path"].as_str().unwrap_or("").to_owned(),
                                    route["backend_group"].as_str().unwrap_or("").to_owned(),
                                    spec.to_owned(),
                                );
                                let route_ns = route["namespace"].as_str().unwrap_or("").to_owned();
                                let route_name = route["name"].as_str().unwrap_or("").to_owned();
                                dead_routes
                                    .entry(key)
                                    .or_insert_with(|| (route_ns, route_name, Vec::new()))
                                    .2
                                    .push(pod_name.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    // Map the routing surface to the source resource kind for the deep-link.
    let route_kind = |spec: &str| {
        if spec == "ingress" {
            "Ingress"
        } else {
            "HTTPRoute"
        }
    };

    let conflicts_json: Vec<serde_json::Value> = conflicts
        .into_iter()
        .map(
            |((host, path, rejected_group, kind), (namespace, name, pods))| {
                serde_json::json!({
                    "host": host,
                    "path": path,
                    "rejected_group": rejected_group,
                    "kind": kind,
                    "pods": pods,
                    "route": { "kind": route_kind(&kind), "namespace": namespace, "name": name },
                })
            },
        )
        .collect();

    let dead_json: Vec<serde_json::Value> = dead_routes
        .into_iter()
        .map(
            |((host, path, backend_group, kind), (namespace, name, pods))| {
                serde_json::json!({
                    "host": host,
                    "path": path,
                    "backend_group": backend_group,
                    "kind": kind,
                    "pods": pods,
                    "route": { "kind": route_kind(&kind), "namespace": namespace, "name": name },
                })
            },
        )
        .collect();

    serde_json::json!({ "conflicts": conflicts_json, "dead_routes": dead_json })
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

    // ── list_problems ─────────────────────────────────────────────────────────

    /// Build a fake proxy-routes fan-out result for list_problems testing.
    fn fake_routes_result(
        pod_name: &str,
        reachable: bool,
        ingress_conflicts: Vec<serde_json::Value>,
        ingress_hosts: Vec<serde_json::Value>,
    ) -> serde_json::Value {
        if !reachable {
            return serde_json::json!({ "pod_name": pod_name, "reachable": false });
        }
        serde_json::json!({
            "pod_name": pod_name,
            "reachable": true,
            "routes": {
                "ingress": { "hosts": ingress_hosts, "conflicts": ingress_conflicts },
                "gateway": { "hosts": [], "conflicts": [] }
            }
        })
    }

    #[test]
    fn aggregate_problems_dedupes_and_carries_route_identity() {
        // Two pods report the same conflict + dead route (shared table). Each
        // carries the source route's namespace/name for deep-linking.
        let conflict = serde_json::json!({
            "host": "api.example.com",
            "path": "/v1",
            "rejected_group": "default/shadowed-svc:80",
            "namespace": "default",
            "name": "v1-route",
        });
        let dead_host = serde_json::json!({
            "port": 80,
            "host": "api.example.com",
            "routes": [{
                "type": "prefix",
                "path": "/broken",
                "backend_group": "default/no-pods:8080",
                "namespace": "default",
                "name": "broken-ingress",
                "endpoints": [],
            }]
        });
        let raw = vec![
            fake_routes_result(
                "proxy-0",
                true,
                vec![conflict.clone()],
                vec![dead_host.clone()],
            ),
            fake_routes_result(
                "proxy-1",
                true,
                vec![conflict.clone()],
                vec![dead_host.clone()],
            ),
            fake_routes_result("proxy-2", false, vec![], vec![]),
        ];

        let out = aggregate_problems(&raw);

        // One unique conflict (de-duped from two pods), tagged with kind + route.
        let conflicts = out["conflicts"].as_array().unwrap();
        assert_eq!(conflicts.len(), 1);
        let c = &conflicts[0];
        assert_eq!(c["host"], "api.example.com");
        assert_eq!(c["path"], "/v1");
        assert_eq!(c["rejected_group"], "default/shadowed-svc:80");
        assert_eq!(
            c["kind"], "ingress",
            "fake_routes_result populates the ingress block"
        );
        assert_eq!(
            c["pods"].as_array().unwrap().len(),
            2,
            "both reachable proxies reported it"
        );
        // The card deep-links to the rejected route's Route Inspector.
        assert_eq!(c["route"]["kind"], "Ingress");
        assert_eq!(c["route"]["namespace"], "default");
        assert_eq!(c["route"]["name"], "v1-route");

        // One unique dead route (de-duped from two pods), with route identity.
        let dead = out["dead_routes"].as_array().unwrap();
        assert_eq!(dead.len(), 1);
        let d = &dead[0];
        assert_eq!(d["host"], "api.example.com");
        assert_eq!(d["path"], "/broken");
        assert_eq!(d["backend_group"], "default/no-pods:8080");
        assert_eq!(d["kind"], "ingress");
        assert_eq!(d["pods"].as_array().unwrap().len(), 2);
        assert_eq!(d["route"]["kind"], "Ingress");
        assert_eq!(d["route"]["namespace"], "default");
        assert_eq!(d["route"]["name"], "broken-ingress");

        // Unreachable pod (proxy-2) contributed nothing.
        let all_pods: Vec<&str> = conflicts
            .iter()
            .chain(dead.iter())
            .flat_map(|p| p["pods"].as_array().unwrap())
            .map(|p| p.as_str().unwrap())
            .collect();
        assert!(!all_pods.contains(&"proxy-2"), "unreachable pod is skipped");
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

    // ── html_response ─────────────────────────────────────────────────────────

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

    // ── Async test helpers ────────────────────────────────────────────────────

    /// Build an [`OperatorAggregator`] with a short (200 ms) timeout for tests.
    ///
    /// Struct literal is allowed here because tests live inside the defining
    /// crate (`#[non_exhaustive]` only blocks external-crate construction).
    fn make_agg(fleet: SharedFleet, cluster: SharedClusterSummary) -> OperatorAggregator {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(200))
            .build()
            .unwrap_or_else(|e| panic!("invariant: {e}"));
        OperatorAggregator {
            http,
            fleet,
            cluster,
            kube: OnceCell::new(),
            log_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_LOG_STREAMS)),
        }
    }

    /// Build a [`SharedFleet`] pre-loaded with the given pods.
    fn fleet_with(pods: impl IntoIterator<Item = Pod>) -> SharedFleet {
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

    async fn start_mock_http(body: &'static str) -> u16 {
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
    fn refused_port() -> u16 {
        let l =
            std::net::TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("invariant: {e}"));
        let port = l.local_addr().unwrap().port();
        drop(l);
        port
    }

    // ── response helpers ──────────────────────────────────────────────────────

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

    // ── component_str ─────────────────────────────────────────────────────────

    #[test]
    fn entry_json_controller_component_field() {
        let pod = make_pod("ctrl-0", "controller", "10.0.0.1", "8082", None);
        let snap = build_snapshot([&pod]);
        let e = &snap.controllers[0];
        let v = OperatorAggregator::entry_json(e);
        assert_eq!(v["component"], "controller");
        assert_eq!(v["pod_name"], "ctrl-0");
    }

    // ── fleet-miss 404 ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_proxy_returns_404_when_pod_not_in_fleet() {
        let agg = make_agg(SharedFleet::default(), SharedClusterSummary::default());
        assert_eq!(
            agg.get_proxy("missing").await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn get_proxy_routes_returns_404_when_pod_not_in_fleet() {
        let agg = make_agg(SharedFleet::default(), SharedClusterSummary::default());
        assert_eq!(
            agg.get_proxy_routes("missing").await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn get_proxy_health_returns_404_when_pod_not_in_fleet() {
        let agg = make_agg(SharedFleet::default(), SharedClusterSummary::default());
        assert_eq!(
            agg.get_proxy_health("missing").await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn get_controller_returns_404_when_pod_not_in_fleet() {
        let agg = make_agg(SharedFleet::default(), SharedClusterSummary::default());
        assert_eq!(
            agg.get_controller("missing").await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn get_controller_health_returns_404_when_pod_not_in_fleet() {
        let agg = make_agg(SharedFleet::default(), SharedClusterSummary::default());
        assert_eq!(
            agg.get_controller_health("missing").await.status(),
            StatusCode::NOT_FOUND
        );
    }

    // ── list_gateways / list_ingresses handlers ───────────────────────────────

    #[test]
    fn list_gateways_handler_returns_200_with_gateways_key() {
        let summary = ClusterSummary::new(
            vec![GatewaySummary::new("gw-a", "default").with_route_count(2)],
            vec![],
            ControllerSummary::new(false),
        );
        let cluster = SharedClusterSummary::default();
        cluster.store(std::sync::Arc::new(summary));
        let agg = make_agg(SharedFleet::default(), cluster);

        let resp = agg.list_gateways();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["gateways"][0]["name"], "gw-a");
        assert_eq!(body["gateways"][0]["route_count"], 2);
    }

    #[test]
    fn list_ingresses_handler_returns_200_with_ingresses_key() {
        let summary = ClusterSummary::new(
            vec![],
            vec![
                IngressSummary::new("ing-a", "default")
                    .with_route_count(1)
                    .with_load_balancer("10.0.0.5"),
            ],
            ControllerSummary::new(false),
        );
        let cluster = SharedClusterSummary::default();
        cluster.store(std::sync::Arc::new(summary));
        let agg = make_agg(SharedFleet::default(), cluster);

        let resp = agg.list_ingresses();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["ingresses"][0]["name"], "ing-a");
        assert_eq!(body["ingresses"][0]["load_balancer"], "10.0.0.5");
    }

    // ── fan-out: list_proxies ─────────────────────────────────────────────────

    #[tokio::test]
    async fn list_proxies_empty_fleet_returns_empty_array() {
        let agg = make_agg(SharedFleet::default(), SharedClusterSummary::default());
        let resp = agg.list_proxies().await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["proxies"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn list_proxies_marks_reachable_and_unreachable_pods() {
        let live_port = start_mock_http(r#"{"ok":true}"#).await;
        let dead_port = refused_port();
        let pods = [
            make_pod(
                "proxy-live",
                "shared-proxy",
                "127.0.0.1",
                &live_port.to_string(),
                None,
            ),
            make_pod(
                "proxy-dead",
                "shared-proxy",
                "127.0.0.1",
                &dead_port.to_string(),
                None,
            ),
        ];
        let agg = make_agg(fleet_with(pods), SharedClusterSummary::default());

        let resp = agg.list_proxies().await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        let proxies = body["proxies"].as_array().unwrap();
        assert_eq!(proxies.len(), 2);
        let live = proxies
            .iter()
            .find(|p| p["pod_name"] == "proxy-live")
            .unwrap();
        assert_eq!(live["reachable"], true);
        let dead = proxies
            .iter()
            .find(|p| p["pod_name"] == "proxy-dead")
            .unwrap();
        assert_eq!(dead["reachable"], false);
    }

    // ── fan-out: get_proxy ────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_proxy_reachable_returns_pod_info_with_reachable_true() {
        let port = start_mock_http(r#"{"ok":true}"#).await;
        let pod = make_pod(
            "proxy-0",
            "shared-proxy",
            "127.0.0.1",
            &port.to_string(),
            None,
        );
        let agg = make_agg(fleet_with([pod]), SharedClusterSummary::default());

        let resp = agg.get_proxy("proxy-0").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["pod_name"], "proxy-0");
        assert_eq!(body["reachable"], true);
        assert_eq!(body["component"], "shared-proxy");
    }

    #[tokio::test]
    async fn get_proxy_unreachable_returns_reachable_false() {
        let port = refused_port();
        let pod = make_pod(
            "proxy-0",
            "shared-proxy",
            "127.0.0.1",
            &port.to_string(),
            None,
        );
        let agg = make_agg(fleet_with([pod]), SharedClusterSummary::default());

        let resp = agg.get_proxy("proxy-0").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["pod_name"], "proxy-0");
        assert_eq!(body["reachable"], false);
    }

    // ── fan-out: get_proxy_routes ─────────────────────────────────────────────

    #[tokio::test]
    async fn get_proxy_routes_reachable_returns_routes_key() {
        let routes_body =
            r#"{"ingress":{"hosts":[],"conflicts":[]},"gateway":{"hosts":[],"conflicts":[]}}"#;
        let port = start_mock_http(routes_body).await;
        let pod = make_pod(
            "proxy-0",
            "shared-proxy",
            "127.0.0.1",
            &port.to_string(),
            None,
        );
        let agg = make_agg(fleet_with([pod]), SharedClusterSummary::default());

        let resp = agg.get_proxy_routes("proxy-0").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["pod_name"], "proxy-0");
        assert_eq!(body["reachable"], true);
        assert!(body.get("routes").is_some());
    }

    #[tokio::test]
    async fn get_proxy_routes_unreachable_omits_routes_key() {
        let port = refused_port();
        let pod = make_pod(
            "proxy-0",
            "shared-proxy",
            "127.0.0.1",
            &port.to_string(),
            None,
        );
        let agg = make_agg(fleet_with([pod]), SharedClusterSummary::default());

        let resp = agg.get_proxy_routes("proxy-0").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["reachable"], false);
        assert!(body.get("routes").is_none());
    }

    // ── fan-out: get_proxy_health ─────────────────────────────────────────────

    #[tokio::test]
    async fn get_proxy_health_reachable_returns_health_key() {
        let health_body = r#"{"version":"0.0.1","subsystems":{"reflector":"ok"}}"#;
        let port = start_mock_http(health_body).await;
        let pod = make_pod(
            "proxy-0",
            "shared-proxy",
            "127.0.0.1",
            &port.to_string(),
            None,
        );
        let agg = make_agg(fleet_with([pod]), SharedClusterSummary::default());

        let resp = agg.get_proxy_health("proxy-0").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["pod_name"], "proxy-0");
        assert_eq!(body["reachable"], true);
        assert!(body.get("health").is_some());
    }

    // ── fan-out: list_controllers ─────────────────────────────────────────────

    #[tokio::test]
    async fn list_controllers_marks_reachable_and_unreachable_pods() {
        let live_port = start_mock_http(r#"{"ok":true}"#).await;
        let dead_port = refused_port();
        let pods = [
            make_pod(
                "ctrl-live",
                "controller",
                "127.0.0.1",
                &live_port.to_string(),
                None,
            ),
            make_pod(
                "ctrl-dead",
                "controller",
                "127.0.0.1",
                &dead_port.to_string(),
                None,
            ),
        ];
        let agg = make_agg(fleet_with(pods), SharedClusterSummary::default());

        let resp = agg.list_controllers().await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        let controllers = body["controllers"].as_array().unwrap();
        assert_eq!(controllers.len(), 2);
        let live = controllers
            .iter()
            .find(|c| c["pod_name"] == "ctrl-live")
            .unwrap();
        assert_eq!(live["reachable"], true);
        // /cluster body had no controller.leader → defaults to false.
        assert_eq!(live["is_leader"], false);
        let dead = controllers
            .iter()
            .find(|c| c["pod_name"] == "ctrl-dead")
            .unwrap();
        assert_eq!(dead["reachable"], false);
    }

    #[tokio::test]
    async fn list_controllers_reports_is_leader_from_cluster_endpoint() {
        // The /cluster probe carries controller.leader; the reachable entry must
        // surface it as is_leader so the UI doesn't misread a healthy
        // single-leader cluster as having no elected leader.
        let port =
            start_mock_http(r#"{"controller":{"leader":true},"gateways":[],"ingresses":[]}"#).await;
        let pods = [make_pod(
            "ctrl-leader",
            "controller",
            "127.0.0.1",
            &port.to_string(),
            None,
        )];
        let agg = make_agg(fleet_with(pods), SharedClusterSummary::default());

        let resp = agg.list_controllers().await;
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        let leader = body["controllers"][0].clone();
        assert_eq!(leader["reachable"], true);
        assert_eq!(leader["is_leader"], true);
    }
}
