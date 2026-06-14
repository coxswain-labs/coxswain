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
use crate::page::{ListParams, Page, page_response};
use coxswain_core::cluster::{
    CategorySummary, ClusterSummary, GatewayCondition, Severity, SharedClusterSummary,
};
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

    /// `GET /api/v1/fleet/proxies/{pod-name}/routes` — fan-out to the pod's
    /// `/routes`, relaying the filter/pagination `params` so the **proxy** does
    /// the filtering at the source (the typed routing table lives there, #286).
    /// The controller is a transparent relay: it never receives non-matching rows.
    pub(crate) async fn get_proxy_routes(
        &self,
        pod_name: &str,
        params: &ListParams,
    ) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entry = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .find(|e| e.pod_name == pod_name);
        let Some(entry) = entry else {
            return not_found();
        };
        let base = pod_base_url(entry);
        let url = if params.is_empty() {
            format!("{base}/routes")
        } else {
            format!("{base}/routes?{}", params.to_query())
        };
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
    /// Probes each controller's `/api/v1/health`: it doubles as a liveness check
    /// (200 ⇒ reachable) and carries that pod's live `leader` flag and subsystem
    /// state in one hop, so the response reports `is_leader` per pod. (This
    /// replaced the retired `/api/v1/cluster` leader probe.)
    pub(crate) async fn list_controllers(&self) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entries: Vec<FleetEntry> = snapshot.controllers.to_vec();
        let probes: Vec<_> = entries
            .iter()
            .map(|e| async move {
                let health_url = format!("{}/api/v1/health", pod_base_url(e));
                match self.fetch_json(&health_url).await {
                    Some(body) => {
                        let is_leader = body["leader"].as_bool().unwrap_or(false);
                        let mut v = Self::entry_json(e);
                        v["reachable"] = serde_json::Value::Bool(true);
                        v["is_leader"] = serde_json::Value::Bool(is_leader);
                        attach_health_rollup(&mut v, &body);
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
    /// Probes `/api/v1/health`: it doubles as a liveness check and carries this
    /// pod's live `leader` flag, so the controller detail page can show
    /// leader/standby without a second call — mirroring [`Self::list_controllers`].
    pub(crate) async fn get_controller(&self, pod_name: &str) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let Some(entry) = snapshot.controllers.iter().find(|e| e.pod_name == pod_name) else {
            return not_found();
        };
        let url = format!("{}/api/v1/health", pod_base_url(entry));
        match self.fetch_json(&url).await {
            Some(body) => {
                let is_leader = body["leader"].as_bool().unwrap_or(false);
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
    /// `GET /api/v1/routing/summary` — compact per-category counts + worst
    /// severity (Gateways/HTTPRoutes/Ingresses) from the cluster summary, plus the
    /// cluster-wide `namespaces` set. Backs the routing-tab badges + warning icons
    /// and the namespace dropdown without shipping the full lists.
    pub(crate) fn routing_summary(&self) -> Response<Vec<u8>> {
        let snapshot = self.cluster.load();
        let mut v = match serde_json::to_value(snapshot.routing_summary()) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "failed to serialise /api/v1/routing/summary");
                return internal_error();
            }
        };
        // Every namespace holding a routing resource — the namespace dropdown must
        // list them all regardless of the active page/filter, so it can't be
        // derived from a single (paginated) list response.
        let mut namespaces: Vec<&str> = snapshot
            .gateways
            .iter()
            .map(|g| g.namespace.as_str())
            .chain(snapshot.httproutes.iter().map(|r| r.namespace.as_str()))
            .chain(snapshot.ingresses.iter().map(|i| i.namespace.as_str()))
            .collect();
        namespaces.sort_unstable();
        namespaces.dedup();
        v["namespaces"] = serde_json::json!(namespaces);
        json_response(v.to_string())
    }

    /// `GET /api/v1/routing/gateways` — gateway list from the cluster summary (no
    /// fan-out), with the shared filter/pagination envelope.
    pub(crate) fn list_gateways(&self, params: &ListParams) -> Response<Vec<u8>> {
        let snapshot = self.cluster.load();
        let filtered: Vec<serde_json::Value> = snapshot
            .gateways
            .iter()
            .filter(|g| !params.problems_only || g.status.is_problem())
            .filter(|g| params.namespace_matches(&g.namespace))
            .filter(|g| params.name_matches(&g.name))
            .map(|g| serde_json::to_value(g).unwrap_or(serde_json::Value::Null))
            .collect();
        page_response("gateways", Page::paginate(filtered, params))
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
                // count + conditions for TLS health). Status may be absent before
                // the first reconcile.
                let status_by_name: std::collections::HashMap<&str, &_> = gw
                    .status
                    .as_ref()
                    .and_then(|s| s.listeners.as_deref())
                    .unwrap_or_default()
                    .iter()
                    .map(|l| (l.name.as_str(), l))
                    .collect();

                let lsnrs: Vec<serde_json::Value> = gw
                    .spec
                    .listeners
                    .iter()
                    .map(|l| {
                        let st = status_by_name.get(l.name.as_str()).copied();
                        let attached = st.map(|s| s.attached_routes).unwrap_or(0);
                        // Listener-precise TLS health: a configured listener's
                        // badge reflects whether its certificate refs resolved and
                        // it programmed — not merely that a TLS block exists.
                        let (tls_status, tls_reason) = if l.tls.is_some() {
                            let (sev, why) =
                                listener_tls_health(st.map(|s| s.conditions.as_slice()));
                            (
                                serde_json::to_value(sev).unwrap_or(serde_json::Value::Null),
                                why,
                            )
                        } else {
                            (serde_json::Value::Null, None)
                        };
                        serde_json::json!({
                            "name": l.name,
                            "port": l.port,
                            "protocol": l.protocol,
                            "tls_enabled": l.tls.is_some(),
                            "tls_status": tls_status,
                            "tls_reason": tls_reason,
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

        let attached_routes_list = self
            .list_attached_httproutes(kube, &snapshot, namespace, name)
            .await;

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
        snapshot: &ClusterSummary,
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
                // Enrich with hostnames + rule count straight from the route spec
                // so the Gateway-detail table mirrors the routing HTTPRoutes table
                // (Parent is implicit here — it's this Gateway).
                let hostnames = route.spec.hostnames.as_deref().unwrap_or(&[]).to_vec();
                let rule_count = route.spec.rules.as_deref().map(<[_]>::len).unwrap_or(0);
                // Reflector-computed traffic-served status (same field the routing
                // HTTPRoutes table shows). The UI overlays /problems on top, so
                // dead/conflict routes on a dedicated gateway still surface.
                let status = snapshot
                    .httproutes
                    .iter()
                    .find(|h| h.namespace == route_ns && h.name == route_name)
                    .map(|h| h.status);
                result.push(serde_json::json!({
                    "kind": "HTTPRoute",
                    "namespace": route_ns,
                    "name": route_name,
                    "hostnames": hostnames,
                    "rule_count": rule_count,
                    "status": status,
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
        "status": summary.status,
    })
}

/// Listener-precise TLS health from a listener's Gateway API status conditions.
///
/// `ResolvedRefs=False` (its `certificateRefs` didn't resolve — missing/invalid
/// Secret or a cross-namespace ref not permitted) means no TLS traffic serves on
/// this listener → [`Severity::Error`]. `Programmed=False` means it isn't yet
/// realized in the data plane → [`Severity::Warn`]. Both `True` → [`Severity::Ok`].
/// Absent status (pre-reconcile) is reported as `Warn`, never a confident lock —
/// the badge must not claim a certificate is good when we don't yet know.
fn listener_tls_health(
    conditions: Option<&[k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition]>,
) -> (Severity, Option<String>) {
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
    let Some(conds) = conditions else {
        return (
            Severity::Warn,
            Some("listener status not reported yet".to_string()),
        );
    };
    let why = |c: &Condition| {
        if c.message.is_empty() {
            c.reason.clone()
        } else {
            c.message.clone()
        }
    };
    if let Some(c) = conds.iter().find(|c| c.type_ == "ResolvedRefs")
        && c.status != "True"
    {
        return (Severity::Error, Some(why(c)));
    }
    if let Some(c) = conds.iter().find(|c| c.type_ == "Programmed")
        && c.status != "True"
    {
        return (Severity::Warn, Some(why(c)));
    }
    (Severity::Ok, None)
}

// ── /api/v1/ingresses ────────────────────────────────────────────────────────

impl OperatorAggregator {
    /// `GET /api/v1/routing/ingresses` — ingress list from the cluster summary
    /// (no fan-out), with the shared filter/pagination envelope.
    pub(crate) fn list_ingresses(&self, params: &ListParams) -> Response<Vec<u8>> {
        let snapshot = self.cluster.load();
        let filtered: Vec<serde_json::Value> = snapshot
            .ingresses
            .iter()
            .filter(|i| !params.problems_only || i.status.is_problem())
            .filter(|i| params.namespace_matches(&i.namespace))
            .filter(|i| params.name_matches(&i.name))
            .map(|i| serde_json::to_value(i).unwrap_or(serde_json::Value::Null))
            .collect();
        page_response("ingresses", Page::paginate(filtered, params))
    }

    /// `GET /api/v1/routing/httproutes` — HTTPRoute list from the cluster summary
    /// (no fan-out, #293), with the shared filter/pagination envelope. The `name`
    /// filter matches the route's object name (name-only, like the other routing
    /// lists); declared hostnames are not part of the free-text search.
    pub(crate) fn list_httproutes(&self, params: &ListParams) -> Response<Vec<u8>> {
        let snapshot = self.cluster.load();
        let filtered: Vec<serde_json::Value> = snapshot
            .httproutes
            .iter()
            .filter(|r| !params.problems_only || r.status.is_problem())
            .filter(|r| params.namespace_matches(&r.namespace))
            .filter(|r| params.name_matches(&r.name))
            .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
            .collect();
        page_response("httproutes", Page::paginate(filtered, params))
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

// ── /api/v1/routing/routes/{kind}/{ns}/{name} ──────────────────────────────────

impl OperatorAggregator {
    /// `GET /api/v1/routing/routes/{kind}/{namespace}/{name}` — kind-dispatching
    /// route detail. `kind` is `httproute` or `ingress`; anything else is 404
    /// (mirrors `get_manifest`'s kind validation).
    pub(crate) async fn get_route(
        &self,
        kind: &str,
        namespace: &str,
        name: &str,
    ) -> Response<Vec<u8>> {
        match kind {
            "httproute" => self.get_httproute(namespace, name).await,
            "ingress" => self.get_ingress_route(namespace, name).await,
            _ => not_found(),
        }
    }

    /// Live HTTPRoute status conditions from Kubernetes + parallel `/routes`
    /// fan-out to all proxy pods.
    pub(crate) async fn get_httproute(&self, namespace: &str, name: &str) -> Response<Vec<u8>> {
        let kube = match self.kube().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "kube client unavailable for /api/v1/routes/httproute");
                return service_unavailable("kubernetes client not available");
            }
        };

        let api: Api<HttpRoute> = Api::namespaced(kube.clone(), namespace);
        let route = match api.get(name).await {
            Ok(route) => route,
            Err(kube::Error::Api(e)) if e.code == 404 => return not_found(),
            Err(e) => {
                tracing::warn!(error = %e, namespace, name, "K8s GET HTTPRoute failed");
                return internal_error();
            }
        };

        // Per-parentRef conditions — the richest Gateway-API troubleshooting
        // surface, rendered as the route's conditions table.
        let parent_statuses = route
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
            .collect::<Vec<_>>();

        // Effective config (the route's declared intent, interpreted) for the
        // detail body — sourced from the object we just fetched, no extra calls.
        let hostnames = route.spec.hostnames.clone().unwrap_or_default();
        let rules = httproute_rules_json(&route.spec);

        // Reflector traffic-served status (same field the routing table shows);
        // the UI overlays /problems on top for the header status badge.
        let status = self
            .cluster
            .load()
            .httproutes
            .iter()
            .find(|h| h.namespace == namespace && h.name == name)
            .map(|h| h.status);

        json_response(
            serde_json::json!({
                "namespace": namespace,
                "name": name,
                "status": status,
                "hostnames": hostnames,
                "parent_statuses": parent_statuses,
                "rules": rules,
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
        let ing = match api.get(name).await {
            Ok(ing) => ing,
            Err(kube::Error::Api(e)) if e.code == 404 => return not_found(),
            Err(e) => {
                tracing::warn!(error = %e, namespace, name, "K8s GET Ingress (routes) failed");
                return internal_error();
            }
        };

        let load_balancer = ing
            .status
            .as_ref()
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_deref())
            .and_then(|items| items.first())
            .and_then(|i| i.ip.as_deref().or(i.hostname.as_deref()))
            .map(str::to_owned)
            .unwrap_or_default();

        // Effective config (class, TLS blocks, host/path → backend rules) from
        // the object we just fetched — Ingress is flat, so this is most of what
        // the resource *is*.
        let empty_spec = k8s_openapi::api::networking::v1::IngressSpec::default();
        let spec = ing.spec.as_ref().unwrap_or(&empty_spec);
        let class = spec.ingress_class_name.clone().unwrap_or_default();
        let tls = ingress_tls_json(spec);
        let default_backend = spec.default_backend.as_ref().map(ingress_backend_json);
        let rules = ingress_rules_json(spec);

        let status = self
            .cluster
            .load()
            .ingresses
            .iter()
            .find(|i| i.namespace == namespace && i.name == name)
            .map(|i| i.status);

        let mut v = serde_json::json!({
            "namespace": namespace,
            "name": name,
            "status": status,
            "class": class,
            "tls": tls,
            "default_backend": default_backend,
            "rules": rules,
        });
        if !load_balancer.is_empty() {
            v["load_balancer"] = serde_json::Value::String(load_balancer);
        }
        json_response(v.to_string())
    }

    /// `GET …/routes/{kind}/{ns}/{name}/check` — on-demand data-plane
    /// consistency check against the controller for a single route.
    ///
    /// Everything else on the route detail page reflects the *controller's*
    /// view (status, conditions, `/problems`). This is the one check that asks
    /// each proxy directly. It targets only the proxies that *should* serve the
    /// route — the shared pool, or the dedicated proxies of the route's parent
    /// Gateways (matched by the `gateway-name` label) — fans out to their
    /// `/routes`, and diffs the route-tagged rows across them: a proxy missing a
    /// row its peers have is drift.
    ///
    /// # Errors
    ///
    /// 400 for an unknown kind, 404 when the route does not exist, 503 when the
    /// Kubernetes client is unavailable, 500 for other Kubernetes errors.
    pub(crate) async fn check_route(
        &self,
        kind: &str,
        namespace: &str,
        name: &str,
    ) -> Response<Vec<u8>> {
        let Some(spec_key) = route_kind_key(kind) else {
            return not_found();
        };

        let kube = match self.kube().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "kube client unavailable for route check");
                return service_unavailable("kubernetes client not available");
            }
        };

        // Resolve which proxies should serve this route. HTTPRoute follows its
        // parent Gateways (dedicated → those pods, otherwise the shared pool);
        // Ingress is always served by the shared pool.
        let snapshot = self.fleet.load();
        let serving: Vec<FleetEntry> = match kind {
            "httproute" => {
                let api: Api<HttpRoute> = Api::namespaced(kube.clone(), namespace);
                let route = match api.get(name).await {
                    Ok(r) => r,
                    Err(kube::Error::Api(e)) if e.code == 404 => return not_found(),
                    Err(e) => {
                        tracing::warn!(error = %e, namespace, name, "K8s GET HTTPRoute (check) failed");
                        return internal_error();
                    }
                };
                let parents = route.spec.parent_refs.as_deref().unwrap_or_default();
                serving_proxies_for_parents(&snapshot, namespace, parents)
            }
            "ingress" => {
                let api: Api<Ingress> = Api::namespaced(kube.clone(), namespace);
                match api.get(name).await {
                    Ok(_) => {}
                    Err(kube::Error::Api(e)) if e.code == 404 => return not_found(),
                    Err(e) => {
                        tracing::warn!(error = %e, namespace, name, "K8s GET Ingress (check) failed");
                        return internal_error();
                    }
                }
                snapshot.shared_proxies.clone()
            }
            _ => return not_found(),
        };

        let pod_results = self.fan_out_routes_to(&serving).await;

        // Pass 1: per-pod route-tagged rows + the union of (host, path, backend)
        // keys seen across all reachable serving proxies — the expected set.
        let mut union: Vec<(String, String, String)> = Vec::new();
        let mut union_seen: std::collections::HashSet<(String, String, String)> =
            std::collections::HashSet::new();
        let mut pod_rows: Vec<(String, bool, Vec<serde_json::Value>)> = Vec::new();
        for pr in &pod_results {
            let pod_name = pr
                .get("pod_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let reachable = pr
                .get("reachable")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !reachable {
                pod_rows.push((pod_name, false, Vec::new()));
                continue;
            }
            let routes = pr.get("routes").cloned().unwrap_or(serde_json::Value::Null);
            let rows = route_rows_for(&routes, spec_key, namespace, name);
            for r in &rows {
                let key = row_key(r);
                if union_seen.insert(key.clone()) {
                    union.push(key);
                }
            }
            pod_rows.push((pod_name, true, rows));
        }

        // Pass 2: per-pod present rows (flagging dead backends) + the union keys
        // each pod is missing. Any unreachable pod, any missing key, or a route
        // absent from every proxy means the data plane disagrees.
        let mut consistent = !union.is_empty();
        let mut proxies_json: Vec<serde_json::Value> = Vec::new();
        for (pod_name, reachable, rows) in &pod_rows {
            if !reachable {
                consistent = false;
                proxies_json.push(serde_json::json!({ "pod_name": pod_name, "reachable": false }));
                continue;
            }
            let present: std::collections::HashSet<(String, String, String)> =
                rows.iter().map(row_key).collect();
            let missing: Vec<serde_json::Value> = union
                .iter()
                .filter(|k| !present.contains(*k))
                .map(|(host, path, backend_group)| {
                    serde_json::json!({ "host": host, "path": path, "backend_group": backend_group })
                })
                .collect();
            if !missing.is_empty() {
                consistent = false;
            }
            let rows_json: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    let dead = r
                        .get("endpoints")
                        .and_then(|e| e.as_array())
                        .is_none_or(|a| a.is_empty());
                    let mut rr = r.clone();
                    rr["dead"] = serde_json::Value::Bool(dead);
                    rr
                })
                .collect();
            proxies_json.push(serde_json::json!({
                "pod_name": pod_name,
                "reachable": true,
                "rows": rows_json,
                "missing": missing,
            }));
        }

        let expected: Vec<serde_json::Value> = union
            .iter()
            .map(|(host, path, backend_group)| {
                serde_json::json!({ "host": host, "path": path, "backend_group": backend_group })
            })
            .collect();

        json_response(
            serde_json::json!({
                "kind": kind,
                "namespace": namespace,
                "name": name,
                "consistent": consistent,
                "expected": expected,
                "proxies": proxies_json,
            })
            .to_string(),
        )
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
        self.fan_out_routes_to(&entries).await
    }

    /// Fan out `GET /routes` to a specific set of proxy pods in parallel — the
    /// check path targets only the proxies that should serve a given route,
    /// not the whole fleet.
    async fn fan_out_routes_to(&self, entries: &[FleetEntry]) -> Vec<serde_json::Value> {
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

// ── Route check (data-plane consistency) ─────────────────────────────────────────────────────────────

/// The proxy `/routes` sub-key for a route kind: Gateway-API routes live under
/// `gateway`, classic Ingress under `ingress`. `None` for an unknown kind.
fn route_kind_key(kind: &str) -> Option<&'static str> {
    match kind {
        "httproute" => Some("gateway"),
        "ingress" => Some("ingress"),
        _ => None,
    }
}

/// The proxies that should serve a route, given its parent Gateways. Each parent
/// is served by its dedicated proxies (matched by namespace + `gateway-name`
/// label) when any exist, otherwise by the shared pool. Pods are de-duplicated
/// across parents.
fn serving_proxies_for_parents(
    snapshot: &FleetSnapshot,
    route_ns: &str,
    parents: &[gw_types::v::httproutes::HttpRouteParentRefs],
) -> Vec<FleetEntry> {
    let mut out: Vec<FleetEntry> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for p in parents {
        let gw_ns = p.namespace.as_deref().unwrap_or(route_ns);
        let gw_name = p.name.as_str();
        let dedicated: Vec<&FleetEntry> = snapshot
            .dedicated_proxies
            .iter()
            .filter(|e| e.pod_namespace == gw_ns && e.gateway_ref.as_deref() == Some(gw_name))
            .collect();
        let targets: Vec<&FleetEntry> = if dedicated.is_empty() {
            snapshot.shared_proxies.iter().collect()
        } else {
            dedicated
        };
        for e in targets {
            if seen.insert(e.pod_name.clone()) {
                out.push(e.clone());
            }
        }
    }
    out
}

/// Flatten the rows in one proxy's `/routes` payload that are tagged with the
/// given route object to `{host, path, backend_group, endpoints}`.
fn route_rows_for(
    routes: &serde_json::Value,
    spec_key: &str,
    namespace: &str,
    name: &str,
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let hosts = routes
        .get(spec_key)
        .and_then(|s| s.get("hosts"))
        .and_then(|h| h.as_array());
    for host_entry in hosts.into_iter().flatten() {
        let host = host_entry
            .get("host")
            .and_then(|h| h.as_str())
            .unwrap_or("");
        let rows = host_entry.get("routes").and_then(|r| r.as_array());
        for r in rows.into_iter().flatten() {
            if r.get("namespace").and_then(|v| v.as_str()) == Some(namespace)
                && r.get("name").and_then(|v| v.as_str()) == Some(name)
            {
                out.push(serde_json::json!({
                    "host": host,
                    "path": r.get("path").cloned().unwrap_or(serde_json::Value::Null),
                    "backend_group": r.get("backend_group").cloned().unwrap_or(serde_json::Value::Null),
                    "endpoints": r.get("endpoints").cloned().unwrap_or_else(|| serde_json::json!([])),
                }));
            }
        }
    }
    out
}

/// `(host, path, backend_group)` identity for a check row, for set membership.
fn row_key(r: &serde_json::Value) -> (String, String, String) {
    let s = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_owned();
    (s("host"), s("path"), s("backend_group"))
}

// ── Effective-config serialization (route detail bodies) ──────────────────────

/// Gateway-API spelling for a path-match type. Absent ⇒ the spec default of a
/// `PathPrefix` match on `/`.
fn path_match_str(
    t: Option<&gw_types::v::httproutes::HttpRouteRulesMatchesPathType>,
) -> &'static str {
    use gw_types::v::httproutes::HttpRouteRulesMatchesPathType as T;
    match t {
        Some(T::Exact) => "Exact",
        Some(T::PathPrefix) | None => "PathPrefix",
        Some(T::RegularExpression) => "RegularExpression",
    }
}

/// Gateway-API spelling for an HTTP method matcher.
fn method_match_str(m: &gw_types::v::httproutes::HttpRouteRulesMatchesMethod) -> &'static str {
    use gw_types::v::httproutes::HttpRouteRulesMatchesMethod as M;
    match m {
        M::Get => "GET",
        M::Head => "HEAD",
        M::Post => "POST",
        M::Put => "PUT",
        M::Delete => "DELETE",
        M::Connect => "CONNECT",
        M::Options => "OPTIONS",
        M::Trace => "TRACE",
        M::Patch => "PATCH",
    }
}

/// Gateway-API spelling for a header match type. Absent ⇒ `Exact` (the spec
/// default).
fn header_match_str(
    t: Option<&gw_types::v::httproutes::HttpRouteRulesMatchesHeadersType>,
) -> &'static str {
    use gw_types::v::httproutes::HttpRouteRulesMatchesHeadersType as T;
    match t {
        Some(T::RegularExpression) => "RegularExpression",
        Some(T::Exact) | None => "Exact",
    }
}

/// Gateway-API spelling for a query-param match type. Absent ⇒ `Exact`.
fn query_match_str(
    t: Option<&gw_types::v::httproutes::HttpRouteRulesMatchesQueryParamsType>,
) -> &'static str {
    use gw_types::v::httproutes::HttpRouteRulesMatchesQueryParamsType as T;
    match t {
        Some(T::RegularExpression) => "RegularExpression",
        Some(T::Exact) | None => "Exact",
    }
}

/// Gateway-API spelling for a filter kind (the `type` discriminant only — the
/// effective-config table lists which filters are in play, not their bodies).
fn filter_kind_str(t: &gw_types::v::httproutes::HttpRouteRulesFiltersType) -> &'static str {
    use gw_types::v::httproutes::HttpRouteRulesFiltersType as F;
    match t {
        F::RequestHeaderModifier => "RequestHeaderModifier",
        F::ResponseHeaderModifier => "ResponseHeaderModifier",
        F::RequestMirror => "RequestMirror",
        F::RequestRedirect => "RequestRedirect",
        F::UrlRewrite => "URLRewrite",
        F::ExtensionRef => "ExtensionRef",
        F::Cors => "CORS",
    }
}

/// Interpreted HTTPRoute spec rules for the detail screen's effective-config
/// table.
///
/// Flattens each rule to the fields an operator reads — match predicates
/// (path/method/headers/query), weighted backends, and the filter kinds in
/// play. Sourced from the already-fetched object, so it costs no extra API
/// call. Empty inner collections are emitted as empty arrays for a stable shape.
fn httproute_rules_json(spec: &gw_types::v::httproutes::HttpRouteSpec) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = spec
        .rules
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|rule| {
            let matches: Vec<serde_json::Value> = rule
                .matches
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|m| {
                    let headers: Vec<serde_json::Value> = m
                        .headers
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .map(|h| {
                            serde_json::json!({
                                "name": h.name,
                                "type": header_match_str(h.r#type.as_ref()),
                                "value": h.value,
                            })
                        })
                        .collect();
                    let query_params: Vec<serde_json::Value> = m
                        .query_params
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .map(|q| {
                            serde_json::json!({
                                "name": q.name,
                                "type": query_match_str(q.r#type.as_ref()),
                                "value": q.value,
                            })
                        })
                        .collect();
                    serde_json::json!({
                        "path": {
                            "type": path_match_str(m.path.as_ref().and_then(|p| p.r#type.as_ref())),
                            "value": m.path.as_ref().and_then(|p| p.value.clone()).unwrap_or_else(|| "/".to_owned()),
                        },
                        "method": m.method.as_ref().map(method_match_str),
                        "headers": headers,
                        "query_params": query_params,
                    })
                })
                .collect();
            let backends: Vec<serde_json::Value> = rule
                .backend_refs
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|b| {
                    serde_json::json!({
                        "name": b.name,
                        "namespace": b.namespace,
                        "port": b.port,
                        "weight": b.weight,
                    })
                })
                .collect();
            let filters: Vec<&str> = rule
                .filters
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|f| filter_kind_str(&f.r#type))
                .collect();
            serde_json::json!({
                "matches": matches,
                "backends": backends,
                "filters": filters,
            })
        })
        .collect();
    serde_json::Value::Array(rules)
}

/// Render an [`IngressBackend`] to `{service, port}` (the common case) or
/// `{resource}` for a resource backend. Port renders as the number, falling
/// back to the named port.
fn ingress_backend_json(b: &k8s_openapi::api::networking::v1::IngressBackend) -> serde_json::Value {
    if let Some(s) = &b.service {
        let port = s
            .port
            .as_ref()
            .and_then(|p| p.number.map(|n| n.to_string()).or_else(|| p.name.clone()));
        serde_json::json!({ "service": s.name, "port": port })
    } else if let Some(r) = &b.resource {
        serde_json::json!({ "resource": format!("{}/{}", r.kind, r.name) })
    } else {
        serde_json::Value::Null
    }
}

/// TLS blocks (`{hosts, secret}`) declared inline on the Ingress.
fn ingress_tls_json(spec: &k8s_openapi::api::networking::v1::IngressSpec) -> serde_json::Value {
    let tls: Vec<serde_json::Value> = spec
        .tls
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|t| {
            serde_json::json!({
                "hosts": t.hosts.clone().unwrap_or_default(),
                "secret": t.secret_name,
            })
        })
        .collect();
    serde_json::Value::Array(tls)
}

/// Interpreted Ingress spec rules: `host` → `[{path, path_type, backend}]`.
fn ingress_rules_json(spec: &k8s_openapi::api::networking::v1::IngressSpec) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = spec
        .rules
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|r| {
            let paths: Vec<serde_json::Value> = r
                .http
                .as_ref()
                .map(|h| h.paths.as_slice())
                .unwrap_or_default()
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "path": p.path.clone().unwrap_or_else(|| "/".to_owned()),
                        "path_type": p.path_type,
                        "backend": ingress_backend_json(&p.backend),
                    })
                })
                .collect();
            serde_json::json!({
                "host": r.host,
                "paths": paths,
            })
        })
        .collect();
    serde_json::Value::Array(rules)
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
    /// Cross-cutting problem aggregate, namespaced by the two API axes (#301):
    /// ```json
    /// {
    ///   "fleet":   { "leaderless": bool, "unreachable": [pod…], "degraded": [pod…] },
    ///   "routing": { "conflicts": [...], "dead_routes": [...] }
    /// }
    /// ```
    ///
    /// `routing` conflicts/dead-routes come from fanning out to every proxy's
    /// `/routes` (deduped, `kind`-tagged). `fleet` classes come from probing each
    /// pod's `/api/v1/health`: `unreachable` pods don't answer, `degraded` pods
    /// answer with failing checks, and `leaderless` is `true` when no reachable
    /// controller reports `leader`. The operator UI renders this directly rather
    /// than re-deriving severity client-side.
    pub(crate) async fn list_problems(&self) -> Response<Vec<u8>> {
        let (raw, fleet) = tokio::join!(self.fan_out_routes(), self.fleet_problems());
        let routing = aggregate_problems(&raw);
        json_response(serde_json::json!({ "fleet": fleet, "routing": routing }).to_string())
    }

    /// Probe every coxswain pod's `/api/v1/health` and bucket the fleet problem
    /// classes (`leaderless`/`unreachable`/`degraded`). See [`Self::list_problems`].
    async fn fleet_problems(&self) -> serde_json::Value {
        let snapshot = self.fleet.load();
        // (entry, is_controller) for every pod in the fleet.
        let pods: Vec<(FleetEntry, bool)> = snapshot
            .controllers
            .iter()
            .map(|e| (e.clone(), true))
            .chain(
                snapshot
                    .shared_proxies
                    .iter()
                    .chain(&snapshot.dedicated_proxies)
                    .map(|e| (e.clone(), false)),
            )
            .collect();
        let any_controller = pods.iter().any(|(_, is_ctrl)| *is_ctrl);

        let probes = pods.iter().map(|(e, is_ctrl)| async move {
            let url = format!("{}/api/v1/health", pod_base_url(e));
            (e, *is_ctrl, self.fetch_json(&url).await)
        });
        let results = join_all(probes).await;

        let mut unreachable = Vec::new();
        let mut degraded = Vec::new();
        let mut any_leader = false;
        for (e, is_ctrl, body) in results {
            match body {
                None => {
                    let mut v = Self::entry_json(e);
                    v["reachable"] = serde_json::Value::Bool(false);
                    unreachable.push(v);
                }
                Some(body) => {
                    if is_ctrl && body["leader"].as_bool().unwrap_or(false) {
                        any_leader = true;
                    }
                    let checks = non_ready_checks(&body);
                    if !checks.is_empty() {
                        let mut v = Self::entry_json(e);
                        v["reachable"] = serde_json::Value::Bool(true);
                        v["degraded_checks"] = serde_json::Value::from(checks);
                        degraded.push(v);
                    }
                }
            }
        }

        serde_json::json!({
            "leaderless": any_controller && !any_leader,
            "unreachable": unreachable,
            "degraded": degraded,
        })
    }

    /// `GET /api/v1/fleet/summary` — compact per-category counts + worst severity
    /// for controllers, shared proxies, and dedicated proxies (the Dashboard's
    /// three fleet tiles). Backs the tiles without shipping the full pod lists.
    /// Reuses the per-pod `/health` probe (a pod is `error` when unreachable,
    /// `warn` when degraded, else `ok`).
    pub(crate) async fn fleet_summary(&self) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let controllers: Vec<FleetEntry> = snapshot.controllers.to_vec();
        let shared: Vec<FleetEntry> = snapshot.shared_proxies.to_vec();
        let dedicated: Vec<FleetEntry> = snapshot.dedicated_proxies.to_vec();
        let (controllers, shared_proxies, dedicated_proxies) = tokio::join!(
            self.category_health(&controllers),
            self.category_health(&shared),
            self.category_health(&dedicated),
        );
        let body = serde_json::json!({
            "controllers": controllers,
            "shared_proxies": shared_proxies,
            "dedicated_proxies": dedicated_proxies,
        });
        json_response(body.to_string())
    }

    /// Probe a set of pods and reduce to a [`CategorySummary`] (count + worst
    /// severity).
    async fn category_health(&self, entries: &[FleetEntry]) -> CategorySummary {
        let probes = entries.iter().map(|e| async move {
            let url = format!("{}/api/v1/health", pod_base_url(e));
            match self.fetch_json(&url).await {
                None => Severity::Error,
                Some(body) if non_ready_checks(&body).is_empty() => Severity::Ok,
                Some(_) => Severity::Warn,
            }
        });
        CategorySummary::from_severities(join_all(probes).await)
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
    fn listener_tls_health_maps_conditions_to_severity() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
        let cond = |t: &str, s: &str| Condition {
            last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
            message: String::new(),
            observed_generation: None,
            reason: format!("{t}Reason"),
            status: s.to_string(),
            type_: t.to_string(),
        };
        // Both conditions True → genuinely good.
        let (sev, why) = listener_tls_health(Some(&[
            cond("ResolvedRefs", "True"),
            cond("Programmed", "True"),
        ]));
        assert_eq!(sev, Severity::Ok);
        assert!(why.is_none());
        // Cert ref unresolved → serves no TLS traffic → error, with the reason.
        let (sev, why) = listener_tls_health(Some(&[
            cond("ResolvedRefs", "False"),
            cond("Programmed", "True"),
        ]));
        assert_eq!(sev, Severity::Error);
        assert_eq!(why.as_deref(), Some("ResolvedRefsReason"));
        // Resolved but not yet programmed → warn.
        let (sev, _) = listener_tls_health(Some(&[
            cond("ResolvedRefs", "True"),
            cond("Programmed", "False"),
        ]));
        assert_eq!(sev, Severity::Warn);
        // No status reported yet → warn, never a confident ok.
        let (sev, _) = listener_tls_health(None);
        assert_eq!(sev, Severity::Warn);
    }

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
            vec![],
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
            k8s_version: OnceCell::new(),
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
            agg.get_proxy_routes("missing", &ListParams::default())
                .await
                .status(),
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
            vec![],
            ControllerSummary::new(false),
        );
        let cluster = SharedClusterSummary::default();
        cluster.store(std::sync::Arc::new(summary));
        let agg = make_agg(SharedFleet::default(), cluster);

        let resp = agg.list_gateways(&ListParams::default());
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
            vec![],
            ControllerSummary::new(false),
        );
        let cluster = SharedClusterSummary::default();
        cluster.store(std::sync::Arc::new(summary));
        let agg = make_agg(SharedFleet::default(), cluster);

        let resp = agg.list_ingresses(&ListParams::default());
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

        let resp = agg
            .get_proxy_routes("proxy-0", &ListParams::default())
            .await;
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

        let resp = agg
            .get_proxy_routes("proxy-0", &ListParams::default())
            .await;
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
    async fn list_controllers_reports_is_leader_from_health_endpoint() {
        // The /api/v1/health probe carries the top-level `leader` flag; the
        // reachable entry must surface it as is_leader so the UI doesn't misread a
        // healthy single-leader cluster as having no elected leader.
        let port = start_mock_http(r#"{"version":"0.0.0","leader":true,"subsystems":{}}"#).await;
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

    // ── effective-config serialization ────────────────────────────────────────

    #[test]
    fn httproute_rules_json_flattens_matches_backends_filters() {
        let spec: gw_types::v::httproutes::HttpRouteSpec =
            serde_json::from_value(serde_json::json!({
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "method": "GET",
                        "headers": [{"name": "x-env", "value": "prod"}],
                        "queryParams": [{"name": "v", "value": "2"}]
                    }],
                    "backendRefs": [
                        {"name": "api", "port": 8080, "weight": 90},
                        {"name": "api-canary", "port": 8080, "weight": 10}
                    ],
                    "filters": [{"type": "RequestRedirect", "requestRedirect": {}}]
                }]
            }))
            .expect("valid HTTPRoute spec");
        let v = httproute_rules_json(&spec);
        let rule = &v[0];
        assert_eq!(rule["matches"][0]["path"]["type"], "PathPrefix");
        assert_eq!(rule["matches"][0]["path"]["value"], "/api");
        assert_eq!(rule["matches"][0]["method"], "GET");
        assert_eq!(rule["matches"][0]["headers"][0]["name"], "x-env");
        assert_eq!(rule["matches"][0]["headers"][0]["type"], "Exact");
        assert_eq!(rule["matches"][0]["query_params"][0]["value"], "2");
        assert_eq!(rule["backends"][0]["weight"], 90);
        assert_eq!(rule["backends"][1]["name"], "api-canary");
        assert_eq!(rule["filters"][0], "RequestRedirect");
    }

    #[test]
    fn httproute_rules_json_defaults_path_when_match_omits_it() {
        // A rule with no `matches` still renders its backends; a match with no
        // path defaults to a PathPrefix on "/".
        let spec: gw_types::v::httproutes::HttpRouteSpec =
            serde_json::from_value(serde_json::json!({
                "rules": [
                    { "backendRefs": [{"name": "web", "port": 80}] },
                    { "matches": [{"method": "POST"}] }
                ]
            }))
            .expect("valid HTTPRoute spec");
        let v = httproute_rules_json(&spec);
        assert_eq!(
            v[0]["matches"].as_array().expect("matches is array").len(),
            0
        );
        assert_eq!(v[0]["backends"][0]["name"], "web");
        assert_eq!(v[1]["matches"][0]["path"]["type"], "PathPrefix");
        assert_eq!(v[1]["matches"][0]["path"]["value"], "/");
    }

    #[test]
    fn filter_kind_str_uses_gateway_api_spelling() {
        use gw_types::v::httproutes::HttpRouteRulesFiltersType as F;
        assert_eq!(filter_kind_str(&F::UrlRewrite), "URLRewrite");
        assert_eq!(filter_kind_str(&F::Cors), "CORS");
        assert_eq!(
            filter_kind_str(&F::RequestHeaderModifier),
            "RequestHeaderModifier"
        );
    }

    #[test]
    fn ingress_rules_json_maps_host_paths_backend_and_tls() {
        let spec: k8s_openapi::api::networking::v1::IngressSpec =
            serde_json::from_value(serde_json::json!({
                "ingressClassName": "coxswain",
                "tls": [{"hosts": ["demo.local"], "secretName": "demo-tls"}],
                "rules": [{
                    "host": "demo.local",
                    "http": {"paths": [
                        {"path": "/", "pathType": "Prefix",
                         "backend": {"service": {"name": "web", "port": {"number": 80}}}}
                    ]}
                }]
            }))
            .expect("valid Ingress spec");
        let rules = ingress_rules_json(&spec);
        assert_eq!(rules[0]["host"], "demo.local");
        assert_eq!(rules[0]["paths"][0]["path"], "/");
        assert_eq!(rules[0]["paths"][0]["path_type"], "Prefix");
        assert_eq!(rules[0]["paths"][0]["backend"]["service"], "web");
        assert_eq!(rules[0]["paths"][0]["backend"]["port"], "80");

        let tls = ingress_tls_json(&spec);
        assert_eq!(tls[0]["hosts"][0], "demo.local");
        assert_eq!(tls[0]["secret"], "demo-tls");
    }

    // ── route check helpers ─────────────────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn route_rows_for_filters_to_tagged_rows() {
        let routes = serde_json::json!({
            "gateway": { "hosts": [
                { "host": "api.demo.local", "port": 8080, "routes": [
                    {"name": "api-route", "namespace": "demo", "path": "/",
                     "backend_group": "demo/api", "endpoints": []},
                    {"name": "other", "namespace": "demo", "path": "/x",
                     "backend_group": "demo/other", "endpoints": ["1.2.3.4:80"]}
                ]}
            ]}
        });
        let rows = route_rows_for(&routes, "gateway", "demo", "api-route");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["host"], "api.demo.local");
        assert_eq!(rows[0]["path"], "/");
        assert_eq!(rows[0]["backend_group"], "demo/api");
        assert!(
            rows[0]["endpoints"]
                .as_array()
                .expect("endpoints array")
                .is_empty()
        );
    }

    #[test]
    fn serving_proxies_for_parents_picks_dedicated_else_shared() {
        let pods = [
            make_pod("shared-0", "shared-proxy", "10.0.0.1", "8082", None),
            make_pod("shared-1", "shared-proxy", "10.0.0.2", "8082", None),
            make_pod(
                "ded-demo",
                "dedicated-proxy",
                "10.0.0.3",
                "8082",
                Some("demo-gw"),
            ),
        ];
        let snap = build_snapshot(pods.iter());

        // Parent that owns a dedicated proxy → only that pod serves it.
        let dedicated_parent: Vec<gw_types::v::httproutes::HttpRouteParentRefs> =
            serde_json::from_value(serde_json::json!([{"name": "demo-gw"}]))
                .expect("valid parentRefs");
        let serving = serving_proxies_for_parents(&snap, "", &dedicated_parent);
        let names: Vec<&str> = serving.iter().map(|e| e.pod_name.as_str()).collect();
        assert_eq!(names, ["ded-demo"]);

        // Parent with no dedicated proxy → the shared pool serves it.
        let shared_parent: Vec<gw_types::v::httproutes::HttpRouteParentRefs> =
            serde_json::from_value(serde_json::json!([{"name": "shared-gw"}]))
                .expect("valid parentRefs");
        let serving = serving_proxies_for_parents(&snap, "", &shared_parent);
        let mut names: Vec<&str> = serving.iter().map(|e| e.pod_name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["shared-0", "shared-1"]);
    }
}
