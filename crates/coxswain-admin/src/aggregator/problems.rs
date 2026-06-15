//! `/api/v1/problems` + `/api/v1/fleet/summary` — cross-cutting problem
//! aggregate and per-category fleet health, derived from fan-out probes.

use http::Response;

use coxswain_core::cluster::{CategorySummary, Severity};
use coxswain_core::fleet::FleetEntry;
use futures::future::join_all;

use super::{OperatorAggregator, json_response, non_ready_checks, pod_base_url};

impl OperatorAggregator {
    /// `GET /api/v1/problems` — cluster-wide routing problems derived from
    /// fan-out to all proxy `/api/v1/routes` endpoints.
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
    /// `/api/v1/routes` (deduped, `kind`-tagged). `fleet` classes come from probing each
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

/// De-dupe and aggregate fanned-out proxy `/api/v1/routes` results into the
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
