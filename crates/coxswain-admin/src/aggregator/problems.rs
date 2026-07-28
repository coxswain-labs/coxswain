//! `/api/v1/problems` + `/api/v1/fleet/summary` — cross-cutting problem
//! aggregate and per-category fleet health.
//!
//! Three sources, one per class of question. Routing problems come from the
//! controller's own compiled snapshot (#537). Proxy and relay status comes from
//! the node registry and the Pod watch (#677) — their health rides the discovery
//! stream, so nothing here dials a data-plane pod. Only peer **controller**
//! replicas are still probed over HTTP, because controllers run a discovery
//! server rather than a client and no stream carries their health.

use http::Response;

use coxswain_core::cluster::{CategorySummary, Severity};
use coxswain_core::fleet::FleetEntry;
use coxswain_core::node_registry::NodeRegistry;
use futures::future::join_all;

use super::proxies::routes_block;
use super::{OperatorAggregator, json_response, non_ready_checks, pod_statusz_url};
use crate::page::ListParams;
use crate::routes_dto::{Problem, ProxyRoutes, RouteRef, RoutesResponse, RoutingProblems};

impl OperatorAggregator {
    /// `GET /api/v1/problems` — cluster-wide routing problems derived from the
    /// controller's own local routing snapshot (#537).
    ///
    /// Cross-cutting problem aggregate, namespaced by the two API axes (#301):
    /// ```json
    /// {
    ///   "fleet":   { "leaderless": bool, "not_ready": [pod…],
    ///                "disconnected": [pod…], "degraded": [pod…] },
    ///   "routing": { "conflicts": [...], "dead_routes": [...] }
    /// }
    /// ```
    ///
    /// `routing` conflicts/dead-routes come from [`Self::local_proxy_routes`]
    /// (deduped, `kind`-tagged) rather than a fan-out — no proxy query surface
    /// remains beyond metrics. `fleet` classes come from three authorities:
    /// `leaderless` from the Lease (so a leader that is momentarily unreachable
    /// does not raise a false alarm), the proxy classes from the node registry
    /// and the Pod watch (#677), and the controller classes from probing peer
    /// replicas' `/statusz` — the one hop with no stream to ride, since
    /// controllers are never discovery clients. The operator UI renders this
    /// directly rather than re-deriving severity client-side.
    pub(crate) async fn list_problems(&self, is_leader: bool) -> Response<Vec<u8>> {
        let raw = self.local_proxy_routes();
        let fleet = self.fleet_problems(is_leader).await;
        let routing = aggregate_problems(&raw);
        json_response(serde_json::json!({ "fleet": fleet, "routing": routing }).to_string())
    }

    /// Build a [`ProxyRoutes`] entry for every shared + dedicated proxy pod
    /// from the controller's own local routing state (#537) — no HTTP
    /// involved. Shared-pool pods all share one identical compiled table
    /// (read once per pod, cheap in-memory work, not a network round-trip);
    /// each dedicated pod reads its owning Gateway's registry entry via
    /// [`super::proxies::OperatorAggregator::local_route_tables`]. `reachable`
    /// is always `true` — this is a local read, not a liveness probe.
    /// Mirrors the shape the old per-pod HTTP fan-out produced, so
    /// [`aggregate_problems`]'s dedup logic is unchanged.
    fn local_proxy_routes(&self) -> Vec<ProxyRoutes> {
        let snapshot = self.fleet.load();
        let full = ListParams::default();
        snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .map(|e| {
                let (ingress, gateway) = self.local_route_tables(e);
                ProxyRoutes {
                    pod_name: e.pod_name.clone(),
                    reachable: true,
                    routes: Some(RoutesResponse {
                        ingress: routes_block(&ingress, &full),
                        gateway: routes_block(&gateway, &full),
                    }),
                }
            })
            .collect()
    }

    /// Bucket the fleet problem classes: `leaderless`, `not_ready`,
    /// `disconnected`, `degraded`. See [`Self::list_problems`].
    ///
    /// `not_ready` and `disconnected` are separate buckets, not one
    /// `unreachable` list, because the probe that used to conflate them is gone
    /// and the two now have genuinely different causes and remedies (#677):
    ///
    /// - `not_ready` — kubelet says the pod is not Ready. The pod is the
    ///   problem.
    /// - `disconnected` — the pod is Ready but holds no discovery stream, so it
    ///   is serving its last-good snapshot and will not pick up config changes.
    ///   The *path to the controller* is the problem.
    ///
    /// Collapsing them would misreport the case that motivated the split: a
    /// relay's stream dropping evicts its entire leaf subtree at once, so a
    /// single relay flap puts N pods in `disconnected` while every one of them
    /// is still `ready` and still serving traffic.
    async fn fleet_problems(&self, is_leader: bool) -> serde_json::Value {
        let snapshot = self.fleet.load();
        let any_controller = !snapshot.controllers.is_empty();
        let holder = self.lease_holder();

        let mut not_ready = Vec::new();
        let mut disconnected = Vec::new();
        let mut degraded = Vec::new();

        // ── proxies + relays: registry + Pod watch, no probe ────────────────
        //
        // A standby has an empty registry, which would read as "every proxy
        // disconnected". Skip the proxy classes entirely there rather than
        // publish that; the operator Service selects the leader, so this is the
        // direct-to-standby path only.
        if let Ok(registry) = self.require_registry(is_leader) {
            for e in snapshot
                .shared_proxies
                .iter()
                .chain(&snapshot.dedicated_proxies)
                .chain(&snapshot.relays)
            {
                let node = registry.nodes.get(&e.pod_name);
                // `ready == None` (condition not yet published) is unknown, not
                // a fault — a pod seconds into scheduling must not alarm.
                if e.ready == Some(false) {
                    not_ready.push(Self::entry_json(e));
                } else if node.is_none() {
                    disconnected.push(Self::entry_json(e));
                }
                if let Some(health) = node.and_then(|n| n.health.as_ref()) {
                    let checks = super::non_ready_check_names(&health.snapshot);
                    if !checks.is_empty() {
                        let mut v = Self::entry_json(e);
                        v["degraded_checks"] = serde_json::Value::from(checks);
                        degraded.push(v);
                    }
                }
            }
        }

        // ── controllers: the one hop that still probes ──────────────────────
        //
        // Controllers are never discovery clients (they run a discovery
        // *server*, and standbys reject inbound streams), so no stream carries
        // their health and `/statusz` is the only channel that can.
        let controllers: Vec<FleetEntry> = snapshot.controllers.to_vec();
        let probes = join_all(controllers.iter().map(|e| async move {
            let url = pod_statusz_url(e);
            (e, self.fetch_json(&url).await)
        }));
        for (e, body) in probes.await {
            match body {
                None => {
                    let mut v = Self::entry_json(e);
                    v["reachable"] = serde_json::Value::Bool(false);
                    not_ready.push(v);
                }
                Some(body) => {
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
            // From the Lease, not from any probe: a leader that is momentarily
            // unreachable still holds the lease, and reporting the cluster as
            // leaderless then would raise a false alarm for the one condition
            // this field exists to detect.
            "leaderless": any_controller && holder.is_none(),
            "not_ready": not_ready,
            "disconnected": disconnected,
            "degraded": degraded,
        })
    }

    /// `GET /api/v1/fleet/summary` — compact per-category counts + worst severity
    /// for controllers, shared proxies, and dedicated proxies (the Dashboard's
    /// three fleet tiles), plus `all_in_sync` for the topology convergence banner.
    /// Backs the tiles without shipping the full pod lists.
    ///
    /// Proxies are scored from the node registry and the Pod watch by
    /// [`proxy_severity`] — `error` when kubelet says not Ready, `warn` when
    /// disconnected or reporting a non-ready check. Only the controller tile is
    /// probed, via [`Self::category_health`].
    ///
    /// `all_in_sync` is **omitted** unless this replica can actually answer it.
    /// It reads the node registry, which only the leader populates — a standby
    /// would report `true` vacuously off an empty registry and the UI would hide
    /// a convergence warning that is genuinely firing on the leader. Absent
    /// means "unknown here"; the UI banner keys off an explicit `false`.
    pub(crate) async fn fleet_summary(&self, is_leader: bool) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let controllers: Vec<FleetEntry> = snapshot.controllers.to_vec();
        let registry = self.require_registry(is_leader).ok();
        let severities = |entries: &[FleetEntry]| {
            CategorySummary::from_severities(
                entries
                    .iter()
                    .map(|e| proxy_severity(e, registry.as_ref()))
                    .collect::<Vec<_>>(),
            )
        };
        let shared_proxies = severities(&snapshot.shared_proxies);
        let dedicated_proxies = severities(&snapshot.dedicated_proxies);
        let controllers = self.category_health(&controllers).await;
        let mut body = serde_json::json!({
            "controllers": controllers,
            "shared_proxies": shared_proxies,
            "dedicated_proxies": dedicated_proxies,
        });
        // Dev/proxy roles have no registry at all; a standby has an empty one.
        // Both are "cannot answer", not "everything is converged".
        if is_leader && let Some(reg) = self.node_registry.as_ref() {
            body["all_in_sync"] = serde_json::Value::Bool(reg.all_in_sync());
        }
        json_response(body.to_string())
    }

    /// Probe a set of **controller** pods and reduce to a [`CategorySummary`]
    /// (count + worst severity).
    ///
    /// Controllers only: proxies and relays are scored from the registry by
    /// [`proxy_severity`], with no probe. This remains a fan-out because
    /// controllers are never discovery clients, so nothing else can answer for
    /// a peer replica.
    async fn category_health(&self, entries: &[FleetEntry]) -> CategorySummary {
        let probes = entries.iter().map(|e| async move {
            let url = pod_statusz_url(e);
            match self.fetch_json(&url).await {
                None => Severity::Error,
                Some(body) if non_ready_checks(&body).is_empty() => Severity::Ok,
                Some(_) => Severity::Warn,
            }
        });
        CategorySummary::from_severities(join_all(probes).await)
    }
}

/// Score one proxy/relay pod for the fleet-summary tiles (#677).
///
/// Ranked worst-first so the tile shows the condition that most needs acting
/// on:
///
/// - `Error` — kubelet says not Ready, i.e. the pod itself is broken.
/// - `Warn`  — Ready but disconnected (serving a frozen snapshot), or Ready and
///   connected but reporting a non-ready check. Both are "still serving, needs
///   attention", which is precisely what amber means here.
/// - `Ok`    — Ready, connected, nothing degraded.
///
/// `registry` is `None` on a replica that cannot answer (a standby). Every pod
/// then scores `Ok` rather than `Warn`: the tile must not turn amber for the
/// whole fleet because *this replica* cannot see the streams — the accompanying
/// `all_in_sync` is omitted for the same reason.
fn proxy_severity(entry: &FleetEntry, registry: Option<&NodeRegistry>) -> Severity {
    if entry.ready == Some(false) {
        return Severity::Error;
    }
    let Some(registry) = registry else {
        return Severity::Ok;
    };
    let Some(node) = registry.nodes.get(&entry.pod_name) else {
        return Severity::Warn;
    };
    // An unreported node is "connected, health unknown" — not a fault. It is
    // the mid-rollout state of every pod on a pre-#677 build.
    match &node.health {
        Some(h) if !super::non_ready_check_names(&h.snapshot).is_empty() => Severity::Warn,
        _ => Severity::Ok,
    }
}

/// De-dupe and aggregate per-proxy [`ProxyRoutes`] results into the
/// `/api/v1/problems` payload. Split out from [`OperatorAggregator::list_problems`]
/// so it is unit-testable without touching the fleet snapshot.
///
/// Shared proxies carry an identical table, so each problem is keyed by
/// `(host, path, group, kind)` and de-duped across pods; `pods` lists which
/// proxies reported it. Each problem also carries `route: {kind, namespace, name}`
/// — the source Ingress/HTTPRoute identity — so the operator UI can deep-link the
/// card to that route in the Route Inspector. (For a conflict, this is the
/// rejected/shadowed route.)
fn aggregate_problems(raw: &[ProxyRoutes]) -> RoutingProblems {
    // (host, path, group, kind) → (route_ns, route_name, pods). BTreeMap for
    // stable output ordering.
    type ProblemMap =
        std::collections::BTreeMap<(String, String, String, String), (String, String, Vec<String>)>;
    let mut conflicts: ProblemMap = std::collections::BTreeMap::new();
    let mut dead_routes: ProblemMap = std::collections::BTreeMap::new();

    for proxy in raw {
        // `routes: None` ⇒ unreachable; skip (no problems to attribute).
        let Some(routes) = &proxy.routes else {
            continue;
        };
        let pod_name = &proxy.pod_name;

        for (spec, block) in [("ingress", &routes.ingress), ("gateway", &routes.gateway)] {
            for c in &block.conflicts {
                let key = (
                    c.host.clone(),
                    c.path.clone(),
                    c.rejected_group.clone(),
                    spec.to_owned(),
                );
                conflicts
                    .entry(key)
                    .or_insert_with(|| (c.namespace.clone(), c.name.clone(), Vec::new()))
                    .2
                    .push(pod_name.clone());
            }

            for host_group in &block.hosts {
                for route in &host_group.routes {
                    if route.endpoints.is_empty() {
                        let key = (
                            host_group.host.clone(),
                            route.path.clone(),
                            route.backend_group.clone(),
                            spec.to_owned(),
                        );
                        dead_routes
                            .entry(key)
                            .or_insert_with(|| {
                                (route.namespace.clone(), route.name.clone(), Vec::new())
                            })
                            .2
                            .push(pod_name.clone());
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

    let conflicts = conflicts
        .into_iter()
        .map(
            |((host, path, rejected_group, kind), (namespace, name, pods))| {
                let route = RouteRef {
                    kind: route_kind(&kind).to_owned(),
                    namespace,
                    name,
                };
                Problem {
                    host,
                    path,
                    kind,
                    rejected_group: Some(rejected_group),
                    backend_group: None,
                    pods,
                    route,
                }
            },
        )
        .collect();

    let dead_routes = dead_routes
        .into_iter()
        .map(
            |((host, path, backend_group, kind), (namespace, name, pods))| {
                let route = RouteRef {
                    kind: route_kind(&kind).to_owned(),
                    namespace,
                    name,
                };
                Problem {
                    host,
                    path,
                    kind,
                    rejected_group: None,
                    backend_group: Some(backend_group),
                    pods,
                    route,
                }
            },
        )
        .collect();

    RoutingProblems {
        conflicts,
        dead_routes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregator::tests::*;
    use crate::routes_dto::ProxyRoutes;
    use coxswain_core::cluster::SharedClusterSummary;
    use coxswain_core::health::CheckState;

    // ── fleet problem buckets (#677) ──────────────────────────────────────────

    /// Extract the pod names in one `fleet` bucket of a `/problems` payload.
    fn bucket(body: &serde_json::Value, name: &str) -> Vec<String> {
        body["fleet"][name]
            .as_array()
            .unwrap_or_else(|| panic!("fleet.{name} must be an array, got {body}"))
            .iter()
            .map(|v| v["pod_name"].as_str().unwrap_or_default().to_owned())
            .collect()
    }

    #[tokio::test]
    async fn a_ready_proxy_with_no_stream_is_disconnected_not_not_ready() {
        // The relay-flap case that motivated splitting the bucket: when a
        // relay's stream drops, `evict_children` removes its whole leaf subtree
        // at once. Every one of those pods is still Ready and still serving
        // traffic on its last-good snapshot, so reporting them as dead pods
        // would raise N false alarms for one real problem.
        let pods = [
            make_pod("proxy-cut", "shared-proxy", "10.0.0.1", "8082", None),
            make_pod("proxy-ok", "shared-proxy", "10.0.0.2", "8082", None),
        ];
        let agg = make_agg_with_registry(
            fleet_with(pods),
            SharedClusterSummary::default(),
            registry_with([(
                "proxy-ok",
                Some(vec![("routing_table_loaded", CheckState::Ready)]),
            )]),
        );

        let resp = agg.list_problems(true).await;
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();

        assert_eq!(bucket(&body, "disconnected"), ["proxy-cut"]);
        assert!(
            bucket(&body, "not_ready").is_empty(),
            "a lost stream is not a dead pod: {body}"
        );
        assert!(bucket(&body, "degraded").is_empty());
    }

    #[tokio::test]
    async fn a_not_ready_pod_is_bucketed_by_kubelet_not_by_its_stream() {
        // The converse: the pod holds a perfectly good stream but kubelet says
        // it is not Ready. That belongs in `not_ready`, and must NOT also appear
        // in `disconnected` — one problem, one bucket, or the dashboard
        // double-counts it.
        let pods = [make_pod_not_ready("proxy-sick", "shared-proxy", "10.0.0.1")];
        let agg = make_agg_with_registry(
            fleet_with(pods),
            SharedClusterSummary::default(),
            registry_with([(
                "proxy-sick",
                Some(vec![("routing_table_loaded", CheckState::Ready)]),
            )]),
        );

        let resp = agg.list_problems(true).await;
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();

        assert_eq!(bucket(&body, "not_ready"), ["proxy-sick"]);
        assert!(
            bucket(&body, "disconnected").is_empty(),
            "a not-Ready pod that is streaming is not disconnected: {body}"
        );
    }

    #[tokio::test]
    async fn a_non_ready_check_reported_over_the_stream_lands_in_degraded() {
        let pods = [make_pod(
            "proxy-0",
            "shared-proxy",
            "10.0.0.1",
            "8082",
            None,
        )];
        let agg = make_agg_with_registry(
            fleet_with(pods),
            SharedClusterSummary::default(),
            registry_with([(
                "proxy-0",
                Some(vec![(
                    "routing_table_loaded",
                    CheckState::Failed {
                        reason: std::sync::Arc::from("snapshot rejected"),
                    },
                )]),
            )]),
        );

        let resp = agg.list_problems(true).await;
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();

        assert_eq!(bucket(&body, "degraded"), ["proxy-0"]);
        assert_eq!(
            body["fleet"]["degraded"][0]["degraded_checks"],
            serde_json::json!(["proxy/routing_table_loaded"])
        );
        assert!(
            bucket(&body, "not_ready").is_empty(),
            "a degraded check keeps /readyz at 200, so the pod is still Ready"
        );
    }

    #[tokio::test]
    async fn a_relay_is_bucketed_alongside_proxies() {
        // Relays report health on the same channel and are equally capable of
        // being disconnected; leaving them out would make the relay tier the one
        // component whose failure the problems view cannot see.
        let pods = [make_pod("relay-0", "relay", "10.0.0.1", "8082", None)];
        let agg = make_agg_with_registry(
            fleet_with(pods),
            SharedClusterSummary::default(),
            registry_with([]),
        );

        let resp = agg.list_problems(true).await;
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(bucket(&body, "disconnected"), ["relay-0"]);
    }

    #[tokio::test]
    async fn a_standby_reports_no_proxy_problems_rather_than_inventing_them() {
        // A standby's registry is empty, so every proxy would read as
        // disconnected. Publishing that would page an operator for a cluster
        // that is entirely healthy.
        let pods = [make_pod(
            "proxy-0",
            "shared-proxy",
            "10.0.0.1",
            "8082",
            None,
        )];
        let agg = make_agg_with_registry(
            fleet_with(pods),
            SharedClusterSummary::default(),
            registry_with([]),
        );

        let resp = agg.list_problems(false).await;
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert!(
            bucket(&body, "disconnected").is_empty(),
            "a standby cannot see streams and must not guess: {body}"
        );
    }

    // ── all_in_sync leader gating (#676) ──────────────────────────────────────

    #[tokio::test]
    async fn fleet_summary_omits_all_in_sync_on_a_standby() {
        // A standby's registry is empty because it accepts no discovery
        // streams, so `all_in_sync()` reads vacuously true there. Publishing
        // that would hide a convergence warning genuinely firing on the leader.
        // Absent means "cannot answer here"; the UI banner keys on an explicit
        // `false`, so absence is safe and a stray `true` is not.
        let reg = coxswain_core::node_registry::NodeRegistryHandle::new();
        let agg = make_agg_with_registry(
            coxswain_core::fleet::SharedFleet::default(),
            SharedClusterSummary::default(),
            reg,
        );

        let resp = agg.fleet_summary(false).await;

        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap_or_default();
        assert!(
            body.get("all_in_sync").is_none(),
            "a standby must not answer the convergence question at all, got {body}"
        );
    }

    #[tokio::test]
    async fn fleet_summary_reports_all_in_sync_on_the_leader() {
        // The counterpart: without this, omitting the key unconditionally would
        // also satisfy the assertion above and the banner would never fire.
        let reg = coxswain_core::node_registry::NodeRegistryHandle::new();
        let agg = make_agg_with_registry(
            coxswain_core::fleet::SharedFleet::default(),
            SharedClusterSummary::default(),
            reg,
        );

        let resp = agg.fleet_summary(true).await;

        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap_or_default();
        assert!(
            body.get("all_in_sync").is_some(),
            "the leader must answer the convergence question, got {body}"
        );
    }

    // ── local_proxy_routes (#537) ─────────────────────────────────────────────

    #[test]
    fn local_proxy_routes_attributes_every_shared_and_dedicated_pod() {
        // No mock HTTP server: local_proxy_routes reads the aggregator's own
        // (default-empty) table cells directly, one entry per fleet pod.
        let pods = [
            make_pod("shared-0", "shared-proxy", "10.0.0.1", "8082", None),
            make_pod("shared-1", "shared-proxy", "10.0.0.2", "8082", None),
            make_pod("ded-0", "dedicated-proxy", "10.0.0.3", "8082", Some("gw-a")),
        ];
        let agg = make_agg(fleet_with(pods), SharedClusterSummary::default());

        let raw = agg.local_proxy_routes();
        let mut names: Vec<&str> = raw.iter().map(|p| p.pod_name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["ded-0", "shared-0", "shared-1"]);
        // Every entry is a local read — always reachable, always carries a body,
        // never the `routes: None` shape an HTTP timeout used to produce.
        assert!(
            raw.iter().all(|p| p.reachable && p.routes.is_some()),
            "local read never reports unreachable"
        );
    }

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
            "port": 80,
            "host": "api.example.com",
            "type": "exact",
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
        let raw: Vec<ProxyRoutes> = vec![
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
        ]
        .into_iter()
        .map(|v| serde_json::from_value(v).expect("fixture deserialises into ProxyRoutes"))
        .collect();

        // Serialise the typed aggregate back to a Value so the structural
        // assertions below exercise the full round-trip.
        let out =
            serde_json::to_value(aggregate_problems(&raw)).expect("problems serialise to Value");

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
