//! `/api/v1/proxies` endpoints — shared + dedicated proxy pods with status.
//!
//! Every field here comes from a source the controller already holds, and none
//! from a probe of the pod (#677). Three questions, three authorities:
//!
//! - **"is this pod alive?"** — the Pod's `Ready` condition, off the watch the
//!   controller already runs. Kubelet ran the probe; re-running it from here
//!   only adds a way to be wrong when the controller→pod path breaks.
//! - **"is it taking config?"** — the node registry, fed by the pod's own
//!   authenticated discovery stream.
//! - **"what is broken on it?"** — the health report riding that same stream.
//!
//! These endpoints therefore answer only on the leader, which is where the
//! registry lives; see [`OperatorAggregator::require_registry`].

use http::Response;

use coxswain_core::fleet::{Component, FleetEntry};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::routing::{GatewayRoutingTable, IngressRoutingTable, RoutingTable};
use std::collections::BTreeSet;
use std::sync::Arc;

use super::{OperatorAggregator, attach_node_status, json_response, not_found};
use crate::page::ListParams;
use crate::routes_dto::{ConflictRow, HostGroup, RouteBlock, RouteRow, RoutesResponse};

impl OperatorAggregator {
    /// `GET /api/v1/fleet/proxies` — all shared + dedicated proxy pods.
    ///
    /// 503 on a standby, per [`Self::require_registry`].
    pub(crate) fn list_proxies(&self, is_leader: bool) -> Response<Vec<u8>> {
        let registry = match self.require_registry(is_leader) {
            Ok(reg) => reg,
            Err(resp) => return *resp,
        };
        let snapshot = self.fleet.load();
        let results: Vec<serde_json::Value> = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .map(|e| {
                // The full entry (component, namespace, restarts, …) is carried
                // even for a disconnected pod: losing the stream does not lose
                // the pod's identity, and "which pool was that dead pod in" is
                // exactly what an operator needs then.
                let mut v = Self::entry_json(e);
                attach_node_status(&mut v, registry.nodes.get(&e.pod_name));
                v
            })
            .collect();
        json_response(serde_json::json!({ "proxies": results }).to_string())
    }

    /// `GET /api/v1/fleet/proxies/{pod-name}` — single proxy pod status.
    ///
    /// 503 on a standby, per [`Self::require_registry`].
    pub(crate) fn get_proxy(&self, pod_name: &str, is_leader: bool) -> Response<Vec<u8>> {
        let registry = match self.require_registry(is_leader) {
            Ok(reg) => reg,
            Err(resp) => return *resp,
        };
        let snapshot = self.fleet.load();
        let entry = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .find(|e| e.pod_name == pod_name);
        let Some(entry) = entry else {
            return not_found();
        };
        let mut v = Self::entry_json(entry);
        attach_node_status(&mut v, registry.nodes.get(pod_name));
        json_response(v.to_string())
    }

    /// `GET /api/v1/fleet/proxies/{pod-name}/routes` — this pod's compiled
    /// routing table, filtered/windowed by `params` (#286).
    ///
    /// Read from the controller's own local snapshot (#537) rather than an
    /// HTTP fan-out to the pod: the controller computed this pod's routing
    /// world and pushed it over the discovery stream, so it already holds
    /// exactly what the proxy would report.
    ///
    /// Carries no status field. It used to emit a constant `reachable: true`,
    /// left over from the fan-out it replaced — nothing read it, and keeping a
    /// second, differently-defined `reachable` on the proxy surface after #677
    /// split the real one into `ready`/`connected` would only invite reading
    /// this one as pod liveness. That question is
    /// `/api/v1/fleet/proxies/{name}/health`.
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
        let (ingress, gateway) = self.local_route_tables(entry);
        let routes = RoutesResponse {
            ingress: routes_block(&ingress, params),
            gateway: routes_block(&gateway, params),
        };
        json_response(serde_json::json!({ "pod_name": pod_name, "routes": routes }).to_string())
    }

    /// `GET /api/v1/fleet/proxies/{pod-name}/facets` — this pod's distinct
    /// hosts + route namespaces (the route table's filter-dropdown options).
    ///
    /// Same local re-source as [`Self::get_proxy_routes`] (#537): a Gateway
    /// not yet in the dedicated registry (cutover in flight) reads as empty
    /// lists, so the UI's combos just offer "All …" until the snapshot lands.
    pub(crate) async fn get_proxy_facets(&self, pod_name: &str) -> Response<Vec<u8>> {
        let snapshot = self.fleet.load();
        let entry = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .find(|e| e.pod_name == pod_name);
        let Some(entry) = entry else {
            return not_found();
        };
        let (ingress, gateway) = self.local_route_tables(entry);
        let mut hosts: BTreeSet<String> = BTreeSet::new();
        let mut namespaces: BTreeSet<String> = BTreeSet::new();
        collect_facets(&ingress, &mut hosts, &mut namespaces);
        collect_facets(&gateway, &mut hosts, &mut namespaces);
        json_response(
            serde_json::json!({
                "hosts": hosts.into_iter().collect::<Vec<_>>(),
                "namespaces": namespaces.into_iter().collect::<Vec<_>>(),
            })
            .to_string(),
        )
    }

    /// Resolve the routing tables backing `entry`'s scope (#537).
    ///
    /// `SharedProxy` (and any future component — the dumb-proxy model has
    /// exactly two proxy roles today) reads the controller's shared-pool
    /// tables; `DedicatedProxy` reads its owning Gateway's entry in the
    /// dedicated registry, keyed by `(pod_namespace, gateway_ref)` — the
    /// dedicated-proxy Deployment is always rendered into its Gateway's own
    /// namespace, so the pod's namespace *is* the Gateway's namespace. A
    /// Gateway missing from the registry (cutover in flight, or a
    /// `gateway_ref` somehow absent) reads as an empty pair of tables rather
    /// than an error — matches the discovery server's own fail-closed
    /// behaviour for an unregistered dedicated scope.
    pub(super) fn local_route_tables(
        &self,
        entry: &FleetEntry,
    ) -> (Arc<IngressRoutingTable>, Arc<GatewayRoutingTable>) {
        match entry.component {
            Component::DedicatedProxy => {
                let dedicated = entry.gateway_ref.as_deref().and_then(|name| {
                    let key = ObjectKey::new(entry.pod_namespace.clone(), name.to_owned());
                    self.dedicated_registry.load().map.get(&key).cloned()
                });
                match dedicated {
                    Some(snap) => (
                        Arc::new(IngressRoutingTable::default()),
                        Arc::clone(&snap.gateway),
                    ),
                    None => (
                        Arc::new(IngressRoutingTable::default()),
                        Arc::new(GatewayRoutingTable::default()),
                    ),
                }
            }
            _ => (self.ingress_routes.load(), self.gateway_routes.load()),
        }
    }

    /// `GET /api/v1/fleet/proxies/{pod-name}/health` — that pod's subsystem
    /// detail, as it last reported over the discovery stream (#677).
    ///
    /// The `health` body is byte-identical to what the pod's own `/statusz`
    /// renders — same `HealthSnapshot` type, same `Serialize` impl — so this
    /// swapped its source without changing its shape.
    ///
    /// `health` is **absent** when the node has not reported: a pod that just
    /// connected, or a pre-#677 build mid-rollout. Absent means "unknown here",
    /// which the UI must not render as unhealthy; `connected` distinguishes it
    /// from a pod that is not streaming at all.
    ///
    /// 503 on a standby, per [`Self::require_registry`].
    pub(crate) fn get_proxy_health(&self, pod_name: &str, is_leader: bool) -> Response<Vec<u8>> {
        let registry = match self.require_registry(is_leader) {
            Ok(reg) => reg,
            Err(resp) => return *resp,
        };
        let snapshot = self.fleet.load();
        let entry = snapshot
            .shared_proxies
            .iter()
            .chain(&snapshot.dedicated_proxies)
            .find(|e| e.pod_name == pod_name);
        let Some(entry) = entry else {
            return not_found();
        };
        let node = registry.nodes.get(pod_name);
        let mut body = serde_json::json!({
            "pod_name": pod_name,
            "ready": entry.ready,
            "connected": node.is_some(),
        });
        if let Some(health) = node.and_then(|n| n.health.as_ref()) {
            body["health"] = serde_json::json!({
                "version": health.version,
                "subsystems": health.snapshot.subsystems,
            });
            body["reported_at"] = serde_json::Value::String(super::fmt_rfc3339(health.reported_at));
        }
        json_response(body.to_string())
    }
}

/// Collect the distinct hosts and route namespaces from one typed table into
/// the shared sorted sets (`BTreeSet` keeps them de-duplicated and ordered
/// for a stable dropdown). Skips placeholder routes with no backend, matching
/// the rows the route table actually shows.
pub(super) fn collect_facets<K>(
    table: &RoutingTable<K>,
    hosts: &mut BTreeSet<String>,
    namespaces: &mut BTreeSet<String>,
) {
    for (_port, host, router) in table.host_routes() {
        hosts.insert(host.clone());
        for r in router
            .routes()
            .iter()
            .filter(|r| !r.backend_group.name().is_empty())
        {
            if let Some((ns, _)) = r.route_id.split_once('/').filter(|(ns, _)| !ns.is_empty()) {
                namespaces.insert(ns.to_string());
            }
        }
    }
}

/// Build the per-spec block of a proxy's routes payload from a typed table.
///
/// Generic over `Kind` so the same body serialises both the Ingress and the
/// Gateway-API tables; the type parameter prevents the caller from passing the
/// wrong table to the wrong block label.
///
/// `params` filter the flattened route rows by `host` (exact), `path` (substring),
/// `namespace` (exact, the route's namespace) and `status=problem` (keep only
/// dead-backend rows — zero ready endpoints), then window them by `limit`/`offset`.
/// The same host/path/namespace predicates also narrow the conflict list (a
/// conflict belongs to a host/path and a rejected route's namespace), so a scoped
/// view shows only the conflicts in scope; `problems_only` leaves conflicts whole
/// (a conflict is itself a problem). When [`ListParams::is_empty`] the output is
/// structurally the legacy full dump; when any param is set the block also carries
/// `total`/`returned`/`offset` over the post-filter rows.
pub(super) fn routes_block<K>(table: &RoutingTable<K>, params: &ListParams) -> RouteBlock {
    // Flatten to (port, host, RouteRow) so the offset/limit window applies across
    // the whole table, not per host-group. The exact `host` filter skips a whole
    // host-group; `path`/`namespace` filter per row.
    let mut matched: Vec<(u16, String, RouteRow)> = Vec::new();
    for (port, host, router) in table.host_routes() {
        if !params.host_matches(&host) {
            continue;
        }
        for r in router
            .routes()
            .iter()
            .filter(|r| !r.backend_group.name().is_empty())
        {
            if !params.path_matches(&r.path) {
                continue;
            }
            // `RouteRow::from_info` splits `route_id` into `namespace`/`name` so the
            // UI can deep-link a compiled row back to its source resource.
            let row = RouteRow::from_info(r);
            if !params.namespace_matches(&row.namespace) {
                continue;
            }
            // `status=problem`: a compiled route "with a problem" is one serving
            // zero ready endpoints (a dead backend) — the only per-row health the
            // compiled table can see.
            if params.problems_only && !row.endpoints.is_empty() {
                continue;
            }
            matched.push((port, host.clone(), row));
        }
    }

    let total = matched.len();
    let offset = params.offset.min(total);
    let limit = params.effective_limit();
    let windowed: Vec<(u16, String, RouteRow)> = if params.is_empty() {
        matched
    } else {
        matched.into_iter().skip(offset).take(limit).collect()
    };
    let returned = windowed.len();

    // Regroup the (possibly windowed) rows back into `(port, host)` host-groups.
    let mut hosts: Vec<HostGroup> = Vec::new();
    for (port, host, route) in windowed {
        match hosts.last_mut() {
            Some(last) if last.port == port && last.host == host => last.routes.push(route),
            _ => hosts.push(HostGroup {
                port,
                host,
                routes: vec![route],
            }),
        }
    }

    let conflicts: Vec<ConflictRow> = table
        .conflicts()
        .iter()
        .map(ConflictRow::from_conflict)
        // Narrow conflicts by the same host/path/namespace scope as the rows
        // (problems_only is intentionally ignored — a conflict is a problem).
        .filter(|c| {
            params.host_matches(&c.host)
                && params.path_matches(&c.path)
                && params.namespace_matches(&c.namespace)
        })
        .collect();

    if params.is_empty() {
        RouteBlock {
            hosts,
            conflicts,
            ..RouteBlock::default()
        }
    } else {
        RouteBlock {
            hosts,
            conflicts,
            total: Some(total),
            returned: Some(returned),
            offset: Some(offset),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregator::tests::*;
    use coxswain_core::cluster::SharedClusterSummary;
    use coxswain_core::fleet::SharedFleet;
    use coxswain_core::health::CheckState;
    use http::StatusCode;

    // ── fleet-miss 404 ────────────────────────────────────────────────────────

    /// Aggregator over `pods` whose registry holds `nodes`, on the leader.
    fn agg_with(
        pods: impl IntoIterator<Item = k8s_openapi::api::core::v1::Pod>,
        nodes: impl IntoIterator<Item = (&'static str, Option<Vec<(&'static str, CheckState)>>)>,
    ) -> OperatorAggregator {
        make_agg_with_registry(
            fleet_with(pods),
            SharedClusterSummary::default(),
            registry_with(nodes),
        )
    }

    /// A single healthy check set, the common case.
    fn healthy() -> Option<Vec<(&'static str, CheckState)>> {
        Some(vec![("routing_table_loaded", CheckState::Ready)])
    }

    #[test]
    fn get_proxy_returns_404_when_pod_not_in_fleet() {
        let agg = agg_with([], []);
        assert_eq!(
            agg.get_proxy("missing", true).status(),
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

    #[test]
    fn get_proxy_health_returns_404_when_pod_not_in_fleet() {
        let agg = agg_with([], []);
        assert_eq!(
            agg.get_proxy_health("missing", true).status(),
            StatusCode::NOT_FOUND
        );
    }

    // ── leader gate (#677) ────────────────────────────────────────────────────

    #[test]
    fn proxy_views_return_503_on_a_standby_rather_than_an_all_disconnected_fleet() {
        // A standby accepts no discovery streams, so its registry is EMPTY, not
        // partial. Serving it would report every proxy in the cluster as
        // disconnected — indistinguishable from a real outage. 503 is the only
        // honest answer.
        let agg = agg_with(
            [make_pod(
                "proxy-0",
                "shared-proxy",
                "10.0.0.1",
                "8082",
                None,
            )],
            [("proxy-0", healthy())],
        );

        for (label, resp) in [
            ("list", agg.list_proxies(false)),
            ("get", agg.get_proxy("proxy-0", false)),
            ("health", agg.get_proxy_health("proxy-0", false)),
        ] {
            assert_eq!(
                resp.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{label} must refuse to answer on a standby, got {}",
                resp.status()
            );
        }
    }

    // ── list_proxies ──────────────────────────────────────────────────────────

    #[test]
    fn list_proxies_empty_fleet_returns_empty_array() {
        let agg = agg_with([], []);
        let resp = agg.list_proxies(true);
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["proxies"], serde_json::json!([]));
    }

    #[test]
    fn list_proxies_reports_ready_and_connected_as_independent_facts() {
        // The heart of #677. Three pods, three distinct states that the old
        // single `reachable` bit could not tell apart:
        //   - converged:    Ready + streaming
        //   - disconnected: Ready + serving traffic, but stream gone (a relay
        //                   flap evicts N of these at once)
        //   - not_ready:    kubelet says the pod itself is broken
        let pods = [
            make_pod("proxy-ok", "shared-proxy", "10.0.0.1", "8082", None),
            make_pod("proxy-cut", "shared-proxy", "10.0.0.2", "8082", None),
            make_pod_not_ready("proxy-sick", "shared-proxy", "10.0.0.3"),
        ];
        // Only proxy-ok and proxy-sick hold streams; proxy-cut's is gone.
        let agg = agg_with(pods, [("proxy-ok", healthy()), ("proxy-sick", healthy())]);

        let resp = agg.list_proxies(true);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        let proxies = body["proxies"].as_array().unwrap();
        let by_name = |n: &str| {
            proxies
                .iter()
                .find(|p| p["pod_name"] == n)
                .unwrap_or_else(|| panic!("{n} missing from the proxy list"))
        };

        assert_eq!(by_name("proxy-ok")["ready"], true);
        assert_eq!(by_name("proxy-ok")["connected"], true);
        assert_eq!(by_name("proxy-ok")["health"], "ready");
        assert_eq!(by_name("proxy-ok")["version"], "1.2.3");

        assert_eq!(
            by_name("proxy-cut")["ready"],
            true,
            "a lost stream says nothing about whether the pod is alive"
        );
        assert_eq!(by_name("proxy-cut")["connected"], false);

        assert_eq!(by_name("proxy-sick")["ready"], false);
        assert_eq!(
            by_name("proxy-sick")["connected"],
            true,
            "a not-Ready pod can still hold its stream"
        );
    }

    #[test]
    fn list_proxies_keeps_pod_identity_for_a_disconnected_pod() {
        // Losing the stream must not lose the fleet-snapshot identity: "which
        // pool was that dead pod in" is exactly what an operator needs then.
        let pods = [make_pod(
            "ded-0",
            "dedicated-proxy",
            "10.0.0.1",
            "8082",
            Some("gw-a"),
        )];
        let agg = agg_with(pods, []);

        let resp = agg.list_proxies(true);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        let entry = &body["proxies"][0];
        assert_eq!(entry["connected"], false);
        assert_eq!(entry["component"], "dedicated-proxy");
        assert_eq!(entry["gateway_ref"], "gw-a");
    }

    #[test]
    fn a_connected_pod_that_has_not_reported_health_is_not_rendered_unhealthy() {
        // Mid-rollout, a pre-#677 build streams but sends no HealthReport. That
        // must read as "connected, health unknown" — rendering it degraded would
        // turn every rolling upgrade into a fleet-wide alarm.
        let pods = [make_pod(
            "proxy-old",
            "shared-proxy",
            "10.0.0.1",
            "8082",
            None,
        )];
        let agg = agg_with(pods, [("proxy-old", None)]);

        let resp = agg.list_proxies(true);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        let entry = &body["proxies"][0];
        assert_eq!(entry["connected"], true);
        assert_eq!(entry["ready"], true);
        assert!(
            entry.get("health").is_none(),
            "absent, not \"degraded\": got {entry}"
        );
        assert!(entry.get("degraded_checks").is_none());
    }

    #[test]
    fn a_non_ready_check_surfaces_as_degraded_with_the_check_named() {
        let pods = [make_pod(
            "proxy-0",
            "shared-proxy",
            "10.0.0.1",
            "8082",
            None,
        )];
        let agg = agg_with(
            pods,
            [(
                "proxy-0",
                Some(vec![(
                    "routing_table_loaded",
                    CheckState::Degraded {
                        reason: std::sync::Arc::from("snapshot stale"),
                    },
                )]),
            )],
        );

        let resp = agg.list_proxies(true);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        let entry = &body["proxies"][0];
        assert_eq!(entry["health"], "degraded");
        assert_eq!(
            entry["degraded_checks"],
            serde_json::json!(["proxy/routing_table_loaded"]),
            "the check must be named subsystem/check so the UI can point at it"
        );
    }

    // ── get_proxy / get_proxy_health ──────────────────────────────────────────

    #[test]
    fn get_proxy_returns_pod_info_with_both_status_fields() {
        let pods = [make_pod(
            "proxy-0",
            "shared-proxy",
            "10.0.0.1",
            "8082",
            None,
        )];
        let agg = agg_with(pods, [("proxy-0", healthy())]);

        let resp = agg.get_proxy("proxy-0", true);
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["pod_name"], "proxy-0");
        assert_eq!(body["ready"], true);
        assert_eq!(body["connected"], true);
        assert_eq!(body["component"], "shared-proxy");
    }

    #[test]
    fn get_proxy_health_returns_the_reported_subsystem_tree() {
        // The `health` body must keep the shape `/statusz` produced, so the UI's
        // per-pod health view did not change contract when its source did.
        let pods = [make_pod(
            "proxy-0",
            "shared-proxy",
            "10.0.0.1",
            "8082",
            None,
        )];
        let agg = agg_with(pods, [("proxy-0", healthy())]);

        let resp = agg.get_proxy_health("proxy-0", true);
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["pod_name"], "proxy-0");
        assert_eq!(body["connected"], true);
        assert_eq!(body["health"]["version"], "1.2.3");
        assert_eq!(
            body["health"]["subsystems"]["proxy"]["checks"]["routing_table_loaded"]["state"],
            "ready"
        );
        assert!(body.get("reported_at").is_some());
    }

    #[test]
    fn get_proxy_health_omits_health_for_a_pod_that_has_not_reported() {
        let pods = [make_pod(
            "proxy-0",
            "shared-proxy",
            "10.0.0.1",
            "8082",
            None,
        )];
        let agg = agg_with(pods, []);

        let resp = agg.get_proxy_health("proxy-0", true);
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["connected"], false);
        assert!(
            body.get("health").is_none(),
            "no report yet means absent, not an empty or failed tree: got {body}"
        );
    }

    // ── local re-source: get_proxy_routes / get_proxy_facets (#537) ──────────

    #[tokio::test]
    async fn get_proxy_routes_shared_pod_reads_local_shared_tables() {
        // No mock HTTP server involved any more: the shared pool's routes are
        // read straight from the aggregator's own (here, default-empty) table
        // cells — the same ones the discovery server pushes to proxies.
        let pod = make_pod("proxy-0", "shared-proxy", "127.0.0.1", "8082", None);
        let agg = make_agg(fleet_with([pod]), SharedClusterSummary::default());

        let resp = agg
            .get_proxy_routes("proxy-0", &ListParams::default())
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["pod_name"], "proxy-0");
        assert!(
            body.get("reachable").is_none(),
            "the routes view carries no status field — that question belongs to \
             /health, and a second `reachable` with a different meaning would be \
             read as pod liveness; body: {body}"
        );
        assert_eq!(body["routes"]["ingress"]["hosts"], serde_json::json!([]));
        assert_eq!(body["routes"]["gateway"]["hosts"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn get_proxy_routes_dedicated_pod_without_registry_entry_reads_empty_tables() {
        // A dedicated proxy pod whose Gateway hasn't landed in the dedicated
        // registry yet (cutover in flight) must fail open to empty tables,
        // not 404/error — mirrors the discovery server's own behaviour for an
        // unregistered dedicated scope.
        let pod = make_pod(
            "ded-0",
            "dedicated-proxy",
            "127.0.0.1",
            "8082",
            Some("gw-a"),
        );
        let agg = make_agg(fleet_with([pod]), SharedClusterSummary::default());

        let resp = agg.get_proxy_routes("ded-0", &ListParams::default()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["routes"]["ingress"]["hosts"], serde_json::json!([]));
        assert_eq!(body["routes"]["gateway"]["hosts"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn get_proxy_facets_shared_pod_returns_empty_lists_by_default() {
        let pod = make_pod("proxy-0", "shared-proxy", "127.0.0.1", "8082", None);
        let agg = make_agg(fleet_with([pod]), SharedClusterSummary::default());

        let resp = agg.get_proxy_facets("proxy-0").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["hosts"], serde_json::json!([]));
        assert_eq!(body["namespaces"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn get_proxy_facets_returns_404_when_pod_not_in_fleet() {
        let agg = make_agg(SharedFleet::default(), SharedClusterSummary::default());
        assert_eq!(
            agg.get_proxy_facets("missing").await.status(),
            StatusCode::NOT_FOUND
        );
    }
}
