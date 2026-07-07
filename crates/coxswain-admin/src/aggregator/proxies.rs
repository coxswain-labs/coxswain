//! `/api/v1/proxies` endpoints — shared + dedicated proxy pods with liveness.

use http::Response;

use coxswain_core::fleet::{Component, FleetEntry};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::routing::{GatewayRoutingTable, IngressRoutingTable, RoutingTable};
use futures::future::join_all;
use std::collections::BTreeSet;
use std::sync::Arc;

use super::{OperatorAggregator, attach_health_rollup, json_response, not_found, pod_base_url};
use crate::page::ListParams;
use crate::routes_dto::{ConflictRow, HostGroup, RouteBlock, RouteRow, RoutesResponse};

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

    /// `GET /api/v1/fleet/proxies/{pod-name}/routes` — this pod's compiled
    /// routing table, filtered/windowed by `params` (#286).
    ///
    /// Read from the controller's own local snapshot (#537) rather than an
    /// HTTP fan-out to the pod: the controller computed this pod's routing
    /// world and pushed it over the discovery stream, so it already holds
    /// exactly what the proxy would report. `reachable` is `true` whenever
    /// `pod_name` is a known fleet member — there is no network call left to
    /// fail here; pod-level liveness is `/api/v1/fleet/proxies/{name}/health`.
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
        json_response(
            serde_json::json!({ "pod_name": pod_name, "reachable": true, "routes": routes })
                .to_string(),
        )
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
                    self.dedicated_registry.load().get(&key).cloned()
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
    use http::StatusCode;

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
        assert_eq!(body["reachable"], true);
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
        assert_eq!(body["reachable"], true);
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
}
