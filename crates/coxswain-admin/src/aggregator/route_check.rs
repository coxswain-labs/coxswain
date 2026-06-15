//! Route check (data-plane consistency) helpers — pure functions backing
//! `…/routes/{kind}/{ns}/{name}/check`: resolving the serving proxies for a
//! route and diffing route-tagged rows across them.

use coxswain_core::fleet::{FleetEntry, FleetSnapshot};

use crate::gw_types;
use crate::routes_dto::{CheckRow, RouteKey, RoutesResponse};

/// The proxy `/api/v1/routes` sub-key for a route kind: Gateway-API routes live under
/// `gateway`, classic Ingress under `ingress`. `None` for an unknown kind.
pub(super) fn route_kind_key(kind: &str) -> Option<&'static str> {
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
pub(super) fn serving_proxies_for_parents(
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

/// Flatten the rows in one proxy's routes payload that are tagged with the given
/// route object to [`CheckRow`]s, computing `dead` (zero endpoints) per row.
pub(super) fn route_rows_for(
    routes: &RoutesResponse,
    spec_key: &str,
    namespace: &str,
    name: &str,
) -> Vec<CheckRow> {
    let block = match spec_key {
        "ingress" => &routes.ingress,
        "gateway" => &routes.gateway,
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    for host_group in &block.hosts {
        for r in &host_group.routes {
            if r.namespace == namespace && r.name == name {
                out.push(CheckRow {
                    host: host_group.host.clone(),
                    path: r.path.clone(),
                    backend_group: r.backend_group.clone(),
                    dead: r.endpoints.is_empty(),
                    endpoints: r.endpoints.clone(),
                });
            }
        }
    }
    out
}

/// `(host, path, backend_group)` identity of a check row, for set membership.
pub(super) fn row_key(r: &CheckRow) -> RouteKey {
    RouteKey {
        host: r.host.clone(),
        path: r.path.clone(),
        backend_group: r.backend_group.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregator::tests::*;
    use coxswain_core::fleet::build_snapshot;

    #[test]
    fn route_rows_for_filters_to_tagged_rows() {
        let routes: RoutesResponse = serde_json::from_value(serde_json::json!({
            "gateway": { "hosts": [
                { "host": "api.demo.local", "port": 8080, "routes": [
                    {"type": "prefix", "name": "api-route", "namespace": "demo", "path": "/",
                     "backend_group": "demo/api", "endpoints": []},
                    {"type": "exact", "name": "other", "namespace": "demo", "path": "/x",
                     "backend_group": "demo/other", "endpoints": ["1.2.3.4:80"]}
                ]}
            ]}
        }))
        .expect("deserialise routes body");
        let rows = route_rows_for(&routes, "gateway", "demo", "api-route");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].host, "api.demo.local");
        assert_eq!(rows[0].path, "/");
        assert_eq!(rows[0].backend_group, "demo/api");
        assert!(rows[0].endpoints.is_empty());
        assert!(rows[0].dead, "zero endpoints ⇒ dead");
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
