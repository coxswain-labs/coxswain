//! Route check (data-plane consistency) helpers — pure functions backing
//! `…/routes/{kind}/{ns}/{name}/check`: resolving the serving proxies for a
//! route and diffing route-tagged rows across them.

use coxswain_core::fleet::{FleetEntry, FleetSnapshot};

use crate::gw_types;

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

/// Flatten the rows in one proxy's `/api/v1/routes` payload that are tagged with the
/// given route object to `{host, path, backend_group, endpoints}`.
pub(super) fn route_rows_for(
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
pub(super) fn row_key(r: &serde_json::Value) -> (String, String, String) {
    let s = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_owned();
    (s("host"), s("path"), s("backend_group"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregator::tests::*;
    use coxswain_core::fleet::build_snapshot;

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
