//! `GET /api/v1/topology` — discovery convergence view.
//!
//! Returns the controller's current snapshot version, every connected proxy
//! node with its scope and convergence state, and a boolean indicating whether
//! discovery is active (false in dev/proxy roles). The UI uses this to render
//! the dedicated Topology screen and its lagging-proxy warning banner.

use coxswain_core::node_registry::{NodeEntry, NodeRegistry, NodeScope};
use http::Response;
use std::time::SystemTime;

use super::{OperatorAggregator, json_response};

impl OperatorAggregator {
    /// `GET /api/v1/topology` — discovery convergence snapshot.
    ///
    /// Returns `{"discovery_active":false,...}` on dev/proxy roles (no
    /// registry wired in). Returns `{"discovery_active":true,...}` on the
    /// controller role, with nodes sorted by scope then node_id for stable
    /// output.
    ///
    /// # Errors
    ///
    /// None — this is infallible; failure modes are surfaced in the payload.
    pub(crate) async fn topology(&self) -> Response<Vec<u8>> {
        match &self.node_registry {
            None => {
                let body = serde_json::json!({
                    "discovery_active": false,
                    "controller_version": null,
                    "nodes": [],
                });
                json_response(body.to_string())
            }
            Some(reg) => {
                let snap = reg.load();
                let controller_version = reg.controller_version();
                let mut body = build_topology(&snap);
                body["discovery_active"] = serde_json::Value::Bool(true);
                body["controller_version"] =
                    controller_version.map_or(serde_json::Value::Null, serde_json::Value::String);
                json_response(body.to_string())
            }
        }
    }
}

/// Build the topology payload from a point-in-time [`NodeRegistry`] snapshot.
///
/// Exported as a free function so it is unit-testable without a live admin
/// aggregator. Nodes are sorted SharedPool-first, then Gateway (namespace,
/// name), then node_id within each scope, for deterministic output.
pub(super) fn build_topology(snap: &NodeRegistry) -> serde_json::Value {
    let mut entries: Vec<&NodeEntry> = snap.nodes.values().collect();
    entries.sort_by(|a, b| {
        scope_sort_key(&a.scope)
            .cmp(&scope_sort_key(&b.scope))
            .then(a.node_id.cmp(&b.node_id))
    });

    let nodes: Vec<serde_json::Value> = entries.iter().map(|e| node_json(e)).collect();
    serde_json::json!({ "nodes": nodes })
}

/// Produce a stable sort key for [`NodeScope`] (SharedPool < Gateway).
fn scope_sort_key(scope: &NodeScope) -> (u8, &str, &str) {
    match scope {
        NodeScope::SharedPool => (0, "", ""),
        NodeScope::Gateway { namespace, name } => (1, namespace.as_str(), name.as_str()),
        _ => (2, "", ""),
    }
}

/// Serialise a [`NodeEntry`] into the topology wire shape.
fn node_json(entry: &NodeEntry) -> serde_json::Value {
    serde_json::json!({
        "node_id": entry.node_id,
        "scope": entry.scope,
        "last_acked_version": entry.last_acked_version,
        "connected_since": fmt_time(entry.connected_since),
        "last_ack_at": entry.last_ack_at.map(fmt_time),
        "in_sync": entry.in_sync(),
    })
}

/// Format a [`SystemTime`] as an RFC 3339 string.
fn fmt_time(t: SystemTime) -> String {
    humantime::format_rfc3339(t).to_string()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::node_registry::{NodeScope, SharedNodeRegistry};
    use std::time::SystemTime;

    fn epoch() -> SystemTime {
        SystemTime::UNIX_EPOCH
    }

    /// Build a `SharedNodeRegistry` with a single SharedPool node that has the
    /// given `target` and `acked` versions.
    fn reg_with_shared(
        node_id: &str,
        target: Option<&str>,
        acked: Option<&str>,
    ) -> SharedNodeRegistry {
        let reg = SharedNodeRegistry::new();
        reg.connect(node_id, NodeScope::SharedPool, epoch());
        if let Some(t) = target {
            reg.record_target(node_id, t.to_owned());
        }
        if let Some(a) = acked {
            reg.record_ack(node_id, a.to_owned(), epoch());
        }
        reg
    }

    #[test]
    fn build_topology_empty_snap_returns_empty_nodes() {
        let snap = SharedNodeRegistry::new().load();
        let v = build_topology(&snap);
        assert_eq!(v["nodes"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn build_topology_in_sync_node() {
        let reg = reg_with_shared("node-a", Some("v1"), Some("v1"));
        let snap = reg.load();
        let v = build_topology(&snap);
        let nodes = v["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["node_id"], "node-a");
        assert_eq!(nodes[0]["in_sync"], true);
        assert_eq!(nodes[0]["scope"]["kind"], "SharedPool");
    }

    #[test]
    fn build_topology_lagging_node() {
        let reg = reg_with_shared("node-b", Some("v2"), Some("v1"));
        let snap = reg.load();
        let v = build_topology(&snap);
        assert_eq!(v["nodes"][0]["in_sync"], false);
    }

    #[test]
    fn build_topology_stable_sort_shared_first_then_gateway() {
        let reg = SharedNodeRegistry::new();
        reg.connect(
            "gw-node",
            NodeScope::Gateway {
                namespace: "default".to_owned(),
                name: "my-gw".to_owned(),
            },
            epoch(),
        );
        reg.connect("sp-node", NodeScope::SharedPool, epoch());
        let snap = reg.load();
        let v = build_topology(&snap);
        let nodes = v["nodes"].as_array().unwrap();
        assert_eq!(nodes[0]["node_id"], "sp-node", "SharedPool must sort first");
        assert_eq!(nodes[1]["node_id"], "gw-node");
        assert_eq!(nodes[1]["scope"]["kind"], "Gateway");
        assert_eq!(nodes[1]["scope"]["namespace"], "default");
        assert_eq!(nodes[1]["scope"]["name"], "my-gw");
    }

    #[tokio::test]
    async fn topology_handler_returns_inactive_when_no_registry() {
        use coxswain_core::cluster::SharedClusterSummary;
        use coxswain_core::fleet::SharedFleet;
        let agg =
            super::super::tests::make_agg(SharedFleet::default(), SharedClusterSummary::default());
        let resp = agg.topology().await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["discovery_active"], false);
        assert_eq!(body["nodes"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn topology_handler_returns_active_with_registry() {
        use coxswain_core::cluster::SharedClusterSummary;
        use coxswain_core::fleet::SharedFleet;
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", NodeScope::SharedPool, epoch());
        reg.record_target("node-a", "v1".to_owned());
        reg.record_ack("node-a", "v1".to_owned(), epoch());
        let agg = super::super::tests::make_agg_with_registry(
            SharedFleet::default(),
            SharedClusterSummary::default(),
            reg,
        );
        let resp = agg.topology().await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["discovery_active"], true);
        assert_eq!(body["controller_version"], "v1");
        let nodes = body["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["in_sync"], true);
    }
}
