//! `GET /api/v1/topology` — discovery convergence view.
//!
//! Returns the controller's current snapshot version, every connected proxy
//! node with its scope and convergence state, and a boolean indicating whether
//! discovery is active (false in dev/proxy roles). The UI uses this to render
//! the dedicated Topology screen and its lagging-proxy warning banner.
//!
//! ## Cross-replica fan-out
//!
//! Each controller replica's [`SharedNodeRegistry`] is populated only by the
//! proxy discovery connections *that replica* accepted — the discovery server
//! deliberately has no leader gate (connections load-balance across every
//! replica, so no single pod becomes a fan-in bottleneck at scale). A read of
//! `/api/v1/topology` therefore fans out to every controller pod's
//! [`Self::topology_local`] endpoint (via the fleet snapshot, no new
//! peer-discovery mechanism needed) and unions the results before responding,
//! so any replica answering gives the same complete view. A peer that doesn't
//! respond within `fetch_json`'s 2 s budget is simply missing from the merge
//! (logged as a WARN) — the response never fails because one replica is slow.

use coxswain_core::fleet::FleetEntry;
use coxswain_core::node_registry::{NodeEntry, NodeRegistry, NodeScope};
use http::Response;
use std::time::SystemTime;

use super::{OperatorAggregator, json_response, pod_base_url};

impl OperatorAggregator {
    /// `GET /api/v1/topology` — discovery convergence snapshot, merged across
    /// every controller replica.
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
                let mut merged = reg.load();
                for peer in self.fetch_peer_registries().await {
                    merged.merge(peer);
                }
                let controller_version = merged.controller_version();
                let mut body = build_topology(&merged);
                body["discovery_active"] = serde_json::Value::Bool(true);
                body["controller_version"] =
                    controller_version.map_or(serde_json::Value::Null, serde_json::Value::String);
                json_response(body.to_string())
            }
        }
    }

    /// `GET /api/v1/topology/local` — this pod's own registry snapshot, raw.
    ///
    /// Internal-only: fetched by peer controller replicas to build the merged
    /// [`Self::topology`] view, not intended for direct operator/UI
    /// consumption (harmless to call directly — it is read-only and carries
    /// no more detail than the public endpoint already exposes per-node).
    ///
    /// Returns an empty registry (`{"nodes":{}}`) on dev/proxy roles.
    ///
    /// # Errors
    ///
    /// None — this is infallible.
    pub(crate) async fn topology_local(&self) -> Response<Vec<u8>> {
        let body = self
            .node_registry
            .as_ref()
            .map(|r| r.load())
            .unwrap_or_default();
        json_response(serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_string()))
    }

    /// Fetch every OTHER controller pod's local registry snapshot, tolerating
    /// unreachable peers.
    ///
    /// Includes `self`'s own fleet entry in the fan-out target list — the
    /// resulting self-fetch is redundant with the caller's own `reg.load()`
    /// but harmless (identical `node_id`s just overwrite themselves on
    /// merge), and skipping it would require the aggregator to know its own
    /// pod identity, which it does not currently track.
    async fn fetch_peer_registries(&self) -> Vec<NodeRegistry> {
        let controllers: Vec<FleetEntry> = self.fleet.load().controllers.to_vec();
        let fetches = controllers.iter().map(|e| async move {
            let url = format!("{}/api/v1/topology/local", pod_base_url(e));
            match self.fetch_json(&url).await {
                Some(v) => match serde_json::from_value::<NodeRegistry>(v) {
                    Ok(reg) => Some(reg),
                    Err(err) => {
                        tracing::warn!(
                            pod = %e.pod_name,
                            error = %err,
                            "topology: peer registry response was not valid NodeRegistry JSON"
                        );
                        None
                    }
                },
                None => {
                    tracing::warn!(
                        pod = %e.pod_name,
                        "topology: peer controller unreachable — its nodes are missing from this response"
                    );
                    None
                }
            }
        });
        futures::future::join_all(fetches)
            .await
            .into_iter()
            .flatten()
            .collect()
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

    // ── cross-replica fan-out (#500 HA) ──────────────────────────────────────

    #[tokio::test]
    async fn topology_local_returns_raw_registry_for_this_pod() {
        use coxswain_core::cluster::SharedClusterSummary;
        use coxswain_core::fleet::SharedFleet;
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", NodeScope::SharedPool, epoch());
        let agg = super::super::tests::make_agg_with_registry(
            SharedFleet::default(),
            SharedClusterSummary::default(),
            reg,
        );
        let resp = agg.topology_local().await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let parsed: NodeRegistry = serde_json::from_slice(resp.body()).unwrap();
        assert!(parsed.nodes.contains_key("node-a"));
    }

    #[tokio::test]
    async fn topology_local_returns_empty_registry_without_discovery() {
        use coxswain_core::cluster::SharedClusterSummary;
        use coxswain_core::fleet::SharedFleet;
        let agg =
            super::super::tests::make_agg(SharedFleet::default(), SharedClusterSummary::default());
        let resp = agg.topology_local().await;
        let parsed: NodeRegistry = serde_json::from_slice(resp.body()).unwrap();
        assert!(parsed.nodes.is_empty());
    }

    #[tokio::test]
    async fn topology_merges_a_reachable_peers_nodes() {
        use coxswain_core::cluster::SharedClusterSummary;

        // Peer registry, serialised the same way `topology_local` would emit it.
        let peer_reg = SharedNodeRegistry::new();
        peer_reg.connect("node-b", NodeScope::SharedPool, epoch());
        peer_reg.record_target("node-b", "v1".to_owned());
        let peer_json = serde_json::to_string(&peer_reg.load()).unwrap();
        let peer_port =
            super::super::tests::start_mock_http(Box::leak(peer_json.into_boxed_str())).await;

        // Local registry has a different node.
        let local_reg = SharedNodeRegistry::new();
        local_reg.connect("node-a", NodeScope::SharedPool, epoch());
        local_reg.record_target("node-a", "v1".to_owned());

        let peer_pod = super::super::tests::make_pod(
            "peer-ctrl",
            "controller",
            "127.0.0.1",
            &peer_port.to_string(),
            None,
        );
        let fleet = super::super::tests::fleet_with([peer_pod]);

        let agg = super::super::tests::make_agg_with_registry(
            fleet,
            SharedClusterSummary::default(),
            local_reg,
        );
        let resp = agg.topology().await;
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        let node_ids: Vec<&str> = body["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["node_id"].as_str().unwrap())
            .collect();
        assert!(
            node_ids.contains(&"node-a"),
            "must keep this pod's own node: {node_ids:?}"
        );
        assert!(
            node_ids.contains(&"node-b"),
            "must include the peer's node: {node_ids:?}"
        );
    }

    #[tokio::test]
    async fn topology_tolerates_an_unreachable_peer() {
        use coxswain_core::cluster::SharedClusterSummary;

        let dead_port = super::super::tests::refused_port();
        let local_reg = SharedNodeRegistry::new();
        local_reg.connect("node-a", NodeScope::SharedPool, epoch());

        let dead_pod = super::super::tests::make_pod(
            "unreachable-ctrl",
            "controller",
            "127.0.0.1",
            &dead_port.to_string(),
            None,
        );
        let fleet = super::super::tests::fleet_with([dead_pod]);

        let agg = super::super::tests::make_agg_with_registry(
            fleet,
            SharedClusterSummary::default(),
            local_reg,
        );
        let resp = agg.topology().await;
        assert_eq!(
            resp.status(),
            http::StatusCode::OK,
            "an unreachable peer must not fail the whole request"
        );
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        let nodes = body["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["node_id"], "node-a");
    }
}
