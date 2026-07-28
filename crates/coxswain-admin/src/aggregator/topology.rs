//! `GET /api/v1/topology` — discovery convergence view.
//!
//! Returns the controller's current snapshot version, every connected proxy
//! node with its scope and convergence state, and a boolean indicating whether
//! discovery is active (false in dev/proxy roles). The UI uses this to render
//! the dedicated Topology screen and its lagging-proxy warning banner.
//!
//! ## Why only the leader can answer
//!
//! The node registry is the one piece of genuinely leader-local state the
//! controller holds. Routing state is identical on every replica — they all run
//! reflectors — but "which proxies and relays are connected to me" is inherently
//! local, and since #531 only the leader has any: standbys reject streams with
//! `FAILED_PRECONDITION` and a demotion tears live ones down so proxies redial
//! the new leader. A standby's registry is therefore **empty**, not partial.
//!
//! This endpoint used to fan out over HTTP to every peer replica's
//! `/api/v1/topology/local` and union the results. That was correct under #500,
//! when standbys did accept streams and each registry held a genuine fragment;
//! after #531 it merged the leader with N−1 empties — a no-op that kept an
//! inter-pod RPC alive on the operator API for no gain, and forced an auth
//! carve-out to keep working.
//!
//! Two things replace it. Operators reach the leader through a
//! leader-selecting `Service` (the same `discovery.coxswain-labs.dev/leader`
//! pod label the discovery stream Service already uses), so the common path
//! lands on the replica that can answer. And a standby reached directly anyway
//! — a pod-IP `port-forward`, say — returns 503 saying so, rather than an empty
//! node list that looks like a converged cluster with nothing in it.

use coxswain_core::node_registry::{NodeEntry, NodeRegistry, NodeScope};
use http::Response;

use super::{OperatorAggregator, fmt_rfc3339, json_response, service_unavailable};

impl OperatorAggregator {
    /// `GET /api/v1/topology` — discovery convergence snapshot.
    ///
    /// Returns `{"discovery_active":false,...}` on dev/proxy roles (no registry
    /// wired in), and on the controller role a node list sorted by scope then
    /// `node_id` for stable output.
    ///
    /// `is_leader` gates the registry read: only the leader accepts discovery
    /// streams, so a standby's registry is empty and reporting it as the
    /// topology would be indistinguishable from a cluster with no proxies. It
    /// returns 503 instead — see the module header.
    ///
    /// # Errors
    ///
    /// None — this is infallible; failure modes are surfaced in the payload.
    pub(crate) fn topology(&self, is_leader: bool) -> Response<Vec<u8>> {
        let Some(reg) = &self.node_registry else {
            let body = serde_json::json!({
                "discovery_active": false,
                "controller_version": null,
                "nodes": [],
            });
            return json_response(body.to_string());
        };
        if !is_leader {
            return service_unavailable(
                "not the discovery leader — only the leader accepts proxy streams, so this \
                 replica has no topology to report; reach the leader-selecting operator Service",
            );
        }
        let snapshot = reg.load();
        let controller_version = snapshot.controller_version();
        let mut body = build_topology(&snapshot);
        body["discovery_active"] = serde_json::Value::Bool(true);
        body["controller_version"] =
            controller_version.map_or(serde_json::Value::Null, serde_json::Value::String);
        json_response(body.to_string())
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

/// Produce a stable sort key for [`NodeScope`] (SharedPool < Gateway < Namespace).
fn scope_sort_key(scope: &NodeScope) -> (u8, &str, &str) {
    match scope {
        NodeScope::SharedPool => (0, "", ""),
        NodeScope::Gateway { namespace, name } => (1, namespace.as_str(), name.as_str()),
        NodeScope::Namespace { namespace } => (2, namespace.as_str(), ""),
    }
}

/// Serialise a [`NodeEntry`] into the topology wire shape.
///
/// `parent` and `is_relay` (#585) let the UI render N tiers: a node with a
/// `parent` is a leaf folded from that relay's `RosterReport`, and an
/// `is_relay` node is a relay tier node. Both absent/false for a directly
/// connected proxy, which the UI draws one hop below the controller as before.
fn node_json(entry: &NodeEntry) -> serde_json::Value {
    let mut v = serde_json::json!({
        "node_id": entry.node_id,
        "scope": entry.scope,
        "last_acked_version": entry.last_acked_version,
        "connected_since": fmt_rfc3339(entry.connected_since),
        "last_ack_at": entry.last_ack_at.map(fmt_rfc3339),
        "in_sync": entry.in_sync(),
        "parent": entry.parent,
        "is_relay": entry.is_relay,
    });
    // Self-reported health (#677). This is the only place a RELAY's own health
    // is rendered: `/api/v1/fleet/proxies` lists shared and dedicated proxies
    // only, and a relay never appears in its own `RosterReport`. Absent for a
    // node that has not reported yet or is a pre-#677 build.
    if let Some(health) = &entry.health {
        let degraded = super::non_ready_check_names(&health.snapshot);
        v["health"] = serde_json::Value::String(
            if degraded.is_empty() {
                "ready"
            } else {
                "degraded"
            }
            .to_owned(),
        );
        v["degraded_checks"] = serde_json::Value::from(degraded);
        v["version"] = serde_json::Value::String(health.version.clone());
        v["reported_at"] = serde_json::Value::String(fmt_rfc3339(health.reported_at));
    }
    v
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::node_registry::{NodeRegistryHandle, NodeScope};
    use std::time::SystemTime;

    fn epoch() -> SystemTime {
        SystemTime::UNIX_EPOCH
    }

    /// Build a `NodeRegistryHandle` with a single SharedPool node that has the
    /// given `target` and `acked` versions.
    fn reg_with_shared(
        node_id: &str,
        target: Option<&str>,
        acked: Option<&str>,
    ) -> NodeRegistryHandle {
        let reg = NodeRegistryHandle::new();
        reg.connect(node_id, NodeScope::SharedPool, epoch());
        if let Some(t) = target {
            reg.record_target(node_id, t.to_owned());
        }
        if let Some(a) = acked {
            reg.record_ack(node_id, a.to_owned(), 1, epoch());
        }
        reg
    }

    #[test]
    fn build_topology_empty_snap_returns_empty_nodes() {
        let snap = NodeRegistryHandle::new().load();
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
        let reg = NodeRegistryHandle::new();
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

    #[test]
    fn build_topology_exposes_relay_and_folded_leaf_tiers() {
        use coxswain_core::node_registry::RosterChild;
        let reg = NodeRegistryHandle::new();
        // A namespace relay connects and folds one dedicated leaf.
        reg.connect(
            "relay-a",
            NodeScope::Namespace {
                namespace: "prod".to_owned(),
            },
            epoch(),
        );
        reg.apply_roster(
            "relay-a",
            vec![RosterChild {
                node_id: "leaf-1".to_owned(),
                scope: NodeScope::Gateway {
                    namespace: "prod".to_owned(),
                    name: "gw".to_owned(),
                },
                last_acked_version: Some("v1".to_owned()),
                target_version: Some("v1".to_owned()),
                last_acked_seq: Some(3),
                bound_ports: None,
                connected_since: epoch(),
                last_ack_at: None,
                health: None,
            }],
        );
        let v = build_topology(&reg.load());
        let nodes = v["nodes"].as_array().unwrap();
        let relay = nodes.iter().find(|n| n["node_id"] == "relay-a").unwrap();
        let leaf = nodes.iter().find(|n| n["node_id"] == "leaf-1").unwrap();
        assert_eq!(relay["is_relay"], true, "the relay is flagged for the UI");
        assert_eq!(relay["parent"], serde_json::Value::Null);
        assert_eq!(
            leaf["parent"], "relay-a",
            "the folded leaf points at its relay for the N-tier render"
        );
        assert_eq!(leaf["is_relay"], false);
    }

    #[test]
    fn topology_handler_returns_inactive_when_no_registry() {
        use coxswain_core::cluster::SharedClusterSummary;
        use coxswain_core::fleet::SharedFleet;
        let agg =
            super::super::tests::make_agg(SharedFleet::default(), SharedClusterSummary::default());
        let resp = agg.topology(true);
        assert_eq!(resp.status(), http::StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["discovery_active"], false);
        assert_eq!(body["nodes"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn topology_handler_returns_active_with_registry() {
        use coxswain_core::cluster::SharedClusterSummary;
        use coxswain_core::fleet::SharedFleet;
        let reg = NodeRegistryHandle::new();
        reg.connect("node-a", NodeScope::SharedPool, epoch());
        reg.record_target("node-a", "v1".to_owned());
        reg.record_ack("node-a", "v1".to_owned(), 1, epoch());
        let agg = super::super::tests::make_agg_with_registry(
            SharedFleet::default(),
            SharedClusterSummary::default(),
            reg,
        );
        let resp = agg.topology(true);
        assert_eq!(resp.status(), http::StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["discovery_active"], true);
        assert_eq!(body["controller_version"], "v1");
        let nodes = body["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["in_sync"], true);
    }

    // ── leader gating (#676) ─────────────────────────────────────────────────

    #[test]
    fn topology_on_a_standby_is_503_not_an_empty_node_list() {
        use coxswain_core::cluster::SharedClusterSummary;
        use coxswain_core::fleet::SharedFleet;
        // A standby's registry is empty because it accepts no streams. Serving
        // that as the topology is indistinguishable from a healthy cluster with
        // no proxies connected, which is the bug this endpoint used to have
        // whenever the UI landed on a standby.
        let reg = NodeRegistryHandle::new();
        let agg = super::super::tests::make_agg_with_registry(
            SharedFleet::default(),
            SharedClusterSummary::default(),
            reg,
        );

        let resp = agg.topology(false);

        assert_eq!(
            resp.status(),
            http::StatusCode::SERVICE_UNAVAILABLE,
            "a standby must say it cannot answer, not answer emptily"
        );
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap_or_default();
        assert!(
            body.get("nodes").is_none(),
            "the 503 must not carry a node list that could be rendered as truth"
        );
    }

    #[test]
    fn topology_inactive_role_answers_before_the_leader_check() {
        use coxswain_core::cluster::SharedClusterSummary;
        use coxswain_core::fleet::SharedFleet;
        // Dev/proxy roles wire no registry and never hold the lease. They must
        // still report `discovery_active: false` rather than a leadership 503 —
        // the honest answer there is "this role has no discovery", not "ask the
        // leader".
        let agg =
            super::super::tests::make_agg(SharedFleet::default(), SharedClusterSummary::default());

        let resp = agg.topology(false);

        assert_eq!(resp.status(), http::StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["discovery_active"], false);
    }
}
