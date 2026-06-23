//! Registry of connected proxy nodes and their last-known ACK state.
//!
//! [`NodeRegistry`] is a plain snapshot value (like [`crate::fleet::FleetSnapshot`]).
//! [`SharedNodeRegistry`] is the multi-writer handle: each discovery stream task holds
//! a clone and upserts its own row concurrently. Interior [`Mutex`] makes writes
//! in-place and correct; the lock is never held across an `.await`.
//!
//! The registry is populated by the discovery server (T5, #376) and read by the admin
//! UI convergence panel (T8).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

// ── NodeScope ────────────────────────────────────────────────────────────────

/// Discovery scope a connected node subscribes to.
///
/// Deliberately distinct from `coxswain_discovery::Scope`: `coxswain-core` must
/// not depend on `coxswain-discovery` (the admin reader consumes this type, and
/// admin must stay free of any discovery dependency). The discovery server owns
/// the conversion from its own `Scope` into this core-local mirror at the
/// crate boundary.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind")]
pub enum NodeScope {
    /// The shared proxy pool, serving all Ingress + Gateway routing that is not
    /// claimed by a dedicated per-Gateway proxy.
    SharedPool,
    /// A dedicated proxy provisioned for a single Gateway.
    Gateway {
        /// Namespace of the Gateway this proxy serves.
        namespace: String,
        /// Name of the Gateway this proxy serves.
        name: String,
    },
}

// ── NodeEntry ────────────────────────────────────────────────────────────────

/// Snapshot of a single connected proxy node.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct NodeEntry {
    /// Opaque identifier supplied by the proxy in its `Subscribe` message.
    pub node_id: String,
    /// Discovery scope this node subscribes to. Fixed at connect time.
    pub scope: NodeScope,
    /// Content hash of the last snapshot this node has Ack'd, or `None` if the
    /// node has not yet Ack'd any snapshot.
    pub last_acked_version: Option<String>,
    /// Content hash of the controller's current snapshot for this node's scope,
    /// last stamped by the discovery server, or `None` until the first snapshot
    /// is built. The convergence target the node is racing to match.
    pub target_version: Option<String>,
    /// Wall-clock time of the most recent Ack, or `None` if none received yet.
    pub last_ack_at: Option<SystemTime>,
    /// Wall-clock time when the stream was first established.
    pub connected_since: SystemTime,
}

impl NodeEntry {
    /// Whether this node has Ack'd the controller's current target version.
    ///
    /// Derived rather than stored: `last_acked_version` and `target_version`
    /// are written at independent moments (Ack vs. snapshot build), so a stored
    /// boolean would risk going stale between the two writes.
    #[must_use]
    pub fn in_sync(&self) -> bool {
        self.last_acked_version.is_some() && self.last_acked_version == self.target_version
    }
}

// ── NodeRegistry ─────────────────────────────────────────────────────────────

/// Snapshot of all currently-connected proxy nodes.
///
/// This is a plain value type — create a point-in-time copy via
/// [`SharedNodeRegistry::load`] and hold it briefly; do not cache it across
/// reconcile cycles.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct NodeRegistry {
    /// Map of `node_id` → per-node entry.
    pub nodes: HashMap<String, NodeEntry>,
}

// ── SharedNodeRegistry ────────────────────────────────────────────────────────

/// Multi-writer shared handle to the live [`NodeRegistry`].
///
/// Unlike [`crate::shared::Shared`] (a single-writer primitive), `SharedNodeRegistry`
/// allows N concurrent stream tasks to upsert their own rows. The interior
/// [`Mutex`] is held only for the duration of the map operation, never across
/// an `.await`. Freely `Clone`d into each stream task.
#[non_exhaustive]
#[derive(Clone, Default)]
pub struct SharedNodeRegistry(Arc<Mutex<NodeRegistry>>);

impl SharedNodeRegistry {
    /// Construct a new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a freshly-connected node within a discovery scope.
    ///
    /// Inserts a new [`NodeEntry`] with `connected_since = now`, the given
    /// `scope`, and neither a target nor an ACK yet. If a row already exists
    /// (e.g. rapid reconnect before the prior stream's `disconnect` call races),
    /// it is replaced.
    pub fn connect(&self, node_id: &str, scope: NodeScope, now: SystemTime) {
        let entry = NodeEntry {
            node_id: node_id.to_owned(),
            scope,
            last_acked_version: None,
            target_version: None,
            last_ack_at: None,
            connected_since: now,
        };
        self.0
            .lock()
            .unwrap_or_else(|e| panic!("invariant: NodeRegistry lock must not be poisoned: {e}"))
            .nodes
            .insert(node_id.to_owned(), entry);
    }

    /// Record a successful ACK from a node, updating its convergence state.
    ///
    /// If the node is not in the registry (e.g. late call after `disconnect`),
    /// this is a no-op.
    pub fn record_ack(&self, node_id: &str, version: String, now: SystemTime) {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|e| panic!("invariant: NodeRegistry lock must not be poisoned: {e}"));
        if let Some(entry) = guard.nodes.get_mut(node_id) {
            entry.last_acked_version = Some(version);
            entry.last_ack_at = Some(now);
        }
    }

    /// Stamp the controller's current snapshot version for a node's scope.
    ///
    /// Called by the discovery server at every snapshot build (initial open,
    /// rebuild, and post-ack), independent of whether the node has Ack'd. If
    /// the node is not in the registry, this is a no-op (mirrors
    /// [`Self::record_ack`]).
    pub fn record_target(&self, node_id: &str, version: String) {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|e| panic!("invariant: NodeRegistry lock must not be poisoned: {e}"));
        if let Some(entry) = guard.nodes.get_mut(node_id) {
            entry.target_version = Some(version);
        }
    }

    /// Whether all currently-connected nodes have Ack'd the controller's current
    /// target version.
    ///
    /// Returns `true` when the registry is empty (vacuous convergence). `Some`
    /// registry with no laggards has the same property.
    ///
    /// # Errors
    ///
    /// None — this is infallible.
    #[must_use]
    pub fn all_in_sync(&self) -> bool {
        self.load().nodes.values().all(NodeEntry::in_sync)
    }

    /// Content hash of the controller's current SharedPool snapshot, derived
    /// from the connected SharedPool node with the lexicographically smallest
    /// `node_id` (deterministic across callers). Returns `None` when no
    /// SharedPool node is connected.
    ///
    /// In the single-tier topology every SharedPool node receives the same
    /// snapshot, so their `target_version` values are identical; the
    /// deterministic pick avoids returning a different value on each call.
    #[must_use]
    pub fn controller_version(&self) -> Option<String> {
        self.load()
            .nodes
            .into_values()
            .filter(|e| e.scope == NodeScope::SharedPool)
            .min_by(|a, b| a.node_id.cmp(&b.node_id))
            .and_then(|e| e.target_version)
    }

    /// Remove a node's row on stream exit.
    ///
    /// No-op if the node is not present.
    pub fn disconnect(&self, node_id: &str) {
        self.0
            .lock()
            .unwrap_or_else(|e| panic!("invariant: NodeRegistry lock must not be poisoned: {e}"))
            .nodes
            .remove(node_id);
    }

    /// Return a cloned point-in-time snapshot of the registry.
    ///
    /// Callers should hold the returned value briefly and not cache it across
    /// reconcile cycles.
    #[must_use]
    pub fn load(&self) -> NodeRegistry {
        self.0
            .lock()
            .unwrap_or_else(|e| panic!("invariant: NodeRegistry lock must not be poisoned: {e}"))
            .clone()
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH
    }

    fn shared() -> NodeScope {
        NodeScope::SharedPool
    }

    fn gw(ns: &str, name: &str) -> NodeScope {
        NodeScope::Gateway {
            namespace: ns.to_owned(),
            name: name.to_owned(),
        }
    }

    #[test]
    fn connect_inserts_entry() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        let snap = reg.load();
        assert!(
            snap.nodes.contains_key("node-a"),
            "node-a must appear after connect"
        );
        assert!(snap.nodes["node-a"].last_acked_version.is_none());
        assert!(snap.nodes["node-a"].target_version.is_none());
    }

    #[test]
    fn connect_records_scope() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.connect("node-b", gw("default", "my-gw"), now());
        let snap = reg.load();
        assert_eq!(snap.nodes["node-a"].scope, NodeScope::SharedPool);
        assert_eq!(
            snap.nodes["node-b"].scope,
            gw("default", "my-gw"),
            "gateway scope must be recorded"
        );
    }

    #[test]
    fn record_ack_updates_version_and_time() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        let ack_time = SystemTime::UNIX_EPOCH;
        reg.record_ack("node-a", "abc123".to_owned(), ack_time);
        let snap = reg.load();
        assert_eq!(
            snap.nodes["node-a"].last_acked_version.as_deref(),
            Some("abc123")
        );
        assert_eq!(snap.nodes["node-a"].last_ack_at, Some(ack_time));
    }

    #[test]
    fn record_ack_on_unknown_node_is_noop() {
        let reg = SharedNodeRegistry::new();
        // Must not panic
        reg.record_ack("phantom", "hash".to_owned(), now());
        assert!(reg.load().nodes.is_empty());
    }

    #[test]
    fn record_target_then_ack_is_in_sync() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.record_target("node-a", "v1".to_owned());
        assert!(!reg.load().nodes["node-a"].in_sync(), "not yet acked");
        reg.record_ack("node-a", "v1".to_owned(), now());
        assert!(reg.load().nodes["node-a"].in_sync(), "acked the target");
    }

    #[test]
    fn ack_of_stale_version_is_out_of_sync() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.record_target("node-a", "v2".to_owned());
        reg.record_ack("node-a", "v1".to_owned(), now());
        assert!(
            !reg.load().nodes["node-a"].in_sync(),
            "node acked an old version while target advanced"
        );
    }

    #[test]
    fn record_target_on_unknown_node_is_noop() {
        let reg = SharedNodeRegistry::new();
        reg.record_target("phantom", "v1".to_owned());
        assert!(reg.load().nodes.is_empty());
    }

    #[test]
    fn all_in_sync_true_when_empty() {
        let reg = SharedNodeRegistry::new();
        assert!(reg.all_in_sync(), "vacuously true with no nodes");
    }

    #[test]
    fn all_in_sync_false_with_one_laggard() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.record_target("node-a", "v2".to_owned());
        reg.record_ack("node-a", "v1".to_owned(), now());
        reg.connect("node-b", shared(), now());
        reg.record_target("node-b", "v2".to_owned());
        reg.record_ack("node-b", "v2".to_owned(), now());
        assert!(
            !reg.all_in_sync(),
            "one laggard makes the whole fleet out of sync"
        );
    }

    #[test]
    fn controller_version_from_shared_pool_node() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.record_target("node-a", "v42".to_owned());
        assert_eq!(reg.controller_version().as_deref(), Some("v42"));
    }

    #[test]
    fn controller_version_none_when_no_shared_pool() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", gw("ns", "gw"), now());
        reg.record_target("node-a", "v1".to_owned());
        assert_eq!(
            reg.controller_version(),
            None,
            "gateway node does not contribute controller_version"
        );
    }

    #[test]
    fn disconnect_removes_entry() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.disconnect("node-a");
        assert!(
            reg.load().nodes.is_empty(),
            "node-a must be gone after disconnect"
        );
    }

    #[test]
    fn disconnect_unknown_node_is_noop() {
        let reg = SharedNodeRegistry::new();
        // Must not panic
        reg.disconnect("phantom");
    }

    #[test]
    fn load_returns_independent_clone() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        let snap1 = reg.load();
        reg.disconnect("node-a");
        // The snapshot captured before disconnect is unaffected
        assert!(snap1.nodes.contains_key("node-a"));
        assert!(reg.load().nodes.is_empty());
    }

    #[test]
    fn clone_shares_state() {
        let reg = SharedNodeRegistry::new();
        let reg2 = reg.clone();
        reg.connect("node-a", shared(), now());
        // reg2 sees the same underlying map
        assert!(reg2.load().nodes.contains_key("node-a"));
    }
}
