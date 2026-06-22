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

// ── NodeEntry ────────────────────────────────────────────────────────────────

/// Snapshot of a single connected proxy node.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct NodeEntry {
    /// Opaque identifier supplied by the proxy in its `Subscribe` message.
    pub node_id: String,
    /// Content hash of the last snapshot this node has Ack'd, or `None` if the
    /// node has not yet Ack'd any snapshot.
    pub last_acked_version: Option<String>,
    /// Wall-clock time of the most recent Ack, or `None` if none received yet.
    pub last_ack_at: Option<SystemTime>,
    /// Wall-clock time when the stream was first established.
    pub connected_since: SystemTime,
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

    /// Register a freshly-connected node.
    ///
    /// Inserts a new [`NodeEntry`] with `connected_since = now` and no ACK yet.
    /// If a row already exists (e.g. rapid reconnect before the prior stream's
    /// `disconnect` call races), it is replaced.
    pub fn connect(&self, node_id: &str, now: SystemTime) {
        let entry = NodeEntry {
            node_id: node_id.to_owned(),
            last_acked_version: None,
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

    #[test]
    fn connect_inserts_entry() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", now());
        let snap = reg.load();
        assert!(
            snap.nodes.contains_key("node-a"),
            "node-a must appear after connect"
        );
        assert!(snap.nodes["node-a"].last_acked_version.is_none());
    }

    #[test]
    fn record_ack_updates_version_and_time() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", now());
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
    fn disconnect_removes_entry() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", now());
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
        reg.connect("node-a", now());
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
        reg.connect("node-a", now());
        // reg2 sees the same underlying map
        assert!(reg2.load().nodes.contains_key("node-a"));
    }
}
