//! Registry of connected proxy nodes, their last-known ACK state, and their
//! reported bound listener ports.
//!
//! [`NodeRegistry`] is a plain snapshot value (like [`crate::fleet::FleetSnapshot`]).
//! [`SharedNodeRegistry`] is the multi-writer handle: each discovery stream task holds
//! a clone and upserts its own row concurrently. Interior [`Mutex`] makes writes
//! in-place and correct; the lock is never held across an `.await`.
//!
//! The registry is populated by the discovery server (T5, #376) and read by the admin
//! UI convergence panel (T8) and by the controller's shared-Gateway `Programmed`
//! readiness gate (#531), which subscribes to [`SharedNodeRegistry::subscribe`] for
//! re-drives on membership/bound-port changes.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::Mutex;
use tokio::sync::watch;

// ── NodeScope ────────────────────────────────────────────────────────────────

/// Discovery scope a connected node subscribes to.
///
/// Deliberately distinct from `coxswain_discovery::Scope`: `coxswain-core` must
/// not depend on `coxswain-discovery` (the admin reader consumes this type, and
/// admin must stay free of any discovery dependency). The discovery server owns
/// the conversion from its own `Scope` into this core-local mirror at the
/// crate boundary.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// A relay tier node aggregating every dedicated Gateway in one namespace
    /// (#582). Relay-tier upstream subscription only: no leaf proxy is ever
    /// recorded under this scope.
    Namespace {
        /// Namespace this relay node aggregates.
        namespace: String,
    },
}

// ── NodeEntry ────────────────────────────────────────────────────────────────

/// Snapshot of a single connected proxy node.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
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
    /// Listener ports this node reported as successfully bound (via the
    /// discovery `NodeStatus` message, #531), or `None` if the node has not
    /// reported yet this session.
    ///
    /// `None` is distinct from `Some(∅)`: an unreported node counts as **not**
    /// bound (the `Programmed` gate fails closed), while an empty report is an
    /// affirmative "nothing bound right now" during listener drain/rebind.
    /// Missing in JSON from pre-#531 peers → `None` via `serde(default)`.
    #[serde(default)]
    pub bound_ports: Option<BTreeSet<u16>>,
    /// Publish sequence (see [`crate::publish_index`]) captured by the
    /// discovery server before it built the snapshot this node last Ack'd, or
    /// `None` until the first Ack lands. Because the sequence is captured
    /// *before* the cells are read, `last_acked_seq >= s` proves the node's
    /// applied snapshot contains every rebuild stamped at sequence `<= s` —
    /// the content-convergence half of the #531 `Programmed` gate (bound
    /// ports alone can't cover a Gateway whose ports were already bound for
    /// other Gateways).
    #[serde(default)]
    pub last_acked_seq: Option<u64>,
    /// `node_id` of the relay whose `RosterReport` folded this entry into the
    /// controller's registry (#585), or `None` for a directly-connected node
    /// (including a relay's own stream). Set by [`SharedNodeRegistry::apply_roster`];
    /// the whole subtree is evicted via [`SharedNodeRegistry::evict_children`]
    /// when the relay's stream drops. Missing in JSON from pre-#585 peers →
    /// `None` via `serde(default)`.
    #[serde(default)]
    pub parent: Option<String>,
    /// Whether this node is a relay tier node — set the first time it reports a
    /// `RosterReport` (#585). The #531 quorum queries exclude relay entries so a
    /// relay's own ack never satisfies the gate for its subtree; the folded
    /// leaves (`is_relay == false`) are what the gate evaluates. A namespace
    /// relay's own [`NodeScope::Namespace`] entry is already scope-excluded, but
    /// a shared-pool relay's own entry is [`NodeScope::SharedPool`] and needs
    /// this flag to be skipped. Missing in JSON from pre-#585 peers → `false`.
    #[serde(default)]
    pub is_relay: bool,
}

/// A leaf entry from a relay's `RosterReport` (#585), folded into the registry
/// by [`SharedNodeRegistry::apply_roster`].
///
/// Mirrors the subset of [`NodeEntry`] a relay knows about a downstream leaf;
/// `parent`/`is_relay` are stamped by the registry on fold, so they are not
/// carried here. Lives in `coxswain-core` because [`NodeEntry`] is
/// `#[non_exhaustive]` and so cannot be constructed at the `coxswain-discovery`
/// boundary — the server decodes a `RosterEntry` wire message into this and
/// hands it to the registry, which owns [`NodeEntry`] construction.
// intentionally open: field-literal built at the coxswain-discovery boundary from a RosterEntry
pub struct RosterChild {
    /// The leaf's `node_id` (as it reported to the relay).
    pub node_id: String,
    /// The leaf's discovery scope.
    pub scope: NodeScope,
    /// Content hash the leaf last Ack'd, or `None`.
    pub last_acked_version: Option<String>,
    /// Relay's current downstream world version for this leaf's scope, or `None`.
    pub target_version: Option<String>,
    /// Publish sequence the leaf last Ack'd, in the controller's seq space, or
    /// `None` (see [`NodeEntry::last_acked_seq`]).
    pub last_acked_seq: Option<u64>,
    /// The leaf's reported bound-port set, or `None` if it has not reported —
    /// the `None`/`Some(∅)` distinction is load-bearing for the #531 gate.
    pub bound_ports: Option<BTreeSet<u16>>,
    /// The leaf's stream-open time at the relay.
    pub connected_since: SystemTime,
    /// The leaf's most recent Ack time, or `None`.
    pub last_ack_at: Option<SystemTime>,
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
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NodeRegistry {
    /// Map of `node_id` → per-node entry.
    pub nodes: HashMap<String, NodeEntry>,
}

impl NodeRegistry {
    /// Content hash of the controller's current SharedPool snapshot, derived
    /// from the connected SharedPool node with the lexicographically smallest
    /// `node_id` (deterministic across callers). Returns `None` when no
    /// SharedPool node is present.
    ///
    /// Free-standing on the plain snapshot type (not just
    /// [`SharedNodeRegistry`]) so a registry merged from multiple controller
    /// replicas — e.g. a topology fan-out union — can compute the same value
    /// a single replica's live registry would.
    #[must_use]
    pub fn controller_version(&self) -> Option<String> {
        self.nodes
            .values()
            .filter(|e| e.scope == NodeScope::SharedPool && !e.is_relay)
            .min_by(|a, b| a.node_id.cmp(&b.node_id))
            .and_then(|e| e.target_version.clone())
    }

    /// Merge `other`'s nodes into `self`, keyed by `node_id`.
    ///
    /// A `node_id` present in both is overwritten by `other`'s entry — the
    /// only legitimate source of a collision is the same node represented in
    /// two fan-out responses (e.g. a controller's own local registry fetched
    /// both directly and via its own peer endpoint), where the entries are
    /// equivalent modulo a benign race, not a real conflict.
    pub fn merge(&mut self, other: NodeRegistry) {
        self.nodes.extend(other.nodes);
    }

    /// #531 shared-mode quorum: whether **every** currently-connected
    /// [`NodeScope::SharedPool`] **leaf** node has reported a bound-port set
    /// covering `required`, with at least one such node connected. Relay entries
    /// (`is_relay`) are excluded — a shared-pool relay caches but binds nothing;
    /// its folded leaves (`is_relay == false`) are what the gate evaluates (#585).
    ///
    /// Fails closed on the two dark states: an empty pool (`false` — a VIP with
    /// no data plane behind it must not be `Programmed`) and a connected node
    /// that has not yet reported (`bound_ports == None` counts as not bound).
    /// An empty `required` set passes vacuously once any node is connected
    /// (a Gateway with no allocated internal ports has nothing to await).
    #[must_use]
    pub fn all_shared_nodes_bound(&self, required: &BTreeSet<u16>) -> bool {
        self.nodes_bound(
            |e| e.scope == NodeScope::SharedPool && !e.is_relay,
            required,
        )
    }

    /// #531 dedicated-mode quorum: whether a connected
    /// [`NodeScope::Gateway`] node for `namespace`/`name` has reported a
    /// bound-port set covering `required`.
    ///
    /// Same fail-closed semantics as [`Self::all_shared_nodes_bound`]: no
    /// connected node, or a node that has not reported yet, is not bound.
    /// Multiple rows for the same Gateway (a drain/replace overlap during a
    /// dedicated-pod rollout) must **all** be bound — the Service can route to
    /// any of them.
    #[must_use]
    pub fn gateway_node_bound(
        &self,
        namespace: &str,
        name: &str,
        required: &BTreeSet<u16>,
    ) -> bool {
        self.nodes_bound(
            |e| {
                matches!(&e.scope, NodeScope::Gateway { namespace: ns, name: n }
                    if ns == namespace && n == name)
            },
            required,
        )
    }

    /// #531 shared-mode content convergence: whether **every**
    /// currently-connected [`NodeScope::SharedPool`] **leaf** node has Ack'd a
    /// snapshot whose captured publish sequence is `>= min_seq`, with at least
    /// one such node connected. Relay entries (`is_relay`) are excluded (#585);
    /// behind a shared relay the leaves Ack the controller's re-stamped seq.
    ///
    /// Fails closed like [`Self::all_shared_nodes_bound`]: an empty pool or a
    /// node that has not Ack'd yet (`last_acked_seq == None`) holds the gate.
    #[must_use]
    pub fn all_shared_nodes_acked(&self, min_seq: u64) -> bool {
        self.nodes_acked(|e| e.scope == NodeScope::SharedPool && !e.is_relay, min_seq)
    }

    /// #531 dedicated-mode content convergence: whether every connected
    /// [`NodeScope::Gateway`] node for `namespace`/`name` has Ack'd a snapshot
    /// at publish sequence `>= min_seq`, with at least one connected.
    #[must_use]
    pub fn gateway_node_acked(&self, namespace: &str, name: &str, min_seq: u64) -> bool {
        self.nodes_acked(
            |e| {
                matches!(&e.scope, NodeScope::Gateway { namespace: ns, name: n }
                    if ns == namespace && n == name)
            },
            min_seq,
        )
    }

    /// Count of currently-connected leaf nodes serving the dedicated Gateway
    /// `namespace`/`name` — folded-behind-relay or directly connected (#585).
    ///
    /// Feeds the non-latched `coxswain_gateway_dataplane_proxies` gauge: an
    /// operator alerts on `== 0` for a live-data-plane blind spot, distinct from
    /// the latched `Programmed` status. Relay entries are never `Gateway`-scoped,
    /// so no `is_relay` filter is needed here.
    #[must_use]
    pub fn gateway_node_count(&self, namespace: &str, name: &str) -> usize {
        self.nodes
            .values()
            .filter(|e| {
                matches!(&e.scope, NodeScope::Gateway { namespace: ns, name: n }
                    if ns == namespace && n == name)
            })
            .count()
    }

    /// Live count of dedicated-proxy leaf nodes in `namespace` — the relay
    /// control loop's demand **signal** (#602).
    ///
    /// Counts every [`NodeScope::Gateway`] node whose namespace matches, whether
    /// it is streaming directly from the controller or folded behind the
    /// namespace relay (`parent`-tagged). This is the *live* subscriber count the
    /// HPA-style loop sizes and activates on — deliberately not the spec-derived
    /// desired-replica sum, which never jitters and so cannot exercise the
    /// tolerance deadband or the scale-down stabilization window. Relay entries
    /// are never `Gateway`-scoped, so no `is_relay` filter is needed.
    #[must_use]
    pub fn namespace_leaf_count(&self, namespace: &str) -> usize {
        self.nodes
            .values()
            .filter(
                |e| matches!(&e.scope, NodeScope::Gateway { namespace: ns, .. } if ns == namespace),
            )
            .count()
    }

    /// Whether `namespace`'s relay has loaded its upstream cache and is ready to
    /// serve leaves — the make-before-break **provision gate** (#602).
    ///
    /// True once at least one relay replica for the namespace (`is_relay &&
    /// scope == Namespace{namespace}`) has Ack'd the controller's current
    /// [`NodeScope::Namespace`] snapshot ([`NodeEntry::in_sync`]) — i.e. its
    /// routing world is loaded. The control loop gates a leaf repoint on this,
    /// never on mere provisioning intent, so no proxy is pointed at a
    /// not-yet-serving relay.
    #[must_use]
    pub fn relay_ready(&self, namespace: &str) -> bool {
        self.nodes.values().any(|e| {
            e.is_relay
                && matches!(&e.scope, NodeScope::Namespace { namespace: ns } if ns == namespace)
                && e.in_sync()
        })
    }

    /// Count of leaves still subscribed to `namespace`'s relay — the
    /// make-before-break **teardown drain gate** (#602).
    ///
    /// Counts every node whose `parent` is one of the namespace's relay replicas
    /// (`is_relay && scope == Namespace{namespace}`). Teardown deletes the relay
    /// only once this reaches 0 — every leaf has cut its control stream back to
    /// the controller — so deleting the relay never starves a still-connected
    /// proxy of routing updates.
    #[must_use]
    pub fn relay_subscriber_count(&self, namespace: &str) -> usize {
        let relay_ids: BTreeSet<&str> = self
            .nodes
            .values()
            .filter(|e| {
                e.is_relay
                    && matches!(&e.scope, NodeScope::Namespace { namespace: ns } if ns == namespace)
            })
            .map(|e| e.node_id.as_str())
            .collect();
        if relay_ids.is_empty() {
            return 0;
        }
        self.nodes
            .values()
            .filter(|e| e.parent.as_deref().is_some_and(|p| relay_ids.contains(p)))
            .count()
    }

    /// Shared quorum core for both gates: every node matching `scope_pred` has
    /// reported a bound set covering `required`, and at least one matches. The
    /// fail-closed semantics (unreported `None` ≠ bound, empty match set fails)
    /// are load-bearing for both writers — keep them in this single place.
    fn nodes_bound(
        &self,
        scope_pred: impl Fn(&NodeEntry) -> bool,
        required: &BTreeSet<u16>,
    ) -> bool {
        let mut any = false;
        for entry in self.nodes.values().filter(|e| scope_pred(e)) {
            any = true;
            if !entry
                .bound_ports
                .as_ref()
                .is_some_and(|bound| required.is_subset(bound))
            {
                return false;
            }
        }
        any
    }

    /// Ack-sequence quorum core, mirroring [`Self::nodes_bound`]'s fail-closed
    /// shape: every matching node has `last_acked_seq >= min_seq`, and at
    /// least one matches.
    fn nodes_acked(&self, scope_pred: impl Fn(&NodeEntry) -> bool, min_seq: u64) -> bool {
        let mut any = false;
        for entry in self.nodes.values().filter(|e| scope_pred(e)) {
            any = true;
            if entry.last_acked_seq.is_none_or(|s| s < min_seq) {
                return false;
            }
        }
        any
    }
}

// ── SharedNodeRegistry ────────────────────────────────────────────────────────

/// Multi-writer shared handle to the live [`NodeRegistry`].
///
/// Unlike [`crate::shared::Shared`] (a single-writer primitive), `SharedNodeRegistry`
/// allows N concurrent stream tasks to upsert their own rows. The interior
/// [`Mutex`] is held only for the duration of the map operation, never across
/// an `.await`. Freely `Clone`d into each stream task.
#[non_exhaustive]
#[derive(Clone)]
pub struct SharedNodeRegistry(Arc<RegistryInner>);

/// Shared state behind [`SharedNodeRegistry`].
struct RegistryInner {
    /// The live registry map.
    map: Mutex<NodeRegistry>,
    /// Change-notification channel bumped on membership (connect/disconnect)
    /// and bound-port changes — the inputs to the #531 `Programmed` gate.
    /// Deliberately NOT bumped on ack/target stamps: those arrive on every
    /// snapshot push and would re-drive gate consumers on unrelated traffic.
    notify: watch::Sender<u64>,
}

impl Default for SharedNodeRegistry {
    fn default() -> Self {
        Self(Arc::new(RegistryInner {
            map: Mutex::new(NodeRegistry::default()),
            notify: watch::Sender::new(0),
        }))
    }
}

impl SharedNodeRegistry {
    /// Construct a new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bump the change watch. Callers must have released the map lock first —
    /// the watch has its own internal lock and gate consumers immediately call
    /// [`Self::load`] from the woken task.
    fn bump(&self) {
        self.0.notify.send_modify(|v| *v = v.wrapping_add(1));
    }

    /// Subscribe to membership and bound-port changes.
    ///
    /// The carried `u64` is an opaque change counter — consumers should treat
    /// any observed change as "re-read the registry via [`Self::load`]", not
    /// interpret the value. Ack/target stamps do not fire this channel.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.notify.subscribe()
    }

    /// Register a freshly-connected node within a discovery scope.
    ///
    /// Inserts a new [`NodeEntry`] with `connected_since = now`, the given
    /// `scope`, and neither a target, an ACK, nor a bound-port report yet. If a
    /// row already exists (e.g. rapid reconnect before the prior stream's
    /// `disconnect` call races), it is replaced.
    pub fn connect(&self, node_id: &str, scope: NodeScope, now: SystemTime) {
        let entry = NodeEntry {
            node_id: node_id.to_owned(),
            scope,
            last_acked_version: None,
            target_version: None,
            last_ack_at: None,
            connected_since: now,
            bound_ports: None,
            last_acked_seq: None,
            parent: None,
            is_relay: false,
        };
        self.0.map.lock().nodes.insert(node_id.to_owned(), entry);
        self.bump();
    }

    /// Record a successful ACK from a node, updating its convergence state.
    ///
    /// `seq` is the publish sequence the discovery server captured before
    /// building the Ack'd snapshot (see [`NodeEntry::last_acked_seq`]).
    /// If the node is not in the registry (e.g. late call after `disconnect`),
    /// this is a no-op. Deliberately does NOT bump the change watch: Acks
    /// arrive on every snapshot push, and the gate writers' requeue backstops
    /// re-evaluate within seconds.
    pub fn record_ack(&self, node_id: &str, version: String, seq: u64, now: SystemTime) {
        let mut guard = self.0.map.lock();
        if let Some(entry) = guard.nodes.get_mut(node_id) {
            entry.last_acked_version = Some(version);
            entry.last_ack_at = Some(now);
            entry.last_acked_seq = Some(entry.last_acked_seq.unwrap_or(0).max(seq));
        }
    }

    /// Advance a node's Ack'd publish sequence without a new Ack.
    ///
    /// Used by the discovery server's "rebuild produced the same content hash
    /// as the node's last Ack" branch: identical content means the node's
    /// applied snapshot is already equivalent to the freshly-captured
    /// sequence, so its convergence stamp can advance without a push. Without
    /// this, a quiet cluster would strand the #531 ack gate at the sequence
    /// of the last *content-changing* push. Monotone: never moves backwards.
    pub fn advance_acked_seq(&self, node_id: &str, seq: u64) {
        let mut guard = self.0.map.lock();
        if let Some(entry) = guard.nodes.get_mut(node_id) {
            entry.last_acked_seq = Some(entry.last_acked_seq.unwrap_or(0).max(seq));
        }
    }

    /// Stamp the controller's current snapshot version for a node's scope.
    ///
    /// Called by the discovery server at every snapshot build (initial open,
    /// rebuild, and post-ack), independent of whether the node has Ack'd. If
    /// the node is not in the registry, this is a no-op (mirrors
    /// [`Self::record_ack`]).
    pub fn record_target(&self, node_id: &str, version: String) {
        let mut guard = self.0.map.lock();
        if let Some(entry) = guard.nodes.get_mut(node_id) {
            entry.target_version = Some(version);
        }
    }

    /// Record a node's full current bound-port set (wholesale replace, #531).
    ///
    /// No-op if the node is not present (late report after `disconnect`).
    /// Bumps the change watch only when the set actually changed, so periodic
    /// identical re-reports do not re-drive gate consumers.
    pub fn record_bound_ports(&self, node_id: &str, ports: BTreeSet<u16>) {
        let mut guard = self.0.map.lock();
        let Some(entry) = guard.nodes.get_mut(node_id) else {
            return;
        };
        if entry.bound_ports.as_ref() == Some(&ports) {
            return;
        }
        entry.bound_ports = Some(ports);
        drop(guard);
        self.bump();
    }

    /// Fold a relay's `RosterReport` into the registry (#585): wholesale-replace
    /// every child of `parent_node_id` with `children`, and mark the parent as a
    /// relay so the #531 quorum excludes its own ack.
    ///
    /// Each entry in `children` is (re-)stamped `parent = Some(parent_node_id)`
    /// and keyed by its own `node_id`; any prior child of this relay absent from
    /// `children` is dropped (a leaf that disconnected at the relay). No-op on
    /// the `is_relay` marker if the parent stream is not (yet) in the registry —
    /// the children are still folded, and the parent's own `connect` will have
    /// inserted its row first in the normal stream lifecycle.
    ///
    /// Bumps the change watch: folded leaves change the bound-port / ack quorum
    /// inputs, so the #531 gate consumers must re-evaluate.
    ///
    /// A roster child whose `node_id` collides with a **directly-connected** row
    /// (`parent == None` — a leaf that dials the controller itself, or the relay
    /// parent's own row) is skipped, never overwritten: `node_id`s are globally
    /// unique (pod UID / hostname), so a collision is only a transient during a
    /// repoint, and a live direct stream stays authoritative. Without this, a
    /// stale roster copy would displace the direct row and — worse — `parent`
    /// would flip to this relay, so the relay's later disconnect would
    /// [`Self::evict_children`] a healthy direct node.
    pub fn apply_roster(&self, parent_node_id: &str, children: Vec<RosterChild>) {
        let mut guard = self.0.map.lock();
        if let Some(parent) = guard.nodes.get_mut(parent_node_id) {
            parent.is_relay = true;
        }
        // Drop the relay's prior children not present in the new report.
        guard
            .nodes
            .retain(|_, e| e.parent.as_deref() != Some(parent_node_id));
        for child in children {
            // Never let a roster entry displace a directly-connected row.
            if guard
                .nodes
                .get(&child.node_id)
                .is_some_and(|e| e.parent.is_none())
            {
                continue;
            }
            let node_id = child.node_id.clone();
            let entry = NodeEntry {
                node_id: child.node_id,
                scope: child.scope,
                last_acked_version: child.last_acked_version,
                target_version: child.target_version,
                last_ack_at: child.last_ack_at,
                connected_since: child.connected_since,
                bound_ports: child.bound_ports,
                last_acked_seq: child.last_acked_seq,
                parent: Some(parent_node_id.to_owned()),
                is_relay: false,
            };
            guard.nodes.insert(node_id, entry);
        }
        drop(guard);
        self.bump();
    }

    /// Evict a relay's entire subtree (#585): remove every entry whose `parent`
    /// is `parent_node_id`. Called when the relay's upstream stream drops so the
    /// #531 gate fails closed on the now-invisible leaves rather than gating a
    /// new publish on stale roster state. The relay's own row is removed
    /// separately by [`Self::disconnect`]. Bumps the watch only if a row was
    /// actually removed.
    pub fn evict_children(&self, parent_node_id: &str) {
        let mut guard = self.0.map.lock();
        let before = guard.nodes.len();
        guard
            .nodes
            .retain(|_, e| e.parent.as_deref() != Some(parent_node_id));
        let removed = guard.nodes.len() != before;
        drop(guard);
        if removed {
            self.bump();
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
        self.load().controller_version()
    }

    /// Quorum query without a snapshot clone (#531): evaluates
    /// [`NodeRegistry::all_shared_nodes_bound`] under the mutex. Reconciles
    /// answer a bool here on every pass; cloning the whole map for that would
    /// be O(nodes) per Gateway per requeue.
    #[must_use]
    pub fn all_shared_nodes_bound(&self, required: &BTreeSet<u16>) -> bool {
        self.0.map.lock().all_shared_nodes_bound(required)
    }

    /// Quorum query without a snapshot clone (#531): evaluates
    /// [`NodeRegistry::gateway_node_bound`] under the mutex.
    #[must_use]
    pub fn gateway_node_bound(
        &self,
        namespace: &str,
        name: &str,
        required: &BTreeSet<u16>,
    ) -> bool {
        self.0
            .map
            .lock()
            .gateway_node_bound(namespace, name, required)
    }

    /// Quorum query without a snapshot clone (#531): evaluates
    /// [`NodeRegistry::all_shared_nodes_acked`] under the mutex.
    #[must_use]
    pub fn all_shared_nodes_acked(&self, min_seq: u64) -> bool {
        self.0.map.lock().all_shared_nodes_acked(min_seq)
    }

    /// Quorum query without a snapshot clone (#531): evaluates
    /// [`NodeRegistry::gateway_node_acked`] under the mutex.
    #[must_use]
    pub fn gateway_node_acked(&self, namespace: &str, name: &str, min_seq: u64) -> bool {
        self.0
            .map
            .lock()
            .gateway_node_acked(namespace, name, min_seq)
    }

    /// Remove a node's row on stream exit.
    ///
    /// No-op if the node is not present.
    pub fn disconnect(&self, node_id: &str) {
        let removed = self.0.map.lock().nodes.remove(node_id).is_some();
        if removed {
            self.bump();
        }
    }

    /// Return a cloned point-in-time snapshot of the registry.
    ///
    /// Callers should hold the returned value briefly and not cache it across
    /// reconcile cycles.
    #[must_use]
    pub fn load(&self) -> NodeRegistry {
        self.0.map.lock().clone()
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
        reg.record_ack("node-a", "abc123".to_owned(), 1, ack_time);
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
        reg.record_ack("phantom", "hash".to_owned(), 1, now());
        assert!(reg.load().nodes.is_empty());
    }

    #[test]
    fn record_target_then_ack_is_in_sync() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.record_target("node-a", "v1".to_owned());
        assert!(!reg.load().nodes["node-a"].in_sync(), "not yet acked");
        reg.record_ack("node-a", "v1".to_owned(), 1, now());
        assert!(reg.load().nodes["node-a"].in_sync(), "acked the target");
    }

    #[test]
    fn ack_of_stale_version_is_out_of_sync() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.record_target("node-a", "v2".to_owned());
        reg.record_ack("node-a", "v1".to_owned(), 1, now());
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
        reg.record_ack("node-a", "v1".to_owned(), 1, now());
        reg.connect("node-b", shared(), now());
        reg.record_target("node-b", "v2".to_owned());
        reg.record_ack("node-b", "v2".to_owned(), 1, now());
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

    // ── NodeRegistry::merge / controller_version (topology fan-out) ─────────────

    #[test]
    fn merge_unions_disjoint_node_ids() {
        let a = SharedNodeRegistry::new();
        a.connect("node-a", shared(), now());
        let b = SharedNodeRegistry::new();
        b.connect("node-b", shared(), now());
        let mut merged = a.load();
        merged.merge(b.load());
        assert_eq!(merged.nodes.len(), 2);
        assert!(merged.nodes.contains_key("node-a"));
        assert!(merged.nodes.contains_key("node-b"));
    }

    #[test]
    fn merge_overwrites_on_shared_node_id() {
        let a = SharedNodeRegistry::new();
        a.connect("node-a", shared(), now());
        a.record_target("node-a", "v1".to_owned());
        let b = SharedNodeRegistry::new();
        b.connect("node-a", shared(), now());
        b.record_target("node-a", "v2".to_owned());
        let mut merged = a.load();
        merged.merge(b.load());
        assert_eq!(merged.nodes.len(), 1, "same node_id collapses to one entry");
        assert_eq!(
            merged.nodes["node-a"].target_version.as_deref(),
            Some("v2"),
            "the merged-in registry wins on collision"
        );
    }

    #[test]
    fn controller_version_on_plain_registry_matches_shared_handle() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.record_target("node-a", "v42".to_owned());
        let snap = reg.load();
        assert_eq!(snap.controller_version().as_deref(), Some("v42"));
        assert_eq!(snap.controller_version(), reg.controller_version());
    }

    // ── bound-port reports + change watch (#531) ────────────────────────────────

    fn ports(list: &[u16]) -> BTreeSet<u16> {
        list.iter().copied().collect()
    }

    #[test]
    fn record_bound_ports_on_unknown_node_is_noop() {
        let reg = SharedNodeRegistry::new();
        reg.record_bound_ports("phantom", ports(&[8080]));
        assert!(reg.load().nodes.is_empty());
    }

    #[test]
    fn all_shared_nodes_bound_true_when_all_connected_nodes_cover_ports() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.connect("node-b", shared(), now());
        reg.record_bound_ports("node-a", ports(&[30001, 30002, 8443]));
        reg.record_bound_ports("node-b", ports(&[30001, 30002]));
        assert!(
            reg.load().all_shared_nodes_bound(&ports(&[30001, 30002])),
            "both nodes cover the required set (supersets allowed)"
        );
    }

    #[test]
    fn all_shared_nodes_bound_false_when_one_node_misses_a_port() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.connect("node-b", shared(), now());
        reg.record_bound_ports("node-a", ports(&[30001, 30002]));
        reg.record_bound_ports("node-b", ports(&[30001]));
        assert!(
            !reg.load().all_shared_nodes_bound(&ports(&[30001, 30002])),
            "node-b missing 30002 must fail the all-connected quorum"
        );
    }

    #[test]
    fn all_shared_nodes_bound_fails_closed_on_empty_registry() {
        let reg = SharedNodeRegistry::new();
        assert!(
            !reg.load().all_shared_nodes_bound(&ports(&[30001])),
            "zero connected proxies means no data plane — must not pass vacuously"
        );
    }

    #[test]
    fn all_shared_nodes_bound_false_when_node_has_not_reported() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        assert!(
            !reg.load().all_shared_nodes_bound(&ports(&[30001])),
            "unreported node (bound_ports=None) counts as not bound"
        );
        // And None must stay distinct from an affirmative empty report:
        reg.record_bound_ports("node-a", ports(&[]));
        assert!(
            !reg.load().all_shared_nodes_bound(&ports(&[30001])),
            "affirmative empty report still does not cover a non-empty requirement"
        );
    }

    #[test]
    fn all_shared_nodes_bound_empty_required_passes_once_connected_and_reported() {
        let reg = SharedNodeRegistry::new();
        assert!(
            !reg.load().all_shared_nodes_bound(&ports(&[])),
            "empty pool fails closed even with nothing required"
        );
        reg.connect("node-a", shared(), now());
        assert!(
            !reg.load().all_shared_nodes_bound(&ports(&[])),
            "unreported node fails closed even with nothing required"
        );
        reg.record_bound_ports("node-a", ports(&[]));
        assert!(
            reg.load().all_shared_nodes_bound(&ports(&[])),
            "a Gateway with no allocated internal ports has nothing to await"
        );
    }

    #[test]
    fn dedicated_scope_nodes_excluded_from_shared_bound_query() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.record_bound_ports("node-a", ports(&[30001]));
        reg.connect("node-d", gw("ns", "gw"), now());
        // node-d never reports; must not drag the shared quorum down.
        assert!(
            reg.load().all_shared_nodes_bound(&ports(&[30001])),
            "dedicated-scope nodes do not serve the shared VIP and are excluded"
        );
    }

    #[test]
    fn disconnect_of_only_bound_node_fails_the_query_closed() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.record_bound_ports("node-a", ports(&[30001]));
        assert!(reg.load().all_shared_nodes_bound(&ports(&[30001])));
        reg.disconnect("node-a");
        assert!(
            !reg.load().all_shared_nodes_bound(&ports(&[30001])),
            "row removal on stream exit must clear the node's contribution"
        );
    }

    #[test]
    fn re_report_wholesale_replaces_previous_bound_set() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.record_bound_ports("node-a", ports(&[30001, 30002]));
        reg.record_bound_ports("node-a", ports(&[30002]));
        assert!(
            !reg.load().all_shared_nodes_bound(&ports(&[30001])),
            "a shrunk re-report must replace, not union with, the prior set"
        );
        assert!(reg.load().all_shared_nodes_bound(&ports(&[30002])));
    }

    #[test]
    fn gateway_node_bound_matches_only_its_gateway() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-d", gw("ns", "gw"), now());
        reg.record_bound_ports("node-d", ports(&[443]));
        let snap = reg.load();
        assert!(snap.gateway_node_bound("ns", "gw", &ports(&[443])));
        assert!(
            !snap.gateway_node_bound("ns", "other", &ports(&[443])),
            "a different Gateway has no connected node"
        );
        assert!(
            !snap.gateway_node_bound("ns", "gw", &ports(&[443, 8443])),
            "missing port fails the dedicated quorum"
        );
    }

    #[test]
    fn gateway_node_bound_requires_all_overlapping_rollout_pods_bound() {
        let reg = SharedNodeRegistry::new();
        reg.connect("pod-old", gw("ns", "gw"), now());
        reg.record_bound_ports("pod-old", ports(&[443]));
        reg.connect("pod-new", gw("ns", "gw"), now());
        let snap = reg.load();
        assert!(
            !snap.gateway_node_bound("ns", "gw", &ports(&[443])),
            "unreported replacement pod during a rollout overlap must hold the gate"
        );
    }

    #[test]
    fn gateway_node_bound_fails_closed_with_no_connected_node() {
        let reg = SharedNodeRegistry::new();
        assert!(!reg.load().gateway_node_bound("ns", "gw", &ports(&[443])));
    }

    // ── ack-sequence quorum (#531 content convergence) ───────────────────────

    #[test]
    fn all_shared_nodes_acked_true_when_every_node_reached_the_seq() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.connect("node-b", shared(), now());
        reg.record_ack("node-a", "v1".to_owned(), 7, now());
        reg.record_ack("node-b", "v1".to_owned(), 9, now());
        assert!(reg.all_shared_nodes_acked(7), "both at seq >= 7");
        assert!(!reg.all_shared_nodes_acked(8), "node-a is behind seq 8");
    }

    #[test]
    fn all_shared_nodes_acked_fails_closed_on_empty_pool_and_unacked_node() {
        let reg = SharedNodeRegistry::new();
        assert!(!reg.all_shared_nodes_acked(0), "empty pool fails closed");
        reg.connect("node-a", shared(), now());
        assert!(
            !reg.all_shared_nodes_acked(0),
            "connected-but-never-acked node fails closed"
        );
    }

    #[test]
    fn acked_seq_never_moves_backwards() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.record_ack("node-a", "v2".to_owned(), 5, now());
        reg.record_ack("node-a", "v1".to_owned(), 3, now());
        assert!(
            reg.all_shared_nodes_acked(5),
            "a late lower-seq ack must not regress the stamp"
        );
    }

    #[test]
    fn advance_acked_seq_moves_forward_without_an_ack() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", shared(), now());
        reg.record_ack("node-a", "v1".to_owned(), 2, now());
        reg.advance_acked_seq("node-a", 6);
        assert!(reg.all_shared_nodes_acked(6));
        reg.advance_acked_seq("node-a", 4);
        assert!(reg.all_shared_nodes_acked(6), "advance is monotone");
        assert_eq!(
            reg.load().nodes["node-a"].last_acked_version.as_deref(),
            Some("v1"),
            "advance must not touch the acked content hash"
        );
    }

    #[test]
    fn gateway_node_acked_scopes_to_its_gateway() {
        let reg = SharedNodeRegistry::new();
        reg.connect("ded-a", gw("ns", "gw"), now());
        reg.connect("other", gw("ns", "other-gw"), now());
        reg.record_ack("ded-a", "v1".to_owned(), 4, now());
        assert!(reg.gateway_node_acked("ns", "gw", 4));
        assert!(!reg.gateway_node_acked("ns", "gw", 5));
        assert!(
            !reg.gateway_node_acked("ns", "other-gw", 1),
            "the other gateway's node never acked"
        );
        assert!(
            !reg.gateway_node_acked("ns", "absent", 0),
            "no connected node fails closed"
        );
    }

    #[test]
    fn watch_fires_on_membership_and_bound_changes_but_not_acks() {
        let reg = SharedNodeRegistry::new();
        let mut rx = reg.subscribe();
        assert!(!rx.has_changed().unwrap_or(true), "no change at subscribe");

        reg.connect("node-a", shared(), now());
        assert!(rx.has_changed().unwrap_or(false), "connect must fire");
        rx.borrow_and_update();

        reg.record_target("node-a", "v1".to_owned());
        reg.record_ack("node-a", "v1".to_owned(), 1, now());
        assert!(
            !rx.has_changed().unwrap_or(true),
            "ack/target stamps must not fire the gate watch"
        );

        reg.record_bound_ports("node-a", ports(&[30001]));
        assert!(rx.has_changed().unwrap_or(false), "bound change must fire");
        rx.borrow_and_update();

        reg.record_bound_ports("node-a", ports(&[30001]));
        assert!(
            !rx.has_changed().unwrap_or(true),
            "identical re-report must not fire"
        );

        reg.disconnect("node-a");
        assert!(rx.has_changed().unwrap_or(false), "disconnect must fire");
        rx.borrow_and_update();

        reg.disconnect("node-a");
        assert!(
            !rx.has_changed().unwrap_or(true),
            "no-op disconnect must not fire"
        );
    }

    // ── roster fold / subtree eviction / relay exclusion (#585) ──────────────────

    fn leaf(node_id: &str, scope: NodeScope, seq: u64, bound: &[u16]) -> RosterChild {
        RosterChild {
            node_id: node_id.to_owned(),
            scope,
            last_acked_version: Some("v1".to_owned()),
            target_version: Some("v1".to_owned()),
            last_acked_seq: Some(seq),
            bound_ports: Some(ports(bound)),
            connected_since: now(),
            last_ack_at: Some(now()),
        }
    }

    #[test]
    fn apply_roster_folds_children_tagged_with_parent() {
        let reg = SharedNodeRegistry::new();
        reg.connect(
            "relay-a",
            NodeScope::Namespace {
                namespace: "ns".to_owned(),
            },
            now(),
        );
        reg.apply_roster(
            "relay-a",
            vec![
                leaf("leaf-1", gw("ns", "gw1"), 5, &[443]),
                leaf("leaf-2", gw("ns", "gw2"), 6, &[8443]),
            ],
        );
        let snap = reg.load();
        assert_eq!(snap.nodes["leaf-1"].parent.as_deref(), Some("relay-a"));
        assert_eq!(snap.nodes["leaf-2"].parent.as_deref(), Some("relay-a"));
        assert!(
            snap.nodes["relay-a"].is_relay,
            "reporting a roster marks the parent as a relay"
        );
    }

    #[test]
    fn apply_roster_wholesale_replaces_prior_children() {
        let reg = SharedNodeRegistry::new();
        reg.connect(
            "relay-a",
            NodeScope::Namespace {
                namespace: "ns".to_owned(),
            },
            now(),
        );
        reg.apply_roster("relay-a", vec![leaf("leaf-1", gw("ns", "gw1"), 5, &[443])]);
        // Second report drops leaf-1, adds leaf-2 (leaf-1 disconnected at the relay).
        reg.apply_roster("relay-a", vec![leaf("leaf-2", gw("ns", "gw2"), 6, &[8443])]);
        let snap = reg.load();
        assert!(
            !snap.nodes.contains_key("leaf-1"),
            "a child absent from the latest report is evicted"
        );
        assert!(snap.nodes.contains_key("leaf-2"));
    }

    #[test]
    fn apply_roster_does_not_touch_other_relays_children() {
        let reg = SharedNodeRegistry::new();
        reg.apply_roster("relay-a", vec![leaf("leaf-a", gw("ns", "gw1"), 5, &[443])]);
        reg.apply_roster("relay-b", vec![leaf("leaf-b", gw("ns", "gw2"), 6, &[8443])]);
        // Re-report relay-a with a new child; relay-b's subtree is untouched.
        reg.apply_roster("relay-a", vec![leaf("leaf-a2", gw("ns", "gw1"), 7, &[443])]);
        let snap = reg.load();
        assert!(
            snap.nodes.contains_key("leaf-b"),
            "relay-b subtree preserved"
        );
        assert!(!snap.nodes.contains_key("leaf-a"));
        assert!(snap.nodes.contains_key("leaf-a2"));
    }

    #[test]
    fn apply_roster_never_displaces_a_directly_connected_row() {
        let reg = SharedNodeRegistry::new();
        // A directly-connected node dials the controller itself.
        reg.connect("dup", shared(), now());
        reg.record_bound_ports("dup", ports(&[30001]));
        // A relay reports a child with the SAME node_id (repoint transient).
        reg.apply_roster("relay-a", vec![leaf("dup", gw("ns", "gw"), 9, &[443])]);
        let snap = reg.load();
        // The direct row is authoritative: still parent-less, still SharedPool.
        assert_eq!(snap.nodes["dup"].parent, None, "direct row not hijacked");
        assert_eq!(snap.nodes["dup"].scope, NodeScope::SharedPool);
        // And a relay disconnect must NOT evict the healthy direct node.
        reg.evict_children("relay-a");
        assert!(
            reg.load().nodes.contains_key("dup"),
            "relay eviction must not remove a directly-connected node"
        );
    }

    #[test]
    fn evict_children_removes_only_the_named_relays_subtree() {
        let reg = SharedNodeRegistry::new();
        reg.apply_roster("relay-a", vec![leaf("leaf-a", gw("ns", "gw1"), 5, &[443])]);
        reg.apply_roster("relay-b", vec![leaf("leaf-b", gw("ns", "gw2"), 6, &[8443])]);
        reg.evict_children("relay-a");
        let snap = reg.load();
        assert!(
            !snap.nodes.contains_key("leaf-a"),
            "relay-a subtree evicted"
        );
        assert!(
            snap.nodes.contains_key("leaf-b"),
            "relay-b subtree untouched"
        );
    }

    // ── relay control-loop signal / ready / drain gates (#602) ───────────────────

    fn ns_scope(namespace: &str) -> NodeScope {
        NodeScope::Namespace {
            namespace: namespace.to_owned(),
        }
    }

    #[test]
    fn namespace_leaf_count_counts_direct_and_folded_leaves() {
        let reg = SharedNodeRegistry::new();
        // One leaf dialing the controller directly, one folded behind the relay.
        reg.connect("direct", gw("ns", "gw1"), now());
        reg.connect("relay-a", ns_scope("ns"), now());
        reg.apply_roster("relay-a", vec![leaf("folded", gw("ns", "gw2"), 5, &[443])]);
        // A leaf in another namespace must not count.
        reg.connect("other", gw("other-ns", "gw3"), now());
        let snap = reg.load();
        assert_eq!(
            snap.namespace_leaf_count("ns"),
            2,
            "both the direct and the relay-folded leaf in ns count; the relay's own \
             Namespace entry does not"
        );
        assert_eq!(snap.namespace_leaf_count("empty"), 0);
    }

    #[test]
    fn relay_ready_true_only_when_relay_entry_in_sync() {
        let reg = SharedNodeRegistry::new();
        reg.connect("relay-a", ns_scope("ns"), now());
        reg.apply_roster("relay-a", vec![leaf("leaf-1", gw("ns", "gw"), 5, &[443])]);
        let snap = reg.load();
        assert!(
            !snap.relay_ready("ns"),
            "a provisioned-but-unacked relay is not yet ready to serve leaves"
        );
        // The relay Acks the controller's Namespace snapshot: cache loaded.
        reg.record_target("relay-a", "v1".to_owned());
        reg.record_ack("relay-a", "v1".to_owned(), 1, now());
        assert!(
            reg.load().relay_ready("ns"),
            "an in_sync relay entry means the upstream cache is loaded → ready"
        );
    }

    #[test]
    fn relay_subscriber_count_counts_folded_children() {
        let reg = SharedNodeRegistry::new();
        reg.connect("relay-a", ns_scope("ns"), now());
        assert_eq!(
            reg.load().relay_subscriber_count("ns"),
            0,
            "no relay yet folded any leaf"
        );
        reg.apply_roster(
            "relay-a",
            vec![
                leaf("leaf-1", gw("ns", "gw1"), 5, &[443]),
                leaf("leaf-2", gw("ns", "gw2"), 6, &[8443]),
            ],
        );
        assert_eq!(
            reg.load().relay_subscriber_count("ns"),
            2,
            "both folded leaves are still subscribed to the relay"
        );
        // Every leaf repointed back to the controller: the drain gate opens.
        reg.apply_roster("relay-a", vec![]);
        assert_eq!(
            reg.load().relay_subscriber_count("ns"),
            0,
            "with no folded children the relay may be torn down"
        );
    }

    #[test]
    fn folded_gateway_leaf_satisfies_the_dedicated_gate() {
        let reg = SharedNodeRegistry::new();
        reg.connect(
            "relay-a",
            NodeScope::Namespace {
                namespace: "ns".to_owned(),
            },
            now(),
        );
        reg.apply_roster("relay-a", vec![leaf("leaf-1", gw("ns", "gw"), 9, &[443])]);
        let snap = reg.load();
        assert!(
            snap.gateway_node_bound("ns", "gw", &ports(&[443])),
            "the folded leaf's bound ports satisfy the dedicated quorum"
        );
        assert!(
            snap.gateway_node_acked("ns", "gw", 9),
            "the folded leaf's acked seq satisfies the dedicated ack gate"
        );
    }

    #[test]
    fn relay_outage_eviction_fails_the_dedicated_gate_closed() {
        let reg = SharedNodeRegistry::new();
        reg.apply_roster("relay-a", vec![leaf("leaf-1", gw("ns", "gw"), 9, &[443])]);
        assert!(reg.load().gateway_node_bound("ns", "gw", &ports(&[443])));
        reg.evict_children("relay-a");
        assert!(
            !reg.load().gateway_node_bound("ns", "gw", &ports(&[443])),
            "with the subtree evicted, no connected node serves the Gateway — fail closed"
        );
    }

    #[test]
    fn shared_relay_own_entry_excluded_from_shared_quorum() {
        let reg = SharedNodeRegistry::new();
        // A shared-pool relay connects (SharedPool scope) and reports two leaves.
        reg.connect("relay-shared", shared(), now());
        reg.apply_roster(
            "relay-shared",
            vec![
                leaf("leaf-1", shared(), 4, &[30001]),
                leaf("leaf-2", shared(), 4, &[30001]),
            ],
        );
        let snap = reg.load();
        // The relay itself never reported bound ports; without exclusion it would
        // fail the quorum forever. The leaves cover the required set.
        assert!(
            snap.all_shared_nodes_bound(&ports(&[30001])),
            "the relay's own (unbound) entry must be excluded; its leaves satisfy the gate"
        );
        assert!(snap.all_shared_nodes_acked(4), "leaves acked the seq");
        assert_eq!(
            snap.controller_version().as_deref(),
            Some("v1"),
            "controller_version derives from a folded leaf, not the excluded relay entry"
        );
    }

    #[test]
    fn node_entry_json_without_bound_ports_defaults_to_none() {
        // Pre-#531 peers serialize NodeEntry without the field; the admin
        // fan-out merge must keep decoding their JSON.
        let json = r#"{
            "node_id": "node-a",
            "scope": {"kind": "SharedPool"},
            "last_acked_version": null,
            "target_version": null,
            "last_ack_at": null,
            "connected_since": {"secs_since_epoch": 0, "nanos_since_epoch": 0}
        }"#;
        let entry: NodeEntry = serde_json::from_str(json).expect("legacy JSON must decode");
        assert_eq!(entry.bound_ports, None);
    }

    #[test]
    fn node_entry_and_registry_round_trip_json() {
        let reg = SharedNodeRegistry::new();
        reg.connect("node-a", gw("default", "my-gw"), now());
        reg.record_target("node-a", "v1".to_owned());
        reg.record_ack("node-a", "v1".to_owned(), 1, now());
        let snap = reg.load();

        let json = serde_json::to_string(&snap).expect("serialize");
        let round_tripped: NodeRegistry = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(round_tripped.nodes.len(), 1);
        let entry = &round_tripped.nodes["node-a"];
        assert_eq!(entry.scope, gw("default", "my-gw"));
        assert_eq!(entry.target_version.as_deref(), Some("v1"));
        assert_eq!(entry.last_acked_version.as_deref(), Some("v1"));
        assert!(entry.in_sync());
    }
}
