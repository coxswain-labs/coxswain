//! Shared status-record types for Gateway listeners, HTTPRoutes, GRPCRoutes, and BackendTLSPolicies.
//!
//! These are the reconciler-computed status payloads that flow from the reflector
//! to the controller's status writer via [`tokio::sync::watch`]-backed shared
//! cells. They carry `Accepted`/`ResolvedRefs` booleans and Gateway-API reason
//! strings — not process-liveness information (see `coxswain_core::health` for that).
//!
//! The [`GatewayListenerStatus`] family lives in `coxswain-core` so the
//! discovery wire layer can import it without pulling in the reflector crate.
//! It is re-exported here for reflector-internal use.

use crate::keys::RouteParentKey;
use arc_swap::ArcSwap;
use coxswain_core::ownership::ObjectKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::watch;

// Re-export the core listener-status types so reflector-internal modules can
// import everything status-related from one place.
pub use coxswain_core::listener_status::{
    BackendClientCertOutcome, ConflictReason, FrontendValidationOutcome, FrontendValidationStatus,
    GatewayListenerStatus, GatewayListenerStatusHandle, ListenerInfo, ListenerReadiness,
    ListenerSource, ListenerStatusKey, RouteNamespaceSet, is_supported_listener_protocol,
};

/// Status record for one (HTTPRoute/GRPCRoute/TLSRoute, parent Gateway) pair.
///
/// Produced after each reconciler rebuild and consumed by the controller's
/// leader-gated status writer to emit `Accepted` and `ResolvedRefs` conditions.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct RouteParentStatus {
    /// True when all backend refs are valid and resolvable.
    pub resolved_refs: bool,
    /// Reason string for `ResolvedRefs=False` (ignored when `resolved_refs=true`).
    pub resolved_refs_reason: &'static str,
    /// True when the route's hostnames intersect with the listener's hostname,
    /// or there is no hostname restriction.
    pub accepted: bool,
    /// Reason string for `Accepted=False` (ignored when `accepted=true`).
    pub accepted_reason: &'static str,
}

impl Default for RouteParentStatus {
    fn default() -> Self {
        Self {
            resolved_refs: true,
            resolved_refs_reason: "ResolvedRefs",
            accepted: true,
            accepted_reason: "Accepted",
        }
    }
}

/// Map from `(route, parent)` key to per-parent route status.
pub type RouteStatusMap = HashMap<RouteParentKey, RouteParentStatus>;

struct RouteStatusInner {
    map: ArcSwap<RouteStatusMap>,
    tx: watch::Sender<u64>,
}

/// Shared handle to per-(route, parent) status, produced after each reconciler rebuild.
/// The controller reads this to set accurate `Accepted` and `ResolvedRefs` conditions.
///
/// See [`GatewayListenerStatusHandle`] for the rationale behind the `watch`-based
/// notification scheme.
#[non_exhaustive]
#[derive(Clone)]
pub struct RouteStatusHandle(Arc<RouteStatusInner>);

impl Default for RouteStatusHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteStatusHandle {
    /// Construct a new shared route status map (initially empty, generation 0).
    pub fn new() -> Self {
        let (tx, _) = watch::channel(0u64);
        Self(Arc::new(RouteStatusInner {
            map: ArcSwap::from_pointee(HashMap::new()),
            tx,
        }))
    }

    /// Load the current route status map snapshot.
    pub fn load(&self) -> arc_swap::Guard<Arc<RouteStatusMap>> {
        self.0.map.load()
    }

    /// Store a new status map and notify subscribers via the generation counter.
    pub fn store_and_notify(&self, map: RouteStatusMap) {
        self.0.map.store(Arc::new(map));
        self.0.tx.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Re-fire the change notification without touching the stored map.
    ///
    /// The rebuild loop calls this once at the very end of a rebuild, after
    /// the publish index is stamped (#531): discovery subscription loops woken
    /// by the mid-rebuild [`Self::store_and_notify`] may have captured a
    /// pre-stamp publish sequence, and without a trailing tick a quiet
    /// cluster would strand the ack gate until the next content change.
    pub fn notify_rebuilt(&self) {
        self.0.tx.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Returns a `watch::Receiver` for subscribing to change notifications.
    /// See [`GatewayListenerStatusHandle::subscribe`].
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.tx.subscribe()
    }
}

/// Status record for one `BackendTLSPolicy`.
///
/// Produced during each reconciler rebuild and consumed by the controller's
/// leader-gated status writer.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct BackendTlsPolicyStatus {
    /// Owned Gateways that reference the policy's target Service via an HTTPRoute.
    /// Each becomes one entry in `status.ancestors[]`.
    pub ancestors: Vec<ObjectKey>,
    /// `true` when this policy wins conflict resolution for its target Service.
    pub accepted: bool,
    /// Reason string for the `Accepted` condition.
    pub accepted_reason: &'static str,
    /// `true` when all CA cert refs are valid and resolvable.
    pub resolved_refs: bool,
    /// Reason string for the `ResolvedRefs` condition.
    pub resolved_refs_reason: &'static str,
}

impl Default for BackendTlsPolicyStatus {
    fn default() -> Self {
        Self {
            ancestors: Vec::new(),
            accepted: true,
            accepted_reason: "Accepted",
            resolved_refs: true,
            resolved_refs_reason: "ResolvedRefs",
        }
    }
}

/// Map from `(policy_namespace, policy_name)` to its status.
pub type BackendTlsPolicyStatusMap = HashMap<ObjectKey, BackendTlsPolicyStatus>;

struct BackendTlsPolicyStatusInner {
    map: ArcSwap<BackendTlsPolicyStatusMap>,
    tx: watch::Sender<u64>,
}

/// Shared handle to per-`BackendTLSPolicy` status, produced after each reconciler rebuild.
/// The controller reads this to write `status.ancestors[]` when leader.
///
/// See [`GatewayListenerStatusHandle`] for the rationale behind the `watch`-based
/// notification scheme.
#[non_exhaustive]
#[derive(Clone)]
pub struct BackendTlsPolicyStatusHandle(Arc<BackendTlsPolicyStatusInner>);

impl Default for BackendTlsPolicyStatusHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendTlsPolicyStatusHandle {
    /// Construct a new shared policy status map (initially empty, generation 0).
    pub fn new() -> Self {
        let (tx, _) = watch::channel(0u64);
        Self(Arc::new(BackendTlsPolicyStatusInner {
            map: ArcSwap::from_pointee(HashMap::new()),
            tx,
        }))
    }

    /// Load the current policy status map snapshot.
    pub fn load(&self) -> arc_swap::Guard<Arc<BackendTlsPolicyStatusMap>> {
        self.0.map.load()
    }

    /// Store a new status map and notify subscribers via the generation counter.
    pub fn store_and_notify(&self, map: BackendTlsPolicyStatusMap) {
        self.0.map.store(Arc::new(map));
        self.0.tx.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Returns a `watch::Receiver` for subscribing to change notifications.
    /// See [`GatewayListenerStatusHandle::subscribe`].
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.tx.subscribe()
    }
}

/// Status record for one `ClientTrafficPolicy`.
///
/// Produced during each reconciler rebuild and consumed by the controller's
/// leader-gated status writer to patch `status.ancestors[]`.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct ClientTrafficPolicyStatus {
    /// `true` when the policy is accepted (no conflict on any targeted listener).
    pub accepted: bool,
    /// Reason string for the `Accepted` condition.
    pub accepted_reason: &'static str,
    /// `true` when the policy lost conflict resolution on at least one listener.
    pub conflicted: bool,
    /// Human-readable reason for the `Conflicted` condition when `conflicted` is `true`.
    pub conflicted_reason: &'static str,
}

impl Default for ClientTrafficPolicyStatus {
    fn default() -> Self {
        Self {
            accepted: true,
            accepted_reason: "Accepted",
            conflicted: false,
            conflicted_reason: "NoConflicts",
        }
    }
}

/// Map from `(policy_namespace, policy_name)` to its status.
pub type ClientTrafficPolicyStatusMap = HashMap<ObjectKey, ClientTrafficPolicyStatus>;

struct ClientTrafficPolicyStatusInner {
    map: ArcSwap<ClientTrafficPolicyStatusMap>,
    tx: watch::Sender<u64>,
}

/// Shared handle to per-`ClientTrafficPolicy` status, produced after each reconciler rebuild.
///
/// The controller reads this to write `status.ancestors[]` when leader.
#[non_exhaustive]
#[derive(Clone)]
pub struct ClientTrafficPolicyStatusHandle(Arc<ClientTrafficPolicyStatusInner>);

impl Default for ClientTrafficPolicyStatusHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientTrafficPolicyStatusHandle {
    /// Construct a new shared policy status map (initially empty, generation 0).
    #[must_use]
    pub fn new() -> Self {
        let (tx, _) = watch::channel(0u64);
        Self(Arc::new(ClientTrafficPolicyStatusInner {
            map: ArcSwap::from_pointee(HashMap::new()),
            tx,
        }))
    }

    /// Load the current policy status map snapshot.
    pub fn load(&self) -> arc_swap::Guard<Arc<ClientTrafficPolicyStatusMap>> {
        self.0.map.load()
    }

    /// Store a new status map and notify subscribers via the generation counter.
    pub fn store_and_notify(&self, map: ClientTrafficPolicyStatusMap) {
        self.0.map.store(Arc::new(map));
        self.0.tx.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Returns a `watch::Receiver` for subscribing to change notifications.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.tx.subscribe()
    }
}

/// Status record for one `CoxswainExternalAuth` (#23).
///
/// Produced during each reconciler rebuild for every policy that attaches to a
/// Gateway via `targetRefs`, and consumed by the controller's leader-gated status
/// writer to patch `status.ancestors[]` (one ancestor per targeted `Gateway`).
/// Mirrors [`ClientTrafficPolicyStatus`] — the controller turns these flags into
/// per-ancestor `Accepted`/`Conflicted` conditions. An `extensionRef`-only policy
/// (no `targetRefs`) never appears here; its resolution is reflected on the
/// referencing route's own status instead.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct CoxswainExternalAuthStatus {
    /// `true` when the policy is accepted (won conflict resolution on every
    /// targeted Gateway).
    pub accepted: bool,
    /// Reason string for the `Accepted` condition.
    pub accepted_reason: &'static str,
    /// `true` when the policy lost conflict resolution on at least one Gateway
    /// (an older policy already attached).
    pub conflicted: bool,
    /// Human-readable reason for the `Conflicted` condition when `conflicted` is `true`.
    pub conflicted_reason: &'static str,
}

impl Default for CoxswainExternalAuthStatus {
    fn default() -> Self {
        Self {
            accepted: true,
            accepted_reason: "Accepted",
            conflicted: false,
            conflicted_reason: "NoConflicts",
        }
    }
}

/// Map from `(policy_namespace, policy_name)` to its status.
pub type CoxswainExternalAuthStatusMap = HashMap<ObjectKey, CoxswainExternalAuthStatus>;

struct CoxswainExternalAuthStatusInner {
    map: ArcSwap<CoxswainExternalAuthStatusMap>,
    tx: watch::Sender<u64>,
}

/// Shared handle to per-`CoxswainExternalAuth` status, produced after each
/// reconciler rebuild. The controller reads this to write `status.ancestors[]`
/// when leader (#23).
#[non_exhaustive]
#[derive(Clone)]
pub struct CoxswainExternalAuthStatusHandle(Arc<CoxswainExternalAuthStatusInner>);

impl Default for CoxswainExternalAuthStatusHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl CoxswainExternalAuthStatusHandle {
    /// Construct a new shared policy status map (initially empty, generation 0).
    #[must_use]
    pub fn new() -> Self {
        let (tx, _) = watch::channel(0u64);
        Self(Arc::new(CoxswainExternalAuthStatusInner {
            map: ArcSwap::from_pointee(HashMap::new()),
            tx,
        }))
    }

    /// Load the current policy status map snapshot.
    pub fn load(&self) -> arc_swap::Guard<Arc<CoxswainExternalAuthStatusMap>> {
        self.0.map.load()
    }

    /// Store a new status map and notify subscribers via the generation counter.
    pub fn store_and_notify(&self, map: CoxswainExternalAuthStatusMap) {
        self.0.map.store(Arc::new(map));
        self.0.tx.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Returns a `watch::Receiver` for subscribing to change notifications.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.tx.subscribe()
    }
}

/// Status record for one `CoxswainBackendPolicy` (#354).
///
/// Produced during each reconciler rebuild and consumed by the controller's
/// leader-gated status writer to patch `status.ancestors[]` (one ancestor per
/// targeted `Service`). Mirrors [`ClientTrafficPolicyStatus`] — the controller
/// turns these flags into per-ancestor `Accepted`/`Conflicted` conditions.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct CoxswainBackendPolicyStatus {
    /// `true` when the policy is accepted (no conflict on any targeted Service).
    pub accepted: bool,
    /// Reason string for the `Accepted` condition.
    pub accepted_reason: &'static str,
    /// `true` when the policy lost conflict resolution on at least one Service.
    pub conflicted: bool,
    /// Human-readable reason for the `Conflicted` condition when `conflicted` is `true`.
    pub conflicted_reason: &'static str,
}

impl Default for CoxswainBackendPolicyStatus {
    fn default() -> Self {
        Self {
            accepted: true,
            accepted_reason: "Accepted",
            conflicted: false,
            conflicted_reason: "NoConflicts",
        }
    }
}

/// Map from `(policy_namespace, policy_name)` to its status.
pub type CoxswainBackendPolicyStatusMap = HashMap<ObjectKey, CoxswainBackendPolicyStatus>;

struct CoxswainBackendPolicyStatusInner {
    map: ArcSwap<CoxswainBackendPolicyStatusMap>,
    tx: watch::Sender<u64>,
}

/// Shared handle to per-`CoxswainBackendPolicy` status, produced after each
/// reconciler rebuild. The controller reads this to write `status.ancestors[]`
/// when leader.
#[non_exhaustive]
#[derive(Clone)]
pub struct CoxswainBackendPolicyStatusHandle(Arc<CoxswainBackendPolicyStatusInner>);

impl Default for CoxswainBackendPolicyStatusHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl CoxswainBackendPolicyStatusHandle {
    /// Construct a new shared policy status map (initially empty, generation 0).
    #[must_use]
    pub fn new() -> Self {
        let (tx, _) = watch::channel(0u64);
        Self(Arc::new(CoxswainBackendPolicyStatusInner {
            map: ArcSwap::from_pointee(HashMap::new()),
            tx,
        }))
    }

    /// Load the current policy status map snapshot.
    pub fn load(&self) -> arc_swap::Guard<Arc<CoxswainBackendPolicyStatusMap>> {
        self.0.map.load()
    }

    /// Store a new status map and notify subscribers via the generation counter.
    pub fn store_and_notify(&self, map: CoxswainBackendPolicyStatusMap) {
        self.0.map.store(Arc::new(map));
        self.0.tx.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Returns a `watch::Receiver` for subscribing to change notifications.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.tx.subscribe()
    }
}
