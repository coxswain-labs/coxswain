//! Per-Gateway routing snapshot registry for the dedicated proxy model.
//!
//! The shared reconciler publishes one [`DedicatedRoutingSnapshot`] per
//! cut-over Gateway into the [`DedicatedRoutingRegistry`] during every rebuild
//! pass.  The discovery server reads from it when a proxy subscribes with
//! [`crate::Scope::Gateway`][coxswain_discovery::Scope::Gateway] — it looks up
//! the subscribing Gateway's entry and sends only that slice of the routing
//! world.
//!
//! ## Single-writer guarantee
//!
//! Only the shared reconciler writes to the registry (by storing an entirely
//! new map on each rebuild).  Because there is exactly one writer, the
//! per-Gateway clobber described in #426 cannot occur: a dedicated proxy
//! subscribing while a second dedicated Gateway is being provisioned cannot
//! receive a snapshot from which its own routes have been evicted.
//!
//! ## Store-whole-map pattern
//!
//! Every rebuild stores a fresh `HashMap<ObjectKey, Arc<DedicatedRoutingSnapshot>>`
//! atomically via [`Shared::store`], matching the same store-whole-snapshot
//! pattern used by the five shared cells (`gateway_routes`, `tls`, etc.).
//! A Gateway that is no longer cut-over simply does not appear in the new map,
//! so teardown and migration are handled automatically without an explicit
//! remove path.

use std::collections::HashMap;
use std::sync::Arc;

use crate::listener_health::GatewayListenerHealth;
use crate::ownership::ObjectKey;
use crate::routing::GatewayRoutingTable;
use crate::shared::Shared;
use crate::tls::{ClientCertStore, TlsStore};

/// The routing world for a single dedicated Gateway's proxy.
///
/// Holds exactly the slice of the routing world that a dedicated proxy
/// subscribing with `Scope::Gateway{ns, name}` needs to serve traffic:
/// gateway routes, TLS, mTLS client-cert state, and the listener-health entry
/// for the owning Gateway.  Ingress routes are always empty for dedicated
/// scopes (a dedicated proxy does not serve Ingress resources).
///
/// The routing table and stores are held as `Arc<T>` — the same `Arc` already
/// allocated by the [`Shared<T>`] machinery — so building the registry never
/// clones large data structures.
///
/// Constructed in `coxswain-reflector` by the shared reconciler; read in
/// `coxswain-discovery` to build per-subscriber snapshots.
// intentionally open: field-literal constructed in coxswain-reflector
pub struct DedicatedRoutingSnapshot {
    /// Gateway-API routing table for this Gateway only.
    pub gateway: Arc<GatewayRoutingTable>,
    /// TLS certificate store scoped to this Gateway's listeners.
    pub tls: Arc<TlsStore>,
    /// Client-certificate mTLS config store scoped to this Gateway.
    pub client_certs: Arc<ClientCertStore>,
    /// Listener-health map containing exactly the owning Gateway's entry.
    pub listener_health: HashMap<ObjectKey, GatewayListenerHealth>,
    /// ServiceAccount name (GEP-1762 `{gateway-name}-{gatewayclass-name}`) of
    /// the dedicated proxy pod for this Gateway.
    ///
    /// The dedicated proxy's SVID is
    /// `spiffe://<trust-domain>/ns/<key.namespace>/sa/<expected_proxy_sa>`.
    /// The discovery server verifies that a `Scope::Gateway` claim's SVID
    /// matches this field — a proxy authenticating with any other SA identity
    /// receives `PERMISSION_DENIED`.
    ///
    /// Stamped by the reconciler using [`crate::naming::gep1762_resource_name`],
    /// the same formula the operator uses to provision the ServiceAccount, so
    /// the binding check and provisioning can never disagree.
    pub expected_proxy_sa: String,
}

/// Lock-free registry mapping each cut-over Gateway [`ObjectKey`] to its
/// [`DedicatedRoutingSnapshot`].
///
/// Constructed once in `coxswain-bin`'s `run_controller` and cloned into both
/// the shared reconciler (writer) and the [`coxswain_discovery::SnapshotSource`]
/// (reader).  The discovery server looks up the subscribing Gateway's entry on
/// every snapshot build.
///
/// An absent key (Gateway not yet cut over, or between cut-over and snapshot
/// delivery) yields an empty snapshot — the dedicated proxy receives no routes
/// until its Gateway appears in the registry, which is the fail-closed
/// behaviour intended by #426.
pub type DedicatedRoutingRegistry = Shared<HashMap<ObjectKey, Arc<DedicatedRoutingSnapshot>>>;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_snapshot() -> Arc<DedicatedRoutingSnapshot> {
        Arc::new(DedicatedRoutingSnapshot {
            gateway: Arc::new(GatewayRoutingTable::default()),
            tls: Arc::new(TlsStore::default()),
            client_certs: Arc::new(ClientCertStore::default()),
            listener_health: HashMap::new(),
            expected_proxy_sa: "gw-a-coxswain".to_owned(),
        })
    }

    fn key(ns: &str, name: &str) -> ObjectKey {
        ObjectKey::new(ns.to_owned(), name.to_owned())
    }

    #[test]
    fn registry_starts_empty() {
        let reg: DedicatedRoutingRegistry = Shared::new();
        assert!(
            reg.load().is_empty(),
            "fresh registry must contain no entries"
        );
    }

    #[test]
    fn store_and_load_single_entry() {
        let reg: DedicatedRoutingRegistry = Shared::new();
        let k = key("prod", "gw-a");
        let snap = make_snapshot();

        let mut map = HashMap::new();
        map.insert(k.clone(), snap);
        reg.store(Arc::new(map));

        let loaded = reg.load();
        assert!(loaded.contains_key(&k), "stored key must be present");
    }

    #[test]
    fn whole_map_replace_removes_stale_entries() {
        let reg: DedicatedRoutingRegistry = Shared::new();
        let k_a = key("prod", "gw-a");
        let k_b = key("prod", "gw-b");

        // First store: two entries.
        let mut map1 = HashMap::new();
        map1.insert(k_a.clone(), make_snapshot());
        map1.insert(k_b.clone(), make_snapshot());
        reg.store(Arc::new(map1));
        assert_eq!(
            reg.load().len(),
            2,
            "both entries present after first store"
        );

        // Second store: only gw-a (gw-b migrated back to shared pool).
        let mut map2 = HashMap::new();
        map2.insert(k_a.clone(), make_snapshot());
        reg.store(Arc::new(map2));

        let loaded = reg.load();
        assert!(loaded.contains_key(&k_a), "gw-a still present");
        assert!(
            !loaded.contains_key(&k_b),
            "gw-b removed by whole-map replace"
        );
    }

    #[test]
    fn absent_key_returns_none() {
        let reg: DedicatedRoutingRegistry = Shared::new();
        let loaded = reg.load();
        assert!(
            loaded.get(&key("ns", "missing")).is_none(),
            "absent key must return None"
        );
    }
}
