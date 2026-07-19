//! Internal target-port allocator for shared-mode per-Gateway addressing (#472).
//!
//! In shared mode every owned Gateway is given its own Service/VIP that maps each
//! advertised listener `port` (e.g. `:443`) to a **distinct internal `targetPort`**
//! on the one shared proxy pod. The proxy distinguishes Gateways by the local port
//! it accepted on, so cross-Gateway hostname-namespace isolation falls out of the
//! existing port-keyed routing/passthrough/TLS structures without `SO_ORIGINAL_DST`.
//!
//! [`allocate_internal_ports`] is a **pure, deterministic** function of
//! `(desired pairs, existing assignments, range)`. The persistence is the
//! provisioned Service `targetPort` itself: pass the ports read back from existing
//! Services as `existing` and the allocator reuses them, so a controller restart
//! re-derives the identical map. New `(Gateway, listenerPort)` pairs take the
//! first free port in the range under the leader-elected single writer, making the
//! result collision-free by construction.

use std::collections::{HashMap, HashSet};
use std::ops::RangeInclusive;
use std::sync::Arc;

use coxswain_core::ownership::ObjectKey;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

/// Default internal target-port band: high, fixed, and clear of the fixed shared
/// `80/443` Ingress listeners and the proxy's admin/metrics/discovery ports.
pub const DEFAULT_INTERNAL_PORT_RANGE: RangeInclusive<u16> = 30000..=32767;

/// `app.kubernetes.io/component` value stamped on the per-Gateway shared-mode
/// VIP Service (#472). The single source of truth, consumed by the operator
/// (provisioning + Services-watch scoping) and the reflector (reading back the
/// allocation to key routing/TLS by internal port).
pub const SHARED_GATEWAY_VIP_COMPONENT: &str = "shared-gateway-vip";

/// Label carrying the owning Gateway's name on a VIP Service, so its
/// `targetPort`s can be mapped back to `(Gateway, listenerPort)`.
pub const VIP_GATEWAY_NAME_LABEL: &str = "gateway.networking.k8s.io/gateway-name";

/// Label carrying the owning Gateway's **namespace** on a VIP Service. The VIP
/// Service lives in the controller's namespace (with the shared proxy pod, so
/// its selector resolves and the cloud LB assigns a real address — selectorless
/// `LoadBalancer` is unreliable across providers), so the Gateway namespace
/// cannot be inferred from the Service's own namespace and is recorded here.
pub const VIP_GATEWAY_NAMESPACE_LABEL: &str = "gateway.coxswain-labs.dev/gateway-namespace";

/// One `(Gateway, listenerPort)` pair needing an internal port.
pub type ListenerKey = (ObjectKey, u16);

/// Result of an internal-port allocation pass.
///
/// Maps each `(Gateway, listenerPort)` to its allocated internal `targetPort`,
/// and records pairs that could not be placed because the range was exhausted.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PortAllocation {
    assignments: HashMap<ListenerKey, u16>,
    exhausted: Vec<ListenerKey>,
}

impl PortAllocation {
    /// Internal port allocated for `(gateway, listener_port)`, if any.
    #[must_use]
    pub fn get(&self, gateway: &ObjectKey, listener_port: u16) -> Option<u16> {
        self.assignments
            .get(&(gateway.clone(), listener_port))
            .copied()
    }

    /// `true` when no pairs were assigned and none were exhausted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.assignments.is_empty() && self.exhausted.is_empty()
    }

    /// `true` when at least one of `gateway`'s listener ports could not be
    /// allocated (range exhausted) — the controller surfaces `Programmed=False`.
    #[must_use]
    pub fn is_gateway_exhausted(&self, gateway: &ObjectKey) -> bool {
        self.exhausted.iter().any(|(gw, _)| gw == gateway)
    }

    /// The `(Gateway, listenerPort)` pairs that could not be placed.
    #[must_use]
    pub fn exhausted(&self) -> &[ListenerKey] {
        &self.exhausted
    }

    /// Iterate `(gateway, listenerPort, internalPort)` assignments in arbitrary order.
    pub fn iter(&self) -> impl Iterator<Item = (&ObjectKey, u16, u16)> {
        self.assignments.iter().map(|((gw, lp), ip)| (gw, *lp, *ip))
    }

    /// One Gateway's `listenerPort → internalPort` map, sorted by listener port.
    ///
    /// Feeds the per-Gateway Service renderer and the reflector's route-keying:
    /// both need just this Gateway's slice of the global allocation.
    #[must_use]
    pub fn for_gateway(&self, gateway: &ObjectKey) -> std::collections::BTreeMap<u16, u16> {
        self.assignments
            .iter()
            .filter(|((gw, _), _)| gw == gateway)
            .map(|((_, lp), ip)| (*lp, *ip))
            .collect()
    }
}

/// Allocate internal target ports for every `desired` `(Gateway, listenerPort)`
/// pair, reusing `existing` assignments and filling gaps first-free from `range`.
///
/// Deterministic: existing assignments within `range` are kept; new pairs are
/// placed in a stable `(namespace/name, port)` order, each taking the lowest free
/// port. Pairs in `existing` that are absent from `desired` are ignored — their
/// Services get pruned, freeing those ports for reuse. Collision-free under a
/// single writer; a stray duplicate `existing` port is reassigned rather than
/// double-booked.
#[must_use]
pub fn allocate_internal_ports(
    desired: &[ListenerKey],
    existing: &HashMap<ListenerKey, u16>,
    range: RangeInclusive<u16>,
) -> PortAllocation {
    // Stable iteration order so first-free assignment is reproducible across
    // reconciles and controller restarts (ObjectKey is not Ord; sort by its
    // canonical "namespace/name" string, then listener port).
    let mut sorted: Vec<&ListenerKey> = desired.iter().collect();
    sorted.sort_by_key(|(gw, port)| (gw.to_string(), *port));

    let mut assignments: HashMap<ListenerKey, u16> = HashMap::new();
    let mut used: HashSet<u16> = HashSet::new();

    // Pass 1 — keep valid, in-range, collision-free existing assignments.
    for key in &sorted {
        if let Some(&port) = existing.get(*key)
            && range.contains(&port)
            && used.insert(port)
        {
            assignments.insert((*key).clone(), port);
        }
    }

    // Reserve in-range ports still held by existing assignments for keys NOT in
    // `desired` (a Gateway leaving shared mode / mid-deletion whose VIP Service —
    // and its live `targetPort` mapping — has not yet been pruned/GC'd). Reusing
    // such a port for a different Gateway before its old Service is gone would
    // route the old VIP into the new Gateway's namespace — the very isolation
    // breach this feature prevents. They free up on the next pass once the stale
    // Service is gone.
    let desired_keys: HashSet<&ListenerKey> = desired.iter().collect();
    for (key, &port) in existing {
        if !desired_keys.contains(key) && range.contains(&port) {
            used.insert(port);
        }
    }

    // Pass 2 — first-free for everything still unassigned.
    let mut exhausted: Vec<ListenerKey> = Vec::new();
    for key in &sorted {
        if assignments.contains_key(*key) {
            continue;
        }
        match range.clone().find(|p| !used.contains(p)) {
            Some(port) => {
                used.insert(port);
                assignments.insert((*key).clone(), port);
            }
            None => exhausted.push((*key).clone()),
        }
    }

    PortAllocation {
        assignments,
        exhausted,
    }
}

/// Read the `(Gateway, listenerPort) → internalPort` assignments persisted in
/// the provisioned shared-mode VIP Services (#472) — the durable source of truth
/// the reflector reads to key routing/passthrough/TLS by internal port, and the
/// operator reads as the allocator's `existing` input.
///
/// Only Services carrying the [`SHARED_GATEWAY_VIP_COMPONENT`] label are
/// considered; each maps to its Gateway via [`VIP_GATEWAY_NAME_LABEL`] in the
/// Service's own namespace.
#[must_use]
pub fn read_vip_internal_ports(services: &[Arc<Service>]) -> HashMap<ListenerKey, u16> {
    let mut out = HashMap::new();
    for svc in services {
        let labels = match svc.metadata.labels.as_ref() {
            Some(l) => l,
            None => continue,
        };
        if labels
            .get("app.kubernetes.io/component")
            .map(String::as_str)
            != Some(SHARED_GATEWAY_VIP_COMPONENT)
        {
            continue;
        }
        // The VIP Service lives in the controller namespace, so the owning
        // Gateway's namespace+name come from labels, not the Service's namespace.
        let (Some(gw_ns), Some(gw_name)) = (
            labels.get(VIP_GATEWAY_NAMESPACE_LABEL),
            labels.get(VIP_GATEWAY_NAME_LABEL),
        ) else {
            continue;
        };
        let key = ObjectKey::new(gw_ns.as_str(), gw_name.as_str());
        let Some(spec) = svc.spec.as_ref() else {
            continue;
        };
        for port in spec.ports.iter().flatten() {
            let Ok(listener_port) = u16::try_from(port.port) else {
                continue;
            };
            if let Some(IntOrString::Int(tp)) = port.target_port.as_ref()
                && let Ok(internal) = u16::try_from(*tp)
            {
                out.insert((key.clone(), listener_port), internal);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str, port: u16) -> ListenerKey {
        (ObjectKey::new("default", name), port)
    }

    #[test]
    fn new_pairs_get_first_free_in_stable_order() {
        let desired = vec![key("b-gw", 443), key("a-gw", 443), key("a-gw", 80)];
        let alloc = allocate_internal_ports(&desired, &HashMap::new(), 30000..=30005);
        // Sorted order: (a-gw,80),(a-gw,443),(b-gw,443) → 30000,30001,30002.
        assert_eq!(
            alloc.get(&ObjectKey::new("default", "a-gw"), 80),
            Some(30000)
        );
        assert_eq!(
            alloc.get(&ObjectKey::new("default", "a-gw"), 443),
            Some(30001)
        );
        assert_eq!(
            alloc.get(&ObjectKey::new("default", "b-gw"), 443),
            Some(30002)
        );
        assert!(alloc.exhausted().is_empty());
    }

    #[test]
    fn existing_assignments_are_reused_not_reshuffled() {
        // a-gw:443 already provisioned at 30007 (a high, "random" existing port).
        let mut existing = HashMap::new();
        existing.insert(key("a-gw", 443), 30007u16);
        let desired = vec![key("a-gw", 443), key("b-gw", 443)];
        let alloc = allocate_internal_ports(&desired, &existing, 30000..=30010);
        assert_eq!(
            alloc.get(&ObjectKey::new("default", "a-gw"), 443),
            Some(30007),
            "existing assignment is stable across reconciles"
        );
        // b-gw is new → first free avoiding 30007.
        assert_eq!(
            alloc.get(&ObjectKey::new("default", "b-gw"), 443),
            Some(30000)
        );
    }

    #[test]
    fn restart_rederives_identical_map_from_existing() {
        let desired = vec![key("a-gw", 80), key("a-gw", 443), key("b-gw", 443)];
        let first = allocate_internal_ports(&desired, &HashMap::new(), DEFAULT_INTERNAL_PORT_RANGE);
        // Simulate restart: feed first pass's assignments back as the existing
        // (Service-persisted) state; the result must be byte-identical.
        let existing: HashMap<ListenerKey, u16> = first
            .iter()
            .map(|(gw, lp, ip)| ((gw.clone(), lp), ip))
            .collect();
        let second = allocate_internal_ports(&desired, &existing, DEFAULT_INTERNAL_PORT_RANGE);
        assert_eq!(first, second, "allocation is stable across restart");
    }

    #[test]
    fn orphan_existing_port_is_reserved_until_pruned() {
        // a-gw at 30000 still has a live VIP Service (in `existing`) but has left
        // shared mode (absent from `desired`); b-gw is new. b-gw must NOT reuse
        // 30000 while a-gw's stale Service still maps :443 → 30000 — otherwise the
        // old VIP routes into b-gw's namespace.
        let mut existing = HashMap::new();
        existing.insert(key("a-gw", 443), 30000u16);
        let desired = vec![key("b-gw", 443)];
        let alloc = allocate_internal_ports(&desired, &existing, 30000..=30010);
        assert_eq!(
            alloc.get(&ObjectKey::new("default", "b-gw"), 443),
            Some(30001),
            "orphan port 30000 is reserved; b-gw gets the next free port"
        );
        assert_eq!(alloc.get(&ObjectKey::new("default", "a-gw"), 443), None);
    }

    #[test]
    fn port_frees_for_reuse_once_orphan_service_gone() {
        // Next pass after a-gw's Service is pruned: 30000 no longer in `existing`,
        // so b-gw may take it.
        let desired = vec![key("b-gw", 443)];
        let alloc = allocate_internal_ports(&desired, &HashMap::new(), 30000..=30010);
        assert_eq!(
            alloc.get(&ObjectKey::new("default", "b-gw"), 443),
            Some(30000),
            "freed port is reused once the orphan Service is gone"
        );
    }

    #[test]
    fn range_exhaustion_records_overflow() {
        let desired = vec![key("a-gw", 443), key("b-gw", 443), key("c-gw", 443)];
        let alloc = allocate_internal_ports(&desired, &HashMap::new(), 30000..=30001);
        // Only two ports for three pairs → c-gw (last in sort order) overflows.
        assert!(alloc.is_gateway_exhausted(&ObjectKey::new("default", "c-gw")));
        assert_eq!(alloc.exhausted().len(), 1);
        assert!(!alloc.is_gateway_exhausted(&ObjectKey::new("default", "a-gw")));
    }

    #[test]
    fn out_of_range_existing_is_reallocated() {
        // An existing port outside the (possibly reconfigured) range is dropped
        // and a fresh in-range port assigned.
        let mut existing = HashMap::new();
        existing.insert(key("a-gw", 443), 9999u16);
        let desired = vec![key("a-gw", 443)];
        let alloc = allocate_internal_ports(&desired, &existing, 30000..=30005);
        assert_eq!(
            alloc.get(&ObjectKey::new("default", "a-gw"), 443),
            Some(30000)
        );
    }
}
