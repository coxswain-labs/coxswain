use arc_swap::ArcSwap;
use std::collections::HashSet;
use std::sync::Arc;

/// Shared snapshot of `(namespace, name)` pairs for Gateway resources managed by Coxswain.
///
/// Written by the reconciler on every rebuild; read by the controller before writing status.
/// Lock-free: `store` swaps the inner `Arc`; `load` atomically borrows the current snapshot.
#[derive(Clone)]
pub struct OwnedGateways(Arc<ArcSwap<HashSet<(String, String)>>>);

impl OwnedGateways {
    pub fn new() -> Self {
        Self(Arc::new(ArcSwap::from_pointee(HashSet::new())))
    }

    pub fn load(&self) -> arc_swap::Guard<Arc<HashSet<(String, String)>>> {
        self.0.load()
    }

    pub fn store(&self, set: HashSet<(String, String)>) {
        self.0.store(Arc::new(set));
    }
}

impl Default for OwnedGateways {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true if the given `ParentReference` fields refer to a Gateway managed by Coxswain.
///
/// Applies the Gateway API defaults:
///   - `group` defaults to `"gateway.networking.k8s.io"`
///   - `kind` defaults to `"Gateway"`
///   - `namespace` defaults to `default_ns` (the HTTPRoute's own namespace)
pub fn parent_ref_owned(
    group: Option<&str>,
    kind: Option<&str>,
    namespace: Option<&str>,
    name: &str,
    default_ns: &str,
    owned: &HashSet<(String, String)>,
) -> bool {
    let group = group.unwrap_or("gateway.networking.k8s.io");
    let kind = kind.unwrap_or("Gateway");
    if group != "gateway.networking.k8s.io" || kind != "Gateway" {
        return false;
    }
    let ns = namespace.unwrap_or(default_ns);
    owned.contains(&(ns.to_string(), name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(pairs: &[(&str, &str)]) -> HashSet<(String, String)> {
        pairs
            .iter()
            .map(|(ns, name)| (ns.to_string(), name.to_string()))
            .collect()
    }

    #[test]
    fn defaults_group_and_kind() {
        let set = owned(&[("default", "gw")]);
        assert!(parent_ref_owned(None, None, None, "gw", "default", &set));
    }

    #[test]
    fn explicit_correct_group_and_kind() {
        let set = owned(&[("default", "gw")]);
        assert!(parent_ref_owned(
            Some("gateway.networking.k8s.io"),
            Some("Gateway"),
            None,
            "gw",
            "default",
            &set
        ));
    }

    #[test]
    fn wrong_group_returns_false() {
        let set = owned(&[("default", "gw")]);
        assert!(!parent_ref_owned(
            Some("networking.istio.io"),
            None,
            None,
            "gw",
            "default",
            &set
        ));
    }

    #[test]
    fn wrong_kind_returns_false() {
        let set = owned(&[("default", "gw")]);
        assert!(!parent_ref_owned(
            None,
            Some("GatewayClass"),
            None,
            "gw",
            "default",
            &set
        ));
    }

    #[test]
    fn uses_default_ns_when_namespace_is_none() {
        let set = owned(&[("infra", "gw")]);
        assert!(parent_ref_owned(None, None, None, "gw", "infra", &set));
        assert!(!parent_ref_owned(None, None, None, "gw", "default", &set));
    }

    #[test]
    fn explicit_cross_namespace() {
        let set = owned(&[("infra", "gw")]);
        assert!(parent_ref_owned(
            None,
            None,
            Some("infra"),
            "gw",
            "default",
            &set
        ));
    }

    #[test]
    fn unknown_gateway_returns_false() {
        let set = owned(&[("default", "gw")]);
        assert!(!parent_ref_owned(
            None, None, None, "other-gw", "default", &set
        ));
    }

    #[test]
    fn owned_gateways_store_and_load() {
        let og = OwnedGateways::new();
        assert!(og.load().is_empty());
        let mut set = HashSet::new();
        set.insert(("ns".to_string(), "gw".to_string()));
        og.store(set);
        assert!(og.load().contains(&("ns".to_string(), "gw".to_string())));
    }

    #[test]
    fn owned_gateways_clone_shares_state() {
        let og = OwnedGateways::new();
        let og2 = og.clone();
        let mut set = HashSet::new();
        set.insert(("ns".to_string(), "gw".to_string()));
        og.store(set);
        assert!(og2.load().contains(&("ns".to_string(), "gw".to_string())));
    }
}
