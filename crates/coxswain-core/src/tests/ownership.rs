use crate::ownership::*;
use std::collections::HashSet;
use std::sync::Arc;

fn owned(pairs: &[(&str, &str)]) -> HashSet<ObjectKey> {
    pairs
        .iter()
        .map(|(ns, name)| ObjectKey::new(*ns, *name))
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
    set.insert(ObjectKey::new("ns", "gw"));
    og.store(Arc::new(set));
    assert!(og.load().contains(&ObjectKey::new("ns", "gw")));
}

#[test]
fn owned_gateways_clone_shares_state() {
    let og = OwnedGateways::new();
    let og2 = og.clone();
    let mut set = HashSet::new();
    set.insert(ObjectKey::new("ns", "gw"));
    og.store(Arc::new(set));
    assert!(og2.load().contains(&ObjectKey::new("ns", "gw")));
}
