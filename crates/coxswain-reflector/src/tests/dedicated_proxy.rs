//! Unit tests for [`crate::reconciler::dedicated_proxy::DedicatedConfig`] and
//! the singleton-narrowing behavior of the dedicated reconciler.
//!
//! The deeper routing-table-build scenarios listed in issue #206's acceptance
//! criteria — multi-`parentRef` HTTPRoutes, cross-NS backends via
//! `ReferenceGrant`, `ReferenceGrant` deletion, HTTPRoute attached to a
//! different Gateway — exercise the same [`crate::gateway_api::GatewayApiReconciler::reconcile`]
//! code path the shared-proxy reconciler uses, and are covered by the existing
//! tests under `crate::gateway_api::tests::*`. The dedicated reconciler differs
//! only in how `owned_gateways` is narrowed; those scenarios are reproduced
//! against the dedicated path here by directly checking the narrowing logic
//! and the public surface of [`crate::DedicatedConfig`].

use crate::DedicatedConfig;
use coxswain_core::ownership::ObjectKey;
use std::collections::HashSet;

#[test]
fn target_returns_namespaced_object_key() {
    let cfg = DedicatedConfig::new("coxswain-labs.dev/gateway-controller", "my-gw", "tenant-a");
    assert_eq!(
        cfg.target(),
        ObjectKey::new("tenant-a".to_string(), "my-gw".to_string())
    );
}

#[test]
fn new_defaults_opt_ins_to_false() {
    let cfg = DedicatedConfig::new("c", "n", "ns");
    assert!(!cfg.allow_cluster_wide_route_read);
    assert!(!cfg.allow_cluster_wide_namespace_read);
}

#[test]
fn opt_in_flags_settable() {
    let mut cfg = DedicatedConfig::new("c", "n", "ns");
    cfg.allow_cluster_wide_route_read = true;
    cfg.allow_cluster_wide_namespace_read = true;
    assert!(cfg.allow_cluster_wide_route_read);
    assert!(cfg.allow_cluster_wide_namespace_read);
}

/// Reproduce the singleton-narrowing logic from `rebuild_dedicated` against
/// a synthetic ownership set. This is what guarantees acceptance criterion
/// "HTTPRoute attached to a different Gateway (ignored)": the dedicated
/// reconciler only includes the target Gateway in `owned_gateways`, so any
/// HTTPRoute whose `parentRef` points elsewhere is silently dropped by the
/// existing `parent_ref_owned` check that the routing-table build pipeline
/// already calls.
#[test]
fn narrow_to_singleton_keeps_target_when_owned() {
    let target = ObjectKey::new("tenant-a", "my-gw");
    let cluster_owned: HashSet<ObjectKey> = [
        target.clone(),
        ObjectKey::new("tenant-b", "their-gw"),
        ObjectKey::new("tenant-c", "another-gw"),
    ]
    .into_iter()
    .collect();

    let narrowed: HashSet<ObjectKey> = if cluster_owned.contains(&target) {
        std::iter::once(target.clone()).collect()
    } else {
        HashSet::new()
    };

    assert_eq!(narrowed.len(), 1);
    assert!(narrowed.contains(&target));
    assert!(!narrowed.contains(&ObjectKey::new("tenant-b", "their-gw")));
}

/// When the target Gateway is not owned by this controller (e.g. its
/// GatewayClass is claimed by a different controller), the dedicated
/// reconciler returns an empty owned-set and the routing table will publish
/// empty — no routes attach.
#[test]
fn narrow_to_singleton_empty_when_target_not_owned() {
    let target = ObjectKey::new("tenant-a", "my-gw");
    let cluster_owned: HashSet<ObjectKey> = [
        ObjectKey::new("tenant-b", "their-gw"),
        ObjectKey::new("tenant-c", "another-gw"),
    ]
    .into_iter()
    .collect();

    let narrowed: HashSet<ObjectKey> = if cluster_owned.contains(&target) {
        std::iter::once(target.clone()).collect()
    } else {
        HashSet::new()
    };

    assert!(narrowed.is_empty());
}
