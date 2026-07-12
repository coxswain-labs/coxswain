//! Shared fingerprint primitives for the partitioned incremental rebuild (#511).
//!
//! A fingerprint is a `u64` derived from `resourceVersion` strings — cheap,
//! in-memory-only (never persisted across restarts, never compared across
//! process boundaries), and not a stability guarantee: `DefaultHasher`'s
//! algorithm is unspecified across Rust versions, which is fine here since
//! nothing outlives one process's lifetime. Used to detect "did this input
//! change since the fingerprint was last computed" without re-deriving or
//! deep-comparing the object itself.

use kube::Resource;
use kube::runtime::reflector;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Fingerprint of one object's `resourceVersion`, looked up by `(namespace,
/// name)` — O(1) via the store's index, not a scan. Object absent (deleted,
/// or never existed) is a stable fingerprint distinct from any real version
/// string, so a ref target's deletion is itself a fingerprint-moving event.
pub(crate) fn object_fingerprint<K>(store: &reflector::Store<K>, ns: &str, name: &str) -> u64
where
    K: Resource<DynamicType = ()> + Clone + Send + Sync + 'static,
{
    let key = reflector::ObjectRef::<K>::new(name).within(ns);
    let mut hasher = DefaultHasher::new();
    store
        .get(&key)
        .and_then(|o| o.meta().resource_version.clone())
        .hash(&mut hasher);
    hasher.finish()
}

/// Aggregate, order-independent fingerprint of every object currently in
/// `store` — an XOR fold of each member's `(namespace, name, resourceVersion)`,
/// so it moves on any member add/remove/edit regardless of iteration order.
/// O(objects in store); call once per rebuild; never per-route or per-lookup.
///
/// Used as a coarse, always-correct fallback for inputs that a per-route
/// static scan can't cheaply and precisely attribute (`targetRef`-based
/// policy attachment, a CR's own one-hop reference to a Secret/ConfigMap):
/// fold this epoch identically into every partition's fingerprint, so any
/// change here invalidates the whole table for that one rebuild pass rather
/// than risking a partition wrongly believing itself unaffected. These
/// sources churn far less often than the endpoint/route-structural changes
/// the partitioned rebuild specifically targets, so this fallback doesn't
/// undermine its benchmarked wins — see the `RouteResolution`-adjacent doc on
/// `route_fingerprint` for exactly which inputs fall into this bucket.
pub(crate) fn store_epoch<K>(store: &reflector::Store<K>) -> u64
where
    K: Resource<DynamicType = ()> + Clone + Send + Sync + 'static,
{
    store.state().iter().fold(0u64, |acc, obj| {
        let meta = obj.meta();
        let mut hasher = DefaultHasher::new();
        meta.namespace.hash(&mut hasher);
        meta.name.hash(&mut hasher);
        meta.resource_version.hash(&mut hasher);
        acc ^ hasher.finish()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::crd::RateLimit;

    fn store_with(objs: Vec<RateLimit>) -> reflector::Store<RateLimit> {
        let mut writer = reflector::store::Writer::<RateLimit>::default();
        for o in objs {
            writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(o));
        }
        writer.as_reader()
    }

    fn rate_limit(ns: &str, name: &str, resource_version: &str) -> RateLimit {
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: RateLimit\n\
             metadata:\n  name: {name}\n  namespace: {ns}\n  resourceVersion: \"{resource_version}\"\n\
             spec:\n  requestsPerSecond: 1\n",
        );
        serde_yaml::from_str(&yaml).expect("valid RateLimit")
    }

    #[test]
    fn object_fingerprint_differs_for_different_versions() {
        let a = store_with(vec![rate_limit("ns", "rl", "1")]);
        let b = store_with(vec![rate_limit("ns", "rl", "2")]);
        assert_ne!(
            object_fingerprint(&a, "ns", "rl"),
            object_fingerprint(&b, "ns", "rl")
        );
    }

    #[test]
    fn object_fingerprint_stable_for_same_version() {
        let a = store_with(vec![rate_limit("ns", "rl", "1")]);
        let b = store_with(vec![rate_limit("ns", "rl", "1")]);
        assert_eq!(
            object_fingerprint(&a, "ns", "rl"),
            object_fingerprint(&b, "ns", "rl")
        );
    }

    #[test]
    fn object_fingerprint_absent_differs_from_present() {
        let a = store_with(vec![]);
        let b = store_with(vec![rate_limit("ns", "rl", "1")]);
        assert_ne!(
            object_fingerprint(&a, "ns", "rl"),
            object_fingerprint(&b, "ns", "rl")
        );
    }

    #[test]
    fn store_epoch_moves_on_membership_change() {
        let empty = store_with(vec![]);
        let one = store_with(vec![rate_limit("ns", "rl", "1")]);
        assert_ne!(store_epoch(&empty), store_epoch(&one));
    }

    #[test]
    fn store_epoch_moves_on_edit() {
        let v1 = store_with(vec![rate_limit("ns", "rl", "1")]);
        let v2 = store_with(vec![rate_limit("ns", "rl", "2")]);
        assert_ne!(store_epoch(&v1), store_epoch(&v2));
    }

    #[test]
    fn store_epoch_stable_across_iteration_order() {
        let a = store_with(vec![rate_limit("ns", "a", "1"), rate_limit("ns", "b", "1")]);
        let b = store_with(vec![rate_limit("ns", "b", "1"), rate_limit("ns", "a", "1")]);
        assert_eq!(store_epoch(&a), store_epoch(&b));
    }
}
