//! A read-only view that merges one-or-more per-namespace reflector stores
//! into a single logical store.
//!
//! Multi-namespace watch (#59) spawns **one** reflector [`Store`] per watched
//! namespace, rather than one cluster-wide store, so the controller can run
//! with a namespaced `Role` per namespace instead of cluster-wide read. Merging
//! the per-namespace watch *streams* into a single store is not an option: each
//! namespaced `watcher()` emits its own `Init…InitDone` relist cycle, and a
//! shared store would let one namespace's `InitDone` clobber the others'
//! entries. Independent per-namespace stores keep clean relist semantics; this
//! type stitches their read side back together.
//!
//! [`MergedStore`] mirrors exactly the read surface the reconcile/rebuild and
//! status paths use (`state`, `get`, `len`, `is_empty`), so migrating a field
//! from `Store<K>` to `MergedStore<K>` is a type swap with no call-site churn.
//! The common single-store case (cluster-wide, single-namespace, or a
//! cluster-scoped resource) delegates straight through with no extra
//! allocation.

use kube::runtime::reflector::{Lookup, ObjectRef, Store};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

/// Read-only merged view over N per-namespace reflector [`Store`]s.
///
/// Construct with [`MergedStore::single`] for a single cluster-wide or
/// cluster-scoped store, or [`MergedStore::new`] with one `(namespace, store)`
/// pair per watched namespace. Namespaces are disjoint by object key, so the
/// merge needs no de-duplication.
#[non_exhaustive]
pub struct MergedStore<K>
where
    K: Lookup + 'static,
    K::DynamicType: Eq + Hash + Clone,
{
    /// One reflector store per watched namespace (or a single cluster-wide /
    /// cluster-scoped store). May be empty only for a degenerate empty
    /// namespace list, which [`WatchScope::parse`](crate::WatchScope::parse)
    /// never produces; the read methods stay correct (empty) regardless.
    stores: Vec<Store<K>>,
    /// `namespace -> index into stores`, for O(1) [`get`](Self::get) routing.
    /// Empty when there is a single store (routing is unnecessary — `get`
    /// delegates directly) or for cluster-scoped stores (no namespace).
    by_namespace: HashMap<String, usize>,
}

impl<K> MergedStore<K>
where
    K: Lookup + Clone + 'static,
    K::DynamicType: Eq + Hash + Clone,
{
    /// Build a merged view from one `(namespace, store)` pair per watched
    /// namespace. A `None` namespace (cluster-wide or cluster-scoped) is not
    /// indexed for routing. A single-element input behaves exactly like
    /// [`MergedStore::single`].
    #[must_use]
    pub fn new(scoped: Vec<(Option<String>, Store<K>)>) -> Self {
        let mut by_namespace = HashMap::with_capacity(scoped.len());
        let mut stores = Vec::with_capacity(scoped.len());
        for (namespace, store) in scoped {
            if let Some(ns) = namespace {
                by_namespace.insert(ns, stores.len());
            }
            stores.push(store);
        }
        Self {
            stores,
            by_namespace,
        }
    }

    /// A merged view wrapping a single store — the cluster-wide, single-
    /// namespace, or cluster-scoped case. Read methods delegate straight
    /// through with no per-call allocation or lookup.
    #[must_use]
    pub fn single(store: Store<K>) -> Self {
        Self {
            stores: vec![store],
            by_namespace: HashMap::new(),
        }
    }

    /// A full snapshot of the current values across every inner store.
    ///
    /// For a single store this returns its snapshot directly; otherwise the
    /// per-namespace snapshots are concatenated into one pre-sized `Vec`.
    #[must_use]
    pub fn state(&self) -> Vec<Arc<K>> {
        match self.stores.as_slice() {
            [] => Vec::new(),
            [only] => only.state(),
            many => {
                let total: usize = many.iter().map(Store::len).sum();
                let mut out = Vec::with_capacity(total);
                for store in many {
                    out.extend(store.state());
                }
                out
            }
        }
    }

    /// Retrieve a `clone()` of the entry referred to by `key`, if cached.
    ///
    /// With multiple stores the lookup routes to the store watching
    /// `key.namespace` (O(1) via the namespace index). A key with no namespace,
    /// or one naming a namespace outside the watched set, falls back to scanning
    /// every store so cluster-scoped keys and near-miss lookups stay correct.
    #[must_use]
    pub fn get(&self, key: &ObjectRef<K>) -> Option<Arc<K>> {
        if let [only] = self.stores.as_slice() {
            return only.get(key);
        }
        if let Some(index) = key
            .namespace
            .as_deref()
            .and_then(|ns| self.by_namespace.get(ns))
        {
            return self.stores[*index].get(key);
        }
        self.stores.iter().find_map(|store| store.get(key))
    }

    /// The total number of elements across every inner store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.stores.iter().map(Store::len).sum()
    }

    /// Whether every inner store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stores.iter().all(Store::is_empty)
    }
}

// Manual `Clone` keeps the bounds explicit; cloning refreshes the cheap
// `Arc`-backed store handles and the small namespace index.
impl<K> Clone for MergedStore<K>
where
    K: Lookup + Clone + 'static,
    K::DynamicType: Eq + Hash + Clone,
{
    fn clone(&self) -> Self {
        Self {
            stores: self.stores.clone(),
            by_namespace: self.by_namespace.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MergedStore;
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::api::ObjectMeta;
    use kube::runtime::reflector::{self, ObjectRef, store::Writer};

    // A ConfigMap in `namespace` named `name`, used as an arbitrary namespaced
    // resource to exercise the merge/routing logic.
    fn cm(namespace: &str, name: &str) -> ConfigMap {
        ConfigMap {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..ObjectMeta::default()
            },
            ..ConfigMap::default()
        }
    }

    // Build a populated store by upserting each object into its writer.
    fn store_with(objects: Vec<ConfigMap>) -> reflector::Store<ConfigMap> {
        let (reader, mut writer): (_, Writer<ConfigMap>) = reflector::store();
        for object in objects {
            writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(object));
        }
        reader
    }

    #[test]
    fn single_store_delegates() {
        let store = store_with(vec![cm("a", "x")]);
        let merged = MergedStore::single(store);
        assert_eq!(merged.len(), 1);
        assert!(!merged.is_empty());
        assert!(merged.get(&ObjectRef::new("x").within("a")).is_some());
    }

    #[test]
    fn merges_disjoint_namespaces() {
        let merged = MergedStore::new(vec![
            (Some("a".to_string()), store_with(vec![cm("a", "x")])),
            (Some("b".to_string()), store_with(vec![cm("b", "y")])),
        ]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged.state().len(), 2);
        assert!(merged.get(&ObjectRef::new("x").within("a")).is_some());
        assert!(merged.get(&ObjectRef::new("y").within("b")).is_some());
        // A name that exists only in the other namespace is not found there.
        assert!(merged.get(&ObjectRef::new("y").within("a")).is_none());
    }
}
