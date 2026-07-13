//! Incrementally-maintained `(namespace, service, port)` endpoint cache (#511).
//!
//! [`resolve`](super::resolve) does a full `EndpointSlice`-store scan on
//! *every* call — the O(routes × endpoints) cost the reflector pays on every
//! rebuild, once per backend reference. [`EndpointCache`] flattens that to
//! O(slices) + O(changed services × their endpoints):
//!
//! 1. [`EndpointCache::refresh`] does **one** pass over the `EndpointSlice`
//!    store per rebuild, grouping slices by `(namespace, service)` (from the
//!    `kubernetes.io/service-name` label) and folding each group's members
//!    into a single `GroupFingerprint` — a commutative (order-independent)
//!    combination of each member's `(name, resourceVersion)`, so it moves on
//!    any member add/remove/update regardless of iteration order.
//! 2. [`EndpointCache::get`] resolves a specific `(ns, svc, port)`: if the
//!    owning group's fingerprint is unchanged since the entry was cached, it
//!    returns the cached `Arc` — no scan, no allocation. Otherwise it
//!    resolves fresh, but only over that group's already-grouped slice list
//!    (not a full store rescan) via `super::resolve_from_group`.
//!
//! `refresh` must run once per rebuild before any `get` calls. The cache is
//! owned by the rebuild loop (`reconciler::cache::ReflectorCaches`) and lives
//! across rebuilds — `rebuild()` has no other handle to prior state (see the
//! partitioned-rebuild architecture note in this crate's module docs).

use super::resolve_from_group;
use coxswain_core::endpoints::{EndpointKey, ResolvedEndpoints};
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector;
use std::collections::HashMap;
use std::sync::Arc;

/// Order-independent fold of a group's member `(name, resourceVersion)` pairs.
/// In-memory only (never persisted across process restarts), so `DefaultHasher`'s
/// fixed-but-unspecified-across-versions algorithm is an acceptable fingerprint,
/// not a stability guarantee.
type GroupFingerprint = u64;

/// One `(namespace, service)` group's backing slices, rebuilt fresh on every
/// [`EndpointCache::refresh`] call from a single `EndpointSlice`-store pass.
#[derive(Default)]
struct EndpointGroup {
    fingerprint: GroupFingerprint,
    slices: Vec<Arc<EndpointSlice>>,
}

/// Persistent, cross-rebuild endpoint-resolution cache (#511).
///
/// Not `coxswain_core::endpoints::EndpointPool` itself — that type alias is
/// the plain resolved-value shape other consumers (benches, a future wire
/// serializer) key off; this cache additionally tracks per-entry fingerprints
/// to decide reuse, which is reflector-internal bookkeeping.
///
/// [`Self::get`] takes `&self`, not `&mut self`: the route builders that call
/// it are reached through many layers of shared references (`ReflectorStores`,
/// `RuleContext`, per-rule closures) that would otherwise all need converting
/// to `&mut` just to reach one leaf lookup. Since a rebuild pass is
/// single-threaded and synchronous end to end, the resolved-entry table uses
/// `RefCell` interior mutability instead — the textbook single-thread case for
/// it. [`Self::refresh`] is the one caller that legitimately owns `&mut self`
/// (called once, at the top of a rebuild, before any `get`).
#[derive(Default)]
#[non_exhaustive]
pub struct EndpointCache {
    groups: HashMap<(Arc<str>, Arc<str>), EndpointGroup>,
    pool: std::cell::RefCell<HashMap<EndpointKey, (GroupFingerprint, Arc<ResolvedEndpoints>)>>,
}

impl EndpointCache {
    /// Regroups the `EndpointSlice` store by `(namespace, service)` and
    /// recomputes each group's fingerprint. Call once per rebuild, before any
    /// [`Self::get`] calls this cycle.
    pub fn refresh(&mut self, slices: &reflector::Store<EndpointSlice>) {
        let mut groups: HashMap<(Arc<str>, Arc<str>), EndpointGroup> = HashMap::new();
        for slice in slices.state() {
            let Some(ns) = slice.metadata.namespace.as_deref() else {
                continue;
            };
            let Some(svc) = slice
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get("kubernetes.io/service-name"))
                .map(String::as_str)
            else {
                continue;
            };
            let key = (Arc::<str>::from(ns), Arc::<str>::from(svc));
            let group = groups.entry(key).or_default();
            group.fingerprint ^= member_fingerprint(&slice);
            group.slices.push(slice);
        }
        self.groups = groups;
        // Reclaim cached resolutions whose `(namespace, service)` group no
        // longer exists, so churn of short-lived Services can't grow `pool`
        // without bound (#511). Entries for still-live groups whose fingerprint
        // moved are re-resolved lazily by `get`; this only drops vanished ones.
        let live: std::collections::HashSet<(Arc<str>, Arc<str>)> =
            self.groups.keys().cloned().collect();
        self.pool.borrow_mut().retain(|key, _| {
            live.contains(&(Arc::clone(&key.namespace), Arc::clone(&key.service)))
        });
    }

    /// Resolves `(ns, svc, port)`, reusing the cached entry when the owning
    /// group's fingerprint hasn't moved since it was cached. [`Self::refresh`]
    /// must have run this rebuild first — an unrefreshed cache treats every
    /// group as empty (no slices), which still resolves correctly (an
    /// existing-but-endpointless or nonexistent Service both surface via
    /// `ResolvedEndpoints::service_exists`) but pays the resolve cost the
    /// cache exists to avoid — never a staleness hazard, only a
    /// missed-fast-path hazard.
    ///
    /// The cache key folds in the `Service` object's own `resourceVersion`
    /// alongside the `EndpointSlice` group fingerprint: `lookup_service_port`
    /// (inside `resolve_from_group`) reads `Service.spec.ports[].targetPort`
    /// / `.appProtocol`, so a port-mapping or `appProtocol` edit is a real
    /// input change even when no `EndpointSlice` is touched — without this,
    /// such an edit would go unnoticed until unrelated slice churn happened
    /// to force a re-resolve.
    pub fn get(
        &self,
        ns: &str,
        svc: &str,
        port: i32,
        services: &reflector::Store<Service>,
    ) -> Arc<ResolvedEndpoints> {
        let (key, fingerprint) = self.cache_key_and_fingerprint(ns, svc, port, services);

        if let Some((cached_fingerprint, cached)) = self.pool.borrow().get(&key)
            && *cached_fingerprint == fingerprint
        {
            return Arc::clone(cached);
        }

        let group_key = (Arc::<str>::from(ns), Arc::<str>::from(svc));
        let empty: Vec<Arc<EndpointSlice>> = Vec::new();
        let group_slices = self
            .groups
            .get(&group_key)
            .map_or(empty.as_slice(), |g| g.slices.as_slice());
        let resolved = Arc::new(resolve_from_group(ns, svc, port, group_slices, services));
        self.pool
            .borrow_mut()
            .insert(key, (fingerprint, Arc::clone(&resolved)));
        resolved
    }

    /// The fingerprint [`Self::get`] would use for `(ns, svc, port)`, without
    /// resolving or caching a value. For callers that need to know whether an
    /// endpoint dependency moved — a route's per-partition fingerprint (#511)
    /// — without paying the resolve cost themselves; `get` still does the
    /// actual (cached) resolution when the route is later translated.
    #[must_use]
    pub fn fingerprint(
        &self,
        ns: &str,
        svc: &str,
        port: i32,
        services: &reflector::Store<Service>,
    ) -> u64 {
        self.cache_key_and_fingerprint(ns, svc, port, services).1
    }

    /// The [`EndpointKey`] under which [`Self::get`] resolves `(ns, svc, port)`.
    ///
    /// Route builders thread this onto `BackendGroupSpec` as endpoint-resource
    /// provenance (#383) so the discovery wire can name the endpoint resource a
    /// backend depends on. Shares the same port clamp as the cache's own keying
    /// (below), so the returned key is byte-identical to the one `get` pooled
    /// under — this is the single home of that clamp.
    #[must_use]
    pub fn key(&self, ns: &str, svc: &str, port: i32) -> EndpointKey {
        // K8s Service ports are API-server-validated to `1..=65535`; a value
        // outside that range cannot come from a real cluster object and is
        // not reachable via any watched input this cache observes — collapse
        // it to a single degenerate key rather than propagate a bogus one.
        EndpointKey::new(ns, svc, u16::try_from(port).unwrap_or(0))
    }

    fn cache_key_and_fingerprint(
        &self,
        ns: &str,
        svc: &str,
        port: i32,
        services: &reflector::Store<Service>,
    ) -> (EndpointKey, GroupFingerprint) {
        let group_key = (Arc::<str>::from(ns), Arc::<str>::from(svc));
        let group_fingerprint = self.groups.get(&group_key).map_or(0, |g| g.fingerprint);
        let service_fingerprint = crate::fingerprint::object_fingerprint(services, ns, svc);
        let fingerprint = group_fingerprint ^ service_fingerprint;
        (self.key(ns, svc, port), fingerprint)
    }
}

fn member_fingerprint(slice: &EndpointSlice) -> GroupFingerprint {
    crate::fingerprint::hash_one(&(&slice.metadata.name, &slice.metadata.resource_version))
}

#[cfg(test)]
mod tests {
    use super::EndpointCache;
    use crate::tests::fixtures::{
        empty_svc_store, make_slice_with_conditions, make_svc_store, slice_store,
    };
    use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    use kube::api::ObjectMeta;

    fn service_with_version(
        ns: &str,
        name: &str,
        target_port: i32,
        resource_version: &str,
    ) -> Service {
        Service {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                resource_version: Some(resource_version.to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                ports: Some(vec![ServicePort {
                    port: 8080,
                    target_port: Some(IntOrString::Int(target_port)),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// The shared fixture names every slice `"{svc}-slice"` — fine for
    /// single-slice-per-service tests, but a real Service sharded across
    /// multiple `EndpointSlice`s (K8s does this past ~100 endpoints) gets
    /// distinct generated names per slice. Override the name so multi-slice
    /// scenarios exercise genuinely distinct objects, matching what the
    /// fingerprint actually keys on.
    fn renamed(
        mut slice: k8s_openapi::api::discovery::v1::EndpointSlice,
        name: &str,
    ) -> k8s_openapi::api::discovery::v1::EndpointSlice {
        slice.metadata.name = Some(name.to_string());
        slice
    }

    #[test]
    fn get_without_refresh_resolves_empty_but_correct() {
        let cache = EndpointCache::default();
        let r = cache.get("ns", "svc", 8080, &empty_svc_store());
        assert!(r.addrs.is_empty());
        assert!(!r.service_exists);
    }

    #[test]
    fn refresh_then_get_resolves_matching_group() {
        let slices = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            None,
            Some(true),
        )]);
        let mut cache = EndpointCache::default();
        cache.refresh(&slices);
        let r = cache.get("ns", "svc", 8080, &empty_svc_store());
        assert_eq!(r.addrs.len(), 1);
    }

    #[test]
    fn get_is_cached_across_calls_without_refresh() {
        let slices = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            None,
            Some(true),
        )]);
        let mut cache = EndpointCache::default();
        cache.refresh(&slices);
        let first = cache.get("ns", "svc", 8080, &empty_svc_store());
        let second = cache.get("ns", "svc", 8080, &empty_svc_store());
        assert!(std::sync::Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn service_only_port_mapping_change_invalidates_cache_without_slice_churn() {
        // Regression: a Service.spec.ports[].targetPort/appProtocol edit with
        // zero EndpointSlice churn must still invalidate the cached entry —
        // lookup_service_port (inside resolve_from_group) depends on the
        // Service object, not just the slice group.
        let slices = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            None,
            Some(true),
        )]);
        let mut cache = EndpointCache::default();
        cache.refresh(&slices);
        let svcs_v1 = make_svc_store(vec![service_with_version("ns", "svc", 3000, "1")]);
        let first = cache.get("ns", "svc", 8080, &svcs_v1);
        assert_eq!(
            first.addrs,
            vec!["10.0.0.1:3000".parse().unwrap()],
            "first resolve uses targetPort 3000"
        );

        // Same slices (no refresh needed to change), Service edited to a new
        // targetPort under a new resourceVersion.
        let svcs_v2 = make_svc_store(vec![service_with_version("ns", "svc", 4000, "2")]);
        let second = cache.get("ns", "svc", 8080, &svcs_v2);
        assert_eq!(
            second.addrs,
            vec!["10.0.0.1:4000".parse().unwrap()],
            "must re-resolve to the new targetPort, not serve the stale cached entry"
        );
        assert!(!std::sync::Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn refresh_after_slice_change_invalidates_cached_entry() {
        let slices = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            None,
            Some(true),
        )]);
        let mut cache = EndpointCache::default();
        cache.refresh(&slices);
        let first = cache.get("ns", "svc", 8080, &empty_svc_store());

        // A second, distinct EndpointSlice appears for the same service (K8s
        // shards a Service across multiple slices) — the group's membership
        // (and therefore fingerprint) changes even though the first slice's
        // own resourceVersion is untouched.
        let slices = slice_store(vec![
            make_slice_with_conditions("ns", "svc", "10.0.0.1", None, Some(true)),
            renamed(
                make_slice_with_conditions("ns", "svc", "10.0.0.2", None, Some(true)),
                "svc-slice-2",
            ),
        ]);
        cache.refresh(&slices);
        let second = cache.get("ns", "svc", 8080, &empty_svc_store());
        assert_eq!(second.addrs.len(), 2);
        assert!(!std::sync::Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn unrelated_service_group_is_unaffected_by_another_groups_refresh() {
        let slices = slice_store(vec![
            make_slice_with_conditions("ns", "svc-a", "10.0.0.1", None, Some(true)),
            make_slice_with_conditions("ns", "svc-b", "10.0.1.1", None, Some(true)),
        ]);
        let mut cache = EndpointCache::default();
        cache.refresh(&slices);
        let a1 = cache.get("ns", "svc-a", 8080, &empty_svc_store());
        let b1 = cache.get("ns", "svc-b", 8080, &empty_svc_store());

        // svc-a gains a second, distinct slice; svc-b's membership is untouched.
        let slices = slice_store(vec![
            make_slice_with_conditions("ns", "svc-a", "10.0.0.1", None, Some(true)),
            renamed(
                make_slice_with_conditions("ns", "svc-a", "10.0.0.2", None, Some(true)),
                "svc-a-slice-2",
            ),
            make_slice_with_conditions("ns", "svc-b", "10.0.1.1", None, Some(true)),
        ]);
        cache.refresh(&slices);
        let a2 = cache.get("ns", "svc-a", 8080, &empty_svc_store());
        let b2 = cache.get("ns", "svc-b", 8080, &empty_svc_store());

        assert!(!std::sync::Arc::ptr_eq(&a1, &a2), "svc-a must re-resolve");
        assert!(
            std::sync::Arc::ptr_eq(&b1, &b2),
            "svc-b must reuse its cached entry — unaffected by svc-a's churn"
        );
    }

    #[test]
    fn refresh_prunes_pool_entries_for_vanished_services() {
        // Without pruning, every `(ns,svc,port)` ever resolved would leak a
        // permanent `pool` entry — an unbounded controller memory growth under
        // churn of short-lived Services (#511).
        let mut cache = EndpointCache::default();
        let slices = slice_store(vec![
            make_slice_with_conditions("ns", "svc-a", "10.0.0.1", None, Some(true)),
            make_slice_with_conditions("ns", "svc-b", "10.0.1.1", None, Some(true)),
        ]);
        cache.refresh(&slices);
        cache.get("ns", "svc-a", 8080, &empty_svc_store());
        cache.get("ns", "svc-b", 8080, &empty_svc_store());
        assert_eq!(cache.pool.borrow().len(), 2);

        // svc-b's slices vanish (its Service was deleted); the next refresh must
        // reclaim its cached resolution, leaving only svc-a's.
        let slices = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc-a",
            "10.0.0.1",
            None,
            Some(true),
        )]);
        cache.refresh(&slices);
        assert_eq!(
            cache.pool.borrow().len(),
            1,
            "the vanished service's cached resolution must be reclaimed on refresh"
        );
        assert!(
            !cache
                .get("ns", "svc-a", 8080, &empty_svc_store())
                .addrs
                .is_empty(),
            "the surviving service still resolves"
        );
    }
}
