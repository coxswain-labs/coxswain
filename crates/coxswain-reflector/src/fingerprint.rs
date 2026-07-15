//! Shared fingerprint primitives for the partitioned incremental rebuild (#511).
//!
//! A fingerprint is a `u64` derived from an object's change token — cheap,
//! in-memory-only (never persisted across restarts, never compared across
//! process boundaries), and not a stability guarantee: `DefaultHasher`'s
//! algorithm is unspecified across Rust versions, which is fine here since
//! nothing outlives one process's lifetime. Used to detect "did this input
//! change since the fingerprint was last computed" without re-deriving or
//! deep-comparing the object itself.

use crate::MergedStore;
use kube::Resource;
use kube::api::ObjectMeta;
use kube::runtime::reflector;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Hash an object's *spec-change* token: its `metadata.generation` when the API
/// server maintains one, else its `resourceVersion`.
///
/// Generation is bumped only on **spec** changes; `resourceVersion` bumps on
/// *any* write, including the controller's own high-frequency **status** writes
/// (a Gateway's `Programmed`/`observedGeneration`, a policy CR's `Accepted`
/// conditions). Folding generation for objects that track it means those status
/// writes don't churn the fingerprint and needlessly dirty every partition each
/// reconcile — the difference between the partitioned rebuild actually reusing
/// work and rebuilding the whole table on every reconcile of a busy cluster
/// (#511). Objects without a status subresource (Secret, ConfigMap) carry no
/// generation and fall back to `resourceVersion`, which for them moves only on
/// real data edits. The `0`/`1` discriminant keeps a generation `i64` from
/// colliding with a `resourceVersion` string that happens to hash alike.
///
/// `uid` is folded alongside `generation`: generation restarts at 1 on object
/// creation, so a delete + recreate with a different spec — both incarnations
/// at generation 1, coalesced into one debounce window (`kubectl replace
/// --force`, delete+apply pipelines) — would otherwise produce an identical
/// token and the replacement would never invalidate anything. `uid` is unique
/// per incarnation and stable across status writes, so folding it preserves
/// the status-write immunity while catching recreation.
///
/// Invariant: only fold stores whose objects actually maintain `generation`
/// on spec changes (built-ins, and CRDs **with the status subresource
/// enabled** — the API server freezes generation for CRDs without it, which
/// would make spec edits invisible here). Every coxswain CRD and Gateway API
/// type folded into the global epoch has the status subresource.
fn hash_change_token<H: Hasher>(meta: &ObjectMeta, hasher: &mut H) {
    match meta.generation {
        Some(generation) => {
            0u8.hash(hasher);
            meta.uid.hash(hasher);
            generation.hash(hasher);
        }
        None => {
            1u8.hash(hasher);
            meta.resource_version.hash(hasher);
        }
    }
}

/// Hash one value with the crate's fingerprint hasher — the single leaf every
/// fingerprint site funnels through, so the hasher choice (and any future
/// hardening, e.g. a stable hasher if #383 ever puts fingerprints on the
/// wire) lives in exactly one place.
pub(crate) fn hash_one<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Order-independent accumulator for fingerprint contributions.
///
/// Combines with `wrapping_add`, never XOR: XOR self-cancels equal
/// contributions — two rules routing to the same Service, two routes sharing
/// one ExtensionRef CR, two ext-auth CRs naming one backend — silently
/// zeroing that input so its churn goes unseen (#511). Addition is
/// commutative and associative mod 2^64, so it stays order-independent
/// across arbitrary store/route iteration without the idempotent-cancellation
/// hazard.
#[derive(Default)]
pub(crate) struct FingerprintAccumulator(u64);

impl FingerprintAccumulator {
    /// Fold in `value` via [`hash_one`].
    pub(crate) fn add<T: Hash>(&mut self, value: &T) {
        self.add_hash(hash_one(value));
    }

    /// Fold in an already-computed 64-bit fingerprint.
    pub(crate) fn add_hash(&mut self, hash: u64) {
        self.0 = self.0.wrapping_add(hash);
    }

    #[must_use]
    pub(crate) fn finish(&self) -> u64 {
        self.0
    }
}

/// Fingerprint of one object's `resourceVersion`, looked up by `(namespace,
/// name)` — O(1) via the store's index, not a scan. Object absent (deleted,
/// or never existed) is a stable fingerprint distinct from any real version
/// string, so a ref target's deletion is itself a fingerprint-moving event.
pub(crate) fn object_fingerprint<K>(store: &MergedStore<K>, ns: &str, name: &str) -> u64
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
/// `store` — an XOR fold of each member's `(namespace, name, `[change
/// token`](hash_change_token)`)`, so it moves on any member add/remove/**spec**
/// edit regardless of iteration order, but **not** on the controller's own
/// status writes. O(objects in store); call once per rebuild; never per-route
/// or per-lookup.
///
/// Used as a coarse, always-correct fallback for inputs that a per-route
/// static scan can't cheaply and precisely attribute (`targetRef`-based
/// policy attachment, a CR's own one-hop reference to a Secret/ConfigMap):
/// fold this epoch identically into every partition's fingerprint, so any
/// change here invalidates the whole table for that one rebuild pass rather
/// than risking a partition wrongly believing itself unaffected. Ignoring
/// status writes (via the generation-preferring change token) is what keeps
/// this whole-table fallback from firing on essentially every reconcile of a
/// cluster whose Gateways/policies the controller is actively status-writing —
/// see the `RouteResolution`-adjacent doc on `route_fingerprint` for exactly
/// which inputs fall into this bucket.
pub(crate) fn store_epoch<K>(store: &MergedStore<K>) -> u64
where
    K: Resource<DynamicType = ()> + Clone + Send + Sync + 'static,
{
    store.state().iter().fold(0u64, |acc, obj| {
        let meta = obj.meta();
        let mut hasher = DefaultHasher::new();
        meta.namespace.hash(&mut hasher);
        meta.name.hash(&mut hasher);
        hash_change_token(meta, &mut hasher);
        acc ^ hasher.finish()
    })
}

/// The single `ExtensionRef` kind → CR-store fingerprint dispatch (#511),
/// shared by the HTTPRoute and GRPCRoute `route_fingerprint`s so the kind
/// list can never drift between them.
///
/// `Option` fields are kinds only one route type's translator consumes
/// (HTTP-only today): a `None` store hashes the sentinel `(kind, name)`
/// instead — CORRECT there, because the translator ignores those refs (logs
/// and skips), so the compiled output doesn't depend on the CR and a stable
/// token is exactly right.
///
/// Registration requirement: when a translator starts consuming a NEW
/// `ExtensionRef` kind, its store MUST be added here (and populated by both
/// resolutions that support it). An unregistered-but-consumed kind falls to
/// the `(kind, name)` sentinel, which is *stable across CR edits* — in-place
/// edits of that CR would then never dirty any partition and its config would
/// go stale until unrelated churn. The sentinel is only safe for kinds no
/// translator reads.
pub(crate) struct ExtRefStores<'a> {
    pub(crate) rate_limits: &'a MergedStore<coxswain_core::crd::RateLimit>,
    pub(crate) retry_policies: &'a MergedStore<coxswain_core::crd::RetryPolicy>,
    pub(crate) ip_access: &'a MergedStore<coxswain_core::crd::IpAccessControl>,
    pub(crate) jwt_auths: &'a MergedStore<coxswain_core::crd::JwtAuth>,
    pub(crate) path_rewrites: Option<&'a MergedStore<coxswain_core::crd::PathRewriteRegex>>,
    pub(crate) basic_auths: Option<&'a MergedStore<coxswain_core::crd::BasicAuth>>,
    pub(crate) external_auths: Option<&'a MergedStore<coxswain_core::crd::CoxswainExternalAuth>>,
    pub(crate) request_size_limits: Option<&'a MergedStore<coxswain_core::crd::RequestSizeLimit>>,
    pub(crate) compressions: Option<&'a MergedStore<coxswain_core::crd::Compression>>,
}

impl ExtRefStores<'_> {
    /// Fingerprint of one spec-static `ExtensionRef` target `(kind, name)` in
    /// `route_ns` — the referenced CR's own `resourceVersion` via a direct
    /// store lookup (no scan) for registered kinds, the stable `(kind, name)`
    /// sentinel otherwise (see the type-level doc for when that is and isn't
    /// safe).
    pub(crate) fn fingerprint(&self, route_ns: &str, kind: &str, name: &str) -> u64 {
        match kind {
            "RateLimit" => object_fingerprint(self.rate_limits, route_ns, name),
            "RetryPolicy" => object_fingerprint(self.retry_policies, route_ns, name),
            "IpAccessControl" => object_fingerprint(self.ip_access, route_ns, name),
            "JwtAuth" => object_fingerprint(self.jwt_auths, route_ns, name),
            "PathRewriteRegex" => opt_fingerprint(self.path_rewrites, route_ns, kind, name),
            "BasicAuth" => opt_fingerprint(self.basic_auths, route_ns, kind, name),
            "CoxswainExternalAuth" => opt_fingerprint(self.external_auths, route_ns, kind, name),
            "RequestSizeLimit" => opt_fingerprint(self.request_size_limits, route_ns, kind, name),
            "Compression" => opt_fingerprint(self.compressions, route_ns, kind, name),
            _ => hash_one(&(kind, name)),
        }
    }
}

/// [`object_fingerprint`] when the store is present (this route type's
/// translator consumes the kind), the stable `(kind, name)` sentinel when it
/// is `None` (the translator ignores the ref, so the output can't depend on
/// the CR).
fn opt_fingerprint<K>(store: Option<&MergedStore<K>>, route_ns: &str, kind: &str, name: &str) -> u64
where
    K: Resource<DynamicType = ()> + Clone + Send + Sync + 'static,
{
    store.map_or_else(
        || hash_one(&(kind, name)),
        |s| object_fingerprint(s, route_ns, name),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::crd::RateLimit;

    fn store_with(objs: Vec<RateLimit>) -> MergedStore<RateLimit> {
        let mut writer = reflector::store::Writer::<RateLimit>::default();
        for o in objs {
            writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(o));
        }
        MergedStore::single(writer.as_reader())
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

    fn rate_limit_gen(ns: &str, name: &str, generation: i64, resource_version: &str) -> RateLimit {
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: RateLimit\n\
             metadata:\n  name: {name}\n  namespace: {ns}\n  generation: {generation}\n  resourceVersion: \"{resource_version}\"\n\
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

    #[test]
    fn store_epoch_ignores_status_writes_but_catches_spec_changes() {
        // For an object the API server tracks a `generation` for (every object
        // with a status subresource — Gateways, coxswain CRs), a status write
        // bumps `resourceVersion` while leaving `generation` fixed; a spec edit
        // bumps `generation`. The epoch must ignore the former (else the
        // controller's own status writes dirty the whole table every reconcile)
        // and catch the latter (#511).
        let base = store_with(vec![rate_limit_gen("ns", "rl", 5, "100")]);
        let status_write = store_with(vec![rate_limit_gen("ns", "rl", 5, "101")]);
        let spec_change = store_with(vec![rate_limit_gen("ns", "rl", 6, "102")]);

        assert_eq!(
            store_epoch(&base),
            store_epoch(&status_write),
            "a status-only write (generation unchanged) must not churn the epoch"
        );
        assert_ne!(
            store_epoch(&base),
            store_epoch(&spec_change),
            "a spec change (generation bumped) must move the epoch"
        );
    }

    #[test]
    fn store_epoch_catches_delete_and_recreate_at_same_generation() {
        // Delete + recreate (`kubectl replace --force`) restarts generation at
        // 1 for the new incarnation; if both transitions coalesce into one
        // debounce window, (ns, name, generation) alone is identical across the
        // replacement and the epoch would never move — the `uid` fold is what
        // distinguishes the incarnations (#511).
        let mut old = rate_limit_gen("ns", "rl", 1, "100");
        old.metadata.uid = Some("uid-old".to_string());
        let mut recreated = rate_limit_gen("ns", "rl", 1, "200");
        recreated.metadata.uid = Some("uid-new".to_string());

        assert_ne!(
            store_epoch(&store_with(vec![old])),
            store_epoch(&store_with(vec![recreated])),
            "a recreated object at the same (ns, name, generation) must move the epoch via its uid"
        );
    }
}
