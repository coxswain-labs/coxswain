//! Per-generation subscriber view cache (#383, #582).
//!
//! [`Scope::SharedPool`] and [`Scope::Namespace`] streams diff against the same
//! world per rebuild generation, so it is materialized once and shared behind an
//! `Arc`; [`Scope::Gateway`] views bypass the cache (per-stream SVID binding). The
//! cache lock is a `parking_lot::Mutex` never held across a build or an `.await`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;

use coxswain_core::ownership::ObjectKey;

use crate::auth::{PeerSvid, svid_matches_dedicated_gateway};
use crate::materialize::{MaterializedView, empty_view, materialize};
use crate::subscription::Scope;

use super::source::SnapshotSource;

/// Shared, generation-keyed view cache for scopes every subscriber of the same
/// key diffs against identically: [`Scope::SharedPool`] (single slot) and
/// [`Scope::Namespace`] (one slot per namespace, #582). `Gateway` scope bypasses
/// this cache entirely (per-stream SVID binding).
///
/// The lock is a `parking_lot::Mutex` held only for the map read/write, never
/// across the materialize call or an `.await`.
pub(super) type SharedViewCache = Arc<Mutex<ViewCacheState>>;

/// Cache contents behind [`SharedViewCache`]. Split so the two cacheable scopes
/// don't share a single-slot cache key (`Namespace{a}` and `Namespace{b}` must
/// coexist, unlike `SharedPool`'s single world). Each slot is `None` until its
/// first build — rebuild generations start at 0 in production and in tests, so
/// a sentinel generation number cannot distinguish "never built" from "built at
/// generation 0"; `Option` is the only unambiguous representation.
#[derive(Default)]
pub(super) struct ViewCacheState {
    /// `(generation, view)` for `SharedPool`, most recently materialized.
    shared_pool: Option<(u64, Arc<MaterializedView>)>,
    /// `namespace → (generation, view)`, most recently materialized per
    /// namespace; entries are created lazily on first subscribe.
    namespace: HashMap<String, Option<(u64, Arc<MaterializedView>)>>,
    /// `Gateway ObjectKey → (generation, view)`, the SVID-independent real
    /// world per dedicated Gateway. HA replicas of the same Gateway — and every
    /// leaf behind the same relay — share one build per generation instead of
    /// re-hashing the Gateway's whole world per subscriber; the per-peer SVID
    /// decision is a cheap post-cache filter in [`view_for`].
    gateway: HashMap<ObjectKey, Option<(u64, Arc<MaterializedView>)>>,
}

/// Materialize the routing world for `scope` at rebuild generation `generation`.
///
/// [`Scope::SharedPool`] hits the shared per-generation cache: every shared-pool
/// stream diffs against the same world, so it is built once per generation and
/// the resulting `Arc<MaterializedView>` is shared. A cache miss (or a stale
/// generation) rebuilds; the build runs WITHOUT the lock held (materialize is
/// synchronous but potentially non-trivial), and the store re-checks so a
/// concurrent builder of the same-or-newer generation wins without regressing the
/// cache.
///
/// [`Scope::Gateway`] views bypass the cache: each depends on the caller's peer
/// SVID (the build-time binding check), so they are materialized per call.
/// [`Scope::Namespace`] (#582) is peer-independent (authorization happens at
/// stream open, not build time) and every relay subscribing to the same
/// namespace diffs against the same world, so it shares the same
/// build-outside-lock-then-recheck cache discipline as `SharedPool`, keyed by
/// namespace rather than a single slot.
///
/// **One-tick-stale tolerance:** a rebuild stores its cells BEFORE bumping the
/// generation watch, so materializing at generation `generation` always reads content
/// `>= generation`. The reverse — a view tagged `generation` that actually reflects `generation + 1`
/// content because a store landed mid-build — is benign: the view carries its own
/// `version`/`seq`, so a slightly-fresher world only converges faster. The
/// generation is a cache key, not a correctness boundary.
pub(super) fn view_for(
    cache: &SharedViewCache,
    source: &SnapshotSource,
    scope: &Scope,
    peer_svid: Option<&PeerSvid>,
    generation: u64,
) -> Arc<MaterializedView> {
    match scope {
        // Gateway scope: the SVID-independent real world is cached by
        // (generation, ObjectKey) and shared across every subscriber of this
        // Gateway; only the empty-vs-real decision is per-peer (#427).
        Scope::Gateway { name, namespace } => {
            if gateway_svid_denied(source, namespace, name, peer_svid) {
                return Arc::new(empty_view());
            }
            let key = ObjectKey::new(namespace.clone(), name.clone());
            cached_view(cache, source, scope, generation, move |state| {
                state.gateway.entry(key.clone()).or_default()
            })
        }
        Scope::SharedPool => cached_view(cache, source, scope, generation, |state| {
            &mut state.shared_pool
        }),
        Scope::Namespace { namespace } => {
            let namespace = namespace.clone();
            cached_view(cache, source, scope, generation, move |state| {
                state.namespace.entry(namespace.clone()).or_default()
            })
        }
    }
}

/// Per-subscriber SVID gate for a `Scope::Gateway` view: `true` when `peer_svid`
/// must be denied this Gateway's real world (served [`empty_view`] instead).
///
/// The build-time complement to the open-time `PERMISSION_DENIED` check in
/// [`DiscoveryService::stream`](crate::DiscoveryService::stream) — it closes the appear-after-open race (#427)
/// where a Gateway's dedicated-registry entry materializes *after* a stream with a
/// non-matching SVID was already accepted (accepted because, at open time, the
/// absent entry made the world fail-closed empty regardless).
///
/// - No `peer_svid` (plaintext / test path): never denied — mTLS is mandatory in
///   production, so this mirrors the open-time fail-open.
/// - Entry absent: never denied here — the cached real build is already
///   [`empty_view`], so there is nothing to withhold.
/// - Entry present but SVID does not match its `expected_proxy_sa`: denied.
pub(crate) fn gateway_svid_denied(
    source: &SnapshotSource,
    namespace: &str,
    name: &str,
    peer_svid: Option<&PeerSvid>,
) -> bool {
    let Some(peer) = peer_svid else {
        return false;
    };
    let key = ObjectKey::new(namespace.to_owned(), name.to_owned());
    match source.dedicated.load().map.get(&key) {
        Some(snap) => {
            !svid_matches_dedicated_gateway(&peer.uri_sans, namespace, &snap.expected_proxy_sa)
        }
        None => false,
    }
}

/// Shared build-outside-lock-then-recheck cache discipline for a single
/// `(generation, view)` slot, addressed by `slot` inside the locked
/// [`ViewCacheState`]. Used for both the single `SharedPool` slot and each
/// `Namespace` map entry (#582).
pub(super) fn cached_view(
    cache: &SharedViewCache,
    source: &SnapshotSource,
    scope: &Scope,
    generation: u64,
    slot: impl Fn(&mut ViewCacheState) -> &mut Option<(u64, Arc<MaterializedView>)>,
) -> Arc<MaterializedView> {
    // Fast path: a cached view for this (or a newer) generation.
    {
        let mut guard = cache.lock();
        if let Some((cached_gen, view)) = slot(&mut guard).as_ref()
            && *cached_gen >= generation
        {
            return view.clone();
        }
    }

    // Miss: build outside the lock, then re-check before storing.
    let view = Arc::new(build_subscriber_view(source, scope));
    let mut guard = cache.lock();
    let entry = slot(&mut guard);
    if let Some((cached_gen, existing)) = entry.as_ref()
        && *cached_gen >= generation
    {
        // A concurrent builder cached the same-or-newer generation while we
        // built; prefer it so all streams of a generation share one `Arc`.
        return existing.clone();
    }
    *entry = Some((generation, view.clone()));
    view
}

/// Materialize the world for `scope`, timing the #513 snapshot-build stage.
///
/// The single un-cached build path — delegates to [`materialize`] (the only seam
/// between the controller's `Shared` cells and the discovery wire, #383) and
/// records the build duration. Cache hits ([`view_for`]) skip this, so the
/// histogram measures real builds, not served-from-cache reads.
pub(super) fn build_subscriber_view(source: &SnapshotSource, scope: &Scope) -> MaterializedView {
    let start = Instant::now();
    let view = materialize(source, scope);
    crate::metrics::snapshot_build_seconds().observe(start.elapsed().as_secs_f64());
    view
}
