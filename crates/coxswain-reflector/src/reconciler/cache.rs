//! Cross-rebuild reuse caches for the partitioned incremental rebuild (#511).
//!
//! `rebuild()` (`reconciler::proxy`) has no handle to the routing tables it
//! published last cycle — `publish_routes` stores into a `Shared` cell
//! without ever loading it back. So the state a partitioned rebuild needs to
//! reuse — the endpoint-resolution cache ([`EndpointCache`]) and the compiled
//! `(port, host)` `Arc<HostRouter>` partitions ([`PartitionCache`]) — has
//! nowhere to live *inside* `rebuild()` itself. [`ReflectorCaches`] is that
//! home: owned by the debounce loop (`reconciler::proxy`'s rebuild task) as a
//! value that outlives any single `rebuild()` call. The endpoint cache is
//! threaded deep (into every route builder) via
//! [`super::proxy::ReflectorStores::endpoint_cache`]; the partition caches are
//! threaded shallow — as `&mut` parameters straight into
//! `route_builder::build_gateway_routes` — since the reuse-vs-recompile
//! decision happens once per partition, before any per-route translation
//! runs, not deep inside it.

use coxswain_core::ownership::ObjectKey;
use coxswain_core::routing::{HostRouter, RouteConflict};
use std::collections::HashMap;
use std::sync::Arc;

use crate::endpoints::pool::EndpointCache;

/// A compiled routing partition: one listener port plus a hostname selector.
/// `None` is the catch-all bucket; `Some("*.example.com")` a wildcard bucket
/// (matching [`PortTableBuilder`](coxswain_core::routing::PortTableBuilder)'s
/// own `*.` convention); `Some("example.com")` an exact-host bucket. This is
/// exactly the `(hostname_opt, port)` shape
/// `gateway_api::bindings::compute_listener_bindings` already produces, so a
/// route's bindings translate into partition keys with no extra lookup.
///
/// Invariant: this key deliberately omits
/// [`WildcardKind`](coxswain_core::routing::WildcardKind) — the full routing
/// key space is `(port, host, WildcardKind)`, but every Gateway API wildcard
/// is `MultiLabel` (deliberate, see the wildcard-semantics note in the
/// project docs) and the `SingleLabel` (Ingress TLS) path is not partitioned.
/// The assembly in `route_builder` hardcodes `WildcardKind::MultiLabel` on
/// both the `get_compiled` and `insert_compiled_wildcard_host` sides under
/// this invariant. If partitioning is ever extended to a `SingleLabel`
/// producer, this key must grow a `WildcardKind` component first — otherwise
/// two distinct router buckets collide under one cache entry.
pub(crate) type PartitionKey = (u16, Option<String>);

/// One cached partition: the fingerprint it was compiled under, the compiled
/// router, and any `RouteConflict`s detected while compiling it. Conflicts
/// must travel with the cache entry — a reused partition splices its
/// `Arc<HostRouter>` directly, bypassing `HostRouterBuilder::build()` (the
/// only place conflicts are normally detected), so a cached partition's
/// already-known conflicts would otherwise silently vanish from the
/// published table's `conflicts()` (read by, e.g., the admin UI's route
/// conflict view) the moment it stops being freshly recompiled every pass.
struct PartitionEntry {
    fingerprint: u64,
    router: Arc<HostRouter>,
    conflicts: Vec<RouteConflict>,
}

/// Reuse cache for one compiled routing table's `(port, host)` partitions
/// (#511). Maps a partition to the fingerprint it was last compiled under and
/// the resulting `Arc<HostRouter>`; a rebuild reuses the `Arc` when the
/// freshly-computed fingerprint for that partition still matches, and
/// recompiles (via the normal `HostRouterBuilder` path) otherwise.
#[derive(Default)]
pub(crate) struct PartitionCache {
    entries: HashMap<PartitionKey, PartitionEntry>,
}

impl PartitionCache {
    /// Returns the cached `Arc<HostRouter>` for `key` if its fingerprint still
    /// matches `fingerprint` — the reuse fast path. `None` means "recompile":
    /// either this is a new partition, or its inputs changed since it was
    /// last cached.
    pub(crate) fn get(&self, key: &PartitionKey, fingerprint: u64) -> Option<Arc<HostRouter>> {
        self.entries
            .get(key)
            .filter(|e| e.fingerprint == fingerprint)
            .map(|e| Arc::clone(&e.router))
    }

    /// The conflicts recorded for `key`'s cached entry, if any — carried
    /// forward into the published table alongside a reused `Arc<HostRouter>`
    /// (see [`PartitionEntry::conflicts`]).
    pub(crate) fn conflicts_for(&self, key: &PartitionKey) -> &[RouteConflict] {
        self.entries
            .get(key)
            .map_or(&[], |e| e.conflicts.as_slice())
    }

    /// Records the freshly-compiled `Arc<HostRouter>` (and its conflicts, if
    /// any) for `key` under `fingerprint`, so the next rebuild can reuse it
    /// if nothing changes.
    pub(crate) fn insert(
        &mut self,
        key: PartitionKey,
        fingerprint: u64,
        router: Arc<HostRouter>,
        conflicts: Vec<RouteConflict>,
    ) {
        self.entries.insert(
            key,
            PartitionEntry {
                fingerprint,
                router,
                conflicts,
            },
        );
    }

    /// Drops every cached partition not present in `live` — a `(port, host)`
    /// that no longer exists this rebuild (route/listener deleted) must not
    /// linger and be offered as a stale reuse candidate if the same key
    /// reappears later with different bound routes.
    pub(crate) fn retain_only(&mut self, live: &HashMap<PartitionKey, u64>) {
        self.entries.retain(|key, _| live.contains_key(key));
    }
}

/// Persistent, cross-rebuild reuse state. One instance per reconciler task
/// (shared-pool build and each dedicated-Gateway build keep their own — see
/// the dedicated-registry keying note in `reconciler::dedicated`).
#[derive(Default)]
pub(crate) struct ReflectorCaches {
    pub(crate) endpoints: EndpointCache,
    /// Shared-pool Gateway (HTTPRoute + GRPCRoute) routing-table partitions.
    pub(crate) gateway_partitions: PartitionCache,
    /// Per-cut-over-Gateway dedicated routing-table partitions, keyed by the
    /// owning Gateway — each dedicated snapshot is its own independent table,
    /// so its `(port, host)` keys must not collide with the shared pool's or
    /// another Gateway's (see `reconciler::dedicated`).
    pub(crate) dedicated_partitions: HashMap<ObjectKey, PartitionCache>,
}
