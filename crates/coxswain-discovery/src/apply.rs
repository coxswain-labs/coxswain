//! Client-side materialized resource cache and staged apply pipeline (#383).
//!
//! The discovery client keeps a [`ResourceCache`] on its reconnect
//! [`crate::client::Supervisor`] — **outside** the per-session loop, so it
//! survives reconnects. The cache is the single source of truth for what the
//! proxy's routing cells currently serve; its invariant is
//! `cache ≡ what the cells serve ≡ the last Acked world`.
//!
//! [`apply_message`] is the one apply path for both full snapshots and deltas. It
//! runs in four phases so a failure at any point leaves the cache **and** every
//! routing cell byte-for-byte unchanged — strictly stronger than the v1
//! decode-all-then-store-all atomicity:
//!
//! - **A — stage**: build a [`Staged`] set of typed, semantically-keyed maps
//!   (`(table, port, host)` for routes, port for the coarse cells, `ObjectKey` for
//!   listener status, `(ns, svc, port)` for endpoints). A full stages from scratch
//!   (replace-all); a delta clones the committed cache, applies upserts
//!   (whole-resource replace) and `removed_resources` tombstones (idempotent
//!   removes; the upsert and tombstone key sets are disjoint). Nothing live is
//!   touched. Every entry walks its endpoint references (weighted backends +
//!   mirror-filter backends, recursively) so the commit phase can rebuild the
//!   reverse `endpoint → resources` index. Keying is fallible: an unkeyable
//!   resource — or an unparsable tombstone key — fails the whole message closed.
//!   A delta additionally verifies every tombstoned endpoint has no surviving
//!   referrer (invariant 4).
//! - **B — self-check + change detection**: recompute the global version from the
//!   post-apply per-resource digests and compare it to the server's stamp (F6);
//!   a mismatch fails closed. A staged world byte-identical to the cache is then a
//!   no-op — the cells keep their exact `Arc`s (an empty delta, or a free resync).
//! - **C — compile**: rebuild the routing world (fallible), reusing unchanged
//!   work. Each L7 route table recompiles only its *dirty* `(port, host)`
//!   partitions — those whose wire DTO changed or that reference a changed
//!   endpoint — and splices every clean partition's already-compiled
//!   `Arc<HostRouter>` straight from the live table (the #511 partitioned-rebuild
//!   machinery). The coarse per-port cells (TLS, client-certs, listener status,
//!   and the four L4 tables) are rebuilt wholesale, but only when one of their
//!   own resources changed — or, for the endpoint-referencing L4 tables, when a
//!   referenced endpoint changed. A table/cell with nothing dirty is not rebuilt
//!   or stored at all: its live `Arc` is kept. Listener-hostname derivation
//!   (GEP-3567, #96) happens here whenever listener status is rebuilt.
//! - **D — commit**: infallibly swap the cache maps, rebuild the endpoint index,
//!   and store *only* the cells phase C rebuilt.
//!
//! Any failure in A–C returns a typed [`WireError`]; the caller Nacks and the
//! last-good world keeps serving.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use coxswain_core::endpoints::{EndpointKey, EndpointPool};
use coxswain_core::listener_status::{GatewayListenerStatus, SharedGatewayListenerStatus};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::routing::{
    Gateway, Ingress, RouteConflict, RouterError, RoutingTable, RoutingTableBuilder,
    SharedGatewayRoutingTable, SharedIngressRoutingTable, SharedTcpRouteTable,
    SharedTlsPassthroughTable, SharedUdpRouteTable, TcpRouteTable, TlsPassthroughTable,
    UdpRouteTable, WildcardKind,
};
use coxswain_core::tls::{
    ClientCertStore, ListenerHostnames, ListenerHostnamesBuilder, PortTlsStore,
    SharedClientCertStore, SharedListenerHostnames, SharedPortTlsStore,
};

use crate::error::WireError;
use crate::proto::v1 as p;
use crate::wire::endpoints::{endpoint_key_from_wire, resolved_endpoints_from_wire};
use crate::wire::resource::{
    ParsedHost, ParsedKey, ResourceKeyError, canonical_key, parse_canonical_key, resource_hash,
};
use crate::wire::{
    build_route_table, client_cert_from_wire, listener_status_from_wire, passthrough_from_wire,
    port_tls_from_wire, tcp_table_from_wire, udp_table_from_wire,
};

// ────────────────────────────────────────────────────────────────────────────
// Semantic keys
// ────────────────────────────────────────────────────────────────────────────

/// Which L7 routing table a route partition belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RouteTable {
    /// The Ingress routing table.
    Ingress,
    /// The Gateway API routing table.
    Gateway,
}

/// The host dimension of a route partition key.
///
/// Unlike the reflector's routing key, the client's key carries the
/// [`WildcardKind`]: the proxy resolves Ingress single-label wildcards *and*
/// Gateway multi-label wildcards, and two partitions that differ only in wildcard
/// semantics are distinct resources on the wire (distinct canonical keys), so
/// they must be distinct cache keys too.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum HostKey {
    /// An exact hostname (`example.com`).
    Exact(String),
    /// A wildcard host: the bare suffix (no `*.` prefix) plus its match semantics.
    Wildcard {
        /// Suffix after the wildcard label (`example.com` for `*.example.com`).
        suffix: String,
        /// Single-label (Ingress) vs multi-label (Gateway) wildcard semantics.
        kind: WildcardKind,
    },
    /// The port's catch-all host bucket.
    Catchall,
}

/// The client cache key for one route host bucket: `(table, port, host)`.
///
/// Mirrors the canonical-key grammar's route dimension one-for-one, so a wire
/// `route|…` resource and its cached partition address the same identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RoutePartitionKey {
    /// Ingress vs Gateway table.
    pub(crate) table: RouteTable,
    /// Listener (bind) port the host bucket lives under.
    pub(crate) port: u16,
    /// Host dimension (exact / wildcard / catch-all).
    pub(crate) host: HostKey,
}

/// Identity of a cached resource that can reference endpoints, for the reverse
/// `endpoint → resources` index. Only resources carrying backend groups appear
/// here (routes and the four L4 tables); TLS, client-cert, and listener-status
/// resources never reference endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum ResourceId {
    /// An L7 route host bucket.
    Route(RoutePartitionKey),
    /// A TLS-passthrough port.
    Passthrough(u16),
    /// A TLS-terminate port.
    Terminate(u16),
    /// A TCPRoute port.
    Tcp(u16),
    /// A UDPRoute port.
    Udp(u16),
}

// ────────────────────────────────────────────────────────────────────────────
// SnapshotCells borrow bundle
// ────────────────────────────────────────────────────────────────────────────

/// Write handles for every routing [`coxswain_core::Shared`] cell the apply path
/// publishes, grouped into one parameter to stay within the workspace's
/// 7-argument function limit.
pub(crate) struct SnapshotCells<'a> {
    /// Ingress L7 routing table.
    pub(crate) ingress: &'a SharedIngressRoutingTable,
    /// Gateway API L7 routing table.
    pub(crate) gateway: &'a SharedGatewayRoutingTable,
    /// Per-port terminate TLS certificate store.
    pub(crate) tls: &'a SharedPortTlsStore,
    /// Per-port client-certificate (mTLS) config store.
    pub(crate) client_certs: &'a SharedClientCertStore,
    /// Per-Gateway listener status map (drives dynamic bind/unbind).
    pub(crate) status: &'a SharedGatewayListenerStatus,
    /// Per-port HTTPS listener-hostname snapshot (GEP-3567, #96).
    pub(crate) listener_hostnames: &'a SharedListenerHostnames,
    /// SNI→backend TLS passthrough table (#70).
    pub(crate) passthrough: &'a SharedTlsPassthroughTable,
    /// SNI→backend TLS terminate table (#481).
    pub(crate) terminate: &'a SharedTlsPassthroughTable,
    /// Port→backend TCP route table (#505).
    pub(crate) tcp: &'a SharedTcpRouteTable,
    /// Port→backend UDP route table (#506).
    pub(crate) udp: &'a SharedUdpRouteTable,
}

// ────────────────────────────────────────────────────────────────────────────
// Resource cache
// ────────────────────────────────────────────────────────────────────────────

/// The client's materialized resource cache: the wire DTOs the proxy currently
/// serves, keyed by their semantic identity and `Arc`-shared so an unchanged
/// resource is reused across applies without cloning its bytes.
///
/// Committed only in [`apply_message`]'s final phase; a failed apply never
/// mutates it. Persists across reconnects (invariant: `cache ≡ cells ≡ last
/// Acked`).
pub(crate) struct ResourceCache {
    routes: HashMap<RoutePartitionKey, Arc<p::RouteHostResource>>,
    tls: HashMap<u16, Arc<p::PortTlsEntry>>,
    client_certs: HashMap<u16, Arc<p::ClientCertPortResource>>,
    listener_status: HashMap<ObjectKey, Arc<p::GatewayStatusEntry>>,
    passthrough: HashMap<u16, Arc<p::TlsPassthroughPort>>,
    terminate: HashMap<u16, Arc<p::TlsPassthroughPort>>,
    tcp: HashMap<u16, Arc<p::TcpRoutePort>>,
    udp: HashMap<u16, Arc<p::UdpRoutePort>>,
    endpoints: HashMap<EndpointKey, Arc<p::EndpointResource>>,
    /// Endpoint references of each backend-carrying resource, walked at stage.
    refs: HashMap<ResourceId, Arc<HashSet<EndpointKey>>>,
    /// Reverse index: which resources reference each endpoint key. Rebuilt
    /// wholesale from `refs` on every commit; the delta path (commit 6) uses it
    /// to dirty only the partitions an endpoint change touches.
    ep_index: HashMap<EndpointKey, HashSet<ResourceId>>,
    /// Per-resource content digests (`canonical_key → resource_hash`); the
    /// change oracle for the whole-snapshot skip and (commit 6) the version
    /// self-check.
    digests: HashMap<String, String>,
    /// Whether at least one full snapshot has been applied on this cache.
    has_full: bool,
}

impl ResourceCache {
    /// A fresh, empty cache — the state before the first snapshot.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            routes: HashMap::new(),
            tls: HashMap::new(),
            client_certs: HashMap::new(),
            listener_status: HashMap::new(),
            passthrough: HashMap::new(),
            terminate: HashMap::new(),
            tcp: HashMap::new(),
            udp: HashMap::new(),
            endpoints: HashMap::new(),
            refs: HashMap::new(),
            ep_index: HashMap::new(),
            digests: HashMap::new(),
            has_full: false,
        }
    }
}

/// The staged, not-yet-committed successor to a [`ResourceCache`]. Built entirely
/// from the message; on success it becomes the cache verbatim.
#[derive(Default)]
struct Staged {
    routes: HashMap<RoutePartitionKey, Arc<p::RouteHostResource>>,
    tls: HashMap<u16, Arc<p::PortTlsEntry>>,
    client_certs: HashMap<u16, Arc<p::ClientCertPortResource>>,
    listener_status: HashMap<ObjectKey, Arc<p::GatewayStatusEntry>>,
    passthrough: HashMap<u16, Arc<p::TlsPassthroughPort>>,
    terminate: HashMap<u16, Arc<p::TlsPassthroughPort>>,
    tcp: HashMap<u16, Arc<p::TcpRoutePort>>,
    udp: HashMap<u16, Arc<p::UdpRoutePort>>,
    endpoints: HashMap<EndpointKey, Arc<p::EndpointResource>>,
    refs: HashMap<ResourceId, Arc<HashSet<EndpointKey>>>,
    digests: HashMap<String, String>,
}

// ────────────────────────────────────────────────────────────────────────────
// Apply pipeline
// ────────────────────────────────────────────────────────────────────────────

/// Partition-reuse accounting for one applied message (#383).
///
/// The two tallies are the payoff of the partitioned apply: under endpoint churn
/// (rolling deploys) only the partitions referencing the churning service should
/// recompile, everything else reused. Returned so callers (and, crucially,
/// tests) can assert exact reuse without racing the process-global counters, and
/// mirrored into [`crate::metrics`] for observability.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApplyStats {
    /// Route partitions recompiled this apply (dirty DTO or changed endpoint).
    pub(crate) partitions_recompiled: u64,
    /// Route partitions whose compiled `Arc<HostRouter>` was spliced from the
    /// live table instead of recompiling.
    pub(crate) partitions_reused: u64,
}

/// Apply one wire message — a full snapshot or a delta — to the cache and routing
/// cells (#383).
///
/// A full stages the whole world from scratch (replace-all); a delta folds its
/// upserts (whole-resource replace) and `removed_resources` tombstones onto a
/// clone of the committed cache. Either way the staged world flows through the
/// same partitioned compile + commit, so a delta reuses exactly the same clean
/// `Arc<HostRouter>` splices a full does. A staged world byte-identical to the
/// committed one (an empty delta, or an identical full resync) is a no-op: the
/// cells keep their exact `Arc`s. The returned [`ApplyStats`] reports how many
/// partitions were recompiled vs reused.
///
/// `expect_full` is the caller's per-session gate: it is `true` on every
/// (re)connect and cleared after the first successful apply of the session. The
/// cache persists across reconnects, but the server's per-stream acked baseline
/// does not (invariant 1), so a delta as the *first* message of a session has no
/// baseline and is rejected — the server then resyncs with a fresh full.
///
/// # Errors
///
/// - [`WireError::DeltaBeforeFullSnapshot`] for a delta before this session's
///   first full.
/// - [`WireError::UnknownResourceKey`] if a resource cannot be canonically keyed
///   (absent payload / unspecified route table / absent host pattern / unknown
///   wildcard kind / out-of-range port / duplicate canonical key), if a tombstone
///   key is unparsable, or if one delta's upsert and tombstone key sets overlap.
/// - [`WireError::RemovedEndpointStillReferenced`] if a delta tombstones an
///   endpoint a surviving resource still references.
/// - [`WireError::VersionMismatch`] if the recomputed post-apply version differs
///   from the server's stamp.
/// - Any [`WireError`] from compiling the world (bad regex, dangling endpoint
///   ref, malformed address, …).
///
/// On any error the cache **and** every cell are left untouched.
#[must_use = "the apply outcome decides Ack vs Nack; dropping it silently accepts a failed apply"]
pub(crate) fn apply_message(
    cache: &mut ResourceCache,
    msg: &p::Snapshot,
    cells: SnapshotCells<'_>,
    expect_full: bool,
) -> Result<ApplyStats, WireError> {
    // Invariant 1: the first message of a session is a full snapshot. `expect_full`
    // is the caller's per-session flag — true on every (re)connect, cleared after
    // the first successful apply. The cache persists across sessions but the
    // server's per-stream acked baseline does not, so a delta as the first message
    // of a session has nothing to apply against — Nack for a fresh full resync
    // (invariant 6).
    if !msg.full && expect_full {
        return Err(WireError::DeltaBeforeFullSnapshot);
    }
    debug_assert!(
        expect_full || cache.has_full,
        "the first message on a stream must be a full snapshot (invariant 1)"
    );

    // Phase A — stage into typed maps; nothing live is touched. A full stages from
    // scratch (replace-all); a delta folds upserts (whole-resource replace) and
    // tombstones onto a clone of the committed cache (invariant 2: the upsert and
    // tombstone key sets are disjoint, a tombstone of an unheld key is a no-op).
    let staged = if msg.full {
        stage_full(msg)?
    } else {
        stage_delta(cache, msg)?
    };
    let staged_ep_index = build_ep_index(&staged.refs);

    // Referential integrity for a delta's tombstones: every endpoint the delta
    // removed must have no surviving referrer (invariant 4). A full re-checks this
    // structurally at compile (a dangling ref hits `UnknownEndpointRef`), so this
    // guard is delta-only.
    if !msg.full {
        validate_removed_endpoints_unreferenced(&cache.endpoints, &staged, &staged_ep_index)?;
    }

    // Version self-check (F6): recompute the global version from the post-apply
    // per-resource digests and compare to the server's stamp. A mismatch means the
    // two sides disagree on the applied world — Nack for a self-healing resync
    // (invariant 6) before touching anything live.
    let computed =
        crate::version::ContentHash::from_per_resource(staged.digests.values().cloned().collect())
            .as_str()
            .to_owned();
    if computed != msg.version {
        return Err(WireError::VersionMismatch {
            expected: msg.version.clone(),
            computed,
        });
    }

    // Phase B — change detection. With the version confirmed, a staged world
    // byte-identical to the committed one is a no-op: every cell keeps its exact
    // Arc (an empty delta, or an identical full resync). Skip only once a baseline
    // exists — the first full must publish its cells even when empty.
    if cache.has_full && staged.digests == cache.digests {
        return Ok(ApplyStats::default());
    }

    // Phase C — compile (fallible). Nothing is stored until every step below
    // succeeds, so any failure leaves the cache AND every cell byte-for-byte
    // unchanged (atomicity, strictly stronger than v1's per-cell store-all).

    // The endpoint pool is built from the STAGED endpoints (committed ∪ delta
    // upserts − tombstones), not the message: a delta ships only changed
    // endpoints, yet a clean route spliced from live still needs its unchanged refs
    // to resolve. Referential integrity (every ref resolves) plus the address
    // source every dirty-partition and L4 recompile reads.
    let pool = endpoint_pool_from_staged(&staged.endpoints)?;

    // Endpoint-dirty propagation: an endpoint whose resolved value changed (or
    // that vanished) dirties every resource that references it, via the committed
    // reverse index (who referenced it before) unioned with the staged one (who
    // references it now). Routes become dirty partitions; L4 ports mark their
    // whole cell dirty.
    let changed_eps = changed_or_removed_endpoints(&cache.endpoints, &staged.endpoints);
    let ep_dirty = endpoint_dirty_targets(&changed_eps, &staged, &staged_ep_index, &cache.ep_index);

    // Route tables: recompile only dirty partitions, splice the rest from live.
    let live_ingress = cells.ingress.load();
    let live_gateway = cells.gateway.load();
    let ingress = rebuild_route_table::<Ingress>(
        RouteTable::Ingress,
        &staged.routes,
        &cache.routes,
        &ep_dirty.routes,
        live_ingress.as_ref(),
        &pool,
    )?;
    let gateway = rebuild_route_table::<Gateway>(
        RouteTable::Gateway,
        &staged.routes,
        &cache.routes,
        &ep_dirty.routes,
        live_gateway.as_ref(),
        &pool,
    )?;

    // Coarse per-port cells: rebuilt wholesale iff any of their own resources
    // changed. The L4 tables additionally rebuild when a referenced endpoint
    // changed (their DTOs carry only a ref, so an endpoint address change leaves
    // the DTO — but not the compiled backend group — identical). TLS, client-cert
    // and listener-status resources never reference endpoints, so DTO inequality
    // alone decides them.
    let tls_new = (staged.tls != cache.tls)
        .then(|| decode_tls_cell(&staged.tls))
        .transpose()?;
    let client_certs_new = (staged.client_certs != cache.client_certs)
        .then(|| decode_client_certs_cell(&staged.client_certs))
        .transpose()?;
    // Listener status drives the derived per-port HTTPS hostname snapshot; both
    // are rebuilt together, only when the listener-status resources changed.
    let listener_status_new = if staged.listener_status != cache.listener_status {
        let map = decode_listener_status_cell(&staged.listener_status)?;
        let hostnames = derive_listener_hostnames(&map);
        Some((map, hostnames))
    } else {
        None
    };
    let passthrough_new = (ep_dirty.passthrough || staged.passthrough != cache.passthrough)
        .then(|| decode_passthrough_cell(&staged.passthrough, &pool))
        .transpose()?;
    let terminate_new = (ep_dirty.terminate || staged.terminate != cache.terminate)
        .then(|| decode_passthrough_cell(&staged.terminate, &pool))
        .transpose()?;
    let tcp_new = (ep_dirty.tcp || staged.tcp != cache.tcp)
        .then(|| decode_tcp_cell(&staged.tcp, &pool))
        .transpose()?;
    let udp_new = (ep_dirty.udp || staged.udp != cache.udp)
        .then(|| decode_udp_cell(&staged.udp, &pool))
        .transpose()?;

    // Phase D — commit: swap the cache, rebuild the endpoint index, and store
    // ONLY the cells phase C rebuilt (untouched cells keep their live Arc, which
    // still equals the newly-committed cache by value). Infallible from here on.
    cache.routes = staged.routes;
    cache.tls = staged.tls;
    cache.client_certs = staged.client_certs;
    cache.listener_status = staged.listener_status;
    cache.passthrough = staged.passthrough;
    cache.terminate = staged.terminate;
    cache.tcp = staged.tcp;
    cache.udp = staged.udp;
    cache.endpoints = staged.endpoints;
    cache.refs = staged.refs;
    cache.digests = staged.digests;
    // The index was already built from the staged refs (phase A) — the same map
    // that just became `cache.refs`; reuse it instead of rebuilding.
    cache.ep_index = staged_ep_index;
    cache.has_full = true;
    debug_assert!(
        ep_index_is_consistent(&cache.refs, &cache.ep_index),
        "endpoint index must be the exact reverse of the forward refs after commit"
    );

    if let Some(table) = ingress.table {
        cells.ingress.store(Arc::new(table));
    }
    if let Some(table) = gateway.table {
        cells.gateway.store(Arc::new(table));
    }
    if let Some(store) = tls_new {
        cells.tls.store(Arc::new(store));
    }
    if let Some(store) = client_certs_new {
        cells.client_certs.store(Arc::new(store));
    }
    if let Some((map, hostnames)) = listener_status_new {
        cells.listener_hostnames.store(Arc::new(hostnames));
        cells.status.store_and_notify(map);
    }
    if let Some(table) = passthrough_new {
        cells.passthrough.store(Arc::new(table));
    }
    if let Some(table) = terminate_new {
        cells.terminate.store(Arc::new(table));
    }
    if let Some(table) = tcp_new {
        cells.tcp.store(Arc::new(table));
    }
    if let Some(table) = udp_new {
        cells.udp.store(Arc::new(table));
    }

    let stats = ApplyStats {
        partitions_recompiled: ingress.recompiled + gateway.recompiled,
        partitions_reused: ingress.reused + gateway.reused,
    };
    if stats.partitions_recompiled > 0 {
        crate::metrics::client_partitions_recompiled_total().inc_by(stats.partitions_recompiled);
    }
    if stats.partitions_reused > 0 {
        crate::metrics::client_partitions_reused_total().inc_by(stats.partitions_reused);
    }

    Ok(stats)
}

/// Phase A (full): stage the whole world from scratch (replace-all semantics) —
/// every resource folded into fresh typed maps, walking endpoint refs and
/// recording per-resource digests. Fails closed on any unkeyable resource.
fn stage_full(msg: &p::Snapshot) -> Result<Staged, WireError> {
    let mut staged = Staged::default();
    let mut seen = HashSet::new();
    for resource in &msg.resources {
        stage_resource(&mut staged, &mut seen, resource)?;
    }
    Ok(staged)
}

/// Phase A (delta): fold the message's upserts (whole-resource replace) and
/// `removed_resources` tombstones onto a clone of the committed cache.
///
/// The two key sets are disjoint (invariant 2): a key in both is an inconsistent
/// delta, rejected. A tombstone of an unheld key is an idempotent no-op.
fn stage_delta(cache: &ResourceCache, msg: &p::Snapshot) -> Result<Staged, WireError> {
    let mut staged = staged_from_cache(cache);
    // Upserts. `seen` tracks the message's own keys so a duplicate *within* the
    // message is rejected even though the digest map is pre-populated from the
    // committed world (where an "already present" key is a replace, not a dup).
    let mut seen = HashSet::new();
    for resource in &msg.resources {
        stage_resource(&mut staged, &mut seen, resource)?;
    }
    // Tombstones.
    for removed in &msg.removed_resources {
        if seen.contains(removed.as_str()) {
            return Err(WireError::UnknownResourceKey {
                reason: "delta key appears in both the upsert and the tombstone set",
            });
        }
        let parsed = parse_canonical_key(removed).map_err(wire_from_key_err)?;
        remove_from_staged(&mut staged, removed, parsed)?;
    }
    Ok(staged)
}

/// Clone the committed cache into a mutable staged successor. Every map is
/// `HashMap<_, Arc<_>>`, so this bumps refcounts rather than copying payloads. The
/// reverse `ep_index` is intentionally not cloned — it is rebuilt wholesale in the
/// commit phase from the staged forward refs.
fn staged_from_cache(cache: &ResourceCache) -> Staged {
    Staged {
        routes: cache.routes.clone(),
        tls: cache.tls.clone(),
        client_certs: cache.client_certs.clone(),
        listener_status: cache.listener_status.clone(),
        passthrough: cache.passthrough.clone(),
        terminate: cache.terminate.clone(),
        tcp: cache.tcp.clone(),
        udp: cache.udp.clone(),
        endpoints: cache.endpoints.clone(),
        refs: cache.refs.clone(),
        digests: cache.digests.clone(),
    }
}

/// Stage one resource into the typed maps: record its digest, walk its endpoint
/// refs, and place it under its typed key. Whole-resource replace — for a delta
/// upsert onto a clone, re-inserting the same canonical key overwrites the prior
/// DTO, refs, and digest for that identity.
///
/// `seen` holds the canonical keys already staged from *this message*; a key seen
/// twice means the peer sent two resources that fold to one identity — the typed
/// maps would keep only the last while a full recompile would compile both, so the
/// staged cache would silently diverge from what it serves. Fail closed (#383
/// review).
fn stage_resource(
    staged: &mut Staged,
    seen: &mut HashSet<String>,
    resource: &p::Resource,
) -> Result<(), WireError> {
    let key = canonical_key(resource).map_err(wire_from_key_err)?;
    if !seen.insert(key.clone()) {
        return Err(WireError::UnknownResourceKey {
            reason: "message contains a duplicate canonical resource key",
        });
    }
    staged.digests.insert(key, resource_hash(resource));

    let payload = resource
        .payload
        .as_ref()
        .ok_or(WireError::UnknownResourceKey {
            reason: "resource carries no payload arm (unknown future variant)",
        })?;
    match payload {
        p::resource::Payload::RouteHost(rh) => {
            let pk = route_partition_key(rh)?;
            let mut refs = HashSet::new();
            collect_route_host_refs(rh, &mut refs, 0);
            staged
                .refs
                .insert(ResourceId::Route(pk.clone()), Arc::new(refs));
            staged.routes.insert(pk, Arc::new(rh.clone()));
        }
        p::resource::Payload::TlsPort(e) => {
            staged.tls.insert(port_u16(e.port)?, Arc::new(e.clone()));
        }
        p::resource::Payload::ClientCertPort(r) => {
            staged
                .client_certs
                .insert(port_u16(r.port)?, Arc::new(r.clone()));
        }
        p::resource::Payload::ListenerStatus(e) => {
            let ok =
                e.object_key
                    .parse::<ObjectKey>()
                    .map_err(|()| WireError::UnknownResourceKey {
                        reason: "listener_status resource carries a malformed object key",
                    })?;
            staged.listener_status.insert(ok, Arc::new(e.clone()));
        }
        p::resource::Payload::TlsPassthroughPort(pt) => {
            let port = port_u16(pt.port)?;
            staged.refs.insert(
                ResourceId::Passthrough(port),
                Arc::new(passthrough_refs(pt)),
            );
            staged.passthrough.insert(port, Arc::new(pt.clone()));
        }
        p::resource::Payload::TlsTerminatePort(pt) => {
            let port = port_u16(pt.port)?;
            staged
                .refs
                .insert(ResourceId::Terminate(port), Arc::new(passthrough_refs(pt)));
            staged.terminate.insert(port, Arc::new(pt.clone()));
        }
        p::resource::Payload::TcpPort(pt) => {
            let port = port_u16(pt.port)?;
            let mut refs = HashSet::new();
            if let Some(bg) = &pt.backend_group {
                collect_bg_refs(bg, &mut refs, 0);
            }
            staged.refs.insert(ResourceId::Tcp(port), Arc::new(refs));
            staged.tcp.insert(port, Arc::new(pt.clone()));
        }
        p::resource::Payload::UdpPort(pt) => {
            let port = port_u16(pt.port)?;
            let mut refs = HashSet::new();
            if let Some(bg) = &pt.backend_group {
                collect_bg_refs(bg, &mut refs, 0);
            }
            staged.refs.insert(ResourceId::Udp(port), Arc::new(refs));
            staged.udp.insert(port, Arc::new(pt.clone()));
        }
        p::resource::Payload::Endpoints(e) => {
            // Narrow the port like the other seven arms. The canonical key embeds
            // the raw `u32` (distinct digest) while `EndpointKey` narrows to `u16`,
            // so ports 80 and 65616 would key distinct digests yet collide to one
            // `EndpointKey` — last-wins, silently clobbering the legit resolved
            // addresses. Reject the out-of-range resource instead (#383 review).
            let ek = EndpointKey::new(e.namespace.as_str(), e.service.as_str(), port_u16(e.port)?);
            staged.endpoints.insert(ek, Arc::new(e.clone()));
        }
    }
    Ok(())
}

/// Remove one tombstoned resource from the staged world by its parsed canonical
/// key. Idempotent — a key the staged world does not hold is a no-op (invariant
/// 2). Drops the resource's digest and (for backend-carrying resources) its
/// forward refs too, so the rebuilt `ep_index` and the version self-check both
/// observe the removal.
///
/// # Errors
///
/// Returns [`WireError::UnknownResourceKey`] if a listener tombstone carries an
/// object key that does not parse (an unparsable tombstone fails the delta
/// closed).
fn remove_from_staged(
    staged: &mut Staged,
    key_str: &str,
    parsed: ParsedKey,
) -> Result<(), WireError> {
    staged.digests.remove(key_str);
    match parsed {
        ParsedKey::Route {
            gateway,
            port,
            host,
        } => {
            let table = if gateway {
                RouteTable::Gateway
            } else {
                RouteTable::Ingress
            };
            let host = match host {
                ParsedHost::Exact(h) => HostKey::Exact(h),
                ParsedHost::Wildcard {
                    suffix,
                    single_label,
                } => HostKey::Wildcard {
                    suffix,
                    kind: if single_label {
                        WildcardKind::SingleLabel
                    } else {
                        WildcardKind::MultiLabel
                    },
                },
                ParsedHost::Catchall => HostKey::Catchall,
            };
            let pk = RoutePartitionKey { table, port, host };
            staged.routes.remove(&pk);
            staged.refs.remove(&ResourceId::Route(pk));
        }
        ParsedKey::Tls(port) => {
            staged.tls.remove(&port);
        }
        ParsedKey::ClientCert(port) => {
            staged.client_certs.remove(&port);
        }
        ParsedKey::Listener(ok_str) => {
            let ok = ok_str
                .parse::<ObjectKey>()
                .map_err(|()| WireError::UnknownResourceKey {
                    reason: "listener tombstone carries a malformed object key",
                })?;
            staged.listener_status.remove(&ok);
        }
        ParsedKey::TlsPassthrough(port) => {
            staged.passthrough.remove(&port);
            staged.refs.remove(&ResourceId::Passthrough(port));
        }
        ParsedKey::TlsTerminate(port) => {
            staged.terminate.remove(&port);
            staged.refs.remove(&ResourceId::Terminate(port));
        }
        ParsedKey::Tcp(port) => {
            staged.tcp.remove(&port);
            staged.refs.remove(&ResourceId::Tcp(port));
        }
        ParsedKey::Udp(port) => {
            staged.udp.remove(&port);
            staged.refs.remove(&ResourceId::Udp(port));
        }
        ParsedKey::Endpoints {
            namespace,
            service,
            port,
        } => {
            let ek = EndpointKey::new(namespace, service, port);
            staged.endpoints.remove(&ek);
        }
    }
    Ok(())
}

/// Verify every endpoint a delta removed (present in the committed pool, absent
/// from the staged one) has no surviving referrer in the staged world (invariant
/// 4).
///
/// A residual referrer would leave the reverse index pointing at a pool entry the
/// commit deletes, so the next recompile of that referrer would reject it as a
/// dangling reference — fail the whole delta closed instead. `staged_ep_index`
/// only holds keys with at least one referrer, so a present key means the removed
/// endpoint is still reachable.
///
/// # Errors
///
/// Returns [`WireError::RemovedEndpointStillReferenced`] on the first removed
/// endpoint that still has a staged referrer.
fn validate_removed_endpoints_unreferenced(
    committed_eps: &HashMap<EndpointKey, Arc<p::EndpointResource>>,
    staged: &Staged,
    staged_ep_index: &HashMap<EndpointKey, HashSet<ResourceId>>,
) -> Result<(), WireError> {
    for key in committed_eps.keys() {
        if !staged.endpoints.contains_key(key) && staged_ep_index.contains_key(key) {
            return Err(WireError::RemovedEndpointStillReferenced {
                key: format!("{}/{}/{}", key.namespace, key.service, key.port),
            });
        }
    }
    Ok(())
}

/// Build the endpoint pool from the STAGED endpoint resources (committed ∪ delta
/// upserts − tombstones), resolving each into its addresses.
///
/// Unlike `endpoint_pool_from_resources`, which reads only the message, this
/// resolves the whole post-apply endpoint world, so a clean route spliced from
/// live still finds its unchanged refs on a delta that shipped no endpoints.
///
/// # Errors
///
/// Returns the first [`WireError`] from parsing an endpoint resource's addresses.
fn endpoint_pool_from_staged(
    staged: &HashMap<EndpointKey, Arc<p::EndpointResource>>,
) -> Result<EndpointPool, WireError> {
    let mut pool = EndpointPool::new();
    for (key, e) in staged {
        pool.insert(key.clone(), Arc::new(resolved_endpoints_from_wire(e)?));
    }
    Ok(pool)
}

/// Narrow a wire `u32` port to the `u16` listener-port range the typed cache
/// maps key on. The canonical key embeds the raw `u32`, so an out-of-range port
/// would otherwise get a distinct digest yet collide with its truncated twin in
/// the typed maps (`65616 → 80`). Reject it at stage time instead (#383 review).
fn port_u16(port: u32) -> Result<u16, WireError> {
    u16::try_from(port).map_err(|_| WireError::UnknownResourceKey {
        reason: "resource port exceeds the u16 listener-port range",
    })
}

/// Derive the per-port HTTPS listener-hostname snapshot from the listener status
/// map (GEP-3567 misdirected-request detection, #96) — the same data the
/// reflector's `build_tls` feeds, keyed by BIND port so the proxy's check matches
/// by the accepted port (#472). Moved here from `client.rs` so all cell
/// derivation lives on the apply path.
fn derive_listener_hostnames(
    listener_status: &HashMap<ObjectKey, coxswain_core::listener_status::GatewayListenerStatus>,
) -> ListenerHostnames {
    let mut builder = ListenerHostnamesBuilder::new();
    for gw_status in listener_status.values() {
        for li in gw_status.listeners.values() {
            builder.add_listener(
                li.bind_port(),
                &li.hostname,
                li.readiness.is_https_terminate(),
            );
        }
    }
    builder.build()
}

/// Build the reverse `endpoint → resources` index from the forward refs.
fn build_ep_index(
    refs: &HashMap<ResourceId, Arc<HashSet<EndpointKey>>>,
) -> HashMap<EndpointKey, HashSet<ResourceId>> {
    let mut index: HashMap<EndpointKey, HashSet<ResourceId>> = HashMap::new();
    for (rid, keys) in refs {
        for key in keys.iter() {
            index.entry(key.clone()).or_default().insert(rid.clone());
        }
    }
    index
}

/// Whether `index` is the exact reverse of `refs` (test/`debug_assert` oracle).
fn ep_index_is_consistent(
    refs: &HashMap<ResourceId, Arc<HashSet<EndpointKey>>>,
    index: &HashMap<EndpointKey, HashSet<ResourceId>>,
) -> bool {
    build_ep_index(refs) == *index
}

// ────────────────────────────────────────────────────────────────────────────
// Change-set derivation
// ────────────────────────────────────────────────────────────────────────────

/// Endpoint keys whose resolved value changed, that are newly added, or that
/// vanished versus the committed cache.
///
/// Value equality is compared on the wire DTO, which the server emits in
/// canonical form (sorted addresses), so DTO-equality ⇔ resolved-value equality
/// for the same key: an endpoint upsert that resolves to the same addresses is
/// **not** dirty and recompiles nothing (#383). New/removed keys are always
/// included (a new key's referencing resource changed its DTO too, so it is
/// already dirty; a removed key must dirty whatever last referenced it).
fn changed_or_removed_endpoints(
    committed: &HashMap<EndpointKey, Arc<p::EndpointResource>>,
    staged: &HashMap<EndpointKey, Arc<p::EndpointResource>>,
) -> HashSet<EndpointKey> {
    let mut out = HashSet::new();
    for (key, staged_dto) in staged {
        match committed.get(key) {
            Some(prev) if **prev == **staged_dto => {}
            _ => {
                out.insert(key.clone());
            }
        }
    }
    for key in committed.keys() {
        if !staged.contains_key(key) {
            out.insert(key.clone());
        }
    }
    out
}

/// The resources a changed-endpoint set touches: route partitions (recompiled
/// individually) and per-cell L4 dirty flags (recompile the whole cell).
#[derive(Default)]
struct EndpointDirty {
    /// Route partitions that reference at least one changed endpoint.
    routes: HashSet<RoutePartitionKey>,
    /// Whether any TLS-passthrough port references a changed endpoint.
    passthrough: bool,
    /// Whether any TLS-terminate port references a changed endpoint.
    terminate: bool,
    /// Whether any TCPRoute port references a changed endpoint.
    tcp: bool,
    /// Whether any UDPRoute port references a changed endpoint.
    udp: bool,
}

/// Fan a changed-endpoint set out to the resources that reference it, via the
/// committed reverse index (who referenced it before) unioned with the staged
/// forward refs (who references it now). A route target is dirtied only if its
/// partition still exists in the staged world — a removed partition is dropped by
/// the assembly loop, never recompiled.
fn endpoint_dirty_targets(
    changed_eps: &HashSet<EndpointKey>,
    staged: &Staged,
    staged_ep_index: &HashMap<EndpointKey, HashSet<ResourceId>>,
    committed_ep_index: &HashMap<EndpointKey, HashSet<ResourceId>>,
) -> EndpointDirty {
    let mut dirty = EndpointDirty::default();
    if changed_eps.is_empty() {
        return dirty;
    }
    for ek in changed_eps {
        let committed = committed_ep_index.get(ek).into_iter().flatten();
        let staged_side = staged_ep_index.get(ek).into_iter().flatten();
        for rid in committed.chain(staged_side) {
            match rid {
                ResourceId::Route(pk) => {
                    if staged.routes.contains_key(pk) {
                        dirty.routes.insert(pk.clone());
                    }
                }
                ResourceId::Passthrough(_) => dirty.passthrough = true,
                ResourceId::Terminate(_) => dirty.terminate = true,
                ResourceId::Tcp(_) => dirty.tcp = true,
                ResourceId::Udp(_) => dirty.udp = true,
            }
        }
    }
    dirty
}

// ────────────────────────────────────────────────────────────────────────────
// Partitioned route-table rebuild (splice)
// ────────────────────────────────────────────────────────────────────────────

/// The result of a partitioned route-table rebuild.
struct RouteRebuild<Kind> {
    /// `Some` iff a partition was dirty or removed; `None` means the table is
    /// unchanged and its live `Arc` is kept (no store in phase D).
    table: Option<RoutingTable<Kind>>,
    /// Partitions recompiled from the fresh throwaway table.
    recompiled: u64,
    /// Partitions spliced from the live table.
    reused: u64,
}

/// Recompile only the dirty partitions of one L7 route table and splice the clean
/// ones from the live table — the #511 partitioned-rebuild reuse applied to the
/// client (#383).
///
/// A partition is dirty when its wire DTO changed versus the committed cache, an
/// endpoint it references changed (`ep_dirty`), or — defensively — it is absent
/// from the live table (a cache/cells desync: recompile rather than serve a table
/// missing a live partition, protocol invariant §4). The final table is assembled
/// by iterating the staged key set for this table: dirty partitions come from a
/// throwaway table built from only the dirty host buckets; clean partitions splice
/// their compiled `Arc<HostRouter>` straight from `live`. Each partition's
/// conflicts are carried from whichever table compiled it, filtered to that
/// partition's `(port, host)` — otherwise a reused partition's shadowed routes
/// would vanish from `conflicts()`. A dirty partition that the fresh table
/// declined to compile (its bound routes all reduced to zero installed rules — a
/// redirect-only host, or every backend structurally invalid) is dropped; the
/// `None` arms in the assembly loop are the defensive handling for that, not the
/// common case (a populated host registers its bucket and splices normally).
///
/// # Errors
///
/// Returns [`WireError`] if compiling a dirty host bucket fails (bad regex,
/// dangling endpoint ref, unroutable path, …). On error nothing is published.
fn rebuild_route_table<Kind>(
    which: RouteTable,
    staged_routes: &HashMap<RoutePartitionKey, Arc<p::RouteHostResource>>,
    committed_routes: &HashMap<RoutePartitionKey, Arc<p::RouteHostResource>>,
    ep_dirty: &HashSet<RoutePartitionKey>,
    live: &RoutingTable<Kind>,
    pool: &EndpointPool,
) -> Result<RouteRebuild<Kind>, WireError>
where
    RoutingTableBuilder<Kind>: Default,
{
    // Split the staged keys for THIS table into dirty (recompile) and clean
    // (splice). `dirty` holds owned keys so it outlives the `staged_keys` borrows.
    let mut dirty: HashSet<RoutePartitionKey> = HashSet::new();
    let mut staged_keys: Vec<&RoutePartitionKey> = Vec::new();
    for (pk, dto) in staged_routes {
        if pk.table != which {
            continue;
        }
        staged_keys.push(pk);
        let (hostname_opt, kind) = host_selector(&pk.host);
        let changed = match committed_routes.get(pk) {
            Some(prev) => **prev != **dto,
            None => true,
        };
        let missing_live = live
            .get_compiled(pk.port, hostname_opt.as_deref(), kind)
            .is_none();
        if changed || ep_dirty.contains(pk) || missing_live {
            dirty.insert(pk.clone());
        }
    }

    // A partition cached under this table but absent from the staged world was
    // removed. It never enters the assembly loop (we iterate staged keys only), so
    // a rebuild drops it — but we must detect it to decide whether the cell needs
    // republishing at all.
    let removed = committed_routes
        .keys()
        .any(|pk| pk.table == which && !staged_routes.contains_key(pk));

    if dirty.is_empty() && !removed {
        return Ok(RouteRebuild {
            table: None,
            recompiled: 0,
            reused: 0,
        });
    }

    // Compile ONLY the dirty partitions into a throwaway table (grouped per port
    // into the shape `build_route_table` consumes).
    let fresh = if dirty.is_empty() {
        None
    } else {
        let mut hosts_by_port: BTreeMap<u16, Vec<&p::HostEntry>> = BTreeMap::new();
        for pk in &dirty {
            if let Some(he) = staged_routes.get(pk).and_then(|rh| rh.host.as_ref()) {
                hosts_by_port.entry(pk.port).or_default().push(he);
            }
        }
        Some(build_route_table::<Kind>(&hosts_by_port, pool)?)
    };

    // Assemble by iterating the staged key set: dirty from `fresh`, clean from
    // `live`, conflicts carried per partition.
    let mut builder = RoutingTableBuilder::<Kind>::new();
    let mut recompiled = 0u64;
    let mut reused = 0u64;
    for pk in staged_keys {
        let (hostname_opt, kind) = host_selector(&pk.host);
        let host_repr = conflict_host_repr(hostname_opt.as_deref());

        let router = if dirty.contains(pk) {
            let Some(fresh) = fresh.as_ref() else {
                // Unreachable: `dirty` non-empty ⇒ `fresh` is Some. Degrade by
                // skipping rather than panicking on the data plane.
                continue;
            };
            let Some(router) = fresh.get_compiled(pk.port, hostname_opt.as_deref(), kind) else {
                // Every bound route resolved to zero installed rules (redirect-only
                // or all backendRefs invalid) — drop the partition.
                continue;
            };
            carry_conflicts(&mut builder, fresh.conflicts(), pk.port, host_repr);
            recompiled += 1;
            router
        } else {
            let Some(router) = live.get_compiled(pk.port, hostname_opt.as_deref(), kind) else {
                // Pre-checked present during dirty derivation (`missing_live` folds
                // such keys into `dirty`); a race here degrades to skip-and-
                // recompile-next-time, never a silently-dropped-forever partition.
                continue;
            };
            carry_conflicts(&mut builder, live.conflicts(), pk.port, host_repr);
            reused += 1;
            router
        };

        splice_router(
            builder.for_port(pk.port),
            hostname_opt.as_deref(),
            kind,
            router,
        );
    }

    let table = builder.build().map_err(|e| match e {
        RouterError::Regex(re) => WireError::InvalidRegex(re),
        other => WireError::InvalidMatchitPath(other.to_string()),
    })?;
    Ok(RouteRebuild {
        table: Some(table),
        recompiled,
        reused,
    })
}

/// Translate a [`HostKey`] into the `(hostname_opt, kind)` selector the core
/// `get_compiled` / `insert_compiled_*` primitives take. `kind` is meaningful
/// only for the wildcard arm (exact/catchall ignore it).
fn host_selector(host: &HostKey) -> (Option<String>, WildcardKind) {
    match host {
        HostKey::Exact(h) => (Some(h.clone()), WildcardKind::MultiLabel),
        HostKey::Wildcard { suffix, kind } => (Some(format!("*.{suffix}")), *kind),
        HostKey::Catchall => (None, WildcardKind::MultiLabel),
    }
}

/// The `RouteConflict::host` spelling of a host selector: `"*"` for catch-all,
/// the `*.suffix` wildcard string as-is, or the exact hostname — mirroring the
/// reflector's `conflict_host_repr` so a flat conflict list filters down to one
/// partition's slice.
fn conflict_host_repr(hostname_opt: Option<&str>) -> &str {
    hostname_opt.unwrap_or("*")
}

/// Carry the conflicts belonging to one partition from whichever table compiled
/// it into `builder`, so a reused partition's shadowed routes stay reported.
///
/// The filter keys on `(port, host_repr)` without the [`WildcardKind`]: two
/// partitions sharing a port and host string but differing only in wildcard
/// semantics could in principle commingle here, but that is unreachable today
/// (single- vs multi-label wildcards are table-disjoint — Ingress vs Gateway),
/// mirroring the reflector's own `conflict_host_repr` filtering.
fn carry_conflicts<Kind>(
    builder: &mut RoutingTableBuilder<Kind>,
    conflicts: &[RouteConflict],
    port: u16,
    host_repr: &str,
) {
    builder.extend_conflicts(
        conflicts
            .iter()
            .filter(|c| c.port == port && c.host == host_repr)
            .cloned(),
    );
}

/// Splice a compiled `Arc<HostRouter>` into the port builder under its host
/// selector (catchall / wildcard / exact), bypassing `HostRouterBuilder`.
fn splice_router(
    pb: &mut coxswain_core::routing::PortTableBuilder,
    hostname_opt: Option<&str>,
    kind: WildcardKind,
    router: Arc<coxswain_core::routing::HostRouter>,
) {
    match hostname_opt {
        None => pb.insert_compiled_catchall(router),
        Some(h) if h.starts_with("*.") => pb.insert_compiled_wildcard_host(h, kind, router),
        Some(h) => pb.insert_compiled_exact_host(h.to_owned(), router),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Coarse per-port cell decode (rebuilt wholesale, only when dirty)
// ────────────────────────────────────────────────────────────────────────────

/// Reassemble and decode the per-port terminate TLS store from the staged map,
/// sorted by port for deterministic build order.
fn decode_tls_cell(staged: &HashMap<u16, Arc<p::PortTlsEntry>>) -> Result<PortTlsStore, WireError> {
    let mut ports: Vec<p::PortTlsEntry> = staged.values().map(|e| (**e).clone()).collect();
    ports.sort_by_key(|e| e.port);
    port_tls_from_wire(&p::PortTlsStore { ports })
}

/// Reassemble and decode the per-port client-certificate store. Each resource's
/// own `port` is authoritative over the (redundant) per-entry field — mirrors
/// `decode_world`'s rehydration.
fn decode_client_certs_cell(
    staged: &HashMap<u16, Arc<p::ClientCertPortResource>>,
) -> Result<ClientCertStore, WireError> {
    let mut resources: Vec<&p::ClientCertPortResource> =
        staged.values().map(AsRef::as_ref).collect();
    resources.sort_by_key(|r| r.port);
    let mut store = p::ClientCertStore::default();
    for r in resources {
        for entry in &r.entries {
            store.entries.push(p::ClientCertEntry {
                host_pattern: entry.host_pattern.clone(),
                state: entry.state.clone(),
                port: r.port,
            });
        }
    }
    client_cert_from_wire(&store)
}

/// Reassemble and decode the per-Gateway listener-status map, sorted by object
/// key for deterministic build order.
fn decode_listener_status_cell(
    staged: &HashMap<ObjectKey, Arc<p::GatewayStatusEntry>>,
) -> Result<HashMap<ObjectKey, GatewayListenerStatus>, WireError> {
    let mut entries: Vec<p::GatewayStatusEntry> = staged.values().map(|e| (**e).clone()).collect();
    entries.sort_by(|a, b| a.object_key.cmp(&b.object_key));
    listener_status_from_wire(&p::GatewayListenerStatus { entries })
}

/// Reassemble and decode a TLS-passthrough / -terminate table from the staged
/// per-port map, resolving endpoint refs against `pool`.
fn decode_passthrough_cell(
    staged: &HashMap<u16, Arc<p::TlsPassthroughPort>>,
    pool: &EndpointPool,
) -> Result<TlsPassthroughTable, WireError> {
    let mut ports: Vec<p::TlsPassthroughPort> = staged.values().map(|e| (**e).clone()).collect();
    ports.sort_by_key(|pt| pt.port);
    passthrough_from_wire(&p::TlsPassthroughTable { ports }, pool)
}

/// Reassemble and decode the TCPRoute table from the staged per-port map.
fn decode_tcp_cell(
    staged: &HashMap<u16, Arc<p::TcpRoutePort>>,
    pool: &EndpointPool,
) -> Result<TcpRouteTable, WireError> {
    let mut ports: Vec<p::TcpRoutePort> = staged.values().map(|e| (**e).clone()).collect();
    ports.sort_by_key(|pt| pt.port);
    tcp_table_from_wire(&p::TcpRouteTable { ports }, pool)
}

/// Reassemble and decode the UDPRoute table from the staged per-port map.
fn decode_udp_cell(
    staged: &HashMap<u16, Arc<p::UdpRoutePort>>,
    pool: &EndpointPool,
) -> Result<UdpRouteTable, WireError> {
    let mut ports: Vec<p::UdpRoutePort> = staged.values().map(|e| (**e).clone()).collect();
    ports.sort_by_key(|pt| pt.port);
    udp_table_from_wire(&p::UdpRouteTable { ports }, pool)
}

// ────────────────────────────────────────────────────────────────────────────
// Keying + reference walking
// ────────────────────────────────────────────────────────────────────────────

/// Map a canonical-keying failure to the wire error the decode path surfaces.
fn wire_from_key_err(e: ResourceKeyError) -> WireError {
    WireError::UnknownResourceKey {
        reason: match e {
            ResourceKeyError::MissingPayload => {
                "resource carries no payload arm (unknown future variant)"
            }
            ResourceKeyError::MissingHost => "route_host resource missing its host bucket",
            ResourceKeyError::MissingHostPattern => "route_host resource host carries no pattern",
            ResourceKeyError::UnspecifiedTable => {
                "route_host resource has an unspecified table kind"
            }
            ResourceKeyError::UnspecifiedWildcardKind => {
                "route_host wildcard carries an unspecified kind"
            }
            ResourceKeyError::MalformedKey { reason } => reason,
        },
    }
}

/// Derive the typed `(table, port, host)` partition key for a route-host
/// resource, mirroring the canonical-key grammar.
fn route_partition_key(rh: &p::RouteHostResource) -> Result<RoutePartitionKey, WireError> {
    let table =
        match p::RouteTableKind::try_from(rh.table).unwrap_or(p::RouteTableKind::Unspecified) {
            p::RouteTableKind::Ingress => RouteTable::Ingress,
            p::RouteTableKind::Gateway => RouteTable::Gateway,
            p::RouteTableKind::Unspecified => {
                return Err(WireError::UnknownResourceKey {
                    reason: "route_host resource has an unspecified table kind",
                });
            }
        };
    let host = rh.host.as_ref().ok_or(WireError::UnknownResourceKey {
        reason: "route_host resource missing its host bucket",
    })?;
    let pattern = host.pattern.as_ref().ok_or(WireError::UnknownResourceKey {
        reason: "route_host resource host carries no pattern",
    })?;
    let host = match pattern {
        p::host_entry::Pattern::Exact(h) => {
            // Fail closed on an exact host that looks like a wildcard: the splice
            // selector reclassifies any `*.`-prefixed host as a wildcard bucket, so
            // an exact `*.x` would compile under exact semantics yet splice under
            // wildcard ones and silently drop. Reject it here — symmetry with the
            // other stage-time protocol guards (#383 review).
            if h.starts_with("*.") {
                return Err(WireError::UnknownResourceKey {
                    reason: "exact route host must not start with '*.'",
                });
            }
            HostKey::Exact(h.clone())
        }
        p::host_entry::Pattern::Wildcard(w) => {
            let kind =
                match p::WildcardKind::try_from(w.kind).unwrap_or(p::WildcardKind::Unspecified) {
                    p::WildcardKind::SingleLabel => WildcardKind::SingleLabel,
                    p::WildcardKind::MultiLabel => WildcardKind::MultiLabel,
                    p::WildcardKind::Unspecified => {
                        return Err(WireError::UnknownResourceKey {
                            reason: "route_host wildcard carries an unspecified kind",
                        });
                    }
                };
            HostKey::Wildcard {
                suffix: w.suffix.clone(),
                kind,
            }
        }
        p::host_entry::Pattern::Catchall(_) => HostKey::Catchall,
    };
    Ok(RoutePartitionKey {
        table,
        port: port_u16(rh.port)?,
        host,
    })
}

/// Collect every endpoint key a route-host resource references, across all its
/// routes' backend groups and (recursively) their mirror-filter backends.
fn collect_route_host_refs(
    rh: &p::RouteHostResource,
    out: &mut HashSet<EndpointKey>,
    depth: usize,
) {
    let Some(host) = &rh.host else { return };
    for route in &host.routes {
        if let Some(bg) = &route.backend_group {
            collect_bg_refs(bg, out, depth);
        }
        for filter in &route.filters {
            collect_filter_refs(filter, out, depth);
        }
    }
}

/// Collect every endpoint key referenced by a TLS-passthrough / terminate port.
fn passthrough_refs(pt: &p::TlsPassthroughPort) -> HashSet<EndpointKey> {
    let mut out = HashSet::new();
    for entry in &pt.entries {
        if let Some(bg) = &entry.backend_group {
            collect_bg_refs(bg, &mut out, 0);
        }
    }
    out
}

/// Collect endpoint keys from a backend group: its weighted backends' refs plus
/// (recursively) any mirror filter nested in a per-backend filter.
///
/// Recursion is bounded by [`crate::wire::MAX_MIRROR_DEPTH`]; a deeper tree stops
/// collecting (the compile phase rejects it with `MirrorTooDeep` before commit,
/// so incomplete refs never reach the cache). Bounding here keeps a malformed,
/// deeply-nested proto from overflowing the stack on the data plane.
fn collect_bg_refs(bg: &p::BackendGroup, out: &mut HashSet<EndpointKey>, depth: usize) {
    if depth > crate::wire::MAX_MIRROR_DEPTH {
        return;
    }
    for wb in &bg.weighted {
        if let Some(r) = &wb.endpoint_ref {
            out.insert(endpoint_key_from_wire(&r.namespace, &r.service, r.port));
        }
    }
    for pbf in &bg.per_backend_filters {
        for filter in &pbf.filters {
            collect_filter_refs(filter, out, depth + 1);
        }
    }
}

/// Collect endpoint keys from a filter: only a mirror filter carries a backend.
fn collect_filter_refs(f: &p::FilterAction, out: &mut HashSet<EndpointKey>, depth: usize) {
    if depth > crate::wire::MAX_MIRROR_DEPTH {
        return;
    }
    if let Some(p::filter_action::Action::Mirror(m)) = &f.action
        && let Some(bg) = &m.backend
    {
        collect_bg_refs(bg, out, depth + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench_internals::snapshot_version;

    // ── cell bundle over a fresh set of Shared cells ──────────────────────────

    /// Owns the ten routing cells so a test can apply against them and inspect
    /// each cell's `Arc` identity.
    struct Cells {
        ingress: SharedIngressRoutingTable,
        gateway: SharedGatewayRoutingTable,
        tls: SharedPortTlsStore,
        client_certs: SharedClientCertStore,
        status: SharedGatewayListenerStatus,
        listener_hostnames: SharedListenerHostnames,
        passthrough: SharedTlsPassthroughTable,
        terminate: SharedTlsPassthroughTable,
        tcp: SharedTcpRouteTable,
        udp: SharedUdpRouteTable,
    }

    impl Cells {
        fn new() -> Self {
            Self {
                ingress: SharedIngressRoutingTable::new(),
                gateway: SharedGatewayRoutingTable::new(),
                tls: SharedPortTlsStore::new(),
                client_certs: SharedClientCertStore::new(),
                status: SharedGatewayListenerStatus::new(),
                listener_hostnames: SharedListenerHostnames::new(),
                passthrough: SharedTlsPassthroughTable::new(),
                terminate: SharedTlsPassthroughTable::new(),
                tcp: SharedTcpRouteTable::new(),
                udp: SharedUdpRouteTable::new(),
            }
        }

        fn bundle(&self) -> SnapshotCells<'_> {
            SnapshotCells {
                ingress: &self.ingress,
                gateway: &self.gateway,
                tls: &self.tls,
                client_certs: &self.client_certs,
                status: &self.status,
                listener_hostnames: &self.listener_hostnames,
                passthrough: &self.passthrough,
                terminate: &self.terminate,
                tcp: &self.tcp,
                udp: &self.udp,
            }
        }
    }

    // ── resource builders ─────────────────────────────────────────────────────

    fn round_robin() -> p::LoadBalance {
        p::LoadBalance {
            algorithm: Some(p::load_balance::Algorithm::RoundRobin(true)),
        }
    }

    /// A literal-address backend group (no endpoint ref).
    fn literal_bg(name: &str, addr: &str) -> p::BackendGroup {
        p::BackendGroup {
            name: name.to_owned(),
            weighted: vec![p::WeightedBackend {
                addrs: vec![addr.to_owned()],
                weight: 1,
                endpoint_ref: None,
            }],
            load_balance: Some(round_robin()),
            ..Default::default()
        }
    }

    /// A keyed backend group (references an endpoint resource).
    fn keyed_bg(name: &str, ns: &str, svc: &str, port: u32) -> p::BackendGroup {
        p::BackendGroup {
            name: name.to_owned(),
            weighted: vec![p::WeightedBackend {
                addrs: Vec::new(),
                weight: 1,
                endpoint_ref: Some(p::EndpointRef {
                    namespace: ns.to_owned(),
                    service: svc.to_owned(),
                    port,
                }),
            }],
            load_balance: Some(round_robin()),
            ..Default::default()
        }
    }

    fn route_with_bg(bg: p::BackendGroup) -> p::RouteEntry {
        p::RouteEntry {
            kind: p::RouteKind::Prefix as i32,
            path: "/".to_owned(),
            backend_group: Some(bg),
            ..Default::default()
        }
    }

    /// An Ingress catch-all route-host resource carrying one route with `bg`.
    fn ingress_route_resource(bg: p::BackendGroup) -> p::Resource {
        p::Resource {
            payload: Some(p::resource::Payload::RouteHost(p::RouteHostResource {
                table: p::RouteTableKind::Ingress as i32,
                port: 80,
                host: Some(p::HostEntry {
                    pattern: Some(p::host_entry::Pattern::Exact("example.com".to_owned())),
                    routes: vec![route_with_bg(bg)],
                    ..Default::default()
                }),
            })),
        }
    }

    /// A bad-regex Ingress route-host resource — decode rejects it.
    fn bad_regex_resource() -> p::Resource {
        p::Resource {
            payload: Some(p::resource::Payload::RouteHost(p::RouteHostResource {
                table: p::RouteTableKind::Ingress as i32,
                port: 80,
                host: Some(p::HostEntry {
                    pattern: Some(p::host_entry::Pattern::Catchall(true)),
                    routes: vec![p::RouteEntry {
                        kind: p::RouteKind::Regex as i32,
                        path: "[unclosed".to_owned(),
                        backend_group: Some(literal_bg("ns/svc", "10.0.0.1:80")),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            })),
        }
    }

    fn endpoint_resource(ns: &str, svc: &str, port: u32, addrs: &[&str]) -> p::Resource {
        p::Resource {
            payload: Some(p::resource::Payload::Endpoints(p::EndpointResource {
                namespace: ns.to_owned(),
                service: svc.to_owned(),
                port,
                app_protocol: 0,
                service_exists: true,
                addrs: addrs.iter().map(|s| (*s).to_owned()).collect(),
            })),
        }
    }

    /// A full snapshot over `resources`. The `version` is computed from the
    /// resource content (F6), matching what a real server stamps, so the client's
    /// version self-check passes. `_label` documents each call site's intent (e.g.
    /// "v1" → "v2") but no longer drives the wire version.
    fn full(_label: &str, resources: Vec<p::Resource>) -> p::Snapshot {
        p::Snapshot {
            version: snapshot_version(&resources),
            nonce: vec![0],
            full: true,
            resources,
            removed_resources: Vec::new(),
        }
    }

    /// A delta snapshot: `upserts` replace/insert their canonical keys, `removed`
    /// tombstones the given canonical-key strings. The `version` is the hash of the
    /// **post-apply world** the caller declares in `post_apply` — the server stamps
    /// the version of the whole applied world, not of the delta payload, and the
    /// client recomputes exactly that to self-check.
    fn delta(
        upserts: Vec<p::Resource>,
        removed: &[&str],
        post_apply: &[p::Resource],
    ) -> p::Snapshot {
        p::Snapshot {
            version: snapshot_version(post_apply),
            nonce: vec![0],
            full: false,
            resources: upserts,
            removed_resources: removed.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    /// An Ingress exact-host route-host resource: host `host`, one prefix `/`
    /// route with `bg`.
    fn ingress_exact_resource(host: &str, bg: p::BackendGroup) -> p::Resource {
        p::Resource {
            payload: Some(p::resource::Payload::RouteHost(p::RouteHostResource {
                table: p::RouteTableKind::Ingress as i32,
                port: 80,
                host: Some(p::HostEntry {
                    pattern: Some(p::host_entry::Pattern::Exact(host.to_owned())),
                    routes: vec![route_with_bg(bg)],
                    ..Default::default()
                }),
            })),
        }
    }

    /// A TCPRoute port resource on `port` with backend `bg`.
    fn tcp_resource(port: u32, bg: p::BackendGroup) -> p::Resource {
        p::Resource {
            payload: Some(p::resource::Payload::TcpPort(p::TcpRoutePort {
                port,
                backend_group: Some(bg),
            })),
        }
    }

    /// A UDPRoute port resource on `port` with backend `bg`.
    fn udp_resource(port: u32, bg: p::BackendGroup) -> p::Resource {
        p::Resource {
            payload: Some(p::resource::Payload::UdpPort(p::UdpRoutePort {
                port,
                backend_group: Some(bg),
            })),
        }
    }

    /// An Ingress exact-host resource whose host carries two `/dup` prefix routes
    /// with distinct route ids/backends — the second shadows the first, so the
    /// compiled partition reports exactly one conflict (route-id tie order:
    /// `ns/first` wins, `ns/second` is rejected).
    fn conflict_resource(host: &str) -> p::Resource {
        let mk = |rid: &str, name: &str, addr: &str| p::RouteEntry {
            kind: p::RouteKind::Prefix as i32,
            path: "/dup".to_owned(),
            backend_group: Some(literal_bg(name, addr)),
            route_id: rid.to_owned(),
            ..Default::default()
        };
        p::Resource {
            payload: Some(p::resource::Payload::RouteHost(p::RouteHostResource {
                table: p::RouteTableKind::Ingress as i32,
                port: 80,
                host: Some(p::HostEntry {
                    pattern: Some(p::host_entry::Pattern::Exact(host.to_owned())),
                    routes: vec![
                        mk("ns/first", "first", "10.0.0.1:80"),
                        mk("ns/second", "second", "10.0.0.2:80"),
                    ],
                    ..Default::default()
                }),
            })),
        }
    }

    /// Load the compiled `Arc<HostRouter>` for an exact Ingress host on port 80.
    fn ingress_router(cells: &Cells, host: &str) -> Arc<coxswain_core::routing::HostRouter> {
        cells
            .ingress
            .load()
            .get_compiled(80, Some(host), WildcardKind::MultiLabel)
            .expect("host compiled")
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    /// A full snapshot populates both the cache and the routing cells.
    #[test]
    fn full_snapshot_populates_cache_and_cells() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let msg = full(
            "v1",
            vec![ingress_route_resource(literal_bg("ns/svc", "10.0.0.1:80"))],
        );

        apply_message(&mut cache, &msg, cells.bundle(), true).expect("apply");

        assert!(cache.has_full, "cache records the applied full");
        assert_eq!(cache.routes.len(), 1, "the one route partition is cached");
        assert_eq!(cache.digests.len(), 1, "one digest recorded");
        let key = RoutePartitionKey {
            table: RouteTable::Ingress,
            port: 80,
            host: HostKey::Exact("example.com".to_owned()),
        };
        assert!(
            cache.routes.contains_key(&key),
            "the route partition is keyed"
        );
    }

    /// A second byte-identical full is a no-op: every cell keeps its exact Arc
    /// (free resync reuse via DTO-equality clean-skip).
    #[test]
    fn identical_full_is_a_noop_cells_unchanged() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let msg = full(
            "v1",
            vec![ingress_route_resource(literal_bg("ns/svc", "10.0.0.1:80"))],
        );
        apply_message(&mut cache, &msg, cells.bundle(), true).expect("first apply");

        let ingress_before = cells.ingress.load();
        let tls_before = cells.tls.load();

        // Re-send byte-identical content — same computed version, digest-equal to
        // the cache, so phase B short-circuits to a no-op.
        let again = full(
            "v2",
            vec![ingress_route_resource(literal_bg("ns/svc", "10.0.0.1:80"))],
        );
        apply_message(&mut cache, &again, cells.bundle(), true).expect("second apply");

        assert!(
            Arc::ptr_eq(&ingress_before, &cells.ingress.load()),
            "identical full must not replace the ingress cell Arc"
        );
        assert!(
            Arc::ptr_eq(&tls_before, &cells.tls.load()),
            "identical full must not replace the tls cell Arc"
        );
    }

    /// A full with a resource removed prunes the cache and the compiled table.
    #[test]
    fn full_with_resource_removed_prunes_cache_and_table() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let two = full(
            "v1",
            vec![
                ingress_route_resource(literal_bg("ns/a", "10.0.0.1:80")),
                p::Resource {
                    payload: Some(p::resource::Payload::RouteHost(p::RouteHostResource {
                        table: p::RouteTableKind::Ingress as i32,
                        port: 80,
                        host: Some(p::HostEntry {
                            pattern: Some(p::host_entry::Pattern::Exact("other.com".to_owned())),
                            routes: vec![route_with_bg(literal_bg("ns/b", "10.0.0.2:80"))],
                            ..Default::default()
                        }),
                    })),
                },
            ],
        );
        apply_message(&mut cache, &two, cells.bundle(), true).expect("apply two");
        assert_eq!(cache.routes.len(), 2, "both partitions cached");

        // Re-send with only the first route.
        let one = full(
            "v2",
            vec![ingress_route_resource(literal_bg("ns/a", "10.0.0.1:80"))],
        );
        apply_message(&mut cache, &one, cells.bundle(), true).expect("apply one");
        assert_eq!(cache.routes.len(), 1, "removed partition pruned from cache");
        assert!(
            !cache
                .digests
                .contains_key("route|ingress|80|exact|other.com"),
            "removed partition pruned from digests"
        );
    }

    /// A decode failure mid-message leaves the cache and every cell unchanged
    /// (atomicity guard): staging succeeds but compilation rejects the bad regex.
    #[test]
    fn decode_failure_leaves_cache_and_cells_unchanged() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        // Establish a good baseline.
        let good = full(
            "v1",
            vec![ingress_route_resource(literal_bg("ns/svc", "10.0.0.1:80"))],
        );
        apply_message(&mut cache, &good, cells.bundle(), true).expect("baseline");

        let ingress_before = cells.ingress.load();
        let gateway_before = cells.gateway.load();
        let digests_before = cache.digests.clone();
        let routes_before: HashSet<_> = cache.routes.keys().cloned().collect();

        // Apply a snapshot whose route carries an invalid regex.
        let bad = full("v2", vec![bad_regex_resource()]);
        let err = apply_message(&mut cache, &bad, cells.bundle(), true).unwrap_err();
        assert!(matches!(err, WireError::InvalidRegex(_)), "got: {err:?}");

        assert!(
            Arc::ptr_eq(&ingress_before, &cells.ingress.load()),
            "ingress cell must be unchanged after a decode failure"
        );
        assert!(
            Arc::ptr_eq(&gateway_before, &cells.gateway.load()),
            "gateway cell must be unchanged after a decode failure"
        );
        assert_eq!(cache.digests, digests_before, "cache digests unchanged");
        assert_eq!(
            cache.routes.keys().cloned().collect::<HashSet<_>>(),
            routes_before,
            "cache route keys unchanged"
        );
    }

    /// A delta (`full = false`) is rejected until commit 6 lifts the guard.
    #[test]
    fn delta_before_full_is_rejected() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let mut delta = full("v1", Vec::new());
        delta.full = false;
        let err = apply_message(&mut cache, &delta, cells.bundle(), true).unwrap_err();
        assert!(
            matches!(err, WireError::DeltaBeforeFullSnapshot),
            "got: {err:?}"
        );
    }

    /// After committing a full, the endpoint index is the exact reverse of the
    /// forward refs.
    #[test]
    fn ep_index_matches_forward_refs() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let msg = full(
            "v1",
            vec![
                endpoint_resource("ns", "svc", 80, &["10.0.0.1:8080"]),
                ingress_route_resource(keyed_bg("ns/svc", "ns", "svc", 80)),
            ],
        );
        apply_message(&mut cache, &msg, cells.bundle(), true).expect("apply");

        assert!(
            ep_index_is_consistent(&cache.refs, &cache.ep_index),
            "ep_index must be the reverse of refs"
        );
        let ek = endpoint_key_from_wire("ns", "svc", 80);
        let referencing = cache.ep_index.get(&ek).expect("endpoint is referenced");
        assert!(
            referencing.contains(&ResourceId::Route(RoutePartitionKey {
                table: RouteTable::Ingress,
                port: 80,
                host: HostKey::Exact("example.com".to_owned()),
            })),
            "the keyed route must appear in the endpoint's referencing set"
        );
    }

    /// Reference walking follows mirror-filter backends: an endpoint referenced
    /// only through a mirror filter still lands in the resource's ref set.
    #[test]
    fn refs_walk_covers_mirror_filters() {
        let mirror = p::FilterAction {
            action: Some(p::filter_action::Action::Mirror(p::MirrorFilter {
                backend: Some(keyed_bg("ns/mirror", "ns", "mirror-svc", 90)),
                fraction: None,
            })),
        };
        let rh = p::RouteHostResource {
            table: p::RouteTableKind::Ingress as i32,
            port: 80,
            host: Some(p::HostEntry {
                pattern: Some(p::host_entry::Pattern::Exact("example.com".to_owned())),
                routes: vec![p::RouteEntry {
                    kind: p::RouteKind::Prefix as i32,
                    path: "/".to_owned(),
                    backend_group: Some(literal_bg("ns/primary", "10.0.0.1:80")),
                    filters: vec![mirror],
                    ..Default::default()
                }],
                ..Default::default()
            }),
        };
        let mut refs = HashSet::new();
        collect_route_host_refs(&rh, &mut refs, 0);
        assert!(
            refs.contains(&endpoint_key_from_wire("ns", "mirror-svc", 90)),
            "mirror-filter backend endpoint must be walked"
        );
    }

    // ── partitioned recompile (commit 5) ──────────────────────────────────────

    /// (a) A full changing exactly one host among several recompiles only that
    /// partition; every sibling's compiled `Arc<HostRouter>` is ptr_eq-reused,
    /// and the returned stats report 1 recompiled / N−1 reused.
    #[test]
    fn full_changing_one_host_reuses_sibling_partitions() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let v1 = full(
            "v1",
            vec![
                ingress_exact_resource("a.com", literal_bg("a", "10.0.0.1:80")),
                ingress_exact_resource("b.com", literal_bg("b", "10.0.0.2:80")),
                ingress_exact_resource("c.com", literal_bg("c", "10.0.0.3:80")),
            ],
        );
        apply_message(&mut cache, &v1, cells.bundle(), true).expect("v1");
        let ra = ingress_router(&cells, "a.com");
        let rb = ingress_router(&cells, "b.com");
        let rc = ingress_router(&cells, "c.com");

        // Only b.com's backend address moves.
        let v2 = full(
            "v2",
            vec![
                ingress_exact_resource("a.com", literal_bg("a", "10.0.0.1:80")),
                ingress_exact_resource("b.com", literal_bg("b", "10.9.9.9:80")),
                ingress_exact_resource("c.com", literal_bg("c", "10.0.0.3:80")),
            ],
        );
        let stats = apply_message(&mut cache, &v2, cells.bundle(), true).expect("v2");

        assert!(
            Arc::ptr_eq(&ra, &ingress_router(&cells, "a.com")),
            "a.com must be reused (ptr_eq)"
        );
        assert!(
            Arc::ptr_eq(&rc, &ingress_router(&cells, "c.com")),
            "c.com must be reused (ptr_eq)"
        );
        assert!(
            !Arc::ptr_eq(&rb, &ingress_router(&cells, "b.com")),
            "b.com must be recompiled (fresh Arc)"
        );
        assert_eq!(
            stats,
            ApplyStats {
                partitions_recompiled: 1,
                partitions_reused: 2,
            }
        );
    }

    /// (b) An endpoint-only change (every route/L4 DTO byte-identical, one
    /// endpoint address moved) recompiles only the partitions referencing that
    /// endpoint; non-referencing partitions are ptr_eq-reused. The referencing L4
    /// cell (tcp) is rebuilt; the non-referencing L4 cell (udp) keeps its Arc.
    #[test]
    fn endpoint_change_recompiles_only_referencing_partition_and_cell() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let v1 = full(
            "v1",
            vec![
                endpoint_resource("ns", "svc", 80, &["10.0.0.1:8080"]),
                ingress_exact_resource("ref.com", keyed_bg("kref", "ns", "svc", 80)),
                ingress_exact_resource("noref.com", literal_bg("lit", "10.0.0.9:80")),
                tcp_resource(9000, keyed_bg("ktcp", "ns", "svc", 80)),
                udp_resource(9002, literal_bg("ludp", "10.0.0.9:80")),
            ],
        );
        apply_message(&mut cache, &v1, cells.bundle(), true).expect("v1");
        let r_ref = ingress_router(&cells, "ref.com");
        let r_noref = ingress_router(&cells, "noref.com");
        let tcp_before = cells.tcp.load();
        let udp_before = cells.udp.load();

        // Only the endpoint's address changes; all route/L4 DTOs are identical.
        let v2 = full(
            "v2",
            vec![
                endpoint_resource("ns", "svc", 80, &["10.0.0.2:8080"]),
                ingress_exact_resource("ref.com", keyed_bg("kref", "ns", "svc", 80)),
                ingress_exact_resource("noref.com", literal_bg("lit", "10.0.0.9:80")),
                tcp_resource(9000, keyed_bg("ktcp", "ns", "svc", 80)),
                udp_resource(9002, literal_bg("ludp", "10.0.0.9:80")),
            ],
        );
        let stats = apply_message(&mut cache, &v2, cells.bundle(), true).expect("v2");

        assert!(
            !Arc::ptr_eq(&r_ref, &ingress_router(&cells, "ref.com")),
            "ref.com must recompile (endpoint it references changed)"
        );
        assert!(
            Arc::ptr_eq(&r_noref, &ingress_router(&cells, "noref.com")),
            "noref.com must be reused (references no changed endpoint)"
        );
        assert!(
            !Arc::ptr_eq(&tcp_before, &cells.tcp.load()),
            "referencing tcp cell must be rebuilt"
        );
        assert!(
            Arc::ptr_eq(&udp_before, &cells.udp.load()),
            "non-referencing udp cell Arc must be unchanged"
        );
        assert_eq!(stats.partitions_recompiled, 1, "only ref.com recompiled");
        assert_eq!(stats.partitions_reused, 1, "noref.com reused");
    }

    /// (c) An endpoint whose resolved value is unchanged does not dirty the
    /// partitions that reference it, even when a sibling forces the apply past
    /// the whole-snapshot no-op: the referencing partition is ptr_eq-reused.
    #[test]
    fn identical_endpoint_does_not_dirty_referencing_partition() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let v1 = full(
            "v1",
            vec![
                endpoint_resource("ns", "svc", 80, &["10.0.0.1:8080"]),
                ingress_exact_resource("ref.com", keyed_bg("kref", "ns", "svc", 80)),
                ingress_exact_resource("other.com", literal_bg("o", "10.0.0.5:80")),
            ],
        );
        apply_message(&mut cache, &v1, cells.bundle(), true).expect("v1");
        let r_ref = ingress_router(&cells, "ref.com");

        // Endpoint identical; only the unrelated `other.com` route changes.
        let v2 = full(
            "v2",
            vec![
                endpoint_resource("ns", "svc", 80, &["10.0.0.1:8080"]),
                ingress_exact_resource("ref.com", keyed_bg("kref", "ns", "svc", 80)),
                ingress_exact_resource("other.com", literal_bg("o", "10.9.9.9:80")),
            ],
        );
        let stats = apply_message(&mut cache, &v2, cells.bundle(), true).expect("v2");

        assert!(
            Arc::ptr_eq(&r_ref, &ingress_router(&cells, "ref.com")),
            "identical endpoint must not dirty its referencing partition"
        );
        assert_eq!(
            stats,
            ApplyStats {
                partitions_recompiled: 1,
                partitions_reused: 1,
            },
            "only the changed sibling recompiles"
        );
    }

    /// (d) A removed partition is absent from the new table; the surviving
    /// sibling is ptr_eq-reused (not recompiled).
    #[test]
    fn removed_partition_dropped_sibling_reused() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let v1 = full(
            "v1",
            vec![
                ingress_exact_resource("a.com", literal_bg("a", "10.0.0.1:80")),
                ingress_exact_resource("c.com", literal_bg("c", "10.0.0.3:80")),
            ],
        );
        apply_message(&mut cache, &v1, cells.bundle(), true).expect("v1");
        let ra = ingress_router(&cells, "a.com");

        let v2 = full(
            "v2",
            vec![ingress_exact_resource(
                "a.com",
                literal_bg("a", "10.0.0.1:80"),
            )],
        );
        let stats = apply_message(&mut cache, &v2, cells.bundle(), true).expect("v2");

        assert!(
            Arc::ptr_eq(&ra, &ingress_router(&cells, "a.com")),
            "surviving a.com must be reused"
        );
        assert!(
            cells
                .ingress
                .load()
                .get_compiled(80, Some("c.com"), WildcardKind::MultiLabel)
                .is_none(),
            "removed c.com must be gone from the compiled table"
        );
        assert_eq!(
            stats,
            ApplyStats {
                partitions_recompiled: 0,
                partitions_reused: 1,
            }
        );
    }

    /// (e) A coarse cell untouched by a route-only change keeps its exact Arc:
    /// changing a route must not republish the TCP cell (cell/route independence).
    #[test]
    fn coarse_cell_untouched_keeps_arc_when_routes_change() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let v1 = full(
            "v1",
            vec![
                ingress_exact_resource("a.com", literal_bg("a", "10.0.0.1:80")),
                tcp_resource(9000, literal_bg("t", "10.0.0.7:80")),
            ],
        );
        apply_message(&mut cache, &v1, cells.bundle(), true).expect("v1");
        let ra = ingress_router(&cells, "a.com");
        let tcp_before = cells.tcp.load();

        // Only the route changes; the TCP resource is identical.
        let v2 = full(
            "v2",
            vec![
                ingress_exact_resource("a.com", literal_bg("a", "10.9.9.9:80")),
                tcp_resource(9000, literal_bg("t", "10.0.0.7:80")),
            ],
        );
        apply_message(&mut cache, &v2, cells.bundle(), true).expect("v2");

        assert!(
            Arc::ptr_eq(&tcp_before, &cells.tcp.load()),
            "unrelated TCP cell Arc must be unchanged when only a route changes"
        );
        assert!(
            !Arc::ptr_eq(&ra, &ingress_router(&cells, "a.com")),
            "the changed route must be recompiled"
        );
    }

    /// (f) A reused partition's conflicts survive the splice: a partition with a
    /// shadowed route stays in `conflicts()` even when it is spliced (not
    /// recompiled) on a later apply that changed only a sibling.
    #[test]
    fn conflicts_survive_partition_splice() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let v1 = full(
            "v1",
            vec![
                conflict_resource("conf.com"),
                ingress_exact_resource("other.com", literal_bg("o", "10.0.0.5:80")),
            ],
        );
        apply_message(&mut cache, &v1, cells.bundle(), true).expect("v1");
        let r_conf = ingress_router(&cells, "conf.com");
        assert!(
            cells
                .ingress
                .load()
                .conflicts()
                .iter()
                .any(|c| c.host == "conf.com" && c.rejected_route_id == "ns/second"),
            "baseline must report conf.com's shadowed-route conflict"
        );

        // Change only `other.com`; conf.com is clean and gets spliced.
        let v2 = full(
            "v2",
            vec![
                conflict_resource("conf.com"),
                ingress_exact_resource("other.com", literal_bg("o", "10.9.9.9:80")),
            ],
        );
        let stats = apply_message(&mut cache, &v2, cells.bundle(), true).expect("v2");

        assert!(
            Arc::ptr_eq(&r_conf, &ingress_router(&cells, "conf.com")),
            "conf.com must be reused (spliced from live)"
        );
        assert!(
            cells
                .ingress
                .load()
                .conflicts()
                .iter()
                .any(|c| c.host == "conf.com" && c.rejected_route_id == "ns/second"),
            "the reused partition's conflict must survive the splice"
        );
        assert_eq!(stats.partitions_reused, 1, "conf.com reused");
        assert_eq!(stats.partitions_recompiled, 1, "other.com recompiled");
    }

    /// (g) A compile failure mid-apply leaves EVERY cell ptr_eq-unchanged, coarse
    /// cells included — atomicity holds across the partitioned/per-cell path.
    #[test]
    fn compile_failure_leaves_all_cells_ptr_eq() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let good = full(
            "v1",
            vec![
                ingress_exact_resource("a.com", literal_bg("a", "10.0.0.1:80")),
                tcp_resource(9000, literal_bg("t", "10.0.0.7:80")),
                udp_resource(9002, literal_bg("u", "10.0.0.8:80")),
            ],
        );
        apply_message(&mut cache, &good, cells.bundle(), true).expect("baseline");

        let ingress_before = cells.ingress.load();
        let gateway_before = cells.gateway.load();
        let tcp_before = cells.tcp.load();
        let udp_before = cells.udp.load();

        // A bad regex fails the route compile; nothing must be published.
        let bad = full("v2", vec![bad_regex_resource()]);
        let err = apply_message(&mut cache, &bad, cells.bundle(), true).unwrap_err();
        assert!(matches!(err, WireError::InvalidRegex(_)), "got: {err:?}");

        assert!(Arc::ptr_eq(&ingress_before, &cells.ingress.load()));
        assert!(Arc::ptr_eq(&gateway_before, &cells.gateway.load()));
        assert!(
            Arc::ptr_eq(&tcp_before, &cells.tcp.load()),
            "coarse TCP cell must be untouched on a compile failure"
        );
        assert!(Arc::ptr_eq(&udp_before, &cells.udp.load()));
    }

    /// (addendum) A stage-phase failure (duplicate canonical key) leaves the
    /// cache maps AND every cell ptr_eq-untouched — atomicity holds before
    /// compilation, not just during it.
    #[test]
    fn stage_failure_leaves_cache_and_cells_ptr_eq() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let good = full(
            "v1",
            vec![ingress_exact_resource(
                "a.com",
                literal_bg("a", "10.0.0.1:80"),
            )],
        );
        apply_message(&mut cache, &good, cells.bundle(), true).expect("baseline");

        let ingress_before = cells.ingress.load();
        let digests_before = cache.digests.clone();
        let routes_before: HashSet<_> = cache.routes.keys().cloned().collect();

        // Two resources fold to the same canonical key — rejected in phase A.
        let dup = full(
            "v2",
            vec![
                ingress_exact_resource("dup.com", literal_bg("d", "10.0.0.2:80")),
                ingress_exact_resource("dup.com", literal_bg("d", "10.0.0.2:80")),
            ],
        );
        let err = apply_message(&mut cache, &dup, cells.bundle(), true).unwrap_err();
        assert!(
            matches!(err, WireError::UnknownResourceKey { .. }),
            "got: {err:?}"
        );

        assert!(
            Arc::ptr_eq(&ingress_before, &cells.ingress.load()),
            "ingress cell must be untouched after a stage failure"
        );
        assert_eq!(cache.digests, digests_before, "cache digests unchanged");
        assert_eq!(
            cache.routes.keys().cloned().collect::<HashSet<_>>(),
            routes_before,
            "cache route keys unchanged"
        );
    }

    // ── delta apply (commit 6) ────────────────────────────────────────────────

    /// A TLS-passthrough or -terminate port resource with one SNI entry backed by
    /// `bg`.
    fn passthrough_resource(
        terminate: bool,
        port: u32,
        sni: &str,
        bg: p::BackendGroup,
    ) -> p::Resource {
        let pt = p::TlsPassthroughPort {
            port,
            entries: vec![p::TlsPassthroughEntry {
                backend_group: Some(bg),
                pattern: Some(p::tls_passthrough_entry::Pattern::Exact(sni.to_owned())),
            }],
        };
        let payload = if terminate {
            p::resource::Payload::TlsTerminatePort(pt)
        } else {
            p::resource::Payload::TlsPassthroughPort(pt)
        };
        p::Resource {
            payload: Some(payload),
        }
    }

    /// A delta upserting one changed route recompiles only that partition; every
    /// sibling is ptr_eq-reused and the stats report 1 recompiled / N−1 reused. The
    /// version is the hash of the declared post-apply world, so the self-check
    /// passes and the delta Acks.
    #[test]
    fn delta_route_upsert_recompiles_only_that_partition() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let v1 = full(
            "v1",
            vec![
                ingress_exact_resource("a.com", literal_bg("a", "10.0.0.1:80")),
                ingress_exact_resource("b.com", literal_bg("b", "10.0.0.2:80")),
                ingress_exact_resource("c.com", literal_bg("c", "10.0.0.3:80")),
            ],
        );
        apply_message(&mut cache, &v1, cells.bundle(), true).expect("v1 full");
        let ra = ingress_router(&cells, "a.com");
        let rc = ingress_router(&cells, "c.com");
        let rb = ingress_router(&cells, "b.com");

        // Delta: upsert only b.com (new backend addr). The post-apply world is a.com
        // + b.com(new) + c.com.
        let b_new = ingress_exact_resource("b.com", literal_bg("b", "10.9.9.9:80"));
        let post = vec![
            ingress_exact_resource("a.com", literal_bg("a", "10.0.0.1:80")),
            b_new.clone(),
            ingress_exact_resource("c.com", literal_bg("c", "10.0.0.3:80")),
        ];
        let d = delta(vec![b_new], &[], &post);
        let stats = apply_message(&mut cache, &d, cells.bundle(), false).expect("delta acks");

        assert!(
            Arc::ptr_eq(&ra, &ingress_router(&cells, "a.com")),
            "a.com reused"
        );
        assert!(
            Arc::ptr_eq(&rc, &ingress_router(&cells, "c.com")),
            "c.com reused"
        );
        assert!(
            !Arc::ptr_eq(&rb, &ingress_router(&cells, "b.com")),
            "b.com recompiled"
        );
        assert_eq!(
            stats,
            ApplyStats {
                partitions_recompiled: 1,
                partitions_reused: 2,
            }
        );
    }

    /// An endpoint-only delta (only the `EndpointResource` changes) recompiles just
    /// the partitions referencing that endpoint and rebuilds the referencing L4
    /// cell; the non-referencing route and L4 cell keep their Arcs.
    #[test]
    fn endpoint_only_delta_recompiles_referencing_partition_and_l4() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let v1 = full(
            "v1",
            vec![
                endpoint_resource("ns", "svc", 80, &["10.0.0.1:8080"]),
                ingress_exact_resource("ref.com", keyed_bg("kref", "ns", "svc", 80)),
                ingress_exact_resource("noref.com", literal_bg("lit", "10.0.0.9:80")),
                tcp_resource(9000, keyed_bg("ktcp", "ns", "svc", 80)),
                udp_resource(9002, literal_bg("ludp", "10.0.0.9:80")),
            ],
        );
        apply_message(&mut cache, &v1, cells.bundle(), true).expect("v1 full");
        let r_ref = ingress_router(&cells, "ref.com");
        let r_noref = ingress_router(&cells, "noref.com");
        let tcp_before = cells.tcp.load();
        let udp_before = cells.udp.load();

        // Delta: only the endpoint's address moves. Every route/L4 DTO is unchanged.
        let ep_new = endpoint_resource("ns", "svc", 80, &["10.0.0.2:8080"]);
        let post = vec![
            ep_new.clone(),
            ingress_exact_resource("ref.com", keyed_bg("kref", "ns", "svc", 80)),
            ingress_exact_resource("noref.com", literal_bg("lit", "10.0.0.9:80")),
            tcp_resource(9000, keyed_bg("ktcp", "ns", "svc", 80)),
            udp_resource(9002, literal_bg("ludp", "10.0.0.9:80")),
        ];
        let d = delta(vec![ep_new], &[], &post);
        let stats = apply_message(&mut cache, &d, cells.bundle(), false).expect("delta acks");

        assert!(
            !Arc::ptr_eq(&r_ref, &ingress_router(&cells, "ref.com")),
            "ref.com recompiled (endpoint changed)"
        );
        assert!(
            Arc::ptr_eq(&r_noref, &ingress_router(&cells, "noref.com")),
            "noref.com reused"
        );
        assert!(
            !Arc::ptr_eq(&tcp_before, &cells.tcp.load()),
            "tcp cell rebuilt"
        );
        assert!(
            Arc::ptr_eq(&udp_before, &cells.udp.load()),
            "udp cell unchanged"
        );
        assert_eq!(stats.partitions_recompiled, 1);
        assert_eq!(stats.partitions_reused, 1);
    }

    /// A tombstone removes exactly its partition; the surviving sibling is reused
    /// and the removed host disappears from the compiled table and the cache.
    #[test]
    fn tombstone_removes_partition() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let v1 = full(
            "v1",
            vec![
                ingress_exact_resource("a.com", literal_bg("a", "10.0.0.1:80")),
                ingress_exact_resource("b.com", literal_bg("b", "10.0.0.2:80")),
            ],
        );
        apply_message(&mut cache, &v1, cells.bundle(), true).expect("v1 full");
        let ra = ingress_router(&cells, "a.com");

        // Delta tombstoning b.com; post-apply world is a.com only.
        let post = vec![ingress_exact_resource(
            "a.com",
            literal_bg("a", "10.0.0.1:80"),
        )];
        let d = delta(Vec::new(), &["route|ingress|80|exact|b.com"], &post);
        apply_message(&mut cache, &d, cells.bundle(), false).expect("delta acks");

        assert!(
            Arc::ptr_eq(&ra, &ingress_router(&cells, "a.com")),
            "a.com reused"
        );
        assert!(
            cells
                .ingress
                .load()
                .get_compiled(80, Some("b.com"), WildcardKind::MultiLabel)
                .is_none(),
            "b.com gone from the compiled table"
        );
        assert_eq!(cache.routes.len(), 1, "b.com pruned from the cache");
        assert!(
            !cache.digests.contains_key("route|ingress|80|exact|b.com"),
            "b.com digest pruned"
        );
    }

    /// A tombstone for a key the cache does not hold is an idempotent no-op
    /// (invariant 2): the world is unchanged, so the version still matches and every
    /// cell keeps its Arc.
    #[test]
    fn unheld_key_tombstone_is_noop() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let v1 = full(
            "v1",
            vec![ingress_exact_resource(
                "a.com",
                literal_bg("a", "10.0.0.1:80"),
            )],
        );
        apply_message(&mut cache, &v1, cells.bundle(), true).expect("v1 full");
        let ra = ingress_router(&cells, "a.com");

        // Tombstone a host we never held; post-apply world equals the committed one.
        let post = vec![ingress_exact_resource(
            "a.com",
            literal_bg("a", "10.0.0.1:80"),
        )];
        let d = delta(Vec::new(), &["route|ingress|80|exact|ghost.com"], &post);
        let stats = apply_message(&mut cache, &d, cells.bundle(), false).expect("delta acks");

        assert!(
            Arc::ptr_eq(&ra, &ingress_router(&cells, "a.com")),
            "no-op tombstone leaves a.com untouched"
        );
        assert_eq!(cache.routes.len(), 1);
        assert_eq!(
            stats,
            ApplyStats::default(),
            "no partition recompiled or reused"
        );
    }

    /// A route tombstone and its endpoint tombstone in the same message (invariant 7
    /// GC) apply cleanly: the referrer and its now-orphaned endpoint drop together,
    /// so the removed-endpoint referential check passes.
    #[test]
    fn route_and_endpoint_tombstone_same_message_applies_clean() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let v1 = full(
            "v1",
            vec![
                endpoint_resource("ns", "svc", 80, &["10.0.0.1:8080"]),
                ingress_exact_resource("ref.com", keyed_bg("kref", "ns", "svc", 80)),
                ingress_exact_resource("other.com", literal_bg("o", "10.0.0.5:80")),
            ],
        );
        apply_message(&mut cache, &v1, cells.bundle(), true).expect("v1 full");
        let r_other = ingress_router(&cells, "other.com");

        // Drop ref.com and its endpoint together; post-apply world is other.com only.
        let post = vec![ingress_exact_resource(
            "other.com",
            literal_bg("o", "10.0.0.5:80"),
        )];
        let d = delta(
            Vec::new(),
            &["route|ingress|80|exact|ref.com", "endpoints|ns/svc/80"],
            &post,
        );
        apply_message(&mut cache, &d, cells.bundle(), false).expect("GC delta acks");

        assert!(
            Arc::ptr_eq(&r_other, &ingress_router(&cells, "other.com")),
            "unrelated other.com reused"
        );
        assert!(
            cells
                .ingress
                .load()
                .get_compiled(80, Some("ref.com"), WildcardKind::MultiLabel)
                .is_none(),
            "ref.com gone"
        );
        assert!(
            !cache
                .endpoints
                .contains_key(&endpoint_key_from_wire("ns", "svc", 80)),
            "orphaned endpoint pruned"
        );
        assert!(
            ep_index_is_consistent(&cache.refs, &cache.ep_index),
            "ep_index stays the exact reverse of refs after GC"
        );
    }

    /// A passthrough/terminate cell is reused (Arc unchanged) when untouched by a
    /// delta, and rebuilt when a referenced endpoint changes — the L4 per-cell path
    /// (`decode_passthrough_cell`, `ep_dirty`) exercised for both tables.
    #[test]
    fn passthrough_and_terminate_cells_reuse_and_rebuild() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        let v1 = full(
            "v1",
            vec![
                endpoint_resource("ns", "pt", 443, &["10.0.0.1:8443"]),
                // passthrough references the endpoint; terminate uses a literal.
                passthrough_resource(
                    false,
                    8443,
                    "pt.example.com",
                    keyed_bg("kpt", "ns", "pt", 443),
                ),
                passthrough_resource(
                    true,
                    9443,
                    "tm.example.com",
                    literal_bg("ltm", "10.0.0.5:8443"),
                ),
            ],
        );
        apply_message(&mut cache, &v1, cells.bundle(), true).expect("v1 full");
        let pass_before = cells.passthrough.load();
        let term_before = cells.terminate.load();

        // Delta: only the passthrough-referenced endpoint's address moves.
        let ep_new = endpoint_resource("ns", "pt", 443, &["10.0.0.2:8443"]);
        let post = vec![
            ep_new.clone(),
            passthrough_resource(
                false,
                8443,
                "pt.example.com",
                keyed_bg("kpt", "ns", "pt", 443),
            ),
            passthrough_resource(
                true,
                9443,
                "tm.example.com",
                literal_bg("ltm", "10.0.0.5:8443"),
            ),
        ];
        let d = delta(vec![ep_new], &[], &post);
        apply_message(&mut cache, &d, cells.bundle(), false).expect("delta acks");

        assert!(
            !Arc::ptr_eq(&pass_before, &cells.passthrough.load()),
            "passthrough cell rebuilt (its referenced endpoint changed)"
        );
        assert!(
            Arc::ptr_eq(&term_before, &cells.terminate.load()),
            "terminate cell reused (references no changed endpoint)"
        );
    }

    // ── delta protocol guards (each leaves cache + cells ptr_eq) ───────────────

    /// Snapshot the ingress cell Arc + cache digests, apply a delta that must fail,
    /// and assert the error plus that nothing live moved.
    fn assert_delta_rejected_untouched(
        cache: &mut ResourceCache,
        cells: &Cells,
        d: &p::Snapshot,
        want: impl Fn(&WireError) -> bool,
    ) {
        let ingress_before = cells.ingress.load();
        let tcp_before = cells.tcp.load();
        let digests_before = cache.digests.clone();

        let err = apply_message(cache, d, cells.bundle(), false).unwrap_err();
        assert!(want(&err), "unexpected error: {err:?}");

        assert!(
            Arc::ptr_eq(&ingress_before, &cells.ingress.load()),
            "ingress cell must be untouched after a rejected delta"
        );
        assert!(
            Arc::ptr_eq(&tcp_before, &cells.tcp.load()),
            "tcp cell must be untouched after a rejected delta"
        );
        assert_eq!(cache.digests, digests_before, "cache digests unchanged");
    }

    /// A baseline full over a keyed route + its endpoint, for the guard tests.
    fn keyed_baseline(cache: &mut ResourceCache, cells: &Cells) {
        let v1 = full(
            "v1",
            vec![
                endpoint_resource("ns", "svc", 80, &["10.0.0.1:8080"]),
                ingress_exact_resource("ref.com", keyed_bg("kref", "ns", "svc", 80)),
            ],
        );
        apply_message(cache, &v1, cells.bundle(), true).expect("baseline full");
    }

    /// A delta as the first message of a session (`expect_full = true`) is rejected
    /// even though the persisted cache already holds a full — the server's per-stream
    /// baseline is not portable across reconnects (invariant 1).
    #[test]
    fn delta_first_in_session_rejected_despite_cached_full() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        keyed_baseline(&mut cache, &cells);
        assert!(cache.has_full, "cache holds a full from the prior session");

        let d = delta(Vec::new(), &[], &[]);
        let ingress_before = cells.ingress.load();
        // expect_full = true simulates the first message of a new session.
        let err = apply_message(&mut cache, &d, cells.bundle(), true).unwrap_err();
        assert!(
            matches!(err, WireError::DeltaBeforeFullSnapshot),
            "got: {err:?}"
        );
        assert!(Arc::ptr_eq(&ingress_before, &cells.ingress.load()));
    }

    /// A delta whose upsert and tombstone key sets overlap is a protocol violation
    /// (invariant 2).
    #[test]
    fn overlapping_upsert_and_remove_keys_rejected() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        keyed_baseline(&mut cache, &cells);

        // Upsert ref.com AND tombstone the same canonical key.
        let d = delta(
            vec![ingress_exact_resource(
                "ref.com",
                literal_bg("r", "10.0.0.7:80"),
            )],
            &["route|ingress|80|exact|ref.com"],
            &[],
        );
        assert_delta_rejected_untouched(&mut cache, &cells, &d, |e| {
            matches!(e, WireError::UnknownResourceKey { .. })
        });
    }

    /// Tombstoning an endpoint a surviving route still references is rejected
    /// (invariant 4).
    #[test]
    fn removed_endpoint_still_referenced_rejected() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        keyed_baseline(&mut cache, &cells);

        // Remove the endpoint but leave ref.com (still references it) in place.
        let d = delta(Vec::new(), &["endpoints|ns/svc/80"], &[]);
        assert_delta_rejected_untouched(&mut cache, &cells, &d, |e| {
            matches!(e, WireError::RemovedEndpointStillReferenced { .. })
        });
    }

    /// A delta upserting a route that references an endpoint present nowhere in the
    /// post-apply pool is a dangling reference, caught at compile.
    #[test]
    fn dangling_ref_in_delta_rejected() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        keyed_baseline(&mut cache, &cells);

        // Upsert a new route referencing a ghost endpoint; declare it in the
        // post-apply world so the version self-check passes and the compile guard
        // (not the version check) is what rejects it.
        let ghost = ingress_exact_resource("new.com", keyed_bg("kg", "ns", "ghost", 99));
        let post = vec![
            endpoint_resource("ns", "svc", 80, &["10.0.0.1:8080"]),
            ingress_exact_resource("ref.com", keyed_bg("kref", "ns", "svc", 80)),
            ghost.clone(),
        ];
        let d = delta(vec![ghost], &[], &post);
        assert_delta_rejected_untouched(&mut cache, &cells, &d, |e| {
            matches!(e, WireError::UnknownEndpointRef { .. })
        });
    }

    /// A delta whose stamped version does not match the client's recomputed
    /// post-apply hash is rejected (F6 self-check) before anything is published.
    #[test]
    fn tampered_version_rejected() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        keyed_baseline(&mut cache, &cells);

        // A well-formed upsert, but with a bogus version stamp.
        let mut d = delta(
            vec![ingress_exact_resource(
                "added.com",
                literal_bg("x", "10.0.0.8:80"),
            )],
            &[],
            &[],
        );
        d.version = "tampered-not-a-real-hash".to_owned();
        assert_delta_rejected_untouched(&mut cache, &cells, &d, |e| {
            matches!(e, WireError::VersionMismatch { .. })
        });
    }

    /// An unparsable tombstone key fails the delta closed (invariant 7 / fail-safe
    /// keying).
    #[test]
    fn unparsable_tombstone_key_rejected() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        keyed_baseline(&mut cache, &cells);

        let d = delta(Vec::new(), &["not-a-valid-canonical-key"], &[]);
        assert_delta_rejected_untouched(&mut cache, &cells, &d, |e| {
            matches!(e, WireError::UnknownResourceKey { .. })
        });
    }

    /// An exact route host that looks like a wildcard (`*.`) is rejected at stage —
    /// fail-closed symmetry with the delta guards (addendum item 6). Routed through
    /// the shared harness so it also proves cache + cells stay ptr_eq.
    #[test]
    fn exact_host_with_wildcard_prefix_rejected() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        keyed_baseline(&mut cache, &cells);

        let d = delta(
            vec![ingress_exact_resource(
                "*.evil.com",
                literal_bg("e", "10.0.0.1:80"),
            )],
            &[],
            &[],
        );
        assert_delta_rejected_untouched(&mut cache, &cells, &d, |e| {
            matches!(e, WireError::UnknownResourceKey { .. })
        });
    }

    /// An out-of-range endpoint-resource port is rejected at stage rather than
    /// truncated into a colliding key (addendum item 1). Routed through the shared
    /// harness so it also proves cache + cells stay ptr_eq.
    #[test]
    fn out_of_range_endpoint_port_rejected() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        keyed_baseline(&mut cache, &cells);

        let d = delta(
            vec![endpoint_resource("ns", "svc", 65616, &["10.0.0.1:8080"])],
            &[],
            &[],
        );
        assert_delta_rejected_untouched(&mut cache, &cells, &d, |e| {
            matches!(e, WireError::UnknownResourceKey { .. })
        });
    }

    /// A `listener|<object-key>` tombstone whose object-key substring is not
    /// `ns/name` is rejected in `remove_from_staged`: `parse_canonical_key` accepts
    /// any non-empty tail, but the subsequent `ObjectKey` parse fails closed, so the
    /// delta leaves cache + cells untouched (addendum: listener-tombstone parse gap).
    #[test]
    fn listener_tombstone_malformed_object_key_rejected() {
        let mut cache = ResourceCache::new();
        let cells = Cells::new();
        keyed_baseline(&mut cache, &cells);

        let d = delta(Vec::new(), &["listener|noslash"], &[]);
        assert_delta_rejected_untouched(&mut cache, &cells, &d, |e| {
            matches!(e, WireError::UnknownResourceKey { .. })
        });
    }
}
