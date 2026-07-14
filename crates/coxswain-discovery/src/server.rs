//! Discovery gRPC server: runs inside the controller role.
//!
//! Implements the `Discovery` tonic service, watches the controller's `Shared`
//! routing snapshots, and fans out `Snapshot` messages to connected proxy clients
//! with push-after-Ack flow control.
//!
//! # Flow control and the per-stream delta engine (#383)
//!
//! Each stream keeps a per-node baseline — `StreamState::acked_resources`, the
//! canonical-key → resource-hash map of the world the node last Ack'd. Every
//! outbound message is a diff against that baseline:
//!
//! - The **first** message per session (connect, reconnect) has no baseline yet
//!   (`acked_resources == None`), so it is a `full = true` snapshot of the whole
//!   world. A reconnect is a fresh session — the baseline is not portable across
//!   streams, so a redial always re-sends a full.
//! - Every subsequent message is a `full = false` delta: resources whose hash
//!   moved (or that are new) ride as upserts; keys that left the world ride as
//!   `removed_resources` tombstones. The two key sets are disjoint by
//!   construction. The delta's `version` is the global hash of the POST-APPLY
//!   world (identical formula to a full), so the client's version self-check
//!   passes and NodeRegistry / #531 convergence is unchanged.
//! - A new snapshot is only sent after the prior one is Ack'd (one in-flight).
//!   Rebuilds arriving while a snapshot is in-flight are coalesced: after the Ack
//!   promotes the pending world into the baseline, the server reads the current
//!   world once and sends a single delta spanning baseline → latest. An empty
//!   delta (the world equals the baseline) is not sent — the node's convergence
//!   stamp is advanced instead (quiet-cluster #531 liveness).
//!
//! Nacks trigger a **full resync** of the current world with a fresh version and
//! nonce (self-healing — the per-stream payload retention is gone). The client's
//! baseline is untrustworthy after a Nack, so a full re-establishes it from
//! scratch; `in_flight`/`pending` become that fresh full.
//!
//! # Shared view cache
//!
//! [`Scope::SharedPool`] streams all diff against the same routing world, so the
//! server materializes it at most once per rebuild generation and shares the
//! resulting `Arc<MaterializedView>` across every shared-pool stream
//! (`DiscoveryService::shared_view`). Gateway-scope views stay per-call (each
//! carries a per-stream SVID check). The cache lock is a `parking_lot::Mutex`
//! never held across an `.await`.
//!
//! # Node registry
//!
//! Each stream task calls [`SharedNodeRegistry::connect`] on entry and
//! [`SharedNodeRegistry::disconnect`] on exit, recording every Ack — and every
//! `NodeStatus` bound-port report (#531) — in between. The registry is read by
//! the admin UI convergence panel (T8) and by the controller's Gateway
//! `Programmed` readiness gate (#531).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, warn};

use coxswain_core::Shared;
use coxswain_core::dedicated_registry::DedicatedRoutingRegistry;
use coxswain_core::identity::SpiffeId;
use coxswain_core::listener_status::SharedGatewayListenerStatus;
use coxswain_core::node_registry::{NodeScope, SharedNodeRegistry};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::publish_index::SharedGatewayPublishIndex;
use coxswain_core::routing::{
    SharedGatewayRoutingTable, SharedIngressRoutingTable, SharedTcpRouteTable,
    SharedTlsPassthroughTable, SharedUdpRouteTable,
};
use coxswain_core::tls::{SharedClientCertStore, SharedPortTlsStore};

use crate::auth::{PeerSvid, svid_matches_dedicated_gateway};
use crate::subscription::Scope;

use crate::materialize::{MaterializedView, materialize};
use crate::proto::v1::{
    self as p, client_message::Kind as CKind, discovery_server::Discovery,
    server_message::Kind as SKind,
};
use crate::version::WIRE_VERSION;
use crate::wire::scope_from_wire;

// ── SnapshotSource ────────────────────────────────────────────────────────────

/// The routing-table [`Shared`] cells the server reads to build snapshots (the
/// nine shared L7/status/L4 cells, plus the per-Gateway dedicated registry and the
/// publish-sequence index).
///
/// Populated in `coxswain-bin` from `StatusWriter::outputs`; no K8s API access
/// happens at serve time.
///
/// [`Shared`]: coxswain_core::Shared
// intentionally open: field-literal constructed in coxswain-bin
pub struct SnapshotSource {
    /// Ingress routing table shared cell.
    pub ingress: SharedIngressRoutingTable,
    /// Gateway-API routing table shared cell.
    pub gateway: SharedGatewayRoutingTable,
    /// TLS certificate store shared cell.
    pub tls: SharedPortTlsStore,
    /// Client-certificate mTLS config store shared cell.
    pub client_certs: SharedClientCertStore,
    /// Per-Gateway listener status map. Serialised into the
    /// `listener_status` wire field so proxy nodes can drive dynamic
    /// Gateway listener port bind/unbind without Kubernetes API access.
    pub listener_status: SharedGatewayListenerStatus,
    /// Per-cut-over-Gateway routing snapshots, keyed by Gateway [`ObjectKey`].
    /// Read when a client subscribes with [`Scope::Gateway`]; all the other
    /// routing cells (the L7/status cells above and the four L4 tables below)
    /// serve [`Scope::SharedPool`] and deliberately exclude cut-over Gateways. The
    /// shared reconciler is the sole writer.
    pub dedicated: DedicatedRoutingRegistry,
    /// SNI-keyed TLS passthrough routing table for TLSRoute / GEP-2643 (#70).
    /// Only populated for [`Scope::SharedPool`] subscribers; dedicated proxies
    /// receive an empty table (TLSRoutes are shared-pool only).
    pub passthrough_routes: SharedTlsPassthroughTable,
    /// SNI-keyed TLS terminate routing table for TLSRouteModeTerminate (#481).
    /// Only populated for [`Scope::SharedPool`] subscribers; dedicated proxies
    /// receive an empty table (TLSRoutes are shared-pool only).
    pub terminate_routes: SharedTlsPassthroughTable,
    /// Port-keyed TCP routing table for TCPRoute / GEP-1901 (#505).
    /// Only populated for [`Scope::SharedPool`] subscribers; dedicated proxies
    /// receive an empty table (TCPRoutes are shared-pool only).
    pub tcp_routes: SharedTcpRouteTable,
    /// Port-keyed UDP routing table for UDPRoute / GEP-2645 (#506).
    /// Only populated for [`Scope::SharedPool`] subscribers; dedicated proxies
    /// receive an empty table (UDPRoutes are shared-pool only).
    pub udp_routes: SharedUdpRouteTable,
    /// Per-Gateway publish-sequence index (#531). The server captures its
    /// counter **before** loading any cell for a snapshot build; a node that
    /// Acks that snapshot has therefore applied every rebuild stamped at a
    /// sequence `<=` the captured value — the content-convergence input to
    /// the `Programmed` ack gate.
    pub publish: SharedGatewayPublishIndex,
}

impl Clone for SnapshotSource {
    fn clone(&self) -> Self {
        Self {
            ingress: self.ingress.clone(),
            gateway: self.gateway.clone(),
            tls: self.tls.clone(),
            client_certs: self.client_certs.clone(),
            listener_status: self.listener_status.clone(),
            dedicated: self.dedicated.clone(),
            passthrough_routes: self.passthrough_routes.clone(),
            terminate_routes: self.terminate_routes.clone(),
            tcp_routes: self.tcp_routes.clone(),
            udp_routes: self.udp_routes.clone(),
            publish: self.publish.clone(),
        }
    }
}

// ── DiscoveryService ──────────────────────────────────────────────────────────

/// Authorizes a [`Scope::Namespace`] subscribe (#582, the relay tier's upstream
/// aggregation scope).
///
/// `Namespace` fans out every dedicated Gateway's routing world in one
/// namespace to a single stream, so a wrongly-authorized subscriber gets a much
/// bigger blast radius than a single `Scope::Gateway` binding — hence a
/// dedicated seam rather than reusing the private Gateway-scope SVID binding
/// check. Provisioning-backed implementations land with #584; until then every
/// [`DiscoveryService`] defaults to [`DenyAllNamespaces`].
pub trait ScopeAuthorizer: Send + Sync {
    /// Returns `true` if `peer` may open a `Namespace{namespace}` subscribe.
    fn allows_namespace(&self, peer: &PeerSvid, namespace: &str) -> bool;
}

/// Fail-closed default [`ScopeAuthorizer`]: denies every `Namespace` subscribe.
///
/// Safe until a provenance-backed authorizer (#584) is wired in via
/// [`DiscoveryService::with_scope_authorizer`] — no relay can be provisioned
/// yet, so there is no legitimate `Namespace` subscriber to allow.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllNamespaces;

impl ScopeAuthorizer for DenyAllNamespaces {
    fn allows_namespace(&self, _peer: &PeerSvid, _namespace: &str) -> bool {
        false
    }
}

/// Provenance-backed [`ScopeAuthorizer`] (#584): authorizes a `Namespace{ns}`
/// subscribe only for the relay ServiceAccount the controller provisioned in
/// `ns`.
///
/// `provisioned` is the live set of namespaces where the operator currently has
/// a relay — published by the controller's relay convergence from the *same*
/// computation that drives provisioning, so the grant cannot drift from the
/// rendered Deployment. Authorization is the conjunction of two independent
/// facts, both deny-by-default:
///
/// 1. **Provenance** — `ns` is in `provisioned` (a namespace with no dedicated
///    Gateway, hence no relay, is absent and rejected).
/// 2. **Identity** — some peer URI SAN parses to a SPIFFE ID whose namespace and
///    ServiceAccount are exactly `(ns, relay_sa)` in `trust_domain`.
///
/// A Kubernetes projected token cryptographically binds the SVID's namespace to
/// the pod's own namespace, so the worst a forged label buys an attacker is a
/// `Namespace` stream for **their own** namespace — never a peer tenant's.
/// The trust domain is already enforced at the TLS handshake
/// ([`crate::auth::SpiffeClientCertVerifier`]); re-checking it here is
/// defense-in-depth, not the primary control.
#[derive(Clone)]
// intentionally open: constructed only via `new`; all fields private
pub struct ProvisionedRelayAuthorizer {
    /// Namespaces with a controller-provisioned relay, kept live by the operator.
    provisioned: Shared<HashSet<String>>,
    /// The ServiceAccount name every provisioned relay runs as (`coxswain-relay`).
    relay_sa: String,
    /// Trust domain the relay SVID must carry.
    trust_domain: String,
}

impl ProvisionedRelayAuthorizer {
    /// Build an authorizer over the operator's live provisioned-relay set.
    ///
    /// `provisioned` is shared with the controller's relay convergence (its
    /// writer); `relay_sa` is the fixed relay ServiceAccount name; `trust_domain`
    /// is the cluster SPIFFE trust domain.
    #[must_use]
    pub fn new(
        provisioned: Shared<HashSet<String>>,
        relay_sa: impl Into<String>,
        trust_domain: impl Into<String>,
    ) -> Self {
        Self {
            provisioned,
            relay_sa: relay_sa.into(),
            trust_domain: trust_domain.into(),
        }
    }
}

impl ScopeAuthorizer for ProvisionedRelayAuthorizer {
    fn allows_namespace(&self, peer: &PeerSvid, namespace: &str) -> bool {
        // No fail-open: an absent PeerSvid reaches the call site as empty SANs.
        if peer.uri_sans.is_empty() {
            return false;
        }
        // Provenance gate: the operator must currently have a relay in `namespace`.
        if !self.provisioned.load().contains(namespace) {
            return false;
        }
        // Identity gate: some SVID is exactly the relay SA in this namespace.
        peer.uri_sans.iter().any(|uri| {
            SpiffeId::parse(uri.as_str()).is_ok_and(|id| {
                id.trust_domain() == self.trust_domain
                    && id.namespace() == namespace
                    && id.service_account() == self.relay_sa
            })
        })
    }
}

/// Discovery gRPC service.
///
/// Wired by `coxswain-bin` into a tonic server that runs as a Pingora background
/// service on the controller role. Every connected proxy client gets a dedicated
/// task spawned inside [`DiscoveryService::stream`]; all tasks share the same
/// `source` and `registry` via `Clone`.
///
/// Cloneable because tonic requires the service to be `Clone`.
#[non_exhaustive]
#[derive(Clone)]
pub struct DiscoveryService {
    source: SnapshotSource,
    registry: SharedNodeRegistry,
    rebuild_rx: watch::Receiver<u64>,
    /// Leadership gate (#531). `Some(rx)`: streams are accepted only while the
    /// watched value is `true`, and live streams are terminated on a
    /// `true → false` flip. `None`: ungated (unit tests; the bin always gates).
    leader_rx: Option<watch::Receiver<bool>>,
    /// Per-generation [`Scope::SharedPool`] / [`Scope::Namespace`] view cache
    /// (#383, #582). Every shared-pool stream diffs against the same world, and
    /// every relay subscribing to the same namespace diffs against the same
    /// namespace world, so each is materialized once per rebuild generation and
    /// shared here behind an `Arc`. Cloning the service (tonic clones per
    /// connection) shares this cache; Gateway-scope views bypass it (each
    /// carries a per-stream SVID check). See [`view_for`].
    shared_view: SharedViewCache,
    /// Authorizer for `Scope::Namespace` subscribes (#582). Defaults to
    /// [`DenyAllNamespaces`]; `coxswain-bin` installs a provenance-backed
    /// implementation once #584 provisions relays.
    authorizer: Arc<dyn ScopeAuthorizer>,
}

/// Shared, generation-keyed view cache for scopes every subscriber of the same
/// key diffs against identically: [`Scope::SharedPool`] (single slot) and
/// [`Scope::Namespace`] (one slot per namespace, #582). `Gateway` scope bypasses
/// this cache entirely (per-stream SVID binding).
///
/// The lock is a `parking_lot::Mutex` held only for the map read/write, never
/// across the materialize call or an `.await`.
type SharedViewCache = Arc<Mutex<ViewCacheState>>;

/// Cache contents behind [`SharedViewCache`]. Split so the two cacheable scopes
/// don't share a single-slot cache key (`Namespace{a}` and `Namespace{b}` must
/// coexist, unlike `SharedPool`'s single world). Each slot is `None` until its
/// first build — rebuild generations start at 0 in production and in tests, so
/// a sentinel generation number cannot distinguish "never built" from "built at
/// generation 0"; `Option` is the only unambiguous representation.
#[derive(Default)]
struct ViewCacheState {
    /// `(generation, view)` for `SharedPool`, most recently materialized.
    shared_pool: Option<(u64, Arc<MaterializedView>)>,
    /// `namespace → (generation, view)`, most recently materialized per
    /// namespace; entries are created lazily on first subscribe.
    namespace: HashMap<String, Option<(u64, Arc<MaterializedView>)>>,
}

/// Stream-rejection message sent by a non-leader replica (#531).
///
/// The discovery client matches on this text (plus `FAILED_PRECONDITION`) to
/// classify the rejection as an expected fast-retry — `FAILED_PRECONDITION`
/// alone is ambiguous (wire-version mismatch uses the same code). Keep the
/// phrase "not the leader" stable; `client::is_not_leader` depends on it.
pub(crate) const NOT_LEADER_MSG: &str =
    "discovery: this replica is not the leader; redial to reach the leader";

/// The wire-stable substring `client::is_not_leader` matches on. Must appear
/// verbatim in [`NOT_LEADER_MSG`] — enforced by a unit test — and must never
/// change wording: controller and proxy binaries skew across upgrades, so an
/// old proxy classifies a new controller's rejection by this exact phrase.
pub(crate) const NOT_LEADER_NEEDLE: &str = "not the leader";

impl DiscoveryService {
    /// Construct a new service handle.
    ///
    /// `rebuild_rx` must be cloned from `route_health.subscribe()` — the
    /// reconciler's rebuild-generation watch channel. Each newly accepted stream
    /// gets its own clone so ticks are delivered independently.
    #[must_use]
    pub fn new(
        source: SnapshotSource,
        registry: SharedNodeRegistry,
        rebuild_rx: watch::Receiver<u64>,
    ) -> Self {
        Self {
            source,
            registry,
            rebuild_rx,
            leader_rx: None,
            shared_view: Arc::new(Mutex::new(ViewCacheState::default())),
            authorizer: Arc::new(DenyAllNamespaces),
        }
    }

    /// Gate the `Stream` RPC on a leadership watch (#531).
    ///
    /// While the watched value is `false` (standby, or leadership not yet
    /// established), new streams are rejected at accept with
    /// `FAILED_PRECONDITION` / `NOT_LEADER_MSG`, and a demotion terminates
    /// every live stream with the same status so proxies redial immediately —
    /// their bound-port Acks must land on the leader that writes status, never
    /// in a demoted replica's registry. The Bootstrap RPC is deliberately NOT
    /// gated: SVID issuance is stateless (shared CA Secret) and must work on
    /// every replica.
    #[must_use]
    pub fn with_leader_gate(mut self, rx: watch::Receiver<bool>) -> Self {
        self.leader_rx = Some(rx);
        self
    }

    /// Install a [`ScopeAuthorizer`] for `Scope::Namespace` subscribes (#582).
    ///
    /// Replaces the [`DenyAllNamespaces`] default. `coxswain-bin` calls this
    /// once a provenance-backed authorizer exists (#584); until then every
    /// service denies every `Namespace` subscribe.
    #[must_use]
    pub fn with_scope_authorizer(mut self, authorizer: Arc<dyn ScopeAuthorizer>) -> Self {
        self.authorizer = authorizer;
        self
    }
}

// ── nonce counter ─────────────────────────────────────────────────────────────

/// Global monotone counter for nonce generation.
///
/// Nonces are not cryptographic; they let the client correlate an Ack/Nack with
/// the specific transmission that triggered it.
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_nonce() -> Vec<u8> {
    NONCE_COUNTER
        .fetch_add(1, Ordering::Relaxed)
        .to_be_bytes()
        .to_vec()
}

// ── snapshot construction ─────────────────────────────────────────────────────

/// The world a node last confirmed (or is about to), retained per stream as the
/// delta baseline. Replaces the v1 full-blob retention: a diff only needs the
/// key → hash map, never the resource bytes (those stay behind the view's `Arc`s).
struct PendingWorld {
    /// Global content hash of this world (echoed by the node's Ack).
    version: String,
    /// Canonical-key → per-resource-hash map — the diff baseline. Shared with the
    /// view behind an `Arc`, so retaining it per stream is a cheap clone.
    resources: Arc<BTreeMap<String, String>>,
    /// Publish sequence captured before the cells were read (never on the wire);
    /// recorded into the node registry when this world is Ack'd (#531).
    seq: u64,
}

/// An outbound snapshot ready to send: the wire message (nonce already stamped)
/// paired with the post-apply world the client will hold once it Acks.
struct Outbound {
    /// The wire message — `full = true` for a full, `false` for a delta.
    message: p::Snapshot,
    /// The world this message brings the client to; retained as `pending`.
    world: PendingWorld,
}

/// Diff `view` against a node's acked baseline into the message to send next.
///
/// - `acked == None` ⇒ a **full**: every resource in canonical-key order,
///   `full = true`, no tombstones. Used for the first message of a session.
/// - `acked == Some(base)` ⇒ a **delta**: upserts are the view resources whose
///   key is absent from `base` or whose hash moved; tombstones are the `base`
///   keys absent from the view. Both lists are canonical-key sorted (the view and
///   `base` are `BTreeMap`s), and the two key sets are disjoint by construction.
///   An **empty** delta (no upserts, no tombstones — the world equals the
///   baseline, so `view.version` necessarily equals the acked version) returns
///   `None`: nothing is sent, and the caller advances the node's convergence
///   stamp instead of pushing.
///
/// In every case the message `version` is `view.version` — the global hash of the
/// POST-APPLY world (never the delta payload's own hash), so the client's
/// per-resource version self-check reproduces it exactly.
fn build_outbound(
    view: &MaterializedView,
    acked: Option<&BTreeMap<String, String>>,
) -> Option<Outbound> {
    // The post-apply world a client reaches once it Acks this message. Built ONLY
    // on a send path (never on the empty-delta no-op below), and cheap regardless:
    // the hash map is shared with the view behind an `Arc`, so this is an `Arc`
    // clone plus the version string, not a copy of the whole key→hash map.
    let world = || PendingWorld {
        version: view.version.clone(),
        resources: Arc::clone(&view.resource_hashes),
        seq: view.seq,
    };
    match acked {
        // First message of a session: the whole world as a full.
        None => {
            let resources = view
                .resources
                .values()
                .map(|entry| (*entry.resource).clone())
                .collect();
            Some(Outbound {
                message: p::Snapshot {
                    version: view.version.clone(),
                    nonce: next_nonce(),
                    full: true,
                    resources,
                    removed_resources: Vec::new(),
                },
                world: world(),
            })
        }
        // Steady state: diff the view against what the node last confirmed.
        Some(base) => {
            // Upserts: new keys or keys whose per-resource hash moved. BTreeMap
            // iteration is canonical-key order, so the wire list is sorted.
            let resources: Vec<p::Resource> = view
                .resources
                .iter()
                .filter(|(key, entry)| {
                    base.get(*key).map(String::as_str) != Some(entry.hash.as_str())
                })
                .map(|(_, entry)| (*entry.resource).clone())
                .collect();
            // Tombstones: baseline keys the view no longer carries. `base` is a
            // BTreeMap, so this is already canonical-key sorted.
            let removed_resources: Vec<String> = base
                .keys()
                .filter(|key| !view.resources.contains_key(*key))
                .cloned()
                .collect();
            // Empty delta: the world matches the baseline. Do not send — the
            // caller advances the convergence stamp (quiet-cluster #531 liveness).
            if resources.is_empty() && removed_resources.is_empty() {
                return None;
            }
            Some(Outbound {
                message: p::Snapshot {
                    version: view.version.clone(),
                    nonce: next_nonce(),
                    full: false,
                    resources,
                    removed_resources,
                },
                world: world(),
            })
        }
    }
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
fn view_for(
    cache: &SharedViewCache,
    source: &SnapshotSource,
    scope: &Scope,
    peer_svid: Option<&PeerSvid>,
    generation: u64,
) -> Arc<MaterializedView> {
    match scope {
        // Gateway scope: per-stream SVID binding, never cached.
        Scope::Gateway { .. } => Arc::new(build_view(source, scope, peer_svid)),
        Scope::SharedPool => cached_view(cache, source, scope, peer_svid, generation, |state| {
            &mut state.shared_pool
        }),
        Scope::Namespace { namespace } => {
            let namespace = namespace.clone();
            cached_view(cache, source, scope, peer_svid, generation, move |state| {
                state.namespace.entry(namespace.clone()).or_default()
            })
        }
    }
}

/// Shared build-outside-lock-then-recheck cache discipline for a single
/// `(generation, view)` slot, addressed by `slot` inside the locked
/// [`ViewCacheState`]. Used for both the single `SharedPool` slot and each
/// `Namespace` map entry (#582).
fn cached_view(
    cache: &SharedViewCache,
    source: &SnapshotSource,
    scope: &Scope,
    peer_svid: Option<&PeerSvid>,
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
    let view = Arc::new(build_view(source, scope, peer_svid));
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
fn build_view(
    source: &SnapshotSource,
    scope: &Scope,
    peer_svid: Option<&PeerSvid>,
) -> MaterializedView {
    let start = Instant::now();
    let view = materialize(source, scope, peer_svid);
    crate::metrics::snapshot_build_seconds().observe(start.elapsed().as_secs_f64());
    view
}

// ── tonic service impl ────────────────────────────────────────────────────────

#[async_trait]
impl Discovery for DiscoveryService {
    type StreamStream = ReceiverStream<Result<p::ServerMessage, Status>>;

    /// Bootstrap RPC is served by [`crate::bootstrap_server::BootstrapService`]
    /// on the separate bootstrap listener (port 50052).  This implementation
    /// always returns `Unimplemented` so callers connecting to the wrong port
    /// get a clear error rather than a hang.
    async fn bootstrap(
        &self,
        _request: Request<p::BootstrapRequest>,
    ) -> Result<Response<p::BootstrapResponse>, Status> {
        Err(Status::unimplemented(
            "Bootstrap RPC is served on the bootstrap port (50052), not the Stream port (50051)",
        ))
    }

    async fn stream(
        &self,
        request: Request<Streaming<p::ClientMessage>>,
    ) -> Result<Response<Self::StreamStream>, Status> {
        // Leader gate (#531): a standby replica accepts no streams — readiness
        // reports must land on the status-writing leader's registry. Checked
        // before reading the subscription so a rejected dial costs one RTT.
        if let Some(rx) = &self.leader_rx
            && !*rx.borrow()
        {
            crate::metrics::streams_total()
                .with_label_values(&["rejected_not_leader"])
                .inc();
            return Err(Status::failed_precondition(NOT_LEADER_MSG));
        }

        // Extract peer SVID from TLS connection info BEFORE consuming the request.
        // PeerSvid is populated by transport::PeerSvidStream::connect_info() on
        // mTLS connections; absent on plaintext (test/degraded) connections.
        let peer_svid = request.extensions().get::<PeerSvid>().cloned();
        let mut inbound = request.into_inner();

        // First message from client must be Subscribe.
        let sub = read_subscribe(&mut inbound).await?;

        if sub.wire_version != WIRE_VERSION {
            crate::metrics::streams_total()
                .with_label_values(&["rejected"])
                .inc();
            return Err(Status::failed_precondition(format!(
                "discovery wire version mismatch: server={WIRE_VERSION}, client={}",
                sub.wire_version,
            )));
        }

        // Decode the subscription scope; it pins which slice of the routing world
        // every snapshot on this stream is built from. An absent scope (no `scope`
        // field at all) is treated as `SharedPool` — the default subscription.
        // A scope with an absent `kind` discriminator is rejected as malformed to
        // prevent a zero-value message from silently escalating to SharedPool (#427).
        let scope = match sub.scope.as_ref() {
            None => Scope::SharedPool,
            Some(dto) => scope_from_wire(dto).map_err(|e| {
                crate::metrics::streams_total()
                    .with_label_values(&["rejected"])
                    .inc();
                Status::invalid_argument(format!("discovery: invalid scope: {e}"))
            })?,
        };

        // Gap A — open-time scope binding (#427): verify that a Gateway scope
        // claim matches the authenticated peer SVID identity.
        //
        // A dedicated proxy must present a SVID whose namespace + SA equal those
        // of its provisioned ServiceAccount (`{gw}-{class}`). The check fires only
        // when the Gateway's dedicated-registry entry exists — if absent, the
        // snapshot is fail-closed empty regardless, so we let the stream open and
        // re-check on every build_snapshot call.
        //
        // When no PeerSvid is present (plaintext/test path) we skip the check and
        // fail-open — mTLS is mandatory in production, so this branch is
        // test/degraded-mode only.
        if let Some(peer) = peer_svid.as_ref()
            && let Scope::Gateway { name, namespace } = &scope
        {
            let key = ObjectKey::new(namespace.clone(), name.clone());
            if let Some(entry) = self.source.dedicated.load().get(&key)
                && !svid_matches_dedicated_gateway(
                    &peer.uri_sans,
                    namespace,
                    &entry.expected_proxy_sa,
                )
            {
                crate::metrics::streams_total()
                    .with_label_values(&["rejected"])
                    .inc();
                return Err(Status::permission_denied(
                    "scope claim does not match authenticated SVID identity",
                ));
            }
        }

        // Open-time scope authorization for `Scope::Namespace` (#582): unlike
        // the Gateway binding check above, this does NOT fail-open on an
        // absent PeerSvid — a Namespace subscribe fans out every dedicated
        // Gateway in the namespace to one stream, so an unauthenticated
        // connection must be denied by the same authorizer as an
        // authenticated one (the default `DenyAllNamespaces` denies both; a
        // stub-allow authorizer in tests can accept either explicitly).
        if let Scope::Namespace { namespace } = &scope {
            let peer = peer_svid.clone().unwrap_or_default();
            if !self.authorizer.allows_namespace(&peer, namespace) {
                crate::metrics::streams_total()
                    .with_label_values(&["rejected"])
                    .inc();
                return Err(Status::permission_denied(
                    "discovery: Namespace scope not authorized for this identity",
                ));
            }
        }

        let node_id = sub.node_id.clone();

        // Register the node before spawning so connect() is visible
        // even if the first snapshot races with a load().
        self.registry
            .connect(&node_id, node_scope_from(&scope), SystemTime::now());
        crate::metrics::streams_total()
            .with_label_values(&["accepted"])
            .inc();
        crate::metrics::connected_proxies().inc();

        let services = StreamServices {
            source: self.source.clone(),
            registry: self.registry.clone(),
            rebuild_rx: self.rebuild_rx.clone(),
            shared_view: self.shared_view.clone(),
            leader_rx: self.leader_rx.clone(),
        };
        let (tx, rx) = mpsc::channel::<Result<p::ServerMessage, Status>>(4);

        let subscription = StreamSubscription {
            node_id,
            scope,
            peer_svid,
        };
        tokio::spawn(async move {
            run_stream(subscription, services, inbound, tx).await;
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// Read the first `ClientMessage` from the stream and unwrap the `Subscribe`.
///
/// # Errors
///
/// Returns a tonic `Status` if the stream closes before a message arrives,
/// if the transport errors, or if the first message is not a `Subscribe`.
async fn read_subscribe(inbound: &mut Streaming<p::ClientMessage>) -> Result<p::Subscribe, Status> {
    match inbound.message().await {
        Ok(Some(msg)) => match msg.kind {
            Some(CKind::Subscribe(s)) => Ok(s),
            _ => Err(Status::invalid_argument(
                "discovery: first client message must be Subscribe",
            )),
        },
        Ok(None) => Err(Status::cancelled(
            "discovery: stream closed before Subscribe",
        )),
        Err(e) => Err(Status::internal(format!(
            "discovery: stream error reading Subscribe: {e}"
        ))),
    }
}

// ── per-stream state machine ──────────────────────────────────────────────────

/// Immutable per-stream subscriber identity, grouped so function signatures
/// stay under the 7-argument threshold.
///
/// Groups the three fields that together describe WHO is subscribing and with
/// what credential: the node identifier, the requested scope, and the peer SVID
/// extracted from the mTLS client certificate (absent on plaintext connections).
struct StreamSubscription {
    /// Unique identifier for this proxy node.
    node_id: String,
    /// Subscription scope (SharedPool or a specific Gateway).
    scope: Scope,
    /// URI SANs from the peer's mTLS client certificate; absent on plaintext
    /// connections (test/degraded mode).  Used to bind `Scope::Gateway` claims
    /// to the authenticated SVID identity on every snapshot build.
    peer_svid: Option<PeerSvid>,
}

/// Mutable per-stream flow-control state, grouped to keep helper function
/// signatures under the 7-argument threshold.
struct StreamState {
    /// The canonical-key → resource-hash world the node last Ack'd — the delta
    /// baseline. `None` until the first Ack, which is exactly when the next
    /// outbound must be a full: on connect (no baseline yet) and on any defensive
    /// path that clears it. Every delta is diffed against this map.
    acked_resources: Option<Arc<BTreeMap<String, String>>>,
    /// Version hash of the snapshot currently awaiting an Ack from the client;
    /// `None` when no snapshot is in-flight (safe to push the next one).
    in_flight: Option<String>,
    /// The world currently in-flight, retained until its Ack promotes it into
    /// [`Self::acked_resources`]. Replaces the v1 full-blob retention: a Nack no
    /// longer retransmits it (it triggers a fresh full resync instead), so only
    /// the diff baseline is kept, never the resource bytes. `Some` iff a snapshot
    /// is in flight.
    pending: Option<PendingWorld>,
    /// When the in-flight snapshot was transmitted (#513 ack-latency stage). A
    /// Nack-driven full resync of the SAME version keeps this original send time
    /// (the snapshot took a Nack round trip before converging — its true
    /// end-to-end latency spans both legs); a resync at a DIFFERENT version is a
    /// new snapshot and refreshes it.
    sent_at: Option<Instant>,
}

/// Shared per-stream service handles, cloned from [`DiscoveryService`] into the
/// stream task and passed to the Ack / Nack / rebuild handlers by reference.
/// Grouped so those handlers stay under the 7-argument workspace limit.
struct StreamServices {
    source: SnapshotSource,
    registry: SharedNodeRegistry,
    rebuild_rx: watch::Receiver<u64>,
    shared_view: SharedViewCache,
    leader_rx: Option<watch::Receiver<bool>>,
}

/// Immutable references the outbound handlers need, borrowed from the stream
/// task's owned locals. Grouped to keep [`handle_ack`] / [`handle_nack`] under the
/// 7-argument limit. Deliberately excludes the mutable `rebuild_rx`/`leader_rx`
/// watches (owned as `mut` locals in [`run_stream`]); the current generation is
/// read at the select-arm call site and passed as a scalar.
struct StreamCtx<'a> {
    sub: &'a StreamSubscription,
    source: &'a SnapshotSource,
    registry: &'a SharedNodeRegistry,
    shared_view: &'a SharedViewCache,
    tx: &'a mpsc::Sender<Result<p::ServerMessage, Status>>,
}

/// Map a discovery [`Scope`] to the core-local [`NodeScope`] mirror.
///
/// `coxswain-admin` consumes [`NodeScope`] without importing `coxswain-discovery`,
/// so the conversion lives here at the crate boundary.
fn node_scope_from(scope: &Scope) -> NodeScope {
    match scope {
        Scope::SharedPool => NodeScope::SharedPool,
        Scope::Gateway { name, namespace } => NodeScope::Gateway {
            namespace: namespace.clone(),
            name: name.clone(),
        },
        Scope::Namespace { namespace } => NodeScope::Namespace {
            namespace: namespace.clone(),
        },
    }
}

/// Drive the push-after-Ack state machine for one connected proxy node.
///
/// Exits when the client disconnects, the outbound channel closes, or a stream
/// error is received. Calls [`SharedNodeRegistry::disconnect`] unconditionally
/// on exit so the registry stays consistent.
async fn run_stream(
    sub: StreamSubscription,
    services: StreamServices,
    mut inbound: Streaming<p::ClientMessage>,
    tx: mpsc::Sender<Result<p::ServerMessage, Status>>,
) {
    // Destructure so the mutable watches stay as `mut` locals (they are polled in
    // the select loop) while the rest is borrowed immutably by `ctx`.
    let StreamServices {
        source,
        registry,
        mut rebuild_rx,
        shared_view,
        mut leader_rx,
    } = services;
    let ctx = StreamCtx {
        sub: &sub,
        source: &source,
        registry: &registry,
        shared_view: &shared_view,
        tx: &tx,
    };

    let mut state = StreamState {
        acked_resources: None,
        in_flight: None,
        pending: None,
        sent_at: None,
    };

    // Send the initial snapshot immediately on stream open. With no baseline yet
    // (`acked_resources == None`) this is always a full; `build_outbound`
    // therefore always yields `Some`, so the initial send never no-ops.
    let generation = *rebuild_rx.borrow();
    let view = view_for(
        &shared_view,
        &source,
        &sub.scope,
        sub.peer_svid.as_ref(),
        generation,
    );
    registry.record_target(&sub.node_id, view.version.clone());
    match push_if_changed(&ctx, &view, &mut state).await {
        Ok(_) => {}
        Err(()) => {
            registry.disconnect(&sub.node_id);
            crate::metrics::connected_proxies().dec();
            return;
        }
    }

    loop {
        tokio::select! {
            // Inbound message from the proxy client.
            result = inbound.message() => {
                match result {
                    Ok(Some(client_msg)) => {
                        match client_msg.kind {
                            Some(CKind::Ack(ack)) => {
                                let generation = *rebuild_rx.borrow();
                                if handle_ack(&ctx, ack, &mut state, generation).await.is_err() {
                                    break;
                                }
                            }
                            Some(CKind::Nack(nack)) => {
                                let generation = *rebuild_rx.borrow();
                                if handle_nack(&ctx, &nack, &mut state, generation).await.is_err() {
                                    break;
                                }
                            }
                            Some(CKind::NodeStatus(ns)) => {
                                record_node_status(&sub.node_id, &ns, &registry);
                            }
                            Some(CKind::Subscribe(_)) => {
                                // Duplicate Subscribe mid-stream; ignore (idempotent).
                                debug!(node_id = %sub.node_id, "discovery: duplicate Subscribe ignored");
                            }
                            None => {
                                debug!(
                                    node_id = %sub.node_id,
                                    "discovery: unrecognised ClientMessage kind, ignoring"
                                );
                            }
                        }
                    }
                    Ok(None) => {
                        debug!(node_id = %sub.node_id, "discovery: client disconnected (stream closed)");
                        break;
                    }
                    Err(e) => {
                        warn!(node_id = %sub.node_id, error = %e, "discovery: stream error from client");
                        break;
                    }
                }
            }

            // Leadership lost (#531) — terminate the stream so the proxy
            // redials and its readiness reports land on the new leader, not in
            // this demoted replica's registry.
            () = watch_demotion(&mut leader_rx) => {
                debug!(node_id = %sub.node_id, "discovery: leadership lost; terminating stream");
                let _ = tx
                    .send(Err(Status::failed_precondition(NOT_LEADER_MSG)))
                    .await;
                break;
            }

            // Routing world was rebuilt — check for a new delta to push.
            _ = rebuild_rx.changed() => {
                if state.in_flight.is_some() {
                    // A snapshot is already awaiting Ack; coalesce this rebuild.
                    // After its Ack promotes the baseline, `handle_ack` reads the
                    // current world once and sends a single delta spanning
                    // baseline → latest.
                    debug!(node_id = %sub.node_id, "discovery: rebuild while in-flight, coalescing");
                    continue;
                }
                let generation = *rebuild_rx.borrow();
                let view = view_for(&shared_view, &source, &sub.scope, sub.peer_svid.as_ref(), generation);
                registry.record_target(&sub.node_id, view.version.clone());
                match push_if_changed(&ctx, &view, &mut state).await {
                    Ok(true) => {}
                    Ok(false) => {
                        // No change vs the node's acked baseline: advance its
                        // convergence stamp to the freshly-captured sequence so
                        // the #531 ack gate converges without a content change.
                        debug!(
                            node_id = %sub.node_id,
                            "discovery: rebuild produced no change vs baseline — no push needed"
                        );
                        registry.advance_acked_seq(&sub.node_id, view.seq);
                    }
                    Err(()) => break,
                }
            }
        }
    }

    registry.disconnect(&sub.node_id);
    crate::metrics::connected_proxies().dec();
}

/// Build the outbound message for `view` against the stream's acked baseline and,
/// if it is non-empty, send it and record it as the new in-flight/pending world.
///
/// Returns:
/// - `Ok(true)`  — a message was sent; `in_flight`/`pending`/`sent_at` updated.
/// - `Ok(false)` — an empty delta (the world equals the baseline); nothing sent,
///   caller advances the node's convergence stamp.
/// - `Err(())`   — the outbound channel closed.
///
/// A full (baseline `None`) is never empty, so the initial send always returns
/// `Ok(true)`.
async fn push_if_changed(
    ctx: &StreamCtx<'_>,
    view: &MaterializedView,
    state: &mut StreamState,
) -> Result<bool, ()> {
    let Some(Outbound { message, world }) = build_outbound(view, state.acked_resources.as_deref())
    else {
        return Ok(false);
    };
    state.in_flight = Some(world.version.clone());
    state.pending = Some(world);
    state.sent_at = Some(Instant::now());
    send_outbound(ctx.tx, message).await?;
    Ok(true)
}

/// Handle an `Ack` from the client.
///
/// An Ack that matches the in-flight world (`pending.version`) is honest: it
/// promotes that world into the delta baseline ([`StreamState::acked_resources`]),
/// records its publish sequence (#531), observes the #513 ack latency, and clears
/// `in_flight`. Then — the world may have moved on while the Ack was in flight
/// (coalesced rebuilds) — the current world is re-materialized and a single delta
/// spanning baseline → latest is sent (or the convergence stamp advanced if the
/// world matches the baseline).
///
/// A stale / duplicate Ack (no in-flight world, or a version mismatch) does NOT
/// promote the baseline and does NOT clear `in_flight` — the honest Ack for the
/// still-in-flight world is yet to come. It records sequence 0 (a no-op under the
/// registry's monotone max) so the registry stays consistent with the v1 filter.
///
/// Returns `Err(())` if the outbound channel is closed.
async fn handle_ack(
    ctx: &StreamCtx<'_>,
    ack: p::Ack,
    state: &mut StreamState,
    generation: u64,
) -> Result<(), ()> {
    debug!(node_id = %ctx.sub.node_id, version = %ack.version, "discovery: Ack received");

    // Promote only an Ack matching the in-flight world. The nested `take()` is
    // guarded by the same predicate, so the `Some` arm always fires when honest;
    // a `None` there would leave `acked_seq` at 0 without panicking.
    let mut acked_seq = 0;
    let honest = state
        .pending
        .as_ref()
        .is_some_and(|p| p.version == ack.version);
    if honest {
        // #513 ack-latency stage: observed only for the honest Ack — a stale one
        // carries no send timestamp to measure against.
        if let Some(sent_at) = state.sent_at {
            crate::metrics::ack_latency_seconds().observe(sent_at.elapsed().as_secs_f64());
        }
        if let Some(pending) = state.pending.take() {
            acked_seq = pending.seq;
            state.acked_resources = Some(pending.resources);
            state.in_flight = None;
            state.sent_at = None;
        }
    }
    ctx.registry
        .record_ack(&ctx.sub.node_id, ack.version, acked_seq, SystemTime::now());
    crate::metrics::acks_total().inc();

    // Re-check the current world only once nothing is in flight. A stale Ack that
    // did not clear `in_flight` skips this — the world genuinely in flight must
    // Ack before the next push (one in-flight invariant).
    if state.in_flight.is_none() {
        let view = view_for(
            ctx.shared_view,
            ctx.source,
            &ctx.sub.scope,
            ctx.sub.peer_svid.as_ref(),
            generation,
        );
        ctx.registry
            .record_target(&ctx.sub.node_id, view.version.clone());
        match push_if_changed(ctx, &view, state).await {
            Ok(true) => {}
            Ok(false) => {
                // World matches the baseline: advance the convergence stamp
                // without a push (#531 ack-gate liveness on a quiet cluster).
                ctx.registry.advance_acked_seq(&ctx.sub.node_id, view.seq);
            }
            Err(()) => return Err(()),
        }
    }
    Ok(())
}

/// Handle a `Nack` from the client → **full resync**.
///
/// A Nack means the client rejected the last message and its baseline is now
/// untrustworthy, so the server re-materializes the current world and sends it as
/// a fresh `full = true` snapshot (new version + nonce). That full becomes the new
/// in-flight/pending world; the per-stream payload retention is gone, so there is
/// nothing to "retransmit" — the client self-heals from the full.
///
/// The #513 ack-latency send timestamp is refreshed only when the resync's version
/// differs from the Nack'd one: a converged-but-transiently-Nack'd snapshot keeps
/// its original send time so the eventual Ack measures the true end-to-end
/// latency across both legs, not just the retry.
///
/// Returns `Err(())` if the outbound channel is closed.
async fn handle_nack(
    ctx: &StreamCtx<'_>,
    nack: &p::Nack,
    state: &mut StreamState,
    generation: u64,
) -> Result<(), ()> {
    warn!(
        node_id = %ctx.sub.node_id,
        version = %nack.version,
        detail = %nack.detail,
        "discovery: Nack received; sending full resync of the current world",
    );
    let view = view_for(
        ctx.shared_view,
        ctx.source,
        &ctx.sub.scope,
        ctx.sub.peer_svid.as_ref(),
        generation,
    );
    ctx.registry
        .record_target(&ctx.sub.node_id, view.version.clone());
    // Force a full (ignore the acked baseline — it is untrustworthy after a Nack).
    // `build_outbound(_, None)` is always a full, hence never `None`; the else arm
    // degrades to a no-op rather than panicking on the impossible case.
    let Some(Outbound { message, world }) = build_outbound(&view, None) else {
        return Ok(());
    };
    // Preserve #513 latency semantics: keep the original send time when the
    // resync carries the same version the client Nack'd, refresh it otherwise.
    if world.version != nack.version {
        state.sent_at = Some(Instant::now());
    } else if state.sent_at.is_none() {
        // Same version but no prior timestamp (e.g. a Nack with no in-flight
        // send): stamp now so the eventual Ack still observes a latency.
        state.sent_at = Some(Instant::now());
    }
    state.in_flight = Some(world.version.clone());
    state.pending = Some(world);
    send_outbound(ctx.tx, message).await
}

/// Resolve when the watched leadership value is (or becomes) `false` (#531).
///
/// Pends forever when ungated (`None`). A dropped sender means the controller
/// lease loop is gone (process shutdown) — treated as demotion so streams
/// close promptly rather than lingering on a dying replica.
async fn watch_demotion(rx: &mut Option<watch::Receiver<bool>>) {
    let Some(rx) = rx else {
        return std::future::pending().await;
    };
    loop {
        if !*rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Record a `NodeStatus` bound-port report into the registry (#531).
///
/// Wire carries `u32`; values outside the `u16` port domain are dropped with a
/// debug log rather than rejecting the whole report — a hostile or buggy client
/// must not be able to wedge its own row, and dropping oversized values fails
/// closed (the port reads as not-bound).
fn record_node_status(node_id: &str, status: &p::NodeStatus, registry: &SharedNodeRegistry) {
    let mut ports = std::collections::BTreeSet::new();
    for raw in &status.bound_ports {
        match u16::try_from(*raw) {
            Ok(port) => {
                ports.insert(port);
            }
            Err(_) => {
                debug!(
                    node_id,
                    raw, "discovery: NodeStatus port out of u16 range, dropped"
                );
            }
        }
    }
    registry.record_bound_ports(node_id, ports);
}

/// Wrap a wire snapshot in a `ServerMessage`, send it, and — only on a successful
/// hand-off to the transport — emit the #383 send-side metrics. The nonce is
/// already stamped by [`build_outbound`].
///
/// Counting after the send keeps a closed channel (stream teardown) from inflating
/// the send-side counters with a message that was never delivered.
///
/// Returns `Err(())` if the receiver has been dropped.
async fn send_outbound(
    tx: &mpsc::Sender<Result<p::ServerMessage, Status>>,
    message: p::Snapshot,
) -> Result<(), ()> {
    let kind = if message.full { "full" } else { "delta" };
    let resources_sent = message.resources.len() as u64;
    let resources_removed = message.removed_resources.len() as u64;
    let msg = p::ServerMessage {
        kind: Some(SKind::Snapshot(message)),
    };
    tx.send(Ok(msg)).await.map_err(|_| ())?;
    crate::metrics::snapshot_messages_total()
        .with_label_values(&[kind])
        .inc();
    crate::metrics::snapshot_resources_sent_total().inc_by(resources_sent);
    crate::metrics::snapshot_resources_removed_total().inc_by(resources_removed);
    Ok(())
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::v1::{
        ClientMessage, ServerMessage, Snapshot, client_message::Kind as CKind,
        discovery_server::DiscoveryServer, server_message::Kind as SrvKind,
    };
    use coxswain_core::dedicated_registry::DedicatedRoutingSnapshot;
    use coxswain_core::endpoints::{EndpointKey, ResolvedEndpoints};
    use coxswain_core::listener_status::GatewayListenerStatus;
    use coxswain_core::node_registry::SharedNodeRegistry;
    use coxswain_core::routing::{
        BackendGroup, BackendProtocol, GatewayRoutingTable, IngressRoutingTable,
        IngressRoutingTableBuilder, RouteEntry, SharedGatewayRoutingTable,
        SharedIngressRoutingTable,
    };
    use coxswain_core::tls::{
        ClientCertStore, PortTlsStore, SharedClientCertStore, SharedPortTlsStore,
    };
    use std::collections::{BTreeMap, HashMap};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::sync::watch;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::{Endpoint, Server};

    // ── ProvisionedRelayAuthorizer (#584) ─────────────────────────────────────

    const AUTHZ_TD: &str = "cluster.local";
    const AUTHZ_RELAY_SA: &str = "coxswain-relay";

    fn relay_peer(ns: &str, sa: &str) -> PeerSvid {
        PeerSvid {
            uri_sans: vec![format!("spiffe://{AUTHZ_TD}/ns/{ns}/sa/{sa}")],
        }
    }

    fn provenance_authorizer(provisioned: &[&str]) -> ProvisionedRelayAuthorizer {
        let set: HashSet<String> = provisioned.iter().map(|s| (*s).to_owned()).collect();
        ProvisionedRelayAuthorizer::new(Shared::from_value(set), AUTHZ_RELAY_SA, AUTHZ_TD)
    }

    #[test]
    fn provenance_authorizer_allows_provisioned_relay_sa() {
        let a = provenance_authorizer(&["team-a"]);
        assert!(
            a.allows_namespace(&relay_peer("team-a", AUTHZ_RELAY_SA), "team-a"),
            "the provisioned relay SA in its own namespace must be authorized"
        );
    }

    #[test]
    fn provenance_authorizer_denies_unprovisioned_namespace() {
        let a = provenance_authorizer(&["team-a"]);
        assert!(
            !a.allows_namespace(&relay_peer("team-b", AUTHZ_RELAY_SA), "team-b"),
            "a namespace with no provisioned relay must be denied even for the relay SA"
        );
    }

    #[test]
    fn provenance_authorizer_denies_rogue_service_account() {
        let a = provenance_authorizer(&["team-a"]);
        assert!(
            !a.allows_namespace(&relay_peer("team-a", "rogue"), "team-a"),
            "a self-made SA in a provisioned namespace must be denied"
        );
    }

    #[test]
    fn provenance_authorizer_denies_cross_namespace_svid() {
        // team-a's relay SVID subscribing to team-b (also provisioned): the SVID
        // namespace must equal the requested namespace — forgery is bounded to
        // the tenant's own namespace.
        let a = provenance_authorizer(&["team-a", "team-b"]);
        assert!(
            !a.allows_namespace(&relay_peer("team-a", AUTHZ_RELAY_SA), "team-b"),
            "an SVID from another namespace must not authorize this namespace"
        );
    }

    #[test]
    fn provenance_authorizer_denies_empty_sans() {
        let a = provenance_authorizer(&["team-a"]);
        assert!(
            !a.allows_namespace(&PeerSvid::default(), "team-a"),
            "an absent PeerSvid (empty SANs) must never be authorized (no fail-open)"
        );
    }

    #[test]
    fn provenance_authorizer_denies_wrong_trust_domain() {
        let a = provenance_authorizer(&["team-a"]);
        let peer = PeerSvid {
            uri_sans: vec![format!(
                "spiffe://evil.example/ns/team-a/sa/{AUTHZ_RELAY_SA}"
            )],
        };
        assert!(
            !a.allows_namespace(&peer, "team-a"),
            "an SVID from a foreign trust domain must be denied"
        );
    }

    #[test]
    fn provenance_authorizer_denies_malformed_uri() {
        let a = provenance_authorizer(&["team-a"]);
        let peer = PeerSvid {
            uri_sans: vec!["not-a-spiffe-uri".to_owned()],
        };
        assert!(
            !a.allows_namespace(&peer, "team-a"),
            "a malformed URI SAN must be denied"
        );
    }

    // ── test harness ─────────────────────────────────────────────────────────

    struct TestHarness {
        addr: SocketAddr,
        registry: SharedNodeRegistry,
        rebuild_tx: watch::Sender<u64>,
        publish: SharedGatewayPublishIndex,
        /// The live routing source the server reads. Tests mutate it via
        /// [`TestHarness::publish_ingress`] to drive deltas.
        source: SnapshotSource,
    }

    impl TestHarness {
        /// Store a new ingress routing world, stamp a publish rebuild, and bump
        /// the rebuild-generation watch — the exact store-then-tick order a real
        /// reconciler uses. The generation bump wakes every connected stream's
        /// rebuild arm; the fresh generation invalidates the shared view cache so
        /// the next materialize sees the new cells.
        fn publish_ingress(&self, table: IngressRoutingTable) {
            self.source.ingress.store(Arc::new(table));
            self.publish.stamp_rebuild(std::iter::empty());
            let next = self.rebuild_tx.borrow().wrapping_add(1);
            self.rebuild_tx
                .send(next)
                .unwrap_or_else(|e| panic!("rebuild watch send: {e}"));
        }
    }

    /// An ingress world: one exact `host` on port 80 routed to a single
    /// endpoint-keyed backend `default/<svc>/80` resolving to `addrs`.
    ///
    /// The keyed ref means the route resource carries only an `endpoint_ref`, not
    /// the addresses — so the route's hash is independent of `addrs`. Changing the
    /// addresses rewrites ONLY the derived `endpoints|default/<svc>/80` resource
    /// (EDS), leaving `route|ingress|80|exact|<host>` byte-identical.
    fn ingress_route(host: &str, svc: &str, addrs: &[&str]) -> IngressRoutingTable {
        let mut b = IngressRoutingTableBuilder::new();
        add_host(&mut b, host, svc, addrs);
        b.build().unwrap_or_else(|e| panic!("ingress build: {e}"))
    }

    /// An ingress world with two exact hosts, each routed to its own service.
    fn ingress_two_routes(
        host_a: &str,
        svc_a: &str,
        addrs_a: &[&str],
        host_b: &str,
        svc_b: &str,
        addrs_b: &[&str],
    ) -> IngressRoutingTable {
        let mut b = IngressRoutingTableBuilder::new();
        add_host(&mut b, host_a, svc_a, addrs_a);
        add_host(&mut b, host_b, svc_b, addrs_b);
        b.build().unwrap_or_else(|e| panic!("ingress build: {e}"))
    }

    /// Add one `host → default/<svc>/80` exact route to `b`. Extracted so the
    /// single- and two-route builders share the exact same backend shape.
    fn add_host(b: &mut IngressRoutingTableBuilder, host: &str, svc: &str, addrs: &[&str]) {
        let parsed: Vec<SocketAddr> = addrs
            .iter()
            .map(|a| a.parse().unwrap_or_else(|e| panic!("addr {a}: {e}")))
            .collect();
        let exists = !parsed.is_empty();
        let resolved = Arc::new(ResolvedEndpoints::new(
            parsed,
            BackendProtocol::default(),
            exists,
        ));
        let bg = Arc::new(BackendGroup::weighted_with_endpoints(
            format!("default/{svc}"),
            vec![(resolved, Some(EndpointKey::new("default", svc, 80)), 1)],
        ));
        let entry = Arc::new(RouteEntry::path_only(bg, "default/r".to_owned(), None));
        b.for_port(80).exact_host(host).add_exact_route("/", entry);
    }

    fn empty_source() -> SnapshotSource {
        SnapshotSource {
            ingress: SharedIngressRoutingTable::new(),
            gateway: SharedGatewayRoutingTable::new(),
            tls: SharedPortTlsStore::new(),
            client_certs: SharedClientCertStore::new(),
            listener_status: SharedGatewayListenerStatus::new(),
            dedicated: DedicatedRoutingRegistry::new(),
            passthrough_routes: coxswain_core::routing::SharedTlsPassthroughTable::new(),
            terminate_routes: coxswain_core::routing::SharedTlsPassthroughTable::new(),
            tcp_routes: coxswain_core::routing::SharedTcpRouteTable::new(),
            udp_routes: coxswain_core::routing::SharedUdpRouteTable::new(),
            publish: SharedGatewayPublishIndex::new(),
        }
    }

    async fn start_harness() -> TestHarness {
        start_harness_with_gate(None).await
    }

    /// Start the harness with the leader gate wired to `leader_rx` (#531).
    async fn start_harness_gated() -> (TestHarness, watch::Sender<bool>) {
        let (leader_tx, leader_rx) = watch::channel(false);
        let h = start_harness_with_gate(Some(leader_rx)).await;
        (h, leader_tx)
    }

    async fn start_harness_with_gate(leader_rx: Option<watch::Receiver<bool>>) -> TestHarness {
        start_harness_with(leader_rx, Arc::new(DenyAllNamespaces)).await
    }

    /// Start the harness with a custom [`ScopeAuthorizer`] installed (#582),
    /// ungated (leadership always granted).
    async fn start_harness_with_authorizer(authorizer: Arc<dyn ScopeAuthorizer>) -> TestHarness {
        start_harness_with(None, authorizer).await
    }

    async fn start_harness_with(
        leader_rx: Option<watch::Receiver<bool>>,
        authorizer: Arc<dyn ScopeAuthorizer>,
    ) -> TestHarness {
        let source = empty_source();
        let registry = SharedNodeRegistry::new();
        let (rebuild_tx, rebuild_rx) = watch::channel(0u64);

        let mut svc = DiscoveryService::new(source.clone(), registry.clone(), rebuild_rx)
            .with_scope_authorizer(authorizer);
        if let Some(rx) = leader_rx {
            svc = svc.with_leader_gate(rx);
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(
            Server::builder()
                .add_service(DiscoveryServer::new(svc))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );

        let publish = source.publish.clone();
        TestHarness {
            addr,
            registry,
            rebuild_tx,
            publish,
            source,
        }
    }

    /// A [`ScopeAuthorizer`] test double that allows every `Namespace` subscribe
    /// — the inverse of the production [`DenyAllNamespaces`] default.
    struct AllowAllNamespaces;

    impl ScopeAuthorizer for AllowAllNamespaces {
        fn allows_namespace(&self, _peer: &PeerSvid, _namespace: &str) -> bool {
            true
        }
    }

    /// Open a raw bidi stream to the test server.
    ///
    /// Subscribe is queued into the channel *before* `grpc.stream()` so it is
    /// available the moment hyper starts polling the request body.  Without this
    /// the server blocks in `read_subscribe` before returning response headers,
    /// while the client blocks in `grpc.stream().await` waiting for those same
    /// headers — a mutual deadlock on the single-threaded test runtime.
    async fn open_stream(
        addr: SocketAddr,
        node_id: &str,
    ) -> (
        tokio::sync::mpsc::Sender<ClientMessage>,
        tonic::Streaming<ServerMessage>,
    ) {
        use crate::proto::v1::discovery_client::DiscoveryClient as TonicClient;
        use tokio_stream::wrappers::ReceiverStream;

        let (tx, rx) = tokio::sync::mpsc::channel::<ClientMessage>(16);

        // Pre-queue Subscribe so the server can unblock read_subscribe() as soon
        // as hyper begins polling the request-body stream.
        tx.send(ClientMessage {
            kind: Some(CKind::Subscribe(p::Subscribe {
                node_id: node_id.to_owned(),
                wire_version: WIRE_VERSION,
                scope: Some(crate::wire::scope_to_wire(
                    &crate::subscription::Scope::SharedPool,
                )),
            })),
        })
        .await
        .unwrap();

        let channel = Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect_lazy();
        let mut grpc = TonicClient::new(channel);
        let response = grpc.stream(ReceiverStream::new(rx)).await.unwrap();
        let inbound = response.into_inner();

        (tx, inbound)
    }

    /// Receive the next `Snapshot` from the stream with a timeout.
    async fn recv_snapshot(inbound: &mut tonic::Streaming<ServerMessage>) -> Snapshot {
        let msg = tokio::time::timeout(Duration::from_secs(2), inbound.message())
            .await
            .expect("timed out waiting for Snapshot")
            .expect("stream error")
            .expect("stream closed");
        match msg.kind {
            Some(SrvKind::Snapshot(s)) => s,
            other => panic!("expected Snapshot, got: {other:?}"),
        }
    }

    /// Send an Ack for a received snapshot.
    async fn send_ack(tx: &tokio::sync::mpsc::Sender<ClientMessage>, snapshot: &Snapshot) {
        tx.send(ClientMessage {
            kind: Some(CKind::Ack(p::Ack {
                version: snapshot.version.clone(),
                nonce: snapshot.nonce.clone(),
            })),
        })
        .await
        .unwrap();
    }

    /// Send a Nack for a received snapshot.
    async fn send_nack(tx: &tokio::sync::mpsc::Sender<ClientMessage>, snapshot: &Snapshot) {
        tx.send(ClientMessage {
            kind: Some(CKind::Nack(p::Nack {
                version: snapshot.version.clone(),
                nonce: snapshot.nonce.clone(),
                detail: "test rejection".to_owned(),
            })),
        })
        .await
        .unwrap();
    }

    /// Poll `pred` until it returns `Some` or the deadline passes.
    async fn poll_until<F, T>(pred: F) -> T
    where
        F: Fn() -> Option<T>,
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(v) = pred() {
                return v;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "poll_until: timed out"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    /// Two clients connect to the same server and both receive a Snapshot with
    /// the same version hash (identical empty routing world).
    #[tokio::test]
    async fn multiple_clients_converge_to_current_snapshot_version() {
        let h = start_harness().await;

        let (tx_a, mut rx_a) = open_stream(h.addr, "node-a").await;
        let (tx_b, mut rx_b) = open_stream(h.addr, "node-b").await;

        let snap_a = recv_snapshot(&mut rx_a).await;
        let snap_b = recv_snapshot(&mut rx_b).await;

        assert_eq!(
            snap_a.version, snap_b.version,
            "both clients must receive the same version hash for an identical world"
        );

        drop(tx_a);
        drop(tx_b);
    }

    /// After a client Acks a version, the registry records it on `last_acked_version`.
    #[tokio::test]
    async fn node_registry_records_last_acked_version_after_ack() {
        let h = start_harness().await;
        let (tx, mut rx) = open_stream(h.addr, "node-registry-test").await;

        let snap = recv_snapshot(&mut rx).await;
        send_ack(&tx, &snap).await;

        let expected_version = snap.version.clone();
        poll_until(|| {
            let reg = h.registry.load();
            let entry = reg.nodes.get("node-registry-test")?;
            (entry.last_acked_version.as_deref() == Some(expected_version.as_str())).then_some(())
        })
        .await;

        drop(tx);
    }

    /// The server does not push a second snapshot until the client Acks the first.
    #[tokio::test]
    async fn server_holds_next_snapshot_until_prior_ack() {
        let h = start_harness().await;
        let (tx, mut rx) = open_stream(h.addr, "node-backpressure").await;

        // Receive initial snapshot but do NOT Ack it.
        let snap1 = recv_snapshot(&mut rx).await;

        // Bump the rebuild channel — the server should coalesce and not push yet.
        h.rebuild_tx.send(1).unwrap();

        // Assert no second snapshot arrives within a short window.
        let no_snap = tokio::time::timeout(Duration::from_millis(100), rx.message()).await;
        assert!(
            no_snap.is_err(),
            "server must not push a second snapshot before the first is Ack'd"
        );

        // Now Ack the first snapshot.
        send_ack(&tx, &snap1).await;

        // Trigger another rebuild to ensure the second snapshot is pushed.
        h.rebuild_tx.send(2).unwrap();

        // The second snapshot should now arrive (version may differ from snap1
        // only if the world changed; in this test the world is the same so the
        // server must not push at all after the Ack).
        // Since versions are equal, no push happens. Verify via the timeout again.
        let no_snap2 = tokio::time::timeout(Duration::from_millis(100), rx.message()).await;
        assert!(
            no_snap2.is_err(),
            "server must not push when version matches last Ack'd"
        );

        drop(tx);
    }

    /// A Subscribe with a wrong wire version causes the stream to close with a
    /// `FAILED_PRECONDITION` status.
    #[tokio::test]
    async fn wire_version_mismatch_closes_stream() {
        use crate::proto::v1::discovery_client::DiscoveryClient as TonicClient;
        use tokio_stream::wrappers::ReceiverStream;

        let h = start_harness().await;

        let (tx, rx) = tokio::sync::mpsc::channel::<ClientMessage>(16);

        // Pre-queue the wrong-version Subscribe (same deadlock avoidance as open_stream).
        tx.send(ClientMessage {
            kind: Some(CKind::Subscribe(p::Subscribe {
                node_id: "bad-node".to_owned(),
                wire_version: 99, // intentionally wrong; server should reject
                scope: Some(crate::wire::scope_to_wire(
                    &crate::subscription::Scope::SharedPool,
                )),
            })),
        })
        .await
        .unwrap();

        let channel = Endpoint::from_shared(format!("http://{}", h.addr))
            .unwrap()
            .connect_lazy();
        let mut grpc = TonicClient::new(channel);

        // The server rejects in the handler before sending response headers, so
        // grpc.stream().await returns Err(Status) directly (not via inbound.message()).
        let result = grpc.stream(ReceiverStream::new(rx)).await;
        assert!(
            result.is_err(),
            "stream() must fail with FAILED_PRECONDITION on wire-version mismatch"
        );
        let status = result.unwrap_err();
        assert_eq!(
            status.code(),
            tonic::Code::FailedPrecondition,
            "expected FAILED_PRECONDITION, got: {status}"
        );

        drop(tx);
    }

    /// A Nack causes the server to send a fresh `full = true` resync of the
    /// current world with a new nonce (#383) — not a same-payload retransmit. The
    /// client's baseline is untrustworthy after a Nack, so a full re-establishes
    /// it. (The empty world's version is unchanged here, but that is incidental —
    /// the contract is `full = true`, not version equality.)
    #[tokio::test]
    async fn nack_triggers_full_resync() {
        let h = start_harness().await;
        let (tx, mut rx) = open_stream(h.addr, "node-nack").await;

        let snap1 = recv_snapshot(&mut rx).await;
        send_nack(&tx, &snap1).await;

        let snap2 = recv_snapshot(&mut rx).await;
        assert!(
            snap2.full,
            "a Nack must be answered with a full resync, not a delta"
        );
        assert!(
            snap2.removed_resources.is_empty(),
            "a full resync carries no tombstones"
        );
        assert_ne!(
            snap1.nonce, snap2.nonce,
            "the resync must use a fresh nonce"
        );

        drop(tx);
    }

    /// When the client drops the stream, the node is removed from the registry.
    #[tokio::test]
    async fn client_disconnect_removes_node_from_registry() {
        let h = start_harness().await;
        let (tx, mut rx) = open_stream(h.addr, "node-disconnect").await;

        // Receive initial snapshot so the node is registered.
        let _ = recv_snapshot(&mut rx).await;

        poll_until(|| {
            h.registry
                .load()
                .nodes
                .contains_key("node-disconnect")
                .then_some(())
        })
        .await;

        // Drop the client.
        drop(tx);
        drop(rx);

        // Poll until the node is removed.
        poll_until(|| (!h.registry.load().nodes.contains_key("node-disconnect")).then_some(()))
            .await;
    }

    // ── scope validation (#427) ───────────────────────────────────────────────

    /// Open a stream using a custom `Subscribe` message (not the helpers).
    ///
    /// Returns `Err(Status)` when the server rejects the Subscribe synchronously,
    /// `Ok((tx, inbound))` otherwise.
    async fn open_stream_with_subscribe(
        addr: SocketAddr,
        subscribe: p::Subscribe,
    ) -> Result<
        (
            tokio::sync::mpsc::Sender<ClientMessage>,
            tonic::Streaming<ServerMessage>,
        ),
        tonic::Status,
    > {
        use crate::proto::v1::discovery_client::DiscoveryClient as TonicClient;
        use tokio_stream::wrappers::ReceiverStream;

        let (tx, rx) = tokio::sync::mpsc::channel::<ClientMessage>(16);
        tx.send(ClientMessage {
            kind: Some(CKind::Subscribe(subscribe)),
        })
        .await
        .unwrap_or_else(|e| panic!("invariant: pre-send channel is open: {e}"));

        let channel = Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect_lazy();
        let mut grpc = TonicClient::new(channel);
        let response = grpc.stream(ReceiverStream::new(rx)).await?;
        Ok((tx, response.into_inner()))
    }

    #[tokio::test]
    async fn empty_scope_discriminator_returns_invalid_argument() {
        // A `Scope {}` with `kind == None` must be rejected immediately with
        // INVALID_ARGUMENT — it must not silently promote to SharedPool.
        let h = start_harness().await;
        let err = open_stream_with_subscribe(
            h.addr,
            p::Subscribe {
                node_id: "bad-scope-node".to_owned(),
                wire_version: WIRE_VERSION,
                scope: Some(p::Scope { kind: None }),
            },
        )
        .await
        .expect_err("subscribe with empty scope must be rejected");

        assert_eq!(err.code(), tonic::Code::InvalidArgument, "got: {err:?}",);
    }

    #[tokio::test]
    async fn gateway_scope_without_peer_svid_skips_check() {
        // On the plaintext path no PeerSvid is injected, so the binding check is
        // skipped and the stream opens normally. This is the fail-open path for
        // test/degraded-mode connections where mTLS is not established.
        let h = start_harness().await;
        let (tx, mut inbound) = open_stream_with_subscribe(
            h.addr,
            p::Subscribe {
                node_id: "plaintext-gateway-node".to_owned(),
                wire_version: WIRE_VERSION,
                scope: Some(crate::wire::scope_to_wire(
                    &crate::subscription::Scope::Gateway {
                        name: "some-gw".to_owned(),
                        namespace: "prod".to_owned(),
                    },
                )),
            },
        )
        .await
        .expect("plaintext Gateway scope must be accepted when no PeerSvid is present");

        // Should receive a snapshot (empty since no dedicated entry, but the
        // stream opened — the check was skipped, not denied).
        let snap = recv_snapshot(&mut inbound).await;
        assert!(snap.full, "the first message of a session is always a full");
        assert!(
            snap.resources.is_empty(),
            "no dedicated entry → empty gateway snapshot"
        );
        drop(tx);
    }

    // ── publish-sequence ack recording (#531) ─────────────────────────────────

    /// Acking a fail-closed EMPTY dedicated snapshot (no registry entry for
    /// the Gateway) must NOT advance the node's convergence stamp — a real
    /// sequence there would let the ack gate certify content the node never
    /// received (the pre-cutover / identity-mismatch worlds are deliberately
    /// empty).
    #[tokio::test]
    async fn ack_of_fail_closed_empty_dedicated_snapshot_does_not_advance_seq() {
        let h = start_harness().await;
        // Sequence is non-zero, so a leaked capture would be observable.
        h.publish.stamp_rebuild(std::iter::empty());

        let (tx, mut inbound) = open_stream_with_subscribe(
            h.addr,
            p::Subscribe {
                node_id: "ded-node".to_owned(),
                wire_version: WIRE_VERSION,
                scope: Some(crate::wire::scope_to_wire(
                    &crate::subscription::Scope::Gateway {
                        name: "some-gw".to_owned(),
                        namespace: "prod".to_owned(),
                    },
                )),
            },
        )
        .await
        .expect("gateway scope accepted");
        let snap = recv_snapshot(&mut inbound).await;
        send_ack(&tx, &snap).await;

        // The ack lands (version recorded) but the seq stamp stays at 0.
        let entry = poll_until(|| {
            let reg = h.registry.load();
            let e = reg.nodes.get("ded-node")?;
            e.last_acked_version.is_some().then(|| e.clone())
        })
        .await;
        assert_eq!(
            entry.last_acked_seq,
            Some(0),
            "fail-closed empty snapshot must record seq 0, not the live capture"
        );
        drop(tx);
    }

    /// An Ack records the publish sequence captured before the snapshot was
    /// built, and a rebuild that produces identical content (no push) still
    /// advances the node's acked sequence — the quiet-cluster liveness path.
    #[tokio::test]
    async fn ack_records_publish_seq_and_no_push_rebuild_advances_it() {
        let h = start_harness().await;
        // One stamped rebuild before the client connects: sequence becomes 1.
        h.publish.stamp_rebuild(std::iter::empty());

        let (tx, mut inbound) = open_stream(h.addr, "node-1").await;
        let initial = recv_snapshot(&mut inbound).await;
        send_ack(&tx, &initial).await;
        poll_until(|| {
            h.registry
                .load()
                .nodes
                .get("node-1")
                .and_then(|e| e.last_acked_seq)
                .filter(|s| *s >= 1)
        })
        .await;

        // Advance the sequence with NO content change, then tick the rebuild
        // watch: the server's no-push branch must advance the acked seq.
        h.publish.stamp_rebuild(std::iter::empty());
        h.rebuild_tx.send(1).unwrap();
        poll_until(|| {
            h.registry
                .load()
                .nodes
                .get("node-1")
                .and_then(|e| e.last_acked_seq)
                .filter(|s| *s >= 2)
        })
        .await;
        drop(tx);
    }

    // ── NodeStatus bound-port reports (#531) ──────────────────────────────────

    #[tokio::test]
    async fn node_status_updates_registry_bound_ports() {
        let h = start_harness().await;
        let (tx, mut inbound) = open_stream(h.addr, "node-1").await;
        let _initial = recv_snapshot(&mut inbound).await;

        tx.send(ClientMessage {
            kind: Some(CKind::NodeStatus(p::NodeStatus {
                bound_ports: vec![30001, 30002],
            })),
        })
        .await
        .unwrap();

        let bound = poll_until(|| {
            h.registry
                .load()
                .nodes
                .get("node-1")
                .and_then(|e| e.bound_ports.clone())
        })
        .await;
        assert_eq!(bound, [30001u16, 30002].into_iter().collect());
        assert!(
            h.registry
                .load()
                .all_shared_nodes_bound(&[30001u16].into_iter().collect()),
            "shared quorum must pass once the only connected node reports a superset"
        );
        drop(tx);
    }

    #[tokio::test]
    async fn node_status_out_of_range_ports_are_dropped_not_fatal() {
        let h = start_harness().await;
        let (tx, mut inbound) = open_stream(h.addr, "node-1").await;
        let initial = recv_snapshot(&mut inbound).await;

        tx.send(ClientMessage {
            kind: Some(CKind::NodeStatus(p::NodeStatus {
                bound_ports: vec![30001, 70000], // 70000 exceeds u16
            })),
        })
        .await
        .unwrap();

        let bound = poll_until(|| {
            h.registry
                .load()
                .nodes
                .get("node-1")
                .and_then(|e| e.bound_ports.clone())
        })
        .await;
        assert_eq!(
            bound,
            [30001u16].into_iter().collect(),
            "the oversized value is dropped; the in-range port still lands"
        );

        // The stream must remain healthy after the malformed report: Ack the
        // initial, publish a real routing change, and confirm the delta still
        // reaches this node.
        send_ack(&tx, &initial).await;
        h.publish_ingress(ingress_route("example.com", "svc-a", &["10.0.0.1:80"]));
        let next = recv_snapshot(&mut inbound).await;
        assert!(!next.full, "steady-state change ships as a delta");
        drop(tx);
    }

    #[tokio::test]
    async fn disconnect_clears_bound_ports_from_registry() {
        let h = start_harness().await;
        let (tx, mut inbound) = open_stream(h.addr, "node-1").await;
        let _initial = recv_snapshot(&mut inbound).await;

        tx.send(ClientMessage {
            kind: Some(CKind::NodeStatus(p::NodeStatus {
                bound_ports: vec![30001],
            })),
        })
        .await
        .unwrap();
        poll_until(|| {
            h.registry
                .load()
                .all_shared_nodes_bound(&[30001u16].into_iter().collect())
                .then_some(())
        })
        .await;

        // Close the stream; the registry row must go with it (fail closed).
        drop(tx);
        drop(inbound);
        poll_until(|| h.registry.load().nodes.is_empty().then_some(())).await;
        assert!(
            !h.registry
                .load()
                .all_shared_nodes_bound(&[30001u16].into_iter().collect()),
            "an empty registry must fail the quorum closed"
        );
    }

    // ── leader-gated Stream RPC (#531) ─────────────────────────────────────────

    #[test]
    fn not_leader_message_carries_the_client_needle() {
        assert!(
            NOT_LEADER_MSG.contains(NOT_LEADER_NEEDLE),
            "client::is_not_leader matches on the needle; a reworded NOT_LEADER_MSG \
             that drops it silently breaks fast-retry across the whole proxy fleet"
        );
    }

    #[tokio::test]
    async fn stream_rejected_with_failed_precondition_when_not_leader() {
        // Gate starts `false`: a replica accepts no streams until its first
        // promotion, so a freshly-started standby can never collect Acks.
        let (h, leader_tx) = start_harness_gated().await;
        let err = open_stream_with_subscribe(
            h.addr,
            p::Subscribe {
                node_id: "standby-dialer".to_owned(),
                wire_version: WIRE_VERSION,
                scope: Some(crate::wire::scope_to_wire(
                    &crate::subscription::Scope::SharedPool,
                )),
            },
        )
        .await
        .expect_err("a non-leader replica must reject the stream at accept");

        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "got: {err:?}");
        assert!(
            err.message().contains("not the leader"),
            "the rejection must carry the client-matchable phrase, got: {}",
            err.message()
        );
        assert!(
            h.registry.load().nodes.is_empty(),
            "a rejected stream must not register a node"
        );
        drop(leader_tx);
    }

    #[tokio::test]
    async fn stream_accepted_after_promotion_and_terminated_on_demotion() {
        let (h, leader_tx) = start_harness_gated().await;
        leader_tx.send(true).unwrap();

        let (tx, mut inbound) = open_stream(h.addr, "node-1").await;
        let _initial = recv_snapshot(&mut inbound).await;
        assert!(
            h.registry.load().nodes.contains_key("node-1"),
            "leader must accept and register the stream"
        );

        // Demotion must terminate the live stream with the not-leader status
        // so the proxy fast-retries toward the new leader…
        leader_tx.send(false).unwrap();
        let end = tokio::time::timeout(Duration::from_secs(2), inbound.message())
            .await
            .expect("timed out waiting for demotion to terminate the stream");
        match end {
            Err(status) => {
                assert_eq!(status.code(), tonic::Code::FailedPrecondition);
                assert!(
                    status.message().contains("not the leader"),
                    "got: {}",
                    status.message()
                );
            }
            Ok(other) => panic!("expected not-leader stream termination, got: {other:?}"),
        }

        // …and clear the registry row (readiness fails closed on the demoted
        // replica).
        poll_until(|| h.registry.load().nodes.is_empty().then_some(())).await;
        drop(tx);
    }

    // ── scope-aware snapshot dispatch (#426) ──────────────────────────────────

    /// Build a `SnapshotSource` whose dedicated registry holds one entry for
    /// `key`, with a listener status map keyed by that same `ObjectKey`.  The
    /// shared cells stay empty, so a SharedPool snapshot and a Gateway snapshot
    /// are trivially distinguishable by their `listener_status` entry count.
    fn source_with_dedicated_entry(key: &ObjectKey) -> SnapshotSource {
        let source = empty_source();
        let mut lh = HashMap::new();
        lh.insert(key.clone(), GatewayListenerStatus::default());
        let snap = Arc::new(DedicatedRoutingSnapshot {
            gateway: Arc::new(GatewayRoutingTable::default()),
            tls: Arc::new(PortTlsStore::default()),
            client_certs: Arc::new(ClientCertStore::default()),
            listener_status: lh,
            // Test value; scope-binding tests in tests/scope_binding.rs set the
            // real expected_proxy_sa and exercise the matching logic end-to-end.
            expected_proxy_sa: format!("{}-coxswain", key.name),
        });
        let mut map = HashMap::new();
        map.insert(key.clone(), snap);
        source.dedicated.store(Arc::new(map));
        source
    }

    #[test]
    fn gateway_scope_serves_only_its_own_registry_entry() {
        let key = ObjectKey::new("prod".to_owned(), "gw-a".to_owned());
        let source = source_with_dedicated_entry(&key);

        let view = materialize(
            &source,
            &Scope::Gateway {
                name: "gw-a".to_owned(),
                namespace: "prod".to_owned(),
            },
            // No peer SVID in plaintext unit tests; SVID binding is exercised in
            // tests/scope_binding.rs over real TLS.
            None,
        );

        let listener_keys: Vec<&String> = view
            .resources
            .keys()
            .filter(|k| k.starts_with("listener|"))
            .collect();
        assert_eq!(
            listener_keys.len(),
            1,
            "Gateway scope must serve exactly its own listener-status resource"
        );
        assert_eq!(
            listener_keys[0],
            &format!("listener|{key}"),
            "the served entry must be the subscribing Gateway's"
        );
        assert!(
            !view
                .resources
                .keys()
                .any(|k| k.starts_with("route|ingress|")),
            "a dedicated proxy never receives Ingress routes"
        );
    }

    #[test]
    fn gateway_scope_absent_entry_is_fully_empty() {
        // Registry holds gw-a, but a proxy for gw-b subscribes.
        let present = ObjectKey::new("prod".to_owned(), "gw-a".to_owned());
        let source = source_with_dedicated_entry(&present);

        let view = materialize(
            &source,
            &Scope::Gateway {
                name: "gw-b".to_owned(),
                namespace: "prod".to_owned(),
            },
            None,
        );

        assert!(
            view.resources.is_empty(),
            "fail-closed: an absent Gateway receives no resources, not another scope's"
        );
    }

    #[test]
    fn shared_scope_ignores_dedicated_registry() {
        // A cut-over Gateway sits in the dedicated registry; the shared pool
        // must not pick it up (the shared cells deliberately exclude it).
        let key = ObjectKey::new("prod".to_owned(), "gw-a".to_owned());
        let source = source_with_dedicated_entry(&key);

        let view = materialize(&source, &Scope::SharedPool, None);

        assert!(
            view.resources.is_empty(),
            "SharedPool reads the shared cells (empty here), never the dedicated registry"
        );
    }

    // ── per-stream delta engine (#383) ────────────────────────────────────────

    use crate::bench_internals::snapshot_version;
    use crate::wire::resource::canonical_key;

    /// Canonical keys of a snapshot's upsert resources whose key starts with
    /// `prefix`.
    fn upsert_keys_with(snap: &Snapshot, prefix: &str) -> Vec<String> {
        snap.resources
            .iter()
            .filter_map(|r| canonical_key(r).ok())
            .filter(|k| k.starts_with(prefix))
            .collect()
    }

    /// The `addrs` of every `EndpointResource` upsert in a snapshot.
    fn endpoint_addrs(snap: &Snapshot) -> Vec<Vec<String>> {
        snap.resources
            .iter()
            .filter_map(|r| match &r.payload {
                Some(p::resource::Payload::Endpoints(e)) => Some(e.addrs.clone()),
                _ => None,
            })
            .collect()
    }

    /// Apply one snapshot (full or delta) into a plain key→resource world, then
    /// assert the recomputed global hash equals the message's `version` — the
    /// replay oracle for protocol invariant 2 (delta version = POST-APPLY world
    /// hash). Mirrors what the real client's version self-check enforces.
    fn apply_and_check(world: &mut BTreeMap<String, p::Resource>, snap: &Snapshot) {
        if snap.full {
            world.clear();
        }
        for key in &snap.removed_resources {
            world.remove(key);
        }
        for r in &snap.resources {
            let key = canonical_key(r).unwrap_or_else(|e| panic!("upsert is keyable: {e:?}"));
            world.insert(key, r.clone());
        }
        let resources: Vec<p::Resource> = world.values().cloned().collect();
        assert_eq!(
            snapshot_version(&resources),
            snap.version,
            "recomputed global hash must equal the message version (invariant 2)"
        );
    }

    /// Assert no further server message arrives within a short settle window.
    async fn assert_no_more(inbound: &mut tonic::Streaming<ServerMessage>) {
        let extra = tokio::time::timeout(Duration::from_millis(200), inbound.message()).await;
        assert!(extra.is_err(), "unexpected extra server message: {extra:?}");
    }

    /// The first message is a full snapshot whose `version` is the hash of its
    /// sorted per-resource hashes (invariant 1 + oracle).
    #[tokio::test]
    async fn initial_message_is_full_with_hash_version() {
        let h = start_harness().await;
        h.publish_ingress(ingress_route("example.com", "svc-a", &["10.0.0.1:80"]));
        let (tx, mut rx) = open_stream(h.addr, "node-1").await;

        let snap = recv_snapshot(&mut rx).await;
        assert!(snap.full, "first message must be full");
        assert!(
            snap.removed_resources.is_empty(),
            "a full carries no tombstones"
        );
        assert_eq!(
            snap.version,
            snapshot_version(&snap.resources),
            "full version = hash over its sorted resource hashes"
        );
        assert_eq!(
            upsert_keys_with(&snap, "route|ingress|80|exact|example.com").len(),
            1,
            "the route resource rides the full"
        );
        assert_eq!(
            upsert_keys_with(&snap, "endpoints|default/svc-a/80").len(),
            1,
            "the derived endpoint resource rides the full"
        );
        drop(tx);
    }

    /// An endpoint-only change ships a delta carrying exactly the changed
    /// `endpoints|…` upsert and nothing else — the route bytes are untouched (EDS).
    #[tokio::test]
    async fn endpoint_change_yields_endpoint_only_delta() {
        let h = start_harness().await;
        h.publish_ingress(ingress_route("example.com", "svc-a", &["10.0.0.1:80"]));
        let (tx, mut rx) = open_stream(h.addr, "node-1").await;
        let initial = recv_snapshot(&mut rx).await;
        send_ack(&tx, &initial).await;

        // Same route, different endpoint addresses.
        h.publish_ingress(ingress_route("example.com", "svc-a", &["10.0.0.9:80"]));
        let delta = recv_snapshot(&mut rx).await;

        assert!(!delta.full, "a steady-state change is a delta");
        assert!(delta.removed_resources.is_empty(), "nothing was removed");
        assert_eq!(delta.resources.len(), 1, "exactly one resource changed");
        assert_eq!(
            upsert_keys_with(&delta, "endpoints|default/svc-a/80").len(),
            1,
            "only the endpoint resource changed"
        );
        assert!(
            upsert_keys_with(&delta, "route|").is_empty(),
            "the route bytes are independent of endpoint addrs"
        );
        assert_eq!(endpoint_addrs(&delta), vec![vec!["10.0.0.9:80".to_owned()]]);
        drop(tx);
    }

    /// Adding a host ships a delta carrying exactly that new `route|…` upsert; a
    /// route sharing the existing service adds no new endpoint resource.
    #[tokio::test]
    async fn host_added_yields_route_only_delta() {
        let h = start_harness().await;
        h.publish_ingress(ingress_route("a.example.com", "svc-a", &["10.0.0.1:80"]));
        let (tx, mut rx) = open_stream(h.addr, "node-1").await;
        let initial = recv_snapshot(&mut rx).await;
        send_ack(&tx, &initial).await;

        // Add host b, same service (so no new endpoint resource).
        h.publish_ingress(ingress_two_routes(
            "a.example.com",
            "svc-a",
            &["10.0.0.1:80"],
            "b.example.com",
            "svc-a",
            &["10.0.0.1:80"],
        ));
        let delta = recv_snapshot(&mut rx).await;

        assert!(!delta.full);
        assert!(delta.removed_resources.is_empty());
        assert_eq!(delta.resources.len(), 1, "only the new host's route");
        assert_eq!(
            upsert_keys_with(&delta, "route|ingress|80|exact|b.example.com").len(),
            1
        );
        drop(tx);
    }

    /// Removing a host ships a delta carrying exactly that route tombstone; the
    /// endpoint stays (another host still references it), so it is NOT tombstoned.
    #[tokio::test]
    async fn host_removed_yields_tombstone_only() {
        let h = start_harness().await;
        h.publish_ingress(ingress_two_routes(
            "a.example.com",
            "svc-a",
            &["10.0.0.1:80"],
            "b.example.com",
            "svc-a",
            &["10.0.0.1:80"],
        ));
        let (tx, mut rx) = open_stream(h.addr, "node-1").await;
        let initial = recv_snapshot(&mut rx).await;
        send_ack(&tx, &initial).await;

        // Drop host b; host a still references svc-a.
        h.publish_ingress(ingress_route("a.example.com", "svc-a", &["10.0.0.1:80"]));
        let delta = recv_snapshot(&mut rx).await;

        assert!(!delta.full);
        assert!(delta.resources.is_empty(), "nothing upserted");
        assert_eq!(
            delta.removed_resources,
            vec!["route|ingress|80|exact|b.example.com".to_owned()],
            "only host b's route is tombstoned; svc-a's endpoint survives"
        );
        drop(tx);
    }

    /// Contract 5 (referential integrity): switching a host's backend from svc-x
    /// to svc-y tombstones svc-x's endpoint AND ships svc-y's endpoint AND the
    /// rewritten route ALL in the same message; upsert/remove key sets are
    /// disjoint (contract 3).
    #[tokio::test]
    async fn last_referrer_removal_tombstones_endpoint_in_same_message() {
        let h = start_harness().await;
        h.publish_ingress(ingress_route("a.example.com", "svc-x", &["10.0.0.1:80"]));
        let (tx, mut rx) = open_stream(h.addr, "node-1").await;
        let initial = recv_snapshot(&mut rx).await;
        send_ack(&tx, &initial).await;

        // Repoint host a from svc-x to svc-y (svc-x loses its last referrer).
        h.publish_ingress(ingress_route("a.example.com", "svc-y", &["10.0.0.2:80"]));
        let delta = recv_snapshot(&mut rx).await;

        assert!(!delta.full);
        // svc-x tombstoned the moment its last referrer left.
        assert_eq!(
            delta.removed_resources,
            vec!["endpoints|default/svc-x/80".to_owned()],
            "the no-longer-referenced endpoint is tombstoned in this message"
        );
        // The rewritten route AND the newly-referenced endpoint ship together.
        assert_eq!(
            upsert_keys_with(&delta, "route|ingress|80|exact|a.example.com").len(),
            1,
            "the route's ref changed (svc-x → svc-y), so its bytes moved"
        );
        assert_eq!(
            upsert_keys_with(&delta, "endpoints|default/svc-y/80").len(),
            1,
            "the newly-referenced endpoint ships in the same message"
        );
        // Contract 3: the key sets are disjoint.
        let upserts: std::collections::HashSet<String> = delta
            .resources
            .iter()
            .filter_map(|r| canonical_key(r).ok())
            .collect();
        for removed in &delta.removed_resources {
            assert!(
                !upserts.contains(removed),
                "upsert/remove key sets must be disjoint: {removed}"
            );
        }
        drop(tx);
    }

    /// Coalescing: two endpoint swaps while the initial is un-Acked collapse into
    /// ONE delta after the Ack, carrying only the LATEST world (baseline → latest).
    #[tokio::test]
    async fn coalesced_delta_spans_baseline_to_latest() {
        let h = start_harness().await;
        h.publish_ingress(ingress_route("example.com", "svc-a", &["10.0.0.1:80"]));
        let (tx, mut rx) = open_stream(h.addr, "node-1").await;
        let initial = recv_snapshot(&mut rx).await;

        // Two swaps while the initial is still in-flight (un-Acked): both coalesce.
        h.publish_ingress(ingress_route("example.com", "svc-a", &["10.0.0.2:80"]));
        h.publish_ingress(ingress_route("example.com", "svc-a", &["10.0.0.3:80"]));

        // Ack the initial: the server reads the current world once and sends a
        // single delta straight to the latest (skipping the intermediate).
        send_ack(&tx, &initial).await;
        let delta = recv_snapshot(&mut rx).await;

        assert!(!delta.full);
        assert_eq!(
            endpoint_addrs(&delta),
            vec![vec!["10.0.0.3:80".to_owned()]],
            "the coalesced delta carries the latest world, not the intermediate"
        );
        assert!(
            upsert_keys_with(&delta, "route|").is_empty(),
            "only the endpoint moved across the coalesced swaps"
        );
        assert_no_more(&mut rx).await;
        drop(tx);
    }

    /// A stale Ack (version mismatch) neither promotes the baseline nor clears the
    /// in-flight snapshot: a rebuild still coalesces, and the subsequent delta —
    /// after the honest Ack — diffs the correct (honest) baseline.
    #[tokio::test]
    async fn stale_ack_does_not_promote_or_clear_in_flight() {
        let h = start_harness().await;
        h.publish_ingress(ingress_route("example.com", "svc-a", &["10.0.0.1:80"]));
        let (tx, mut rx) = open_stream(h.addr, "node-1").await;
        let initial = recv_snapshot(&mut rx).await;

        // Stale/duplicate Ack for a version we never sent, while the initial is
        // still in-flight: must NOT promote (no baseline) and must NOT clear
        // in-flight.
        tx.send(ClientMessage {
            kind: Some(CKind::Ack(p::Ack {
                version: "bogus".to_owned(),
                nonce: vec![],
            })),
        })
        .await
        .unwrap();

        // A rebuild now must coalesce (the initial is still in-flight): no push.
        h.publish_ingress(ingress_route("example.com", "svc-a", &["10.0.0.2:80"]));
        assert_no_more(&mut rx).await;

        // The honest Ack of the initial promotes the baseline; the delta then
        // diffs THAT baseline and reflects the latest world.
        send_ack(&tx, &initial).await;
        let delta = recv_snapshot(&mut rx).await;
        assert!(!delta.full);
        assert_eq!(endpoint_addrs(&delta), vec![vec!["10.0.0.2:80".to_owned()]]);
        drop(tx);
    }

    /// A reconnect is a fresh session: the per-stream baseline is not portable, so
    /// the first message on the new stream is a full (invariant 1).
    #[tokio::test]
    async fn reconnect_sends_full() {
        let h = start_harness().await;
        h.publish_ingress(ingress_route("example.com", "svc-a", &["10.0.0.1:80"]));

        let (tx1, mut rx1) = open_stream(h.addr, "node-1").await;
        let first = recv_snapshot(&mut rx1).await;
        assert!(first.full);
        send_ack(&tx1, &first).await;
        drop(tx1);
        drop(rx1);

        // Reconnect (fresh stream): must re-send a full despite an identical world.
        let (tx2, mut rx2) = open_stream(h.addr, "node-1").await;
        let second = recv_snapshot(&mut rx2).await;
        assert!(
            second.full,
            "a reconnect starts a fresh session → full resync"
        );
        drop(tx2);
    }

    /// Replay oracle: a full followed by N deltas, applied into a plain world,
    /// reproduces each message's `version` as the POST-APPLY global hash — the
    /// end-to-end proof that the server's delta stream is self-consistent.
    #[tokio::test]
    async fn replay_full_then_deltas_reproduces_versions() {
        let h = start_harness().await;
        let mut world: BTreeMap<String, p::Resource> = BTreeMap::new();

        h.publish_ingress(ingress_route("a.example.com", "svc-a", &["10.0.0.1:80"]));
        let (tx, mut rx) = open_stream(h.addr, "node-1").await;
        let full = recv_snapshot(&mut rx).await;
        assert!(full.full);
        apply_and_check(&mut world, &full);
        send_ack(&tx, &full).await;

        // Delta 1: add a second host on a new service.
        h.publish_ingress(ingress_two_routes(
            "a.example.com",
            "svc-a",
            &["10.0.0.1:80"],
            "b.example.com",
            "svc-b",
            &["10.0.0.2:80"],
        ));
        let d1 = recv_snapshot(&mut rx).await;
        apply_and_check(&mut world, &d1);
        send_ack(&tx, &d1).await;

        // Delta 2: drop host b (route + endpoint tombstones).
        h.publish_ingress(ingress_route("a.example.com", "svc-a", &["10.0.0.1:80"]));
        let d2 = recv_snapshot(&mut rx).await;
        apply_and_check(&mut world, &d2);
        send_ack(&tx, &d2).await;

        // Delta 3: endpoint-only churn on the surviving route.
        h.publish_ingress(ingress_route("a.example.com", "svc-a", &["10.0.0.9:80"]));
        let d3 = recv_snapshot(&mut rx).await;
        apply_and_check(&mut world, &d3);
        drop(tx);
    }

    // ── #582: Namespace scope authorization ─────────────────────────────────

    fn namespace_subscribe(node_id: &str, namespace: &str) -> p::Subscribe {
        p::Subscribe {
            node_id: node_id.to_owned(),
            wire_version: WIRE_VERSION,
            scope: Some(crate::wire::scope_to_wire(
                &crate::subscription::Scope::Namespace {
                    namespace: namespace.to_owned(),
                },
            )),
        }
    }

    /// The default [`DenyAllNamespaces`] authorizer rejects a `Namespace`
    /// subscribe with `PERMISSION_DENIED`, even on the plaintext (no PeerSvid)
    /// test path — unlike the Gateway binding check, this must NOT fail-open.
    #[tokio::test]
    async fn namespace_subscribe_denied_by_default() {
        let h = start_harness().await;
        let err = open_stream_with_subscribe(h.addr, namespace_subscribe("relay-1", "prod"))
            .await
            .expect_err("Namespace subscribe must be denied by the default authorizer");
        assert_eq!(err.code(), tonic::Code::PermissionDenied, "got: {err:?}");
    }

    /// A [`ScopeAuthorizer`] that allows the namespace lets the subscribe open
    /// and receive a snapshot — proves the seam is wired end-to-end, not just
    /// deny-by-default.
    #[tokio::test]
    async fn namespace_subscribe_allowed_by_stub_authorizer() {
        let h = start_harness_with_authorizer(Arc::new(AllowAllNamespaces)).await;
        let (tx, mut rx) =
            open_stream_with_subscribe(h.addr, namespace_subscribe("relay-1", "prod"))
                .await
                .expect("Namespace subscribe must be accepted by an allowing authorizer");
        let snap = recv_snapshot(&mut rx).await;
        assert!(snap.full, "first message of a session is always a full");
        drop(tx);
    }

    /// `SharedPool`/`Gateway` subscribes are unaffected by the `ScopeAuthorizer`
    /// seam — the default deny-all authorizer only gates `Namespace`.
    #[tokio::test]
    async fn shared_pool_subscribe_unaffected_by_namespace_authorizer() {
        let h = start_harness().await;
        let (tx, mut rx) = open_stream(h.addr, "node-shared").await;
        let snap = recv_snapshot(&mut rx).await;
        assert!(snap.full);
        drop(tx);
    }

    /// The **real** `ProvisionedRelayAuthorizer` (not a stub) wired into the
    /// server fail-closes: even for a namespace that IS provisioned, an
    /// unauthenticated (empty-SAN, plaintext-path) peer is rejected
    /// `PERMISSION_DENIED`. This proves the composition #584 relies on — the
    /// authorizer that denies empty SANs is actually the one the server calls.
    /// The full identity allow/deny matrix is unit-tested on the authorizer
    /// itself; the authorized case is exercised end-to-end (real mTLS) by the
    /// provisioning e2e.
    #[tokio::test]
    async fn provenance_authorizer_denies_unauthenticated_namespace_subscribe() {
        let provisioned = Shared::from_value(HashSet::from(["prod".to_owned()]));
        let authz = Arc::new(ProvisionedRelayAuthorizer::new(
            provisioned,
            "coxswain-relay",
            "cluster.local",
        ));
        let h = start_harness_with_authorizer(authz).await;
        let err = open_stream_with_subscribe(h.addr, namespace_subscribe("relay-1", "prod"))
            .await
            .expect_err(
                "the real ProvisionedRelayAuthorizer must deny an unauthenticated Namespace subscribe",
            );
        assert_eq!(err.code(), tonic::Code::PermissionDenied, "got: {err:?}");
    }
}
