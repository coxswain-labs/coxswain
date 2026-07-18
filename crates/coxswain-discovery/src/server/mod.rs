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
//! Each stream task calls [`NodeRegistryHandle::connect`] on entry and
//! [`NodeRegistryHandle::disconnect`] on exit, recording every Ack — and every
//! `NodeStatus` bound-port report (#531) — in between. The registry is read by
//! the admin UI convergence panel (T8) and by the controller's Gateway
//! `Programmed` readiness gate (#531).

use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use coxswain_core::node_registry::NodeRegistryHandle;
use coxswain_core::ownership::ObjectKey;

use crate::auth::{PeerSvid, svid_matches_dedicated_gateway};
use crate::bootstrap_server::UpstreamResolverConfig;
use crate::proto::v1::{self as p, discovery_server::Discovery};
use crate::subscription::Scope;
use crate::version::WIRE_VERSION;
use crate::wire::scope_from_wire;

mod authz;
mod source;
mod stream;
mod view_cache;

pub use authz::{DenyAllNamespaces, ProvisionedRelayAuthorizer, ScopeAuthorizer};
pub use source::SnapshotSource;
pub(crate) use stream::{NOT_LEADER_MSG, NOT_LEADER_NEEDLE};
// The gate itself is exercised in prod by `view_cache::view_for`; this crate-level
// alias exists only so the cross-module `relay` unit tests can reach it.
#[cfg(test)]
pub(crate) use view_cache::gateway_svid_denied;

use stream::{StreamServices, StreamSubscription, node_scope_from, read_subscribe, run_stream};
use view_cache::{SharedViewCache, ViewCacheState};

// ── DiscoveryService ──────────────────────────────────────────────────────────

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
    registry: NodeRegistryHandle,
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
    /// [`DenyAllNamespaces`]; `coxswain-bin` installs the provenance-backed
    /// [`ProvisionedRelayAuthorizer`] where relays are provisioned.
    authorizer: Arc<dyn ScopeAuthorizer>,
    /// Best-upstream resolver for live repoint directives (#601). When `Some`,
    /// a dedicated (Gateway/Namespace-scope) stream is sent a `PreferredUpstream`
    /// directive whenever its namespace's best upstream changes (a relay is
    /// provisioned or torn down). `None` = no live repoint (unit tests / roles
    /// that don't front leaves).
    upstream_resolver: Option<Arc<UpstreamResolverConfig>>,
    /// Wakes each stream's send loop when relay provisioning changes (#601),
    /// bumped by the operator's `set_relay_provisioned`. Distinct from
    /// `rebuild_rx` (routing changes): a relay provision/teardown is not itself a
    /// routing rebuild, so it needs its own signal to trigger a repoint push.
    relay_changed_rx: Option<watch::Receiver<u64>>,
    /// Relay directive-forwarding fan-out (#601). Set only on a **relay's**
    /// downstream server: its upstream client fans controller-originated
    /// `PreferredUpstream` directives here, and each downstream leaf stream
    /// subscribes and forwards the ones targeting its Gateway. `None` on the
    /// controller's own server (it originates directives, never forwards them).
    directive_tx: Option<broadcast::Sender<p::PreferredUpstream>>,
}

impl DiscoveryService {
    /// Construct a new service handle.
    ///
    /// `rebuild_rx` must be cloned from `route_health.subscribe()` — the
    /// reconciler's rebuild-generation watch channel. Each newly accepted stream
    /// gets its own clone so ticks are delivered independently.
    #[must_use]
    pub fn new(
        source: SnapshotSource,
        registry: NodeRegistryHandle,
        rebuild_rx: watch::Receiver<u64>,
    ) -> Self {
        Self {
            source,
            registry,
            rebuild_rx,
            leader_rx: None,
            shared_view: Arc::new(Mutex::new(ViewCacheState::default())),
            authorizer: Arc::new(DenyAllNamespaces),
            upstream_resolver: None,
            relay_changed_rx: None,
            directive_tx: None,
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

    /// Enable live upstream-repoint directives (#601).
    ///
    /// `resolver` computes each dedicated leaf's current best upstream (its
    /// namespace's relay if provisioned, else the controller). `relay_changed_rx`
    /// wakes every live stream's send loop when relay provisioning changes, so a
    /// leaf is repointed the moment its namespace gains or loses a relay — without
    /// recycling any data-plane listener. Both must be installed together.
    #[must_use]
    pub fn with_upstream_directives(
        mut self,
        resolver: Arc<UpstreamResolverConfig>,
        relay_changed_rx: watch::Receiver<u64>,
    ) -> Self {
        self.upstream_resolver = Some(resolver);
        self.relay_changed_rx = Some(relay_changed_rx);
        self
    }

    /// Enable relay directive-forwarding on a **relay's** downstream server (#601).
    ///
    /// The relay's upstream client fans controller-originated `PreferredUpstream`
    /// directives into `directive_tx`; each downstream leaf stream subscribes and
    /// forwards the ones targeting its Gateway. Only a relay installs this — the
    /// controller originates directives from its resolver instead.
    #[must_use]
    pub fn with_directive_forwarding(
        mut self,
        directive_tx: broadcast::Sender<p::PreferredUpstream>,
    ) -> Self {
        self.directive_tx = Some(directive_tx);
        self
    }
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
            if let Some(entry) = self.source.dedicated.load().map.get(&key)
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
            upstream_resolver: self.upstream_resolver.clone(),
            relay_changed_rx: self.relay_changed_rx.clone(),
            directive_tx: self.directive_tx.clone(),
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

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::authz::*;
    use super::source::*;
    use super::stream::*;
    use super::view_cache::*;
    use super::*;
    use crate::materialize::materialize;
    use crate::proto::v1::{
        ClientMessage, ServerMessage, Snapshot, client_message::Kind as CKind,
        discovery_server::DiscoveryServer, server_message::Kind as SrvKind,
    };
    use coxswain_core::Shared;
    use coxswain_core::dedicated_registry::{
        DedicatedRegistryData, DedicatedRoutingRegistry, DedicatedRoutingSnapshot,
    };
    use coxswain_core::endpoints::{EndpointKey, ResolvedEndpoints};
    use coxswain_core::listener_status::{GatewayListenerStatus, GatewayListenerStatusHandle};
    use coxswain_core::node_registry::{NodeRegistryHandle, NodeScope};
    use coxswain_core::publish_index::GatewayPublishIndexHandle;
    use coxswain_core::routing::{
        BackendGroup, BackendProtocol, GatewayRoutingTable, IngressRoutingTable,
        IngressRoutingTableBuilder, RouteEntry, SharedGatewayRoutingTable,
        SharedIngressRoutingTable,
    };
    use coxswain_core::tls::{
        ClientCertStore, PortTlsStore, SharedClientCertStore, SharedPortTlsStore,
    };
    use std::collections::{BTreeMap, HashMap, HashSet};
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

    /// #585 wire decode: `record_roster_report` folds a `RosterReport` into the
    /// registry, preserving the scope, the `bound_reported` None/Some(∅)
    /// distinction, the acked seq, and tagging each child with the relay parent.
    #[test]
    fn record_roster_report_folds_children_into_registry() {
        let registry = NodeRegistryHandle::new();
        registry.connect(
            "relay-x",
            NodeScope::Namespace {
                namespace: "prod".to_owned(),
            },
            SystemTime::UNIX_EPOCH,
        );
        let report = p::RosterReport {
            children: vec![
                // A bound, acked leaf.
                p::RosterEntry {
                    node_id: "leaf-bound".to_owned(),
                    scope: Some(crate::wire::scope_to_wire(&Scope::Gateway {
                        name: "gw".to_owned(),
                        namespace: "prod".to_owned(),
                    })),
                    acked_version: Some("v1".to_owned()),
                    target_version: Some("v1".to_owned()),
                    acked_seq: Some(9),
                    bound_reported: true,
                    bound_ports: vec![443, 8443],
                    connected_since_unix: 100,
                    last_ack_at_unix: Some(200),
                },
                // A leaf on a DIFFERENT Gateway that has NOT reported bound ports
                // → None, not Some(∅) (fail-closed for its own Gateway).
                p::RosterEntry {
                    node_id: "leaf-unreported".to_owned(),
                    scope: Some(crate::wire::scope_to_wire(&Scope::Gateway {
                        name: "gw2".to_owned(),
                        namespace: "prod".to_owned(),
                    })),
                    acked_version: None,
                    target_version: Some("v1".to_owned()),
                    acked_seq: None,
                    bound_reported: false,
                    bound_ports: Vec::new(),
                    connected_since_unix: 100,
                    last_ack_at_unix: None,
                },
            ],
        };
        record_roster_report("relay-x", report, &registry);

        let snap = registry.load();
        let bound = &snap.nodes["leaf-bound"];
        assert_eq!(
            bound.parent.as_deref(),
            Some("relay-x"),
            "child tagged with parent"
        );
        assert_eq!(
            bound.scope,
            NodeScope::Gateway {
                namespace: "prod".to_owned(),
                name: "gw".to_owned()
            }
        );
        assert_eq!(
            bound
                .bound_ports
                .as_ref()
                .map(|s| s.iter().copied().collect::<Vec<_>>()),
            Some(vec![443u16, 8443])
        );
        assert_eq!(bound.last_acked_seq, Some(9));
        assert_eq!(
            snap.nodes["leaf-unreported"].bound_ports, None,
            "an unreported leaf decodes to None (fail-closed), never Some(empty)"
        );
        assert!(
            snap.nodes["relay-x"].is_relay,
            "the reporting relay is marked"
        );
        // The folded bound leaf satisfies its Gateway's dedicated gate...
        assert!(snap.gateway_node_bound("prod", "gw", &[443u16].into_iter().collect()));
        // ...while the unreported leaf holds its own Gateway's gate closed.
        assert!(!snap.gateway_node_bound("prod", "gw2", &[443u16].into_iter().collect()));
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
        registry: NodeRegistryHandle,
        rebuild_tx: watch::Sender<u64>,
        publish: GatewayPublishIndexHandle,
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
            listener_status: GatewayListenerStatusHandle::new(),
            dedicated: DedicatedRoutingRegistry::new(),
            passthrough_routes: coxswain_core::routing::SharedTlsPassthroughTable::new(),
            terminate_routes: coxswain_core::routing::SharedTlsPassthroughTable::new(),
            tcp_routes: coxswain_core::routing::SharedTcpRouteTable::new(),
            udp_routes: coxswain_core::routing::SharedUdpRouteTable::new(),
            publish: GatewayPublishIndexHandle::new(),
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
        let registry = NodeRegistryHandle::new();
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
        source
            .dedicated
            .store(Arc::new(DedicatedRegistryData::from_map(map)));
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

        let view = materialize(&source, &Scope::SharedPool);

        assert!(
            view.resources.is_empty(),
            "SharedPool reads the shared cells (empty here), never the dedicated registry"
        );
    }

    // ── Gateway view cache + SVID post-cache gate (#621) ──────────────────────

    fn gw_scope() -> Scope {
        Scope::Gateway {
            name: "gw-a".to_owned(),
            namespace: "prod".to_owned(),
        }
    }

    /// Two `view_for` calls for the same Gateway at the same generation share one
    /// `Arc<MaterializedView>`: the SVID-independent world is built once and reused
    /// across subscribers, not re-materialized (re-hashed) per stream.
    #[test]
    fn gateway_view_is_cached_per_generation() {
        let key = ObjectKey::new("prod".to_owned(), "gw-a".to_owned());
        let source = source_with_dedicated_entry(&key);
        let cache: SharedViewCache = Arc::new(Mutex::new(ViewCacheState::default()));

        let a = view_for(&cache, &source, &gw_scope(), None, 7);
        let b = view_for(&cache, &source, &gw_scope(), None, 7);
        assert!(
            Arc::ptr_eq(&a, &b),
            "same generation must share one cached view Arc"
        );
        assert!(
            !a.resources.is_empty(),
            "the cached Gateway world is the real (non-empty) one"
        );
    }

    /// A newer generation invalidates the cached Gateway view (fresh build).
    #[test]
    fn gateway_view_rebuilds_on_new_generation() {
        let key = ObjectKey::new("prod".to_owned(), "gw-a".to_owned());
        let source = source_with_dedicated_entry(&key);
        let cache: SharedViewCache = Arc::new(Mutex::new(ViewCacheState::default()));

        let a = view_for(&cache, &source, &gw_scope(), None, 1);
        let b = view_for(&cache, &source, &gw_scope(), None, 2);
        assert!(!Arc::ptr_eq(&a, &b), "a newer generation must rebuild");
    }

    /// A non-matching peer SVID is served an empty seq-0 world by the post-cache
    /// filter — never the cached real world (the #427 appear-after-open guard) —
    /// while a matching SVID is served the real world.
    #[test]
    fn gateway_view_svid_gate_denies_mismatch_serves_match() {
        let key = ObjectKey::new("prod".to_owned(), "gw-a".to_owned());
        let source = source_with_dedicated_entry(&key);
        let cache: SharedViewCache = Arc::new(Mutex::new(ViewCacheState::default()));

        let wrong = PeerSvid {
            uri_sans: vec!["spiffe://cluster.local/ns/prod/sa/someone-else".to_owned()],
        };
        let denied = view_for(&cache, &source, &gw_scope(), Some(&wrong), 1);
        assert!(
            denied.resources.is_empty() && denied.seq == 0,
            "mismatched SVID must get an empty seq-0 world"
        );

        // expected_proxy_sa is "gw-a-coxswain" (see source_with_dedicated_entry).
        let matching = PeerSvid {
            uri_sans: vec!["spiffe://cluster.local/ns/prod/sa/gw-a-coxswain".to_owned()],
        };
        let served = view_for(&cache, &source, &gw_scope(), Some(&matching), 1);
        assert!(
            !served.resources.is_empty(),
            "matching SVID must be served the real Gateway world"
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

    // ── live upstream-repoint push (#601) ──────────────────────────────────────

    fn upstream_resolver(active: &[&str]) -> Arc<UpstreamResolverConfig> {
        let set: HashSet<String> = active.iter().map(|s| (*s).to_owned()).collect();
        Arc::new(UpstreamResolverConfig {
            controller_endpoint: "https://coxswain-controller-discovery.coxswain-system.svc:50051"
                .to_owned(),
            controller_sa: "coxswain-controller".to_owned(),
            shared_relay_endpoint: "https://coxswain-relay-shared.coxswain-system.svc:50051"
                .to_owned(),
            shared_relay_sa: "coxswain-relay-shared".to_owned(),
            shared_relay_active: Shared::from_value(false),
            relay_service_name: "coxswain-relay".to_owned(),
            relay_port: 50051,
            relay_sa: "coxswain-relay".to_owned(),
            active_relays: Shared::from_value(set),
        })
    }

    /// A `PeerSvid` bearing the shared relay's SVID — the discriminator
    /// `seed_or_push_upstream` uses to treat a SharedPool stream as the relay's own
    /// (forward path) rather than a direct proxy.
    fn shared_relay_peer() -> crate::auth::PeerSvid {
        crate::auth::PeerSvid {
            uri_sans: vec![
                "spiffe://cluster.local/ns/coxswain-system/sa/coxswain-relay-shared".to_owned(),
            ],
        }
    }

    /// Drain any directive currently queued on the receiver without blocking.
    fn try_recv_directive(
        rx: &mut mpsc::Receiver<Result<ServerMessage, Status>>,
    ) -> Option<p::PreferredUpstream> {
        match rx.try_recv() {
            Ok(Ok(ServerMessage {
                kind: Some(SrvKind::PreferredUpstream(d)),
            })) => Some(d),
            _ => None,
        }
    }

    #[tokio::test]
    async fn seed_does_not_push_then_provisioning_change_repoints_gateway_leaf() {
        // Not yet provisioned: seeding a Gateway-scope leaf records the controller
        // baseline and sends nothing (the client already bootstrapped to it).
        let resolver = upstream_resolver(&[]);
        let (tx, mut rx) = mpsc::channel::<Result<ServerMessage, Status>>(4);
        let scope = Scope::Gateway {
            namespace: "team-a".to_owned(),
            name: "my-gw".to_owned(),
        };
        let mut last = None;
        seed_or_push_upstream(&scope, None, Some(&resolver), &mut last, &tx)
            .await
            .expect("seed must not fail");
        assert!(
            try_recv_directive(&mut rx).is_none(),
            "seeding must not push a directive"
        );

        // Namespace becomes provisioned → the leaf is repointed to the relay,
        // untargeted (it is the sole recipient of its own direct stream).
        resolver
            .active_relays
            .store(Arc::new(HashSet::from(["team-a".to_owned()])));
        seed_or_push_upstream(&scope, None, Some(&resolver), &mut last, &tx)
            .await
            .expect("push must not fail");
        let directive = try_recv_directive(&mut rx).expect("a repoint directive must be pushed");
        assert_eq!(
            directive.endpoint,
            "https://coxswain-relay.team-a.svc:50051"
        );
        assert_eq!(directive.expected_server_sa, "coxswain-relay");
        assert_eq!(
            directive.target_namespace, "",
            "a direct Gateway-scope directive is untargeted"
        );
    }

    #[tokio::test]
    async fn gateway_leaf_is_repointed_on_seed_when_relay_already_provisioned() {
        // Race the real provisioning flow reproduces: the proxy bootstrapped to the
        // controller (its stream is served HERE), but its namespace's relay was
        // provisioned before this stream opened. The seed baseline is therefore the
        // controller (where the proxy is actually connected), NOT the already-desired
        // relay — so the very first call pushes the repoint instead of silently
        // seeding `relay` and never moving the proxy off the controller.
        let resolver = upstream_resolver(&["team-a"]);
        let (tx, mut rx) = mpsc::channel::<Result<ServerMessage, Status>>(4);
        let scope = Scope::Gateway {
            namespace: "team-a".to_owned(),
            name: "my-gw".to_owned(),
        };
        let mut last = None;
        seed_or_push_upstream(&scope, None, Some(&resolver), &mut last, &tx)
            .await
            .expect("push must not fail");
        let directive = try_recv_directive(&mut rx)
            .expect("a Gateway leaf whose relay is already provisioned must be repointed on open");
        assert_eq!(
            directive.endpoint,
            "https://coxswain-relay.team-a.svc:50051"
        );
        assert_eq!(directive.expected_server_sa, "coxswain-relay");
    }

    #[tokio::test]
    async fn namespace_relay_stream_forwards_targeted_directive_on_deprovision() {
        // Relay's Namespace stream, provisioned: seed the relay baseline, no push.
        let resolver = upstream_resolver(&["team-a"]);
        let (tx, mut rx) = mpsc::channel::<Result<ServerMessage, Status>>(4);
        let scope = Scope::Namespace {
            namespace: "team-a".to_owned(),
        };
        let mut last = None;
        seed_or_push_upstream(&scope, None, Some(&resolver), &mut last, &tx)
            .await
            .expect("seed must not fail");
        assert!(try_recv_directive(&mut rx).is_none());

        // Deprovision → forward a controller-repoint directive tagged with the
        // namespace so the relay routes it to its downstream leaves.
        resolver.active_relays.store(Arc::new(HashSet::new()));
        seed_or_push_upstream(&scope, None, Some(&resolver), &mut last, &tx)
            .await
            .expect("push must not fail");
        let directive = try_recv_directive(&mut rx).expect("a forward directive must be pushed");
        assert_eq!(
            directive.endpoint,
            "https://coxswain-controller-discovery.coxswain-system.svc:50051"
        );
        assert_eq!(directive.expected_server_sa, "coxswain-controller");
        assert_eq!(
            directive.target_namespace, "team-a",
            "a Namespace-scope directive carries the target namespace for relay forwarding"
        );
    }

    #[tokio::test]
    async fn shared_pool_proxy_is_repointed_when_shared_relay_activates() {
        // A direct shared proxy (no relay SVID) streaming from the controller: seed
        // the controller baseline (no push), then when the shared relay becomes
        // Active it is repointed onto the relay, untargeted (its own direct stream).
        let resolver = upstream_resolver(&[]);
        let (tx, mut rx) = mpsc::channel::<Result<ServerMessage, Status>>(4);
        let mut last = None;
        seed_or_push_upstream(&Scope::SharedPool, None, Some(&resolver), &mut last, &tx)
            .await
            .expect("seed must not fail");
        assert!(
            try_recv_directive(&mut rx).is_none(),
            "seeding a direct shared proxy must not push"
        );

        resolver.shared_relay_active.store(Arc::new(true));
        seed_or_push_upstream(&Scope::SharedPool, None, Some(&resolver), &mut last, &tx)
            .await
            .expect("push must not fail");
        let directive = try_recv_directive(&mut rx).expect("a repoint directive must be pushed");
        assert_eq!(
            directive.endpoint,
            "https://coxswain-relay-shared.coxswain-system.svc:50051"
        );
        assert_eq!(directive.expected_server_sa, "coxswain-relay-shared");
        assert_eq!(
            directive.target_namespace, "",
            "a direct shared-pool directive is untargeted"
        );
    }

    #[tokio::test]
    async fn shared_relay_stream_forwards_repoint_on_deactivate() {
        // The shared relay's OWN SharedPool stream (its SVID carries the shared-relay
        // SA), while Active: seed from the shared best upstream (the relay), no push.
        let resolver = upstream_resolver(&[]);
        resolver.shared_relay_active.store(Arc::new(true));
        let peer = shared_relay_peer();
        let (tx, mut rx) = mpsc::channel::<Result<ServerMessage, Status>>(4);
        let mut last = None;
        seed_or_push_upstream(
            &Scope::SharedPool,
            Some(&peer),
            Some(&resolver),
            &mut last,
            &tx,
        )
        .await
        .expect("seed must not fail");
        assert!(try_recv_directive(&mut rx).is_none());

        // Shared relay deactivates → forward a controller-repoint directive; the
        // shared relay routes it to all its downstream shared-pool leaves
        // (`directive_targets_leaf` matches them without a namespace).
        resolver.shared_relay_active.store(Arc::new(false));
        seed_or_push_upstream(
            &Scope::SharedPool,
            Some(&peer),
            Some(&resolver),
            &mut last,
            &tx,
        )
        .await
        .expect("push must not fail");
        let directive = try_recv_directive(&mut rx).expect("a forward directive must be pushed");
        assert_eq!(
            directive.endpoint,
            "https://coxswain-controller-discovery.coxswain-system.svc:50051"
        );
        assert_eq!(directive.expected_server_sa, "coxswain-controller");
        assert_eq!(
            directive.target_namespace, "",
            "a shared-pool forward directive needs no namespace (a shared relay serves only shared-pool leaves)"
        );
    }

    #[test]
    fn directive_targeting_matches_gateway_in_namespace_only() {
        let directive = |ns: &str, name: &str| p::PreferredUpstream {
            endpoint: "https://x".to_owned(),
            expected_server_sa: "coxswain-controller".to_owned(),
            target_namespace: ns.to_owned(),
            target_name: name.to_owned(),
        };
        let gw = |ns: &str, name: &str| Scope::Gateway {
            namespace: ns.to_owned(),
            name: name.to_owned(),
        };
        // Namespace-wide directive (empty target_name) hits every Gateway in ns.
        assert!(directive_targets_leaf(
            &directive("team-a", ""),
            &gw("team-a", "gw-1")
        ));
        // Gateway-specific directive hits only that Gateway.
        assert!(directive_targets_leaf(
            &directive("team-a", "gw-1"),
            &gw("team-a", "gw-1")
        ));
        assert!(!directive_targets_leaf(
            &directive("team-a", "gw-1"),
            &gw("team-a", "gw-2")
        ));
        // Different namespace never matches.
        assert!(!directive_targets_leaf(
            &directive("team-b", ""),
            &gw("team-a", "gw-1")
        ));
        // A dedicated relay's own Namespace stream is never a forward target.
        assert!(!directive_targets_leaf(
            &directive("team-a", ""),
            &Scope::Namespace {
                namespace: "team-a".to_owned()
            }
        ));
        // A shared-pool leaf downstream of a shared relay always matches (#605): the
        // directive carries no namespace, since a shared relay serves only such leaves.
        assert!(directive_targets_leaf(
            &directive("", ""),
            &Scope::SharedPool
        ));
    }
}
