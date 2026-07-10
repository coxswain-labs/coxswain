//! Discovery gRPC server: runs inside the controller role.
//!
//! Implements the `Discovery` tonic service, watches the controller's `Shared`
//! routing snapshots, and fans out `Snapshot` messages to connected proxy clients
//! with push-after-Ack flow control.
//!
//! # Flow control
//!
//! A new snapshot version is only sent after the prior one has been Ack'd.
//! Rebuilds that arrive while a snapshot is in-flight are coalesced: after the
//! Ack arrives the server reads the current world once and sends it if the
//! version differs from the one just Ack'd.
//!
//! Nacks trigger a retransmit of the same snapshot content with a fresh nonce;
//! `in_flight` is left unchanged (the retransmit awaits an Ack just like the
//! original send).
//!
//! # Node registry
//!
//! Each stream task calls [`SharedNodeRegistry::connect`] on entry and
//! [`SharedNodeRegistry::disconnect`] on exit, recording every Ack — and every
//! `NodeStatus` bound-port report (#531) — in between. The registry is read by
//! the admin UI convergence panel (T8) and by the controller's Gateway
//! `Programmed` readiness gate (#531).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use async_trait::async_trait;
use prost::Message as _;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, warn};

use coxswain_core::dedicated_registry::DedicatedRoutingRegistry;
use coxswain_core::listener_status::SharedGatewayListenerStatus;
use coxswain_core::node_registry::{NodeScope, SharedNodeRegistry};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::publish_index::SharedGatewayPublishIndex;
use coxswain_core::routing::{
    SharedGatewayRoutingTable, SharedIngressRoutingTable, SharedTcpRouteTable,
    SharedTlsPassthroughTable,
};
use coxswain_core::tls::{SharedClientCertStore, SharedPortTlsStore};

use crate::auth::{PeerSvid, svid_matches_dedicated_gateway};
use crate::subscription::Scope;

use crate::proto::v1::{
    self as p, client_message::Kind as CKind, discovery_server::Discovery,
    server_message::Kind as SKind,
};
use crate::version::{ContentHash, WIRE_VERSION};
use crate::wire::{
    client_cert_to_wire, gateway_to_wire, ingress_to_wire, listener_status_to_wire,
    passthrough_to_wire, port_tls_to_wire, scope_from_wire, tcp_table_to_wire,
};

// ── SnapshotSource ────────────────────────────────────────────────────────────

/// The five routing-table [`Shared`] cells the server reads to build snapshots.
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
    /// Read when a client subscribes with [`Scope::Gateway`]; the five cells
    /// above serve [`Scope::SharedPool`] (and deliberately exclude cut-over
    /// Gateways). The shared reconciler is the sole writer.
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
            publish: self.publish.clone(),
        }
    }
}

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
    registry: SharedNodeRegistry,
    rebuild_rx: watch::Receiver<u64>,
    /// Leadership gate (#531). `Some(rx)`: streams are accepted only while the
    /// watched value is `true`, and live streams are terminated on a
    /// `true → false` flip. `None`: ungated (unit tests; the bin always gates).
    leader_rx: Option<watch::Receiver<bool>>,
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
        }
    }

    /// Gate the `Stream` RPC on a leadership watch (#531).
    ///
    /// While the watched value is `false` (standby, or leadership not yet
    /// established), new streams are rejected at accept with
    /// `FAILED_PRECONDITION` / [`NOT_LEADER_MSG`], and a demotion terminates
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

/// Snapshot content built from the current routing world (without a nonce).
///
/// The nonce is assigned immediately before transmission so retransmits can
/// use the same content with a fresh nonce.
#[derive(Clone)]
struct SnapshotContent {
    version: String,
    /// Publish sequence captured before the cells were read (never on the
    /// wire): recorded into the node registry when this snapshot is Ack'd.
    seq: u64,
    ingress_routing: p::RoutingTable,
    gateway_routing: p::RoutingTable,
    tls_store: p::PortTlsStore,
    client_cert_store: p::ClientCertStore,
    listener_status: p::GatewayListenerStatus,
    tls_passthrough: p::TlsPassthroughTable,
    tls_terminate: p::TlsPassthroughTable,
    tcp_proxy: p::TcpRouteTable,
}

impl SnapshotContent {
    /// Stamp a fresh nonce and produce a wire [`p::Snapshot`] ready to send.
    fn into_message(self) -> p::Snapshot {
        p::Snapshot {
            version: self.version,
            nonce: next_nonce(),
            ingress_routing: Some(self.ingress_routing),
            gateway_routing: Some(self.gateway_routing),
            tls_store: Some(self.tls_store),
            client_cert_store: Some(self.client_cert_store),
            listener_status: Some(self.listener_status),
            tls_passthrough: Some(self.tls_passthrough),
            tls_terminate: Some(self.tls_terminate),
            tcp_proxy: Some(self.tcp_proxy),
        }
    }
}

/// Build a [`SnapshotContent`] for the routing world the `scope` subscribes to.
///
/// - [`Scope::SharedPool`] serialises the five shared cells verbatim (these
///   deliberately exclude cut-over Gateways, so the shared pool never serves a
///   migrated Gateway's routes).
/// - [`Scope::Gateway`] looks up the Gateway's entry in the dedicated registry
///   and serialises only that slice (empty Ingress). An absent entry yields an
///   empty snapshot — a dedicated proxy is fail-closed and never receives
///   another scope's routes (#426).
///   When `peer_svid` is present (mTLS connection) and the entry's
///   `expected_proxy_sa` does not match the peer SVID, the function also returns
///   an empty snapshot — this is the build-time complement to the open-time
///   `PERMISSION_DENIED` check in `stream()` and closes the race where a Gateway
///   entry appears *after* the stream was opened (#427).
fn build_snapshot(
    source: &SnapshotSource,
    scope: &Scope,
    peer_svid: Option<&PeerSvid>,
) -> SnapshotContent {
    // Capture the publish sequence BEFORE reading any cell: every rebuild
    // stamped at a sequence <= this value stored its cells before bumping the
    // counter, so the content loaded below is at least that new. Capturing
    // after the loads would claim content the snapshot may not have.
    let seq = source.publish.current_seq();
    let mut content = match scope {
        Scope::SharedPool => {
            let ingress = source.ingress.load();
            let gateway = source.gateway.load();
            let tls = source.tls.load();
            let client_certs = source.client_certs.load();
            let listener_status = source.listener_status.load();
            let passthrough = source.passthrough_routes.load();
            let terminate = source.terminate_routes.load();
            let tcp_proxy = source.tcp_routes.load();

            assemble_snapshot(
                ingress_to_wire(&ingress),
                gateway_to_wire(&gateway),
                port_tls_to_wire(&tls),
                client_cert_to_wire(&client_certs),
                listener_status_to_wire(&listener_status),
                L4TableDtos {
                    tls_passthrough: passthrough_to_wire(&passthrough),
                    tls_terminate: passthrough_to_wire(&terminate),
                    tcp_proxy: tcp_table_to_wire(&tcp_proxy),
                },
            )
        }
        Scope::Gateway { name, namespace } => {
            let key = ObjectKey::new(namespace.clone(), name.clone());
            let registry = source.dedicated.load();
            match registry.get(&key) {
                Some(snap) => {
                    // Build-time SVID binding check: if the peer presented an SVID
                    // but it does not match this Gateway's expected proxy SA, return
                    // an empty snapshot. This closes the race where the Gateway entry
                    // appears in the registry after the open-time check in stream().
                    if let Some(peer) = peer_svid
                        && !svid_matches_dedicated_gateway(
                            &peer.uri_sans,
                            namespace,
                            &snap.expected_proxy_sa,
                        )
                    {
                        // seq 0, NOT the captured seq: this snapshot is a
                        // deliberately-emptied world, so an Ack of it must not
                        // advance the node's convergence stamp — a real seq
                        // here would let the #531 ack gate certify content the
                        // node never received. 0 is a no-op under the
                        // registry's monotone max.
                        return SnapshotContent {
                            seq: 0,
                            ..assemble_snapshot(
                                p::RoutingTable::default(),
                                p::RoutingTable::default(),
                                p::PortTlsStore::default(),
                                p::ClientCertStore::default(),
                                p::GatewayListenerStatus::default(),
                                // Dedicated proxies never serve TLSRoute or TCPRoute traffic.
                                L4TableDtos {
                                    tls_passthrough: p::TlsPassthroughTable::default(),
                                    tls_terminate: p::TlsPassthroughTable::default(),
                                    tcp_proxy: p::TcpRouteTable::default(),
                                },
                            )
                        };
                    }
                    assemble_snapshot(
                        // A dedicated proxy never serves Ingress resources.
                        p::RoutingTable::default(),
                        gateway_to_wire(&snap.gateway),
                        port_tls_to_wire(&snap.tls),
                        client_cert_to_wire(&snap.client_certs),
                        listener_status_to_wire(&snap.listener_status),
                        // Dedicated proxies never serve TLSRoute or TCPRoute traffic.
                        L4TableDtos {
                            tls_passthrough: p::TlsPassthroughTable::default(),
                            tls_terminate: p::TlsPassthroughTable::default(),
                            tcp_proxy: p::TcpRouteTable::default(),
                        },
                    )
                }
                // Fail closed: the Gateway is not (yet) cut over, so this proxy
                // receives an empty world rather than another scope's routes.
                // seq 0 for the same reason as the identity-mismatch branch
                // above: an Ack of a fail-closed empty world must not advance
                // the node's #531 convergence stamp.
                None => {
                    return SnapshotContent {
                        seq: 0,
                        ..assemble_snapshot(
                            p::RoutingTable::default(),
                            p::RoutingTable::default(),
                            p::PortTlsStore::default(),
                            p::ClientCertStore::default(),
                            p::GatewayListenerStatus::default(),
                            L4TableDtos {
                                tls_passthrough: p::TlsPassthroughTable::default(),
                                tls_terminate: p::TlsPassthroughTable::default(),
                                tcp_proxy: p::TcpRouteTable::default(),
                            },
                        )
                    };
                }
            }
        }
    };
    content.seq = seq;
    content
}

/// The L4 wire DTOs [`assemble_snapshot`] groups to stay under the workspace
/// 7-argument limit: TLS passthrough, TLS terminate (#481), and TCP proxy (#505)
/// — the three port-keyed tables that bypass the L7 routing tables entirely.
struct L4TableDtos {
    tls_passthrough: p::TlsPassthroughTable,
    tls_terminate: p::TlsPassthroughTable,
    tcp_proxy: p::TcpRouteTable,
}

/// Assemble a [`SnapshotContent`] from pre-built wire DTOs.
///
/// Derives the global content hash from the sorted per-resource hashes;
/// identical DTO sets produce identical version strings.
fn assemble_snapshot(
    ingress_dto: p::RoutingTable,
    gateway_dto: p::RoutingTable,
    tls_dto: p::PortTlsStore,
    client_certs_dto: p::ClientCertStore,
    listener_status_dto: p::GatewayListenerStatus,
    l4: L4TableDtos,
) -> SnapshotContent {
    let hashes = vec![
        ContentHash::compute(&ingress_dto.encode_to_vec())
            .as_str()
            .to_owned(),
        ContentHash::compute(&gateway_dto.encode_to_vec())
            .as_str()
            .to_owned(),
        ContentHash::compute(&tls_dto.encode_to_vec())
            .as_str()
            .to_owned(),
        ContentHash::compute(&client_certs_dto.encode_to_vec())
            .as_str()
            .to_owned(),
        ContentHash::compute(&listener_status_dto.encode_to_vec())
            .as_str()
            .to_owned(),
        ContentHash::compute(&l4.tls_passthrough.encode_to_vec())
            .as_str()
            .to_owned(),
        ContentHash::compute(&l4.tls_terminate.encode_to_vec())
            .as_str()
            .to_owned(),
        ContentHash::compute(&l4.tcp_proxy.encode_to_vec())
            .as_str()
            .to_owned(),
    ];
    let version = ContentHash::from_per_resource(hashes).as_str().to_owned();

    SnapshotContent {
        version,
        // Placeholder — build_snapshot overwrites with the pre-load capture.
        seq: 0,
        ingress_routing: ingress_dto,
        gateway_routing: gateway_dto,
        tls_store: tls_dto,
        client_cert_store: client_certs_dto,
        listener_status: listener_status_dto,
        tls_passthrough: l4.tls_passthrough,
        tls_terminate: l4.tls_terminate,
        tcp_proxy: l4.tcp_proxy,
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

        let node_id = sub.node_id.clone();

        // Register the node before spawning so connect() is visible
        // even if the first snapshot races with a load().
        self.registry
            .connect(&node_id, node_scope_from(&scope), SystemTime::now());
        crate::metrics::streams_total()
            .with_label_values(&["accepted"])
            .inc();
        crate::metrics::connected_proxies().inc();

        let source = self.source.clone();
        let registry = self.registry.clone();
        let rebuild_rx = self.rebuild_rx.clone();
        let leader_rx = self.leader_rx.clone();
        let (tx, rx) = mpsc::channel::<Result<p::ServerMessage, Status>>(4);

        let subscription = StreamSubscription {
            node_id,
            scope,
            peer_svid,
        };
        tokio::spawn(async move {
            run_stream(
                subscription,
                source,
                registry,
                rebuild_rx,
                leader_rx,
                inbound,
                tx,
            )
            .await;
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
    /// Version hash of the last snapshot the client Ack'd; `None` before the
    /// first Ack.
    last_acked: Option<String>,
    /// Version hash of the snapshot currently awaiting an Ack from the client;
    /// `None` when no snapshot is in-flight (safe to push the next one).
    in_flight: Option<String>,
    /// Content of the last snapshot sent, retained so Nack retransmits can
    /// replay the same payload with a fresh nonce.
    last_sent: Option<SnapshotContent>,
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
    }
}

/// Drive the push-after-Ack state machine for one connected proxy node.
///
/// Exits when the client disconnects, the outbound channel closes, or a stream
/// error is received. Calls [`SharedNodeRegistry::disconnect`] unconditionally
/// on exit so the registry stays consistent.
async fn run_stream(
    sub: StreamSubscription,
    source: SnapshotSource,
    registry: SharedNodeRegistry,
    mut rebuild_rx: watch::Receiver<u64>,
    mut leader_rx: Option<watch::Receiver<bool>>,
    mut inbound: Streaming<p::ClientMessage>,
    tx: mpsc::Sender<Result<p::ServerMessage, Status>>,
) {
    // Send the initial snapshot immediately on stream open.
    let initial = build_snapshot(&source, &sub.scope, sub.peer_svid.as_ref());
    registry.record_target(&sub.node_id, initial.version.clone());
    let mut state = StreamState {
        last_acked: None,
        in_flight: Some(initial.version.clone()),
        last_sent: Some(initial.clone()),
    };
    if send_content(&tx, initial).await.is_err() {
        registry.disconnect(&sub.node_id);
        crate::metrics::connected_proxies().dec();
        return;
    }

    loop {
        tokio::select! {
            // Inbound message from the proxy client.
            result = inbound.message() => {
                match result {
                    Ok(Some(client_msg)) => {
                        match client_msg.kind {
                            Some(CKind::Ack(ack)) => {
                                if handle_ack(&sub, ack, &source, &registry, &tx, &mut state)
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Some(CKind::Nack(nack)) => {
                                if handle_nack(&sub.node_id, &nack, &state.last_sent, &tx)
                                    .await
                                    .is_err()
                                {
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

            // Routing world was rebuilt — check for a new snapshot to push.
            _ = rebuild_rx.changed() => {
                if state.in_flight.is_some() {
                    // A snapshot is already awaiting Ack; coalesce this rebuild.
                    debug!(node_id = %sub.node_id, "discovery: rebuild while in-flight, coalescing");
                    continue;
                }
                let current = build_snapshot(&source, &sub.scope, sub.peer_svid.as_ref());
                registry.record_target(&sub.node_id, current.version.clone());
                if Some(current.version.as_str()) != state.last_acked.as_deref() {
                    state.in_flight = Some(current.version.clone());
                    state.last_sent = Some(current.clone());
                    if send_content(&tx, current).await.is_err() {
                        break;
                    }
                } else {
                    debug!(
                        node_id = %sub.node_id,
                        "discovery: rebuild produced same version as last Ack — no push needed"
                    );
                    // Same content as the node's last Ack: advance its
                    // convergence stamp to the freshly-captured sequence so
                    // the #531 ack gate converges without a content change.
                    registry.advance_acked_seq(&sub.node_id, current.seq);
                }
            }
        }
    }

    registry.disconnect(&sub.node_id);
    crate::metrics::connected_proxies().dec();
}

/// Handle an `Ack` from the client.
///
/// Updates the registry and last-acked state, clears `in_flight`, then checks
/// whether the current world version differs from the just-Ack'd one and sends
/// a new snapshot if so.
///
/// Returns `Err(())` if the outbound channel is closed.
async fn handle_ack(
    sub: &StreamSubscription,
    ack: p::Ack,
    source: &SnapshotSource,
    registry: &SharedNodeRegistry,
    tx: &mpsc::Sender<Result<p::ServerMessage, Status>>,
    state: &mut StreamState,
) -> Result<(), ()> {
    debug!(node_id = %sub.node_id, version = %ack.version, "discovery: Ack received");
    // The Ack'd snapshot's publish sequence comes from the retained last-sent
    // content (Acks echo the version we pushed). A stale Ack for some other
    // version records sequence 0 — a no-op under the registry's monotone max.
    let acked_seq = state
        .last_sent
        .as_ref()
        .filter(|sent| sent.version == ack.version)
        .map_or(0, |sent| sent.seq);
    registry.record_ack(
        &sub.node_id,
        ack.version.clone(),
        acked_seq,
        SystemTime::now(),
    );
    crate::metrics::acks_total().inc();
    state.last_acked = Some(ack.version);
    state.in_flight = None;

    // Check current world against the just-Ack'd version.
    let current = build_snapshot(source, &sub.scope, sub.peer_svid.as_ref());
    registry.record_target(&sub.node_id, current.version.clone());
    if Some(current.version.as_str()) != state.last_acked.as_deref() {
        state.in_flight = Some(current.version.clone());
        state.last_sent = Some(current.clone());
        send_content(tx, current).await?;
    } else {
        // Identical content: the node's applied snapshot is equivalent to the
        // freshly-captured sequence, so advance its convergence stamp without
        // a push (#531 ack gate liveness on a quiet cluster).
        registry.advance_acked_seq(&sub.node_id, current.seq);
    }
    Ok(())
}

/// Handle a `Nack` from the client.
///
/// Logs the rejection and retransmits the last-sent snapshot content with a
/// fresh nonce.  `in_flight` is intentionally left unchanged — the retransmit
/// is a retry of the same logical version, not a new version.
///
/// Returns `Err(())` if the outbound channel is closed.
async fn handle_nack(
    node_id: &str,
    nack: &p::Nack,
    last_sent: &Option<SnapshotContent>,
    tx: &mpsc::Sender<Result<p::ServerMessage, Status>>,
) -> Result<(), ()> {
    warn!(
        node_id,
        version = %nack.version,
        detail = %nack.detail,
        "discovery: Nack received; retransmitting last snapshot",
    );
    match last_sent {
        Some(content) => send_content(tx, content.clone()).await,
        None => {
            // Nack before any snapshot was sent — protocol violation; log and ignore.
            warn!(
                node_id,
                "discovery: Nack received before any snapshot was sent"
            );
            Ok(())
        }
    }
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

/// Stamp a fresh nonce on `content`, wrap it in a `ServerMessage`, and send it.
///
/// Returns `Err(())` if the receiver has been dropped.
async fn send_content(
    tx: &mpsc::Sender<Result<p::ServerMessage, Status>>,
    content: SnapshotContent,
) -> Result<(), ()> {
    let msg = p::ServerMessage {
        kind: Some(SKind::Snapshot(content.into_message())),
    };
    tx.send(Ok(msg)).await.map_err(|_| ())
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
    use coxswain_core::listener_status::GatewayListenerStatus;
    use coxswain_core::node_registry::SharedNodeRegistry;
    use coxswain_core::routing::{
        GatewayRoutingTable, SharedGatewayRoutingTable, SharedIngressRoutingTable,
    };
    use coxswain_core::tls::{
        ClientCertStore, PortTlsStore, SharedClientCertStore, SharedPortTlsStore,
    };
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::sync::watch;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::{Endpoint, Server};

    // ── test harness ─────────────────────────────────────────────────────────

    struct TestHarness {
        addr: SocketAddr,
        registry: SharedNodeRegistry,
        rebuild_tx: watch::Sender<u64>,
        publish: SharedGatewayPublishIndex,
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
        let source = empty_source();
        let registry = SharedNodeRegistry::new();
        let (rebuild_tx, rebuild_rx) = watch::channel(0u64);

        let mut svc = DiscoveryService::new(source.clone(), registry.clone(), rebuild_rx);
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
        let _ = source; // populated in coxswain-bin; empty for tests
        TestHarness {
            addr,
            registry,
            rebuild_tx,
            publish,
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

    /// A Nack causes the server to retransmit a snapshot with the same version
    /// but a different nonce.
    #[tokio::test]
    async fn nack_resends_same_snapshot() {
        let h = start_harness().await;
        let (tx, mut rx) = open_stream(h.addr, "node-nack").await;

        let snap1 = recv_snapshot(&mut rx).await;
        send_nack(&tx, &snap1).await;

        let snap2 = recv_snapshot(&mut rx).await;
        assert_eq!(
            snap1.version, snap2.version,
            "Nack retransmit must carry the same version"
        );
        assert_ne!(
            snap1.nonce, snap2.nonce,
            "Nack retransmit must use a fresh nonce"
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
        let gw_routing = snap.gateway_routing.unwrap_or_default();
        assert!(
            gw_routing.ports.is_empty(),
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
        let _initial = recv_snapshot(&mut inbound).await;

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

        // The stream must remain healthy after the malformed report: a rebuild
        // still reaches this node.
        h.rebuild_tx.send(1).unwrap();
        tx.send(ClientMessage {
            kind: Some(CKind::Ack(p::Ack {
                version: "bogus".to_owned(),
                nonce: vec![],
            })),
        })
        .await
        .unwrap();
        let _next = recv_snapshot(&mut inbound).await;
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

        let snap = build_snapshot(
            &source,
            &Scope::Gateway {
                name: "gw-a".to_owned(),
                namespace: "prod".to_owned(),
            },
            // No peer SVID in plaintext unit tests; SVID binding is exercised in
            // tests/scope_binding.rs over real TLS.
            None,
        );

        let lh = snap.listener_status;
        assert_eq!(
            lh.entries.len(),
            1,
            "Gateway scope must serve exactly its own listener-health entry"
        );
        assert_eq!(
            lh.entries[0].object_key,
            key.to_string(),
            "the served entry must be the subscribing Gateway's"
        );
        assert!(
            snap.ingress_routing.ports.is_empty(),
            "a dedicated proxy never receives Ingress routes"
        );
    }

    #[test]
    fn gateway_scope_absent_entry_is_fully_empty() {
        // Registry holds gw-a, but a proxy for gw-b subscribes.
        let present = ObjectKey::new("prod".to_owned(), "gw-a".to_owned());
        let source = source_with_dedicated_entry(&present);

        let snap = build_snapshot(
            &source,
            &Scope::Gateway {
                name: "gw-b".to_owned(),
                namespace: "prod".to_owned(),
            },
            None,
        );

        assert!(
            snap.listener_status.entries.is_empty(),
            "fail-closed: an absent Gateway receives no routes, not another scope's"
        );
        assert!(snap.gateway_routing.ports.is_empty());
        assert!(snap.ingress_routing.ports.is_empty());
    }

    #[test]
    fn shared_scope_ignores_dedicated_registry() {
        // A cut-over Gateway sits in the dedicated registry; the shared pool
        // must not pick it up (the shared cells deliberately exclude it).
        let key = ObjectKey::new("prod".to_owned(), "gw-a".to_owned());
        let source = source_with_dedicated_entry(&key);

        let snap = build_snapshot(&source, &Scope::SharedPool, None);

        assert!(
            snap.listener_status.entries.is_empty(),
            "SharedPool reads the shared cells, never the dedicated registry"
        );
    }
}
