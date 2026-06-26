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
//! [`SharedNodeRegistry::disconnect`] on exit, recording every Ack in between.
//! The registry is read by the admin UI convergence panel (T8).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use async_trait::async_trait;
use prost::Message as _;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, warn};

use coxswain_core::dedicated_registry::DedicatedRoutingRegistry;
use coxswain_core::listener_health::SharedGatewayListenerHealth;
use coxswain_core::node_registry::{NodeScope, SharedNodeRegistry};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::routing::{
    SharedGatewayRoutingTable, SharedIngressRoutingTable, SharedTlsPassthroughTable,
};
use coxswain_core::tls::{SharedClientCertStore, SharedTlsStore};

use crate::auth::{PeerSvid, svid_matches_dedicated_gateway};
use crate::subscription::Scope;

use crate::proto::v1::{
    self as p, client_message::Kind as CKind, discovery_server::Discovery,
    server_message::Kind as SKind,
};
use crate::version::{ContentHash, WIRE_VERSION};
use crate::wire::{
    client_cert_to_wire, gateway_to_wire, ingress_to_wire, listener_health_to_wire,
    passthrough_to_wire, scope_from_wire, tls_to_wire,
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
    pub tls: SharedTlsStore,
    /// Client-certificate mTLS config store shared cell.
    pub client_certs: SharedClientCertStore,
    /// Per-Gateway listener TLS-health map. Serialised into the
    /// `listener_health` wire field so proxy nodes can drive dynamic
    /// Gateway listener port bind/unbind without Kubernetes API access.
    pub tls_health: SharedGatewayListenerHealth,
    /// Per-cut-over-Gateway routing snapshots, keyed by Gateway [`ObjectKey`].
    /// Read when a client subscribes with [`Scope::Gateway`]; the five cells
    /// above serve [`Scope::SharedPool`] (and deliberately exclude cut-over
    /// Gateways). The shared reconciler is the sole writer.
    pub dedicated: DedicatedRoutingRegistry,
    /// SNI-keyed TLS passthrough routing table for TLSRoute / GEP-2643 (#70).
    /// Only populated for [`Scope::SharedPool`] subscribers; dedicated proxies
    /// receive an empty table (TLSRoutes are shared-pool only).
    pub passthrough_routes: SharedTlsPassthroughTable,
}

impl Clone for SnapshotSource {
    fn clone(&self) -> Self {
        Self {
            ingress: self.ingress.clone(),
            gateway: self.gateway.clone(),
            tls: self.tls.clone(),
            client_certs: self.client_certs.clone(),
            tls_health: self.tls_health.clone(),
            dedicated: self.dedicated.clone(),
            passthrough_routes: self.passthrough_routes.clone(),
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
        registry: SharedNodeRegistry,
        rebuild_rx: watch::Receiver<u64>,
    ) -> Self {
        Self {
            source,
            registry,
            rebuild_rx,
        }
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
    ingress_routing: p::RoutingTable,
    gateway_routing: p::RoutingTable,
    tls_store: p::TlsStore,
    client_cert_store: p::ClientCertStore,
    listener_health: p::GatewayListenerHealth,
    tls_passthrough: p::TlsPassthroughTable,
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
            listener_health: Some(self.listener_health),
            tls_passthrough: Some(self.tls_passthrough),
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
    match scope {
        Scope::SharedPool => {
            let ingress = source.ingress.load();
            let gateway = source.gateway.load();
            let tls = source.tls.load();
            let client_certs = source.client_certs.load();
            let tls_health = source.tls_health.load();
            let passthrough = source.passthrough_routes.load();

            assemble_snapshot(
                ingress_to_wire(&ingress),
                gateway_to_wire(&gateway),
                tls_to_wire(&tls),
                client_cert_to_wire(&client_certs),
                listener_health_to_wire(&tls_health),
                passthrough_to_wire(&passthrough),
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
                        return assemble_snapshot(
                            p::RoutingTable::default(),
                            p::RoutingTable::default(),
                            p::TlsStore::default(),
                            p::ClientCertStore::default(),
                            p::GatewayListenerHealth::default(),
                            // Dedicated proxies never serve TLS passthrough routes.
                            p::TlsPassthroughTable::default(),
                        );
                    }
                    assemble_snapshot(
                        // A dedicated proxy never serves Ingress resources.
                        p::RoutingTable::default(),
                        gateway_to_wire(&snap.gateway),
                        tls_to_wire(&snap.tls),
                        client_cert_to_wire(&snap.client_certs),
                        listener_health_to_wire(&snap.listener_health),
                        // Dedicated proxies never serve TLS passthrough routes.
                        p::TlsPassthroughTable::default(),
                    )
                }
                // Fail closed: the Gateway is not (yet) cut over, so this proxy
                // receives an empty world rather than another scope's routes.
                None => assemble_snapshot(
                    p::RoutingTable::default(),
                    p::RoutingTable::default(),
                    p::TlsStore::default(),
                    p::ClientCertStore::default(),
                    p::GatewayListenerHealth::default(),
                    p::TlsPassthroughTable::default(),
                ),
            }
        }
    }
}

/// Assemble a [`SnapshotContent`] from pre-built wire DTOs.
///
/// Derives the global content hash from the sorted per-resource hashes;
/// identical DTO sets produce identical version strings.
fn assemble_snapshot(
    ingress_dto: p::RoutingTable,
    gateway_dto: p::RoutingTable,
    tls_dto: p::TlsStore,
    client_certs_dto: p::ClientCertStore,
    listener_health_dto: p::GatewayListenerHealth,
    tls_passthrough_dto: p::TlsPassthroughTable,
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
        ContentHash::compute(&listener_health_dto.encode_to_vec())
            .as_str()
            .to_owned(),
        ContentHash::compute(&tls_passthrough_dto.encode_to_vec())
            .as_str()
            .to_owned(),
    ];
    let version = ContentHash::from_per_resource(hashes).as_str().to_owned();

    SnapshotContent {
        version,
        ingress_routing: ingress_dto,
        gateway_routing: gateway_dto,
        tls_store: tls_dto,
        client_cert_store: client_certs_dto,
        listener_health: listener_health_dto,
        tls_passthrough: tls_passthrough_dto,
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
        let (tx, rx) = mpsc::channel::<Result<p::ServerMessage, Status>>(4);

        let subscription = StreamSubscription {
            node_id,
            scope,
            peer_svid,
        };
        tokio::spawn(async move {
            run_stream(subscription, source, registry, rebuild_rx, inbound, tx).await;
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
    registry.record_ack(&sub.node_id, ack.version.clone(), SystemTime::now());
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
    use coxswain_core::listener_health::GatewayListenerHealth;
    use coxswain_core::node_registry::SharedNodeRegistry;
    use coxswain_core::routing::{
        GatewayRoutingTable, SharedGatewayRoutingTable, SharedIngressRoutingTable,
    };
    use coxswain_core::tls::{ClientCertStore, SharedClientCertStore, SharedTlsStore, TlsStore};
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
    }

    fn empty_source() -> SnapshotSource {
        SnapshotSource {
            ingress: SharedIngressRoutingTable::new(),
            gateway: SharedGatewayRoutingTable::new(),
            tls: SharedTlsStore::new(),
            client_certs: SharedClientCertStore::new(),
            tls_health: SharedGatewayListenerHealth::new(),
            dedicated: DedicatedRoutingRegistry::new(),
            passthrough_routes: coxswain_core::routing::SharedTlsPassthroughTable::new(),
        }
    }

    async fn start_harness() -> TestHarness {
        let source = empty_source();
        let registry = SharedNodeRegistry::new();
        let (rebuild_tx, rebuild_rx) = watch::channel(0u64);

        let svc = DiscoveryService::new(source.clone(), registry.clone(), rebuild_rx);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(
            Server::builder()
                .add_service(DiscoveryServer::new(svc))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );

        let _ = source; // populated in coxswain-bin; empty for tests
        TestHarness {
            addr,
            registry,
            rebuild_tx,
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

    // ── scope-aware snapshot dispatch (#426) ──────────────────────────────────

    /// Build a `SnapshotSource` whose dedicated registry holds one entry for
    /// `key`, with a listener-health map keyed by that same `ObjectKey`.  The
    /// shared cells stay empty, so a SharedPool snapshot and a Gateway snapshot
    /// are trivially distinguishable by their `listener_health` entry count.
    fn source_with_dedicated_entry(key: &ObjectKey) -> SnapshotSource {
        let source = empty_source();
        let mut lh = HashMap::new();
        lh.insert(key.clone(), GatewayListenerHealth::default());
        let snap = Arc::new(DedicatedRoutingSnapshot {
            gateway: Arc::new(GatewayRoutingTable::default()),
            tls: Arc::new(TlsStore::default()),
            client_certs: Arc::new(ClientCertStore::default()),
            listener_health: lh,
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

        let lh = snap.listener_health;
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
            snap.listener_health.entries.is_empty(),
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
            snap.listener_health.entries.is_empty(),
            "SharedPool reads the shared cells, never the dedicated registry"
        );
    }
}
