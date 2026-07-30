//! TLS integration tests for Gateway scope claim → SVID identity binding (#427).
//!
//! These tests exercise the full chain over a real TLS handshake:
//! `PeerSvidStream::connect_info` → `PeerSvid` request extension →
//! `svid_matches_dedicated_gateway` → PERMISSION_DENIED or stream open.
//!
//! Plaintext unit coverage (INVALID_ARGUMENT, fail-open path) lives in
//! `server.rs::mod tests`.  Scope binding is only observable over a real TLS
//! connection because `PeerSvid` is only populated by `PeerSvidStream::connect_info`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Endpoint, Server};

use coxswain_core::dedicated_registry::{
    DedicatedRegistryData, DedicatedRoutingRegistry, DedicatedRoutingSnapshot,
};
use coxswain_core::listener_status::{GatewayListenerStatus, GatewayListenerStatusHandle};
use coxswain_core::node_registry::NodeRegistryHandle;
use coxswain_core::ownership::ObjectKey;
use coxswain_core::publish_index::GatewayPublishIndexHandle;
use coxswain_core::routing::{
    GatewayRoutingTable, SharedGatewayRoutingTable, SharedIngressRoutingTable,
};
use coxswain_core::tls::{
    ClientCertStore, PortTlsStore, SharedClientCertStore, SharedPortTlsStore,
};

use crate::auth::tests::gen_certs_with_client_svid;
use crate::auth::{DiscoveryClientTls, DiscoveryServerTls, PeerSvid, SpiffeMatcher};
use crate::proto::v1::{
    self as p, ClientMessage, client_message::Kind as CKind, discovery_server::DiscoveryServer,
};
use crate::server::{DiscoveryService, ScopeAuthorizer, SnapshotSource};
use crate::subscription::Scope;
use crate::transport::PeerSvidStream;
use crate::version::WIRE_VERSION;
use crate::wire::scope_to_wire;

const CONTROLLER_SVID: &str = "spiffe://cluster.local/ns/coxswain-system/sa/coxswain-controller";

/// A [`ScopeAuthorizer`] stub that allows everything. These TLS integration
/// tests exercise Gateway-scope binding (#427) and the `node_id` collision
/// guard (#666/#682/#726) via arbitrary test SVIDs unrelated to the
/// `ScopeAuthorizer` seam — production's real `DenyAll` default would
/// otherwise deny their `SharedPool` subscribes for reasons orthogonal to
/// what each test is actually proving.
struct AllowAll;

impl ScopeAuthorizer for AllowAll {
    fn allows_namespace(&self, _peer: &PeerSvid, _namespace: &str) -> bool {
        true
    }

    fn allows_shared_pool(&self, _peer: &PeerSvid) -> bool {
        true
    }

    fn allows_roster(&self, _peer: &PeerSvid, _scope: &Scope) -> bool {
        true
    }
}

/// SVID that the dedicated proxy for `gw-a` in namespace `prod` runs as.
/// SA name `gw-a-coxswain` follows GEP-1762 (`{gw_name}-{class_name}`).
const GW_A_PROXY_SVID: &str = "spiffe://cluster.local/ns/prod/sa/gw-a-coxswain";

// ── test helpers ──────────────────────────────────────────────────────────────

/// Build a `SnapshotSource` with two dedicated Gateway entries:
///
/// - `(prod, gw-a)` → `expected_proxy_sa = "gw-a-coxswain"`
/// - `(prod, other-gw)` → `expected_proxy_sa = "other-gw-coxswain"`
fn source_with_two_gateways() -> SnapshotSource {
    let source = SnapshotSource {
        ingress: SharedIngressRoutingTable::new(),
        gateway: SharedGatewayRoutingTable::new(),
        tls: SharedPortTlsStore::new(),
        client_certs: SharedClientCertStore::new(),
        listener_status: GatewayListenerStatusHandle::new(),
        dedicated: DedicatedRoutingRegistry::new(),
        // Empty here deliberately: these tests exercise the `source.dedicated`
        // fallback path (the pre-#726 mechanism), not the new pre-cut-over
        // `dedicated_identities` cell — see `server::stream`'s Gap A doc.
        dedicated_identities: coxswain_core::Shared::new(),
        passthrough_routes: coxswain_core::routing::SharedTlsPassthroughTable::new(),
        terminate_routes: coxswain_core::routing::SharedTlsPassthroughTable::new(),
        tcp_routes: coxswain_core::routing::SharedTcpRouteTable::new(),
        udp_routes: coxswain_core::routing::SharedUdpRouteTable::new(),
        publish: GatewayPublishIndexHandle::new(),
    };

    let gw_a_key = ObjectKey::new("prod".to_owned(), "gw-a".to_owned());
    let other_key = ObjectKey::new("prod".to_owned(), "other-gw".to_owned());

    let mut map = HashMap::new();

    let mut lh_a = HashMap::new();
    lh_a.insert(gw_a_key.clone(), GatewayListenerStatus::default());
    map.insert(
        gw_a_key,
        Arc::new(DedicatedRoutingSnapshot {
            gateway: Arc::new(GatewayRoutingTable::default()),
            tls: Arc::new(PortTlsStore::default()),
            client_certs: Arc::new(ClientCertStore::default()),
            listener_status: lh_a,
            expected_proxy_sa: "gw-a-coxswain".to_owned(),
        }),
    );

    let mut lh_other = HashMap::new();
    lh_other.insert(other_key.clone(), GatewayListenerStatus::default());
    map.insert(
        other_key,
        Arc::new(DedicatedRoutingSnapshot {
            gateway: Arc::new(GatewayRoutingTable::default()),
            tls: Arc::new(PortTlsStore::default()),
            client_certs: Arc::new(ClientCertStore::default()),
            listener_status: lh_other,
            expected_proxy_sa: "other-gw-coxswain".to_owned(),
        }),
    );

    source
        .dedicated
        .store(Arc::new(DedicatedRegistryData::from_map(map)));
    source
}

/// A source whose `gw-a` identity is known ONLY pre-cut-over (#726):
/// `dedicated_identities` carries `gw-a-coxswain`, but `dedicated` (the
/// post-cut-over routing registry) is empty — the exact state a fresh
/// dedicated proxy's own Gateway is in the instant it starts, before the
/// operator has observed it Ready and the reflector has rebuilt.
fn source_with_pre_cutover_identity_only() -> SnapshotSource {
    let source = source_with_two_gateways();
    source
        .dedicated
        .store(Arc::new(DedicatedRegistryData::from_map(HashMap::new())));
    let key = ObjectKey::new("prod".to_owned(), "gw-a".to_owned());
    source
        .dedicated_identities
        .store(Arc::new(HashMap::from([(key, "gw-a-coxswain".to_owned())])));
    source
}

/// Start a real `DiscoveryService` behind mTLS, wrapping each accepted stream
/// in `PeerSvidStream` so the handler receives `PeerSvid` in request extensions.
///
/// Returns the bound socket address and a handle to the service's node
/// registry (so callers can inspect connected-node state, e.g. the #682
/// node_id collision guard's tests). The server runs as a detached
/// `tokio::spawn` task and lives until the test runtime drops.
pub(super) async fn start_service(
    server_tls: &DiscoveryServerTls,
) -> (std::net::SocketAddr, NodeRegistryHandle) {
    start_service_with_source(server_tls, source_with_two_gateways()).await
}

/// [`start_service`], parameterised over the `SnapshotSource` — used by tests
/// that need a specific `dedicated`/`dedicated_identities` combination (#726).
async fn start_service_with_source(
    server_tls: &DiscoveryServerTls,
    source: SnapshotSource,
) -> (std::net::SocketAddr, NodeRegistryHandle) {
    let registry = NodeRegistryHandle::new();
    let (_, rebuild_rx) = tokio::sync::watch::channel(0u64);
    let svc = DiscoveryService::new(source, registry.clone(), rebuild_rx)
        .with_scope_authorizer(std::sync::Arc::new(AllowAll));

    let acceptor = server_tls
        .acceptor()
        .unwrap_or_else(|e| panic!("server TLS acceptor: {e}"));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().expect("local addr");

    // Mirror the PeerSvidStream wrapping that serve_discovery_with_tls does,
    // but bind the listener first so we know the port before spawning.
    let incoming = TcpListenerStream::new(listener).then(move |r| {
        let acceptor = acceptor.clone();
        async move {
            let stream = r?;
            let tls = acceptor.accept(stream).await?;
            Ok::<_, std::io::Error>(PeerSvidStream(tls))
        }
    });

    tokio::spawn(
        Server::builder()
            .add_service(DiscoveryServer::new(svc))
            .serve_with_incoming(incoming),
    );

    (addr, registry)
}

/// Open a discovery stream over TLS, sending a `Subscribe` with `scope`,
/// under the fixed test node_id `"test-dedicated-proxy"`. Drops the outbound
/// sender immediately (closing the client's request body right after
/// `Subscribe`) — fine for these tests, which only ever read one message and
/// never need the session to outlive that read.
///
/// Returns the response stream on success, or the gRPC `Status` on rejection
/// (PERMISSION_DENIED, INVALID_ARGUMENT, TLS error, etc.).
async fn try_stream_with_scope(
    addr: std::net::SocketAddr,
    client_tls: &DiscoveryClientTls,
    scope: Scope,
) -> Result<tonic::Streaming<p::ServerMessage>, tonic::Status> {
    let (_tx, stream) =
        try_stream_with_node_id_and_scope(addr, client_tls, "test-dedicated-proxy", scope).await?;
    Ok(stream)
}

/// Open a discovery stream over TLS, sending a `Subscribe` with `node_id` and
/// `scope`.
///
/// Returns the outbound sender alongside the response stream — the caller
/// **must** keep the sender alive for as long as the session should stay
/// open: dropping it closes the client's request body (EOF), which
/// `run_stream` reads as `Ok(None)` and answers by tearing the session down
/// (including releasing its `node_id` claim, #682), same as a real client
/// disconnecting. Returns the gRPC `Status` on rejection (PERMISSION_DENIED,
/// INVALID_ARGUMENT, ALREADY_EXISTS, TLS error, etc.).
pub(super) async fn try_stream_with_node_id_and_scope(
    addr: std::net::SocketAddr,
    client_tls: &DiscoveryClientTls,
    node_id: &str,
    scope: Scope,
) -> Result<
    (
        tokio::sync::mpsc::Sender<ClientMessage>,
        tonic::Streaming<p::ServerMessage>,
    ),
    tonic::Status,
> {
    use crate::proto::v1::discovery_client::DiscoveryClient as TonicClient;
    use tokio_stream::wrappers::ReceiverStream;

    let (tx, rx) = tokio::sync::mpsc::channel::<ClientMessage>(4);
    tx.send(ClientMessage {
        kind: Some(CKind::Subscribe(p::Subscribe {
            node_id: node_id.to_owned(),
            wire_version: WIRE_VERSION,
            scope: Some(scope_to_wire(&scope)),
        })),
    })
    .await
    .unwrap_or_else(|e| panic!("invariant: pre-send channel is open: {e}"));

    let ep = Endpoint::from_shared(format!("https://{addr}"))
        .map_err(|e| tonic::Status::internal(e.to_string()))?;
    let ep = client_tls
        .apply(ep)
        .map_err(|e| tonic::Status::internal(e.to_string()))?;

    let channel = ep.connect_lazy();
    let mut grpc = TonicClient::new(channel);
    let response = grpc.stream(ReceiverStream::new(rx)).await?;
    Ok((tx, response.into_inner()))
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// A dedicated proxy presenting SVID `gw-a-coxswain` and claiming the matching
/// `Scope::Gateway { name: "gw-a", namespace: "prod" }` must have the stream
/// accepted and receive a snapshot.
#[tokio::test]
async fn gateway_svid_matching_scope_accepted() {
    let certs = gen_certs_with_client_svid(GW_A_PROXY_SVID);

    let server_tls = DiscoveryServerTls {
        server_cert_pem: certs.server_cert_pem.clone(),
        server_key_pem: certs.server_key_pem.clone(),
        client_ca_pem: certs.ca_cert_pem.clone(),
        // Admit any cert issued by our CA regardless of path.
        allowed_client: SpiffeMatcher::Prefix("spiffe://cluster.local/".into()),
    };
    let client_tls = DiscoveryClientTls {
        client_cert_pem: certs.client_cert_pem.clone(),
        client_key_pem: certs.client_key_pem.clone(),
        server_ca_pem: certs.ca_cert_pem.clone(),
        expected_server: SpiffeMatcher::Exact(CONTROLLER_SVID.into()),
    };

    let (addr, _registry) = start_service(&server_tls).await;

    let mut inbound = try_stream_with_scope(
        addr,
        &client_tls,
        Scope::Gateway {
            name: "gw-a".to_owned(),
            namespace: "prod".to_owned(),
        },
    )
    .await
    .expect("SVID gw-a-coxswain matches scope Gateway{gw-a, prod} — stream must be accepted");

    let msg = tokio::time::timeout(Duration::from_secs(3), inbound.message())
        .await
        .expect("timed out waiting for initial snapshot")
        .expect("stream error waiting for snapshot")
        .expect("stream closed before snapshot");

    assert!(
        matches!(msg.kind, Some(p::server_message::Kind::Snapshot(_))),
        "expected Snapshot on accepted stream, got {msg:?}",
    );
}

/// A dedicated proxy presenting SVID `gw-a-coxswain` but claiming
/// `Scope::Gateway { name: "other-gw", namespace: "prod" }` (a Gateway whose
/// expected SA is `other-gw-coxswain`) must be rejected with PERMISSION_DENIED
/// before any snapshot is delivered.
#[tokio::test]
async fn gateway_svid_mismatched_scope_permission_denied() {
    let certs = gen_certs_with_client_svid(GW_A_PROXY_SVID);

    let server_tls = DiscoveryServerTls {
        server_cert_pem: certs.server_cert_pem.clone(),
        server_key_pem: certs.server_key_pem.clone(),
        client_ca_pem: certs.ca_cert_pem.clone(),
        allowed_client: SpiffeMatcher::Prefix("spiffe://cluster.local/".into()),
    };
    let client_tls = DiscoveryClientTls {
        client_cert_pem: certs.client_cert_pem.clone(),
        client_key_pem: certs.client_key_pem.clone(),
        server_ca_pem: certs.ca_cert_pem.clone(),
        expected_server: SpiffeMatcher::Exact(CONTROLLER_SVID.into()),
    };

    let (addr, _registry) = start_service(&server_tls).await;

    // `gw-a-coxswain` SVID but claiming `other-gw`'s scope — mismatch.
    let err = try_stream_with_scope(
        addr,
        &client_tls,
        Scope::Gateway {
            name: "other-gw".to_owned(),
            namespace: "prod".to_owned(),
        },
    )
    .await
    .expect_err("SVID gw-a-coxswain must not be allowed to claim scope Gateway{other-gw, prod}");

    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "expected PERMISSION_DENIED, got {err:?}",
    );
}

/// A dedicated proxy presenting a valid SVID but claiming a Gateway with no
/// dedicated-registry entry at all must be rejected `PERMISSION_DENIED` —
/// there is nothing for the claim to legitimately be (#726). Before #726 this
/// case fell through the entry-lookup unchecked and the stream opened
/// (harmless in practice, since `view_cache::gateway_svid_denied` fail-closes
/// the build to an empty world regardless — but the accept path itself was a
/// silent bypass).
#[tokio::test]
async fn gateway_scope_with_no_dedicated_entry_permission_denied() {
    let certs = gen_certs_with_client_svid(GW_A_PROXY_SVID);

    let server_tls = DiscoveryServerTls {
        server_cert_pem: certs.server_cert_pem.clone(),
        server_key_pem: certs.server_key_pem.clone(),
        client_ca_pem: certs.ca_cert_pem.clone(),
        allowed_client: SpiffeMatcher::Prefix("spiffe://cluster.local/".into()),
    };
    let client_tls = DiscoveryClientTls {
        client_cert_pem: certs.client_cert_pem.clone(),
        client_key_pem: certs.client_key_pem.clone(),
        server_ca_pem: certs.ca_cert_pem.clone(),
        expected_server: SpiffeMatcher::Exact(CONTROLLER_SVID.into()),
    };

    let (addr, _registry) = start_service(&server_tls).await;

    let err = try_stream_with_scope(
        addr,
        &client_tls,
        Scope::Gateway {
            name: "no-such-gw".to_owned(),
            namespace: "prod".to_owned(),
        },
    )
    .await
    .expect_err("a Gateway absent from the dedicated registry must deny, not fail open");

    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "expected PERMISSION_DENIED, got {err:?}",
    );
}

/// A dedicated proxy presenting a matching SVID must be accepted even when
/// its Gateway is known ONLY pre-cut-over — `dedicated_identities` carries
/// its identity, but the post-cut-over `dedicated` routing registry is still
/// empty (#726). This is the exact state a fresh dedicated proxy's own
/// Gateway is in the instant the proxy starts: before #726 fixed the
/// bootstrap allowlist's equivalent race, this was the only signal that
/// existed, and it did not exist early enough to cover a proxy's first
/// connect.
#[tokio::test]
async fn gateway_scope_accepted_from_pre_cutover_identity_alone() {
    let certs = gen_certs_with_client_svid(GW_A_PROXY_SVID);

    let server_tls = DiscoveryServerTls {
        server_cert_pem: certs.server_cert_pem.clone(),
        server_key_pem: certs.server_key_pem.clone(),
        client_ca_pem: certs.ca_cert_pem.clone(),
        allowed_client: SpiffeMatcher::Prefix("spiffe://cluster.local/".into()),
    };
    let client_tls = DiscoveryClientTls {
        client_cert_pem: certs.client_cert_pem.clone(),
        client_key_pem: certs.client_key_pem.clone(),
        server_ca_pem: certs.ca_cert_pem.clone(),
        expected_server: SpiffeMatcher::Exact(CONTROLLER_SVID.into()),
    };

    let (addr, _registry) =
        start_service_with_source(&server_tls, source_with_pre_cutover_identity_only()).await;

    let mut inbound = try_stream_with_scope(
        addr,
        &client_tls,
        Scope::Gateway {
            name: "gw-a".to_owned(),
            namespace: "prod".to_owned(),
        },
    )
    .await
    .expect(
        "SVID gw-a-coxswain must be accepted from dedicated_identities alone, \
         before the routing registry has any entry for gw-a",
    );

    let msg = tokio::time::timeout(Duration::from_secs(3), inbound.message())
        .await
        .expect("timed out waiting for initial snapshot")
        .expect("stream error waiting for snapshot")
        .expect("stream closed before snapshot");
    assert!(
        matches!(msg.kind, Some(p::server_message::Kind::Snapshot(_))),
        "expected Snapshot on accepted stream, got {msg:?}",
    );
}
