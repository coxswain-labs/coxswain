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

use coxswain_core::dedicated_registry::{DedicatedRoutingRegistry, DedicatedRoutingSnapshot};
use coxswain_core::listener_status::{GatewayListenerStatus, SharedGatewayListenerStatus};
use coxswain_core::node_registry::SharedNodeRegistry;
use coxswain_core::ownership::ObjectKey;
use coxswain_core::publish_index::SharedGatewayPublishIndex;
use coxswain_core::routing::{
    GatewayRoutingTable, SharedGatewayRoutingTable, SharedIngressRoutingTable,
};
use coxswain_core::tls::{
    ClientCertStore, PortTlsStore, SharedClientCertStore, SharedPortTlsStore,
};

use crate::auth::tests::gen_certs_with_client_svid;
use crate::auth::{DiscoveryClientTls, DiscoveryServerTls, SpiffeMatcher};
use crate::proto::v1::{
    self as p, ClientMessage, client_message::Kind as CKind, discovery_server::DiscoveryServer,
};
use crate::server::{DiscoveryService, SnapshotSource};
use crate::subscription::Scope;
use crate::transport::PeerSvidStream;
use crate::version::WIRE_VERSION;
use crate::wire::scope_to_wire;

const CONTROLLER_SVID: &str = "spiffe://cluster.local/ns/coxswain-system/sa/coxswain-controller";

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
        listener_status: SharedGatewayListenerStatus::new(),
        dedicated: DedicatedRoutingRegistry::new(),
        passthrough_routes: coxswain_core::routing::SharedTlsPassthroughTable::new(),
        terminate_routes: coxswain_core::routing::SharedTlsPassthroughTable::new(),
        tcp_routes: coxswain_core::routing::SharedTcpRouteTable::new(),
        udp_routes: coxswain_core::routing::SharedUdpRouteTable::new(),
        publish: SharedGatewayPublishIndex::new(),
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

    source.dedicated.store(Arc::new(map));
    source
}

/// Start a real `DiscoveryService` behind mTLS, wrapping each accepted stream
/// in `PeerSvidStream` so the handler receives `PeerSvid` in request extensions.
///
/// Returns the bound socket address.  The server runs as a detached
/// `tokio::spawn` task and lives until the test runtime drops.
async fn start_service(server_tls: &DiscoveryServerTls) -> std::net::SocketAddr {
    let source = source_with_two_gateways();
    let registry = SharedNodeRegistry::new();
    let (_, rebuild_rx) = tokio::sync::watch::channel(0u64);
    let svc = DiscoveryService::new(source, registry, rebuild_rx);

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

    addr
}

/// Open a discovery stream over TLS, sending a `Subscribe` with `scope`.
///
/// Returns the response stream on success, or the gRPC `Status` on rejection
/// (PERMISSION_DENIED, INVALID_ARGUMENT, TLS error, etc.).
async fn try_stream_with_scope(
    addr: std::net::SocketAddr,
    client_tls: &DiscoveryClientTls,
    scope: Scope,
) -> Result<tonic::Streaming<p::ServerMessage>, tonic::Status> {
    use crate::proto::v1::discovery_client::DiscoveryClient as TonicClient;
    use tokio_stream::wrappers::ReceiverStream;

    let (tx, rx) = tokio::sync::mpsc::channel::<ClientMessage>(4);
    tx.send(ClientMessage {
        kind: Some(CKind::Subscribe(p::Subscribe {
            node_id: "test-dedicated-proxy".into(),
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
    Ok(response.into_inner())
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

    let addr = start_service(&server_tls).await;

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

    let addr = start_service(&server_tls).await;

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
