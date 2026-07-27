//! TLS integration test for the `node_id` collision guard (#666, generalized
//! #682).
//!
//! Every other test of this guard is either a pure unit test of
//! `server::identity::claim_node_id`/`release_node_id` in isolation, or —
//! over the crate's plaintext test harness, which has no TLS layer — proves
//! only the *same*-identity-passes-through case (`server::mod::tests`'s
//! `same_identity_reconnect_to_a_live_relay_node_id_is_not_refused`), since a
//! plaintext connection carries no `PeerSvid` at all and two such connections
//! are therefore indistinguishable by design. This is the one test that
//! exercises the guard's actual security property — refusing a genuinely
//! DIFFERENT identity — through the real dispatch path, by presenting two
//! distinct, equally-trusted client SVIDs over real TLS handshakes (the same
//! `PeerSvidStream::connect_info` → `PeerSvid` request-extension chain
//! `scope_binding.rs` exercises for the #427 Gateway-scope-binding guard).

use std::time::Duration;

use tonic::Code;

use crate::auth::tests::gen_certs_with_two_client_svids;
use crate::auth::{DiscoveryClientTls, DiscoveryServerTls, SpiffeMatcher};
use crate::proto::v1 as p;
use crate::subscription::Scope;

use super::scope_binding::{start_service, try_stream_with_node_id_and_scope};

const CONTROLLER_SVID: &str = "spiffe://cluster.local/ns/coxswain-system/sa/coxswain-controller";
/// Two distinct, unrelated SVIDs — `Scope::SharedPool` carries no
/// scope-binding restriction (unlike `Scope::Gateway`/`Namespace`), so
/// whatever these name is irrelevant to the guard; only that they differ.
const FIRST_SVID: &str = "spiffe://cluster.local/ns/team-a/sa/coxswain-shared-proxy";
const SECOND_SVID: &str = "spiffe://cluster.local/ns/team-b/sa/coxswain-shared-proxy";

/// A second client presenting a DIFFERENT SVID than the one currently
/// connected under a `node_id` is refused `ALREADY_EXISTS`, and the first
/// connection's registry row is left untouched.
#[tokio::test]
async fn different_identity_claiming_a_live_node_id_is_refused() {
    let certs = gen_certs_with_two_client_svids(FIRST_SVID, SECOND_SVID);

    let server_tls = DiscoveryServerTls {
        server_cert_pem: certs.server_cert_pem.clone(),
        server_key_pem: certs.server_key_pem.clone(),
        client_ca_pem: certs.ca_cert_pem.clone(),
        allowed_client: SpiffeMatcher::Prefix("spiffe://cluster.local/".into()),
    };
    let client_tls_a = DiscoveryClientTls {
        client_cert_pem: certs.client_a_cert_pem.clone(),
        client_key_pem: certs.client_a_key_pem.clone(),
        server_ca_pem: certs.ca_cert_pem.clone(),
        expected_server: SpiffeMatcher::Exact(CONTROLLER_SVID.into()),
    };
    let client_tls_b = DiscoveryClientTls {
        client_cert_pem: certs.client_b_cert_pem.clone(),
        client_key_pem: certs.client_b_key_pem.clone(),
        server_ca_pem: certs.ca_cert_pem.clone(),
        expected_server: SpiffeMatcher::Exact(CONTROLLER_SVID.into()),
    };

    let (addr, registry) = start_service(&server_tls).await;

    // First identity claims "shared-node". Keep its outbound sender
    // (`_tx_a`) alive for the rest of the test: dropping it closes the
    // client's request body (EOF), which `run_stream` reads as the client
    // disconnecting and answers by tearing the whole session down —
    // including releasing its `node_id` claim — which would silently
    // invalidate this test's premise before the second connection ever dials.
    let (_tx_a, mut first_stream) =
        try_stream_with_node_id_and_scope(addr, &client_tls_a, "shared-node", Scope::SharedPool)
            .await
            .expect("the first identity's claim must be accepted");
    let msg = tokio::time::timeout(Duration::from_secs(3), first_stream.message())
        .await
        .expect("timed out waiting for initial snapshot")
        .expect("stream error waiting for snapshot")
        .expect("stream closed before snapshot");
    assert!(
        matches!(msg.kind, Some(p::server_message::Kind::Snapshot(_))),
        "expected Snapshot on accepted stream, got {msg:?}",
    );
    assert!(
        registry.load().nodes.contains_key("shared-node"),
        "the first stream must be visible in the registry"
    );

    // Second, DIFFERENT identity claims the SAME node_id — must be refused.
    let err =
        try_stream_with_node_id_and_scope(addr, &client_tls_b, "shared-node", Scope::SharedPool)
            .await
            .expect_err("a different identity must not be granted a live node_id");
    assert_eq!(
        err.code(),
        Code::AlreadyExists,
        "expected ALREADY_EXISTS, got {err:?}",
    );

    // The first identity's row is untouched by the refused attempt.
    assert!(
        registry.load().nodes.contains_key("shared-node"),
        "the refused second claim must not disturb the first identity's row"
    );
}
