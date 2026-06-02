use coxswain_e2e::{
    fixtures::{
        self, BACKENDS_ECHO, BACKENDS_WEBSOCKET_ECHO, GATEWAY_API_CERT_MANAGER,
        GATEWAY_API_COMBINED_MATCHING, GATEWAY_API_CROSS_NAMESPACE_ROUTE,
        GATEWAY_API_CROSS_NAMESPACE_TENANT, GATEWAY_API_HEADER_MATCHING, GATEWAY_API_HOST_POOL,
        GATEWAY_API_METHOD_MATCHING, GATEWAY_API_PATH_MATCHING, GATEWAY_API_QUERY_PARAM_MATCHING,
        GATEWAY_API_TLS_CROSS_NAMESPACE_CERTS, GATEWAY_API_TLS_CROSS_NAMESPACE_GW,
        GATEWAY_API_TLS_GATEWAY_NO_CERTS, GATEWAY_API_TLS_TERMINATION, GATEWAY_API_WEBSOCKET,
        GATEWAY_API_WILDCARD_HOST,
    },
    harness::{GeneratedCert, Harness, NamespaceGuard, http, wait},
};
use futures::{SinkExt as _, StreamExt as _};
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Api;
use kube::api::PostParams;
use reqwest::Method;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("coxswain_e2e=debug,warn")
        .try_init();
}

#[tokio::test]
async fn path_matching() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-path").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(GATEWAY_API_PATH_MATCHING, &ns.name, &[]).await?;

    let host = format!("echo.{}.local", ns.name);

    // Wait for the route to become live before asserting individual paths.
    let resp = wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    let resp = h.http.get(&host, "/b").await?;
    resp.assert_backend("echo-b");

    // Catch-all rule routes to echo-a.
    let resp = h.http.get(&host, "/").await?;
    resp.assert_backend("echo-a");

    Ok(())
}

#[tokio::test]
async fn host_pool() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-pool").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(GATEWAY_API_HOST_POOL, &ns.name, &[]).await?;

    let host = format!("pool.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // Round-robin across echo-a and echo-b — collect enough responses to see both.
    let mut saw_a = false;
    let mut saw_b = false;
    for _ in 0..20 {
        let resp = h.http.get(&host, "/").await?;
        let pod = resp.pod.as_deref().unwrap_or("");
        if pod.starts_with("echo-a-") {
            saw_a = true;
        }
        if pod.starts_with("echo-b-") {
            saw_b = true;
        }
        if saw_a && saw_b {
            break;
        }
    }
    assert!(saw_a, "never saw echo-a in round-robin pool");
    assert!(saw_b, "never saw echo-b in round-robin pool");

    Ok(())
}

#[tokio::test]
async fn wildcard_host() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-wildcard").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(GATEWAY_API_WILDCARD_HOST, &ns.name, &[]).await?;

    // Any subdomain of *.wildcard.TESTNS.local should reach echo-c.
    let host = format!("foo.wildcard.{}.local", ns.name);
    let resp = wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-c");

    let host2 = format!("bar.wildcard.{}.local", ns.name);
    let resp2 = h.http.get(&host2, "/").await?;
    resp2.assert_backend("echo-c");

    Ok(())
}

#[tokio::test]
async fn cross_namespace_with_grant() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-xns").await?;
    let tenant = NamespaceGuard::create(&h.client, "gw-xns-tenant").await?;

    // Deploy the backend + ReferenceGrant into the tenant namespace.
    fixtures::apply_fixture(
        GATEWAY_API_CROSS_NAMESPACE_TENANT,
        &tenant.name,
        &[("TESTNS", &ns.name)],
    )
    .await?;
    wait::wait_for_deployments(&tenant.name, &["echo-d"]).await?;

    // Deploy the Gateway + HTTPRoute into the primary namespace.
    fixtures::apply_fixture(
        GATEWAY_API_CROSS_NAMESPACE_ROUTE,
        &ns.name,
        &[("TENANTNS", &tenant.name)],
    )
    .await?;

    let host = format!("cross-ns.{}.local", ns.name);
    let resp = wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-d");

    Ok(())
}

#[tokio::test]
async fn gateway_status() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-status").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(GATEWAY_API_PATH_MATCHING, &ns.name, &[]).await?;

    wait::wait_for_gateway_programmed(
        &h.client,
        "coxswain-test",
        &ns.name,
        Duration::from_secs(30),
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn header_matching() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-hdr").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(GATEWAY_API_HEADER_MATCHING, &ns.name, &[]).await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // Exact header match → echo-a
    let (status, body) = h
        .http
        .request(Method::GET, &host, "/hdr", &[("X-Tenant", "a")])
        .await?;
    assert_eq!(status, 200, "expected 200 for exact header match");
    body.unwrap().assert_backend("echo-a");

    // Regex header match → echo-b
    let (status, body) = h
        .http
        .request(Method::GET, &host, "/hdr", &[("X-Tenant", "beta")])
        .await?;
    assert_eq!(status, 200, "expected 200 for regex header match");
    body.unwrap().assert_backend("echo-b");

    // No matching header → no route
    let (status, _) = h.http.request(Method::GET, &host, "/hdr", &[]).await?;
    assert_ne!(
        status, 200,
        "expected non-200 when header predicate not satisfied"
    );

    Ok(())
}

#[tokio::test]
async fn method_matching() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-method").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(GATEWAY_API_METHOD_MATCHING, &ns.name, &[]).await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // GET → echo-a
    let (status, body) = h.http.request(Method::GET, &host, "/method", &[]).await?;
    assert_eq!(status, 200, "expected 200 for GET");
    body.unwrap().assert_backend("echo-a");

    // POST → echo-b
    let (status, body) = h.http.request(Method::POST, &host, "/method", &[]).await?;
    assert_eq!(status, 200, "expected 200 for POST");
    body.unwrap().assert_backend("echo-b");

    Ok(())
}

#[tokio::test]
async fn query_param_matching() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-query").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(GATEWAY_API_QUERY_PARAM_MATCHING, &ns.name, &[]).await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // Exact query param match → echo-a
    let (status, body) = h
        .http
        .request(Method::GET, &host, "/query?version=v1", &[])
        .await?;
    assert_eq!(status, 200, "expected 200 for exact query param match");
    body.unwrap().assert_backend("echo-a");

    // Regex query param match → echo-b
    let (status, body) = h
        .http
        .request(Method::GET, &host, "/query?version=v2.5", &[])
        .await?;
    assert_eq!(status, 200, "expected 200 for regex query param match");
    body.unwrap().assert_backend("echo-b");

    // No matching query param → no route
    let (status, _) = h.http.request(Method::GET, &host, "/query", &[]).await?;
    assert_ne!(
        status, 200,
        "expected non-200 when query predicate not satisfied"
    );

    Ok(())
}

#[tokio::test]
async fn combined_matching() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-combined").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(GATEWAY_API_COMBINED_MATCHING, &ns.name, &[]).await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&h.http, &host, "/", Duration::from_secs(60)).await?;

    // AND semantics: GET + X-Env: prod → echo-a
    let (status, body) = h
        .http
        .request(Method::GET, &host, "/combined", &[("X-Env", "prod")])
        .await?;
    assert_eq!(status, 200, "expected 200 for GET + X-Env: prod");
    body.unwrap().assert_backend("echo-a");

    // OR semantics: second match (POST + X-Env: staging) also routes to echo-a
    let (status, body) = h
        .http
        .request(Method::POST, &host, "/combined", &[("X-Env", "staging")])
        .await?;
    assert_eq!(status, 200, "expected 200 for POST + X-Env: staging");
    body.unwrap().assert_backend("echo-a");

    // AND semantics failure: correct method, wrong header value → no match
    let (status, _) = h
        .http
        .request(Method::GET, &host, "/combined", &[("X-Env", "dev")])
        .await?;
    assert_ne!(
        status, 200,
        "expected non-200 when AND predicates not fully satisfied"
    );

    Ok(())
}

#[tokio::test]
async fn cross_namespace_without_grant() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-xns-deny").await?;
    let tenant = NamespaceGuard::create(&h.client, "gw-xns-deny-tenant").await?;

    // Deploy tenant backend WITHOUT a ReferenceGrant.
    // Apply only the Deployment + Service from the tenant fixture
    // by stripping the ReferenceGrant via a second apply after deletion.
    fixtures::apply_fixture(
        GATEWAY_API_CROSS_NAMESPACE_TENANT,
        &tenant.name,
        &[("TESTNS", &ns.name)],
    )
    .await?;
    wait::wait_for_deployments(&tenant.name, &["echo-d"]).await?;

    // Delete the ReferenceGrant that was just applied.
    tokio::process::Command::new("kubectl")
        .args([
            "delete",
            "referencegrant",
            &format!("allow-httproute-from-{}", ns.name),
            "-n",
            &tenant.name,
            "--ignore-not-found",
        ])
        .status()
        .await?;

    fixtures::apply_fixture(
        GATEWAY_API_CROSS_NAMESPACE_ROUTE,
        &ns.name,
        &[("TENANTNS", &tenant.name)],
    )
    .await?;

    let host = format!("cross-ns.{}.local", ns.name);

    // Give the controller time to reconcile; without the grant the host is
    // never added to the routing table, so requests should return 503.
    tokio::time::sleep(Duration::from_secs(5)).await;

    let status = h.http.get_status(&host, "/").await?;
    assert_eq!(
        status, 503,
        "expected 503 without ReferenceGrant, got {status}"
    );

    Ok(())
}

/// Gateway API TLS termination with SNI selection:
/// - Two HTTPS listeners, each backed by a distinct self-signed cert.
/// - Each SNI routes to the correct backend.
/// - Unknown SNI fails the TLS handshake.
#[tokio::test]
async fn tls_termination_with_sni() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-tls-sni").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host_a = format!("tls-a.{}.local", ns.name);
    let host_b = format!("tls-b.{}.local", ns.name);
    let cert_a = GeneratedCert::for_host(&host_a);
    let cert_b = GeneratedCert::for_host(&host_b);

    fixtures::apply_fixture(
        GATEWAY_API_TLS_TERMINATION,
        &ns.name,
        &[
            ("LISTENER_A_HOSTNAME", &host_a),
            ("LISTENER_B_HOSTNAME", &host_b),
            ("SECRET_A_NAME", "cert-a"),
            ("SECRET_B_NAME", "cert-b"),
            ("TLS_CRT_A_B64", &cert_a.cert_b64()),
            ("TLS_KEY_A_B64", &cert_a.key_b64()),
            ("TLS_CRT_B_B64", &cert_b.cert_b64()),
            ("TLS_KEY_B_B64", &cert_b.key_b64()),
        ],
    )
    .await?;

    let resp_a =
        wait::wait_for_https_route(h.tls_addr, &host_a, "/", Duration::from_secs(60)).await?;
    resp_a.assert_backend("echo-a");

    let resp_b =
        wait::wait_for_https_route(h.tls_addr, &host_b, "/", Duration::from_secs(60)).await?;
    resp_b.assert_backend("echo-b");

    // Unknown SNI must cause a TLS handshake failure (no cert installed).
    let unknown = format!("unknown.{}.local", ns.name);
    let result = http::https_get(&unknown, "/", h.tls_addr).await;
    assert!(
        result.is_err(),
        "expected TLS error for unknown SNI, got: {result:?}"
    );

    Ok(())
}

/// Gateway with an HTTPS listener referencing a non-existent Secret must have
/// `Programmed=False` with `reason=ListenersNotValid`. Once the Secret is
/// created the condition must flip to `Programmed=True`.
#[tokio::test]
async fn tls_missing_secret_marks_gateway_not_programmed() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-tls-missing").await?;

    let host = format!("tls-missing.{}.local", ns.name);
    let secret_name = "cert-missing";

    // Apply a Gateway with an HTTPS listener whose Secret does not exist yet.
    fixtures::apply_fixture(
        GATEWAY_API_TLS_GATEWAY_NO_CERTS,
        &ns.name,
        &[("LISTENER_HOSTNAME", &host), ("SECRET_NAME", secret_name)],
    )
    .await?;

    // Controller must mark the Gateway as not programmed within 30 s.
    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-tls-no-cert",
        &ns.name,
        "Programmed",
        "False",
        Duration::from_secs(30),
    )
    .await?;

    // Per-listener ResolvedRefs must also be False.
    wait::wait_for_gateway_listener_condition(
        &h.client,
        "coxswain-tls-no-cert",
        &ns.name,
        "https",
        "ResolvedRefs",
        "False",
        Duration::from_secs(10),
    )
    .await?;

    // Now create the Secret — the controller should recover.
    let cert = GeneratedCert::for_host(&host);
    let secrets_api: Api<Secret> = Api::namespaced(h.client.clone(), &ns.name);
    secrets_api
        .create(
            &PostParams::default(),
            &Secret {
                metadata: ObjectMeta {
                    name: Some(secret_name.to_string()),
                    ..Default::default()
                },
                type_: Some("kubernetes.io/tls".to_string()),
                data: Some({
                    let mut m = BTreeMap::new();
                    m.insert(
                        "tls.crt".to_string(),
                        k8s_openapi::ByteString(cert.cert_pem.as_bytes().to_vec()),
                    );
                    m.insert(
                        "tls.key".to_string(),
                        k8s_openapi::ByteString(cert.key_pem.as_bytes().to_vec()),
                    );
                    m
                }),
                ..Default::default()
            },
        )
        .await?;

    // After the Secret is available the Gateway must flip to Programmed=True.
    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-tls-no-cert",
        &ns.name,
        "Programmed",
        "True",
        Duration::from_secs(30),
    )
    .await?;

    Ok(())
}

/// Gateway in one namespace references a Secret in a separate namespace,
/// permitted by a ReferenceGrant. HTTPS must work end-to-end.
#[tokio::test]
async fn tls_cross_namespace_with_grant() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-tls-xns").await?;
    let certs_ns = NamespaceGuard::create(&h.client, "gw-tls-xns-certs").await?;

    // Deploy backend in the primary namespace.
    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("tls-xns.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&host);
    let secret_name = "xns-cert";

    // Deploy Secret + ReferenceGrant into the certs namespace.
    fixtures::apply_fixture(
        GATEWAY_API_TLS_CROSS_NAMESPACE_CERTS,
        &certs_ns.name,
        &[
            ("TESTNS", &ns.name),
            ("SECRET_NAME", secret_name),
            ("TLS_CRT_B64", &cert.cert_b64()),
            ("TLS_KEY_B64", &cert.key_b64()),
        ],
    )
    .await?;

    // Deploy Gateway + HTTPRoute into the primary namespace.
    fixtures::apply_fixture(
        GATEWAY_API_TLS_CROSS_NAMESPACE_GW,
        &ns.name,
        &[
            ("CERTS_NS", &certs_ns.name),
            ("LISTENER_HOSTNAME", &host),
            ("SECRET_NAME", secret_name),
        ],
    )
    .await?;

    let resp = wait::wait_for_https_route(h.tls_addr, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    Ok(())
}

/// Verifies that rotating a `kubernetes.io/tls` Secret referenced by a Gateway listener
/// causes the new certificate to be served without a process restart:
/// 1. Apply a Gateway with two HTTPS listeners and capture the leaf DER for listener A.
/// 2. Re-apply the same fixture with new PEM data for Secret A only.
/// 3. Poll until listener A's served leaf DER changes — listener B must remain unchanged.
/// 4. Assert routing still works on both listeners after the swap.
#[tokio::test]
async fn tls_certificate_hot_rotation() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-tls-rotate").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host_a = format!("tls-rot-a.{}.local", ns.name);
    let host_b = format!("tls-rot-b.{}.local", ns.name);
    let cert_a_old = GeneratedCert::for_host(&host_a);
    let cert_a_new = GeneratedCert::for_host(&host_a);
    let cert_b = GeneratedCert::for_host(&host_b);

    // Deploy with original certs.
    fixtures::apply_fixture(
        GATEWAY_API_TLS_TERMINATION,
        &ns.name,
        &[
            ("LISTENER_A_HOSTNAME", &host_a),
            ("LISTENER_B_HOSTNAME", &host_b),
            ("SECRET_A_NAME", "cert-rotate-a"),
            ("SECRET_B_NAME", "cert-rotate-b"),
            ("TLS_CRT_A_B64", &cert_a_old.cert_b64()),
            ("TLS_KEY_A_B64", &cert_a_old.key_b64()),
            ("TLS_CRT_B_B64", &cert_b.cert_b64()),
            ("TLS_KEY_B_B64", &cert_b.key_b64()),
        ],
    )
    .await?;

    wait::wait_for_https_route(h.tls_addr, &host_a, "/", Duration::from_secs(60)).await?;
    wait::wait_for_https_route(h.tls_addr, &host_b, "/", Duration::from_secs(60)).await?;

    let old_der_a = http::https_peer_leaf_der(&host_a, "/", h.tls_addr).await?;
    let old_der_b = http::https_peer_leaf_der(&host_b, "/", h.tls_addr).await?;

    // Rotate only Secret A; Secret B data is unchanged.
    fixtures::apply_fixture(
        GATEWAY_API_TLS_TERMINATION,
        &ns.name,
        &[
            ("LISTENER_A_HOSTNAME", &host_a),
            ("LISTENER_B_HOSTNAME", &host_b),
            ("SECRET_A_NAME", "cert-rotate-a"),
            ("SECRET_B_NAME", "cert-rotate-b"),
            ("TLS_CRT_A_B64", &cert_a_new.cert_b64()),
            ("TLS_KEY_A_B64", &cert_a_new.key_b64()),
            ("TLS_CRT_B_B64", &cert_b.cert_b64()),
            ("TLS_KEY_B_B64", &cert_b.key_b64()),
        ],
    )
    .await?;

    // Listener A must pick up the new cert.
    wait::wait_for_tls_cert_rotation(h.tls_addr, &host_a, &old_der_a, Duration::from_secs(15))
        .await?;

    // Listener B must still serve the original cert (no spurious swap).
    let new_der_b = http::https_peer_leaf_der(&host_b, "/", h.tls_addr).await?;
    assert_eq!(old_der_b, new_der_b, "listener B cert must not change");

    // Both listeners must still route correctly.
    let resp_a = http::https_get(&host_a, "/", h.tls_addr).await?;
    assert!(
        resp_a.1.is_some(),
        "expected response from listener A after rotation"
    );
    resp_a.1.unwrap().assert_backend("echo-a");

    let resp_b = http::https_get(&host_b, "/", h.tls_addr).await?;
    assert!(
        resp_b.1.is_some(),
        "expected response from listener B after rotation"
    );
    resp_b.1.unwrap().assert_backend("echo-b");

    Ok(())
}

/// Verifies cert-manager automatic certificate provisioning for Gateway API:
/// 1. Apply a Gateway with cert-manager.io/cluster-issuer annotation.
/// 2. cert-manager (using the coxswain-e2e-selfsigned ClusterIssuer) provisions
///    the kubernetes.io/tls Secret named in the listener's certificateRefs[0].
/// 3. Coxswain picks up the Secret via its Secret watch and serves TLS.
/// 4. HTTPS request succeeds and routes to the expected backend.
#[tokio::test]
async fn cert_manager_gateway_provisioning() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-cert-mgr").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("tls-cm.{}.local", ns.name);
    let secret_name = "cert-manager-tls";

    fixtures::apply_fixture(
        GATEWAY_API_CERT_MANAGER,
        &ns.name,
        &[("LISTENER_HOSTNAME", &host), ("SECRET_NAME", secret_name)],
    )
    .await?;

    // Wait for cert-manager to issue the certificate and populate the Secret.
    wait::wait_for_tls_secret(&h.client, secret_name, &ns.name, Duration::from_secs(120)).await?;

    // Coxswain picks up the Secret via its Secret watch; wait for HTTPS to become live.
    let resp = wait::wait_for_https_route(h.tls_addr, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    Ok(())
}

/// Verifies that WebSocket upgrade requests are proxied end-to-end through Coxswain:
/// 1. Deploy a WebSocket echo server (jmalloc/echo-server).
/// 2. Route ws.TESTNS.local → ws-echo via an HTTPRoute.
/// 3. Connect via WebSocket through the proxy (Host header set for virtual hosting).
/// 4. Send a text frame and assert the same frame echoes back.
#[tokio::test]
async fn websocket_passthrough() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-ws").await?;

    fixtures::apply_fixture(BACKENDS_WEBSOCKET_ECHO, &ns.name, &[]).await?;
    wait::wait_for_deployments(&ns.name, &["ws-echo"]).await?;
    fixtures::apply_fixture(GATEWAY_API_WEBSOCKET, &ns.name, &[]).await?;

    let host = format!("ws.{}.local", ns.name);

    // Poll until the proxy returns a 101 for this virtual host.
    wait::wait_for_ws_route(h.controller.proxy_addr, &host, Duration::from_secs(60)).await?;

    // Open a fresh WebSocket connection and verify the echo round-trip.
    let uri = format!("ws://{}/", h.controller.proxy_addr);
    let req = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(&uri)
        .header("Host", &host)
        .body(())
        .expect("build WebSocket request");
    let (mut ws, _) = tokio_tungstenite::connect_async(req).await?;

    ws.send(Message::Text("ping".into())).await?;
    let reply = ws
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("WebSocket stream closed before echo"))??;
    assert_eq!(
        reply,
        Message::Text("ping".into()),
        "expected echo of 'ping'"
    );

    ws.close(None).await?;
    Ok(())
}
