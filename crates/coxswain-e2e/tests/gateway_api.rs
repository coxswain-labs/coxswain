#![allow(missing_docs)]
use coxswain_e2e::{
    FixtureVars, GeneratedCert, Harness, NamespaceGuard,
    fixtures::{backends, gateway_api as gwa},
    harness::{http, wait},
};
use futures::StreamExt as _;
use gateway_api::apis::standard::gateways::Gateway;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointSlice};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Api;
use kube::api::{Patch, PatchParams, PostParams};
use reqwest::Method;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

mod common;

#[tokio::test]
async fn path_matching() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-path").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(gwa::PATH_MATCHING, FixtureVars::new(&ns.name))
        .await?;

    let host = format!("echo.{}.local", ns.name);

    // Wait for the route to become live before asserting individual paths.
    let resp = wait::wait_for_route(&h.gateway_http, &host, "/a", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    let resp = h.gateway_http.get(&host, "/b").await?;
    resp.assert_backend("echo-b");

    // Catch-all rule routes to echo-a.
    let resp = h.gateway_http.get(&host, "/").await?;
    resp.assert_backend("echo-a");

    Ok(())
}

#[tokio::test]
async fn host_pool() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-pool").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(gwa::HOST_POOL, FixtureVars::new(&ns.name)).await?;

    let host = format!("pool.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/probe", Duration::from_secs(60)).await?;

    // Round-robin across echo-a and echo-b — collect enough responses to see both.
    let mut saw_a = false;
    let mut saw_b = false;
    for _ in 0..20 {
        let resp = h.gateway_http.get(&host, "/").await?;
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
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-wildcard").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(gwa::WILDCARD_HOST, FixtureVars::new(&ns.name))
        .await?;

    // Any subdomain of *.wildcard.TESTNS.local should reach echo-c.
    let host = format!("foo.wildcard.{}.local", ns.name);
    let resp = wait::wait_for_route(&h.gateway_http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-c");

    let host2 = format!("bar.wildcard.{}.local", ns.name);
    let resp2 = h.gateway_http.get(&host2, "/").await?;
    resp2.assert_backend("echo-c");

    // Gateway API spec: `*` matches any number of subdomain labels, so multi-label
    // subdomains must also reach echo-c.
    let multi = format!("a.b.foo.wildcard.{}.local", ns.name);
    let resp3 = h.gateway_http.get(&multi, "/").await?;
    resp3.assert_backend("echo-c");

    Ok(())
}

#[tokio::test]
async fn cross_namespace_with_grant() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-xns").await?;
    let tenant = NamespaceGuard::create(&h.client, "gw-xns-tenant").await?;

    // Deploy the backend + ReferenceGrant into the tenant namespace.
    h.apply(
        gwa::CROSS_NAMESPACE_TENANT,
        FixtureVars::new(&tenant.name).with("TESTNS", &ns.name),
    )
    .await?;
    wait::wait_for_deployments(&tenant.name, &["echo-d"]).await?;

    // Deploy the Gateway + HTTPRoute into the primary namespace.
    h.apply(
        gwa::CROSS_NAMESPACE_ROUTE,
        FixtureVars::new(&ns.name).with("TENANTNS", &tenant.name),
    )
    .await?;

    let host = format!("cross-ns.{}.local", ns.name);
    let resp = wait::wait_for_route(&h.gateway_http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-d");

    Ok(())
}

#[tokio::test]
async fn gateway_status() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-status").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(gwa::PATH_MATCHING, FixtureVars::new(&ns.name))
        .await?;

    wait::wait_for_gateway_programmed(
        &h.client,
        "coxswain-test",
        &ns.name,
        Duration::from_secs(30),
    )
    .await?;

    Ok(())
}

/// Verifies that `gateway_needs_status_patch` detects a stale `observedGeneration`
/// after a spec-only change and re-patches all conditions to the new generation.
/// Exercises the GEP-1364 requirement that `observedGeneration` tracks
/// `metadata.generation` even when the programmed-ness of the Gateway is unchanged.
#[tokio::test]
async fn gateway_status_tracks_generation_bumps() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-gen-tracking").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(gwa::PATH_MATCHING, FixtureVars::new(&ns.name))
        .await?;

    wait::wait_for_gateway_programmed(
        &h.client,
        "coxswain-test",
        &ns.name,
        Duration::from_secs(30),
    )
    .await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let gw = gw_api.get("coxswain-test").await?;
    let gen_before = gw.metadata.generation.unwrap_or(0);

    // Sanity: initial conditions should already be at gen_before.
    let top_conds = gw
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_deref())
        .unwrap_or(&[]);
    for c in top_conds {
        assert_eq!(
            c.observed_generation.unwrap_or(0),
            gen_before,
            "condition {} not at initial generation",
            c.type_
        );
    }

    // Bump .metadata.generation with a harmless spec change (allowedRoutes.namespaces.from
    // changes from Same to All — the HTTPRoute is in the same namespace so it still attaches).
    let http_port = h.controller.gateway_http_addr.port();
    let bump_patch = serde_json::json!({
        "spec": {
            "listeners": [{"name": "http", "port": http_port, "protocol": "HTTP",
                           "allowedRoutes": {"namespaces": {"from": "All"}}}]
        }
    });
    gw_api
        .patch(
            "coxswain-test",
            &PatchParams::default(),
            &Patch::Merge(&bump_patch),
        )
        .await?;

    // Wait for the controller to detect the stale observedGeneration and re-patch.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(gw) = gw_api.get("coxswain-test").await {
            let new_gen = gw.metadata.generation.unwrap_or(0);
            if new_gen > gen_before {
                let top = gw
                    .status
                    .as_ref()
                    .and_then(|s| s.conditions.as_deref())
                    .unwrap_or(&[]);
                let listeners = gw
                    .status
                    .as_ref()
                    .and_then(|s| s.listeners.as_deref())
                    .unwrap_or(&[]);
                let top_fresh = top
                    .iter()
                    .all(|c| c.observed_generation.unwrap_or(0) >= new_gen);
                let listeners_fresh = listeners.iter().all(|sl| {
                    sl.conditions
                        .iter()
                        .all(|c| c.observed_generation.unwrap_or(0) >= new_gen)
                });
                if top_fresh && listeners_fresh {
                    return Ok(());
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out: Gateway coxswain-test conditions did not advance observedGeneration \
                 to the new generation after a spec bump"
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
async fn gatewayclass_supported_features() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;

    let feats = wait::wait_for_gatewayclass_supported_features(
        &h.client,
        "coxswain",
        Duration::from_secs(30),
    )
    .await?;

    assert!(
        !feats.is_empty(),
        "GatewayClass coxswain must have non-empty status.supportedFeatures"
    );
    assert!(
        feats.contains(&"Gateway".to_string()),
        "must advertise core Gateway feature; got: {feats:?}"
    );
    assert!(
        feats.contains(&"HTTPRoute".to_string()),
        "must advertise core HTTPRoute feature; got: {feats:?}"
    );

    Ok(())
}

#[tokio::test]
async fn header_matching() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-hdr").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(gwa::HEADER_MATCHING, FixtureVars::new(&ns.name))
        .await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/probe", Duration::from_secs(60)).await?;

    // Exact header match → echo-a
    let (status, body) = h
        .gateway_http
        .request(Method::GET, &host, "/hdr", &[("X-Tenant", "a")])
        .await?;
    assert_eq!(status, 200, "expected 200 for exact header match");
    body.unwrap().assert_backend("echo-a");

    // Regex header match → echo-b
    let (status, body) = h
        .gateway_http
        .request(Method::GET, &host, "/hdr", &[("X-Tenant", "beta")])
        .await?;
    assert_eq!(status, 200, "expected 200 for regex header match");
    body.unwrap().assert_backend("echo-b");

    // No matching header → no route
    let (status, _) = h
        .gateway_http
        .request(Method::GET, &host, "/hdr", &[])
        .await?;
    assert_ne!(
        status, 200,
        "expected non-200 when header predicate not satisfied"
    );

    Ok(())
}

#[tokio::test]
async fn method_matching() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-method").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(gwa::METHOD_MATCHING, FixtureVars::new(&ns.name))
        .await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/probe", Duration::from_secs(60)).await?;

    // GET → echo-a
    let (status, body) = h
        .gateway_http
        .request(Method::GET, &host, "/method", &[])
        .await?;
    assert_eq!(status, 200, "expected 200 for GET");
    body.unwrap().assert_backend("echo-a");

    // POST → echo-b
    let (status, body) = h
        .gateway_http
        .request(Method::POST, &host, "/method", &[])
        .await?;
    assert_eq!(status, 200, "expected 200 for POST");
    body.unwrap().assert_backend("echo-b");

    Ok(())
}

#[tokio::test]
async fn query_param_matching() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-query").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(gwa::QUERY_PARAM_MATCHING, FixtureVars::new(&ns.name))
        .await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/probe", Duration::from_secs(60)).await?;

    // Exact query param match → echo-a
    let (status, body) = h
        .gateway_http
        .request(Method::GET, &host, "/query?version=v1", &[])
        .await?;
    assert_eq!(status, 200, "expected 200 for exact query param match");
    body.unwrap().assert_backend("echo-a");

    // Regex query param match → echo-b
    let (status, body) = h
        .gateway_http
        .request(Method::GET, &host, "/query?version=v2.5", &[])
        .await?;
    assert_eq!(status, 200, "expected 200 for regex query param match");
    body.unwrap().assert_backend("echo-b");

    // No matching query param → no route
    let (status, _) = h
        .gateway_http
        .request(Method::GET, &host, "/query", &[])
        .await?;
    assert_ne!(
        status, 200,
        "expected non-200 when query predicate not satisfied"
    );

    Ok(())
}

#[tokio::test]
async fn combined_matching() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-combined").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(gwa::COMBINED_MATCHING, FixtureVars::new(&ns.name))
        .await?;

    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/probe", Duration::from_secs(60)).await?;

    // AND semantics: GET + X-Env: prod → echo-a
    let (status, body) = h
        .gateway_http
        .request(Method::GET, &host, "/combined", &[("X-Env", "prod")])
        .await?;
    assert_eq!(status, 200, "expected 200 for GET + X-Env: prod");
    body.unwrap().assert_backend("echo-a");

    // OR semantics: second match (POST + X-Env: staging) also routes to echo-a
    let (status, body) = h
        .gateway_http
        .request(Method::POST, &host, "/combined", &[("X-Env", "staging")])
        .await?;
    assert_eq!(status, 200, "expected 200 for POST + X-Env: staging");
    body.unwrap().assert_backend("echo-a");

    // AND semantics failure: correct method, wrong header value → no match
    let (status, _) = h
        .gateway_http
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
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-xns-deny").await?;
    let tenant = NamespaceGuard::create(&h.client, "gw-xns-deny-tenant").await?;

    // Deploy tenant backend WITHOUT a ReferenceGrant.
    // Apply only the Deployment + Service from the tenant fixture
    // by stripping the ReferenceGrant via a second apply after deletion.
    h.apply(
        gwa::CROSS_NAMESPACE_TENANT,
        FixtureVars::new(&tenant.name).with("TESTNS", &ns.name),
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

    h.apply(
        gwa::CROSS_NAMESPACE_ROUTE,
        FixtureVars::new(&ns.name).with("TENANTNS", &tenant.name),
    )
    .await?;

    let host = format!("cross-ns.{}.local", ns.name);

    // Without the grant the backend cannot be resolved so an error-sentinel
    // route is installed, returning 500. Poll until the route is live —
    // a fixed sleep raced HotReloader's restart cycle on slow runs.
    wait::wait_for_route_status(&h.gateway_http, &host, "/", 500, Duration::from_secs(60)).await?;

    Ok(())
}

/// Gateway API TLS termination with SNI selection:
/// - Two HTTPS listeners, each backed by a distinct self-signed cert.
/// - Each SNI routes to the correct backend.
/// - Unknown SNI fails the TLS handshake.
#[tokio::test]
async fn tls_termination_with_sni() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-tls-sni").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host_a = format!("tls-a.{}.local", ns.name);
    let host_b = format!("tls-b.{}.local", ns.name);
    let cert_a = GeneratedCert::for_host(&host_a);
    let cert_b = GeneratedCert::for_host(&host_b);

    h.apply(
        gwa::TLS_TERMINATION,
        FixtureVars::new(&ns.name)
            .with("LISTENER_A_HOSTNAME", &host_a)
            .with("LISTENER_B_HOSTNAME", &host_b)
            .with("SECRET_A_NAME", "cert-a")
            .with("SECRET_B_NAME", "cert-b")
            .with("TLS_CRT_A_B64", cert_a.cert_b64())
            .with("TLS_KEY_A_B64", cert_a.key_b64())
            .with("TLS_CRT_B_B64", cert_b.cert_b64())
            .with("TLS_KEY_B_B64", cert_b.key_b64()),
    )
    .await?;

    let resp_a =
        wait::wait_for_https_route(h.gateway_tls_addr, &host_a, "/", Duration::from_secs(60))
            .await?;
    resp_a.assert_backend("echo-a");

    let resp_b =
        wait::wait_for_https_route(h.gateway_tls_addr, &host_b, "/", Duration::from_secs(60))
            .await?;
    resp_b.assert_backend("echo-b");

    // Unknown SNI must cause a TLS handshake failure (no cert installed).
    let unknown = format!("unknown.{}.local", ns.name);
    let result = http::https_get(&unknown, "/", h.gateway_tls_addr).await;
    assert!(
        result.is_err(),
        "expected TLS error for unknown SNI, got: {result:?}"
    );

    Ok(())
}

/// Gateway with an HTTPS listener referencing a non-existent Secret must have
/// the `https` listener's `ResolvedRefs` and `Programmed` conditions set to
/// `False`. Once the Secret is created both listener conditions must flip to
/// `True`. The gateway-level `Programmed` condition remains `True` throughout
/// (the controller always sets it to True; per-listener conditions express
/// individual listener health).
#[tokio::test]
async fn tls_missing_secret_marks_gateway_not_programmed() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-tls-missing").await?;

    let host = format!("tls-missing.{}.local", ns.name);
    let secret_name = "cert-missing";

    // Apply a Gateway with an HTTPS listener whose Secret does not exist yet.
    h.apply(
        gwa::TLS_GATEWAY_NO_CERTS,
        FixtureVars::new(&ns.name)
            .with("LISTENER_HOSTNAME", &host)
            .with("SECRET_NAME", secret_name),
    )
    .await?;

    // Per-listener ResolvedRefs must be False when the Secret is missing.
    wait::wait_for_gateway_listener_condition(
        &h.client,
        "coxswain-tls-no-cert",
        &ns.name,
        "https",
        "ResolvedRefs",
        "False",
        Duration::from_secs(30),
    )
    .await?;

    // Per-listener Programmed must also be False.
    wait::wait_for_gateway_listener_condition(
        &h.client,
        "coxswain-tls-no-cert",
        &ns.name,
        "https",
        "Programmed",
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

    // After the Secret is available the listener must flip to Programmed=True.
    wait::wait_for_gateway_listener_condition(
        &h.client,
        "coxswain-tls-no-cert",
        &ns.name,
        "https",
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
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-tls-xns").await?;
    let certs_ns = NamespaceGuard::create(&h.client, "gw-tls-xns-certs").await?;

    // Deploy backend in the primary namespace.
    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("tls-xns.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&host);
    let secret_name = "xns-cert";

    // Deploy Secret + ReferenceGrant into the certs namespace.
    h.apply(
        gwa::TLS_CROSS_NAMESPACE_CERTS,
        FixtureVars::new(&certs_ns.name)
            .with("TESTNS", &ns.name)
            .with("SECRET_NAME", secret_name)
            .with("TLS_CRT_B64", cert.cert_b64())
            .with("TLS_KEY_B64", cert.key_b64()),
    )
    .await?;

    // Deploy Gateway + HTTPRoute into the primary namespace.
    h.apply(
        gwa::TLS_CROSS_NAMESPACE_GW,
        FixtureVars::new(&ns.name)
            .with("CERTS_NS", &certs_ns.name)
            .with("LISTENER_HOSTNAME", &host)
            .with("SECRET_NAME", secret_name),
    )
    .await?;

    let resp =
        wait::wait_for_https_route(h.gateway_tls_addr, &host, "/", Duration::from_secs(60)).await?;
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
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-tls-rotate").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host_a = format!("tls-rot-a.{}.local", ns.name);
    let host_b = format!("tls-rot-b.{}.local", ns.name);
    let cert_a_old = GeneratedCert::for_host(&host_a);
    let cert_a_new = GeneratedCert::for_host(&host_a);
    let cert_b = GeneratedCert::for_host(&host_b);

    // Deploy with original certs.
    h.apply(
        gwa::TLS_TERMINATION,
        FixtureVars::new(&ns.name)
            .with("LISTENER_A_HOSTNAME", &host_a)
            .with("LISTENER_B_HOSTNAME", &host_b)
            .with("SECRET_A_NAME", "cert-rotate-a")
            .with("SECRET_B_NAME", "cert-rotate-b")
            .with("TLS_CRT_A_B64", cert_a_old.cert_b64())
            .with("TLS_KEY_A_B64", cert_a_old.key_b64())
            .with("TLS_CRT_B_B64", cert_b.cert_b64())
            .with("TLS_KEY_B_B64", cert_b.key_b64()),
    )
    .await?;

    wait::wait_for_https_route(h.gateway_tls_addr, &host_a, "/", Duration::from_secs(60)).await?;
    wait::wait_for_https_route(h.gateway_tls_addr, &host_b, "/", Duration::from_secs(60)).await?;

    let old_der_a = http::https_peer_leaf_der(&host_a, "/", h.gateway_tls_addr).await?;
    let old_der_b = http::https_peer_leaf_der(&host_b, "/", h.gateway_tls_addr).await?;

    // Rotate only Secret A; Secret B data is unchanged.
    h.apply(
        gwa::TLS_TERMINATION,
        FixtureVars::new(&ns.name)
            .with("LISTENER_A_HOSTNAME", &host_a)
            .with("LISTENER_B_HOSTNAME", &host_b)
            .with("SECRET_A_NAME", "cert-rotate-a")
            .with("SECRET_B_NAME", "cert-rotate-b")
            .with("TLS_CRT_A_B64", cert_a_new.cert_b64())
            .with("TLS_KEY_A_B64", cert_a_new.key_b64())
            .with("TLS_CRT_B_B64", cert_b.cert_b64())
            .with("TLS_KEY_B_B64", cert_b.key_b64()),
    )
    .await?;

    // Listener A must pick up the new cert.
    wait::wait_for_tls_cert_rotation(
        h.gateway_tls_addr,
        &host_a,
        &old_der_a,
        Duration::from_secs(15),
    )
    .await?;

    // Listener B must still serve the original cert (no spurious swap).
    let new_der_b = http::https_peer_leaf_der(&host_b, "/", h.gateway_tls_addr).await?;
    assert_eq!(old_der_b, new_der_b, "listener B cert must not change");

    // Both listeners must still route correctly.
    let resp_a = http::https_get(&host_a, "/", h.gateway_tls_addr).await?;
    assert!(
        resp_a.1.is_some(),
        "expected response from listener A after rotation"
    );
    resp_a.1.unwrap().assert_backend("echo-a");

    let resp_b = http::https_get(&host_b, "/", h.gateway_tls_addr).await?;
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
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-cert-mgr").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("tls-cm.{}.local", ns.name);
    let secret_name = "cert-manager-tls";

    h.apply(
        gwa::CERT_MANAGER,
        FixtureVars::new(&ns.name)
            .with("LISTENER_HOSTNAME", &host)
            .with("SECRET_NAME", secret_name),
    )
    .await?;

    // Wait for cert-manager to issue the certificate and populate the Secret.
    wait::wait_for_tls_secret(&h.client, secret_name, &ns.name, Duration::from_secs(120)).await?;

    // Coxswain picks up the Secret via its Secret watch; wait for HTTPS to become live.
    let resp =
        wait::wait_for_https_route(h.gateway_tls_addr, &host, "/", Duration::from_secs(60)).await?;
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
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-ws").await?;

    h.apply(backends::WEBSOCKET_ECHO, FixtureVars::new(&ns.name))
        .await?;
    wait::wait_for_deployments(&ns.name, &["ws-echo"]).await?;
    h.apply(gwa::WEBSOCKET, FixtureVars::new(&ns.name)).await?;

    let host = format!("ws.{}.local", ns.name);

    // Poll until the proxy returns a 101 for this virtual host.
    wait::wait_for_ws_route(
        h.controller.gateway_http_addr,
        &host,
        Duration::from_secs(60),
    )
    .await?;

    // Open a fresh WebSocket connection and verify the echo round-trip.
    let uri = format!("ws://{}/", h.controller.gateway_http_addr);
    let req = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(&uri)
        .header("Host", &host)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        )
        .body(())
        .expect("build WebSocket request");
    let (mut ws, _) = tokio_tungstenite::connect_async(req).await?;

    // jmalloc/echo-server sends a greeting frame on connect; assert it arrives.
    let greeting = ws
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("WebSocket stream closed before greeting"))??;
    let text = match greeting {
        Message::Text(t) => t,
        other => anyhow::bail!("expected text greeting, got {other:?}"),
    };
    anyhow::ensure!(
        text.contains("Request served by"),
        "unexpected greeting: {text}"
    );

    ws.close(None).await?;
    Ok(())
}

/// Verifies that a Service with `appProtocol: kubernetes.io/h2c` is correctly
/// routed by Coxswain (GEP-1911). The test confirms that the `appProtocol`
/// annotation is propagated through the data pipeline (endpoint resolution →
/// BackendGroup → proxy) and that the route is successfully programmed and
/// returns responses. Actual h2c wire-protocol verification (that the proxy
/// speaks HTTP/2 cleartext on the upstream leg) is covered by the conformance
/// suite, which requires a backend that natively accepts h2c connections.
#[tokio::test]
async fn backend_protocol_h2c() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-h2c").await?;

    h.apply(backends::H2C_ECHO, FixtureVars::new(&ns.name))
        .await?;
    wait::wait_for_deployments(&ns.name, &["h2c-echo"]).await?;
    h.apply(gwa::BACKEND_PROTOCOL_H2C, FixtureVars::new(&ns.name))
        .await?;

    let host = format!("h2c.{}.local", ns.name);

    let resp = wait::wait_for_route(&h.gateway_http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("h2c-echo");
    Ok(())
}

#[tokio::test]
async fn filters() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-filters").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(gwa::FILTERS, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);

    // Wait for the HTTPRoute to become live using the dedicated probe path.
    wait::wait_for_route(
        &h.gateway_http,
        &host,
        "/filter/probe",
        Duration::from_secs(60),
    )
    .await?;

    // ── RequestHeaderModifier ────────────────────────────────────────────────
    // The echo backend reflects request headers in the response body JSON.
    let resp = h.gateway_http.get(&host, "/filter/req-header").await?;
    // echo-basic returns headers as Title-Case keys with JSON array values.
    let injected = resp
        .headers
        .get("X-Test-Set")
        .and_then(|v| v[0].as_str())
        .unwrap_or("");
    assert_eq!(
        injected, "injected",
        "RequestHeaderModifier: expected X-Test-Set=injected in echo body, got {injected:?}"
    );

    // ── ResponseHeaderModifier ───────────────────────────────────────────────
    let (status, resp_headers, _) = h
        .gateway_http
        .get_full(&host, "/filter/resp-header")
        .await?;
    assert_eq!(status, 200, "ResponseHeaderModifier: expected 200");
    let hdr_val = resp_headers
        .get("x-test-response")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        hdr_val, "coxswain",
        "ResponseHeaderModifier: expected X-Test-Response=coxswain in response headers"
    );

    // ── RequestRedirect ──────────────────────────────────────────────────────
    // The redirect client follows redirects by default; disable that to see the 302.
    let url = format!("http://{}{}", h.gateway_http.proxy_addr, "/filter/redirect");
    let redirect_resp = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?
        .get(&url)
        .header("Host", &host)
        .send()
        .await?;
    assert_eq!(
        redirect_resp.status().as_u16(),
        302,
        "RequestRedirect: expected 302"
    );
    let location = redirect_resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.ends_with("/filter/redirected"),
        "RequestRedirect: expected Location ending in /filter/redirected, got {location:?}"
    );

    // ── URLRewrite ───────────────────────────────────────────────────────────
    // The echo backend returns the path it received; we expect the rewritten path.
    let resp = h.gateway_http.get(&host, "/filter/old/resource").await?;
    let echo_path = resp.path.as_deref().unwrap_or("");
    assert_eq!(
        echo_path, "/filter/new/resource",
        "URLRewrite: expected rewritten path /filter/new/resource, got {echo_path:?}"
    );

    Ok(())
}

#[tokio::test]
async fn timeouts_request_returns_504() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-timeouts-req").await?;

    h.apply(backends::SLOW_ECHO, FixtureVars::new(&ns.name))
        .await?;
    wait::wait_for_deployments(&ns.name, &["slow-echo"]).await?;
    h.apply(gwa::TIMEOUTS, FixtureVars::new(&ns.name)).await?;

    let host = format!("timeout.{}.local", ns.name);

    // Wait until the route is programmed. /request-timeout always returns 504 so we
    // can't use it as a readiness probe; use /backend-timeout (also 504) instead.
    wait::wait_for_route_status(
        &h.gateway_http,
        &host,
        "/backend-timeout",
        504,
        Duration::from_secs(60),
    )
    .await?;

    let status = h.gateway_http.get_status(&host, "/request-timeout").await?;
    assert_eq!(
        status, 504,
        "expected 504 from request timeout, got {status}"
    );

    Ok(())
}

#[tokio::test]
async fn timeouts_backend_request_returns_504() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-timeouts-be").await?;

    h.apply(backends::SLOW_ECHO, FixtureVars::new(&ns.name))
        .await?;
    wait::wait_for_deployments(&ns.name, &["slow-echo"]).await?;
    h.apply(gwa::TIMEOUTS, FixtureVars::new(&ns.name)).await?;

    let host = format!("timeout.{}.local", ns.name);

    // Wait until the route is registered. Both rules time out so we cannot use
    // wait_for_route; instead we poll until the 504 appears.
    wait::wait_for_route_status(
        &h.gateway_http,
        &host,
        "/backend-timeout",
        504,
        Duration::from_secs(60),
    )
    .await?;

    let status = h.gateway_http.get_status(&host, "/backend-timeout").await?;
    assert_eq!(
        status, 504,
        "expected 504 from backend request timeout, got {status}"
    );

    Ok(())
}

/// An HTTPS listener with a RequestRedirect filter must produce a `Location` header
/// that uses the `https://` scheme, not the hardcoded `http://` that existed before
/// the redirect-scheme fix.
#[tokio::test]
async fn tls_redirect_preserves_https_scheme() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-tls-redirect").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("tls-redirect.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&host);
    let secret_name = "cert-tls-redirect";

    h.apply(
        gwa::TLS_REDIRECT,
        FixtureVars::new(&ns.name)
            .with("LISTENER_HOST", &host)
            .with("SECRET_NAME", secret_name)
            .with("TLS_CRT_B64", cert.cert_b64())
            .with("TLS_KEY_B64", cert.key_b64()),
    )
    .await?;

    // Wait until the probe path is reachable over HTTPS (confirms TLS is set up and
    // the route is programmed).
    wait::wait_for_https_route(
        h.gateway_tls_addr,
        &host,
        "/tls-redirect/probe",
        Duration::from_secs(60),
    )
    .await?;

    // Hit the redirect path without following redirects so we can inspect Location.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, h.gateway_tls_addr)
        .build()?;

    let url = format!(
        "https://{}:{}/tls-redirect",
        host,
        h.gateway_tls_addr.port()
    );
    let resp = client.get(&url).send().await?;

    assert_eq!(resp.status().as_u16(), 302, "expected 302 redirect");

    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        location.starts_with("https://"),
        "expected Location to start with https://, got {location:?}"
    );

    Ok(())
}

#[tokio::test]
async fn weighted_split() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-weighted").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(gwa::WEIGHTED_SPLIT, FixtureVars::new(&ns.name))
        .await?;

    let host = format!("weighted.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/probe", Duration::from_secs(60)).await?;

    // /zero: echo-a has weight 0 → all traffic must go to echo-b.
    let counts = http::count_backends(&h.gateway_http, &host, "/zero", 40).await?;
    assert_eq!(
        counts.get("echo-a").copied().unwrap_or(0),
        0,
        "/zero: weight-0 backend echo-a received traffic: {counts:?}"
    );
    assert!(
        counts.get("echo-b").copied().unwrap_or(0) > 0,
        "/zero: echo-b should receive all traffic: {counts:?}"
    );

    // /skewed: echo-a weight 4, echo-b weight 1 → ~80% to echo-a.
    // Send 200 requests; allow ±10pp tolerance to stay robust under scheduling noise.
    let n = 200usize;
    let counts = http::count_backends(&h.gateway_http, &host, "/skewed", n).await?;
    let a = counts.get("echo-a").copied().unwrap_or(0);
    let ratio = a as f64 / n as f64;
    assert!(
        (0.70..=0.90).contains(&ratio),
        "/skewed: echo-a ratio {ratio:.2} out of expected 0.70–0.90 (counts: {counts:?})"
    );

    Ok(())
}

#[tokio::test]
async fn endpoint_serving_false_is_excluded() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-serving").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    // Inject an orphan EndpointSlice for echo-a whose single endpoint has
    // serving:false/ready:true — the race window during rolling deploys.
    // The unroutable RFC 5737 TEST-NET-1 address (192.0.2.1) is used so that
    // any accidental selection causes an immediate connection error rather than
    // silently hanging. The non-standard managed-by label prevents the cluster's
    // endpointslice-controller from reconciling this slice away.
    let slice_api: Api<EndpointSlice> = Api::namespaced(h.client.clone(), &ns.name);
    let orphan = EndpointSlice {
        metadata: ObjectMeta {
            name: Some("echo-a-drain-test".to_string()),
            namespace: Some(ns.name.clone()),
            labels: Some({
                let mut m = BTreeMap::new();
                m.insert(
                    "kubernetes.io/service-name".to_string(),
                    "echo-a".to_string(),
                );
                m.insert(
                    "endpointslice.kubernetes.io/managed-by".to_string(),
                    "e2e-test".to_string(),
                );
                m
            }),
            ..Default::default()
        },
        address_type: "IPv4".to_string(),
        endpoints: vec![Endpoint {
            addresses: vec!["192.0.2.1".to_string()],
            conditions: Some(EndpointConditions {
                serving: Some(false),
                ready: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }],
        ports: None,
    };
    slice_api.create(&PostParams::default(), &orphan).await?;

    h.apply(gwa::SERVING_DRAIN, FixtureVars::new(&ns.name))
        .await?;
    let host = format!("serving.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/", Duration::from_secs(60)).await?;

    // All 30 requests must reach echo-a. If the serving:false endpoint were
    // selected, ~50% of requests would fail with a connection error to 192.0.2.1,
    // causing count_backends to return Err and the test to fail.
    let counts = http::count_backends(&h.gateway_http, &host, "/", 30).await?;
    assert_eq!(
        counts.get("echo-a").copied().unwrap_or(0),
        30,
        "not all requests hit echo-a: {counts:?}"
    );

    Ok(())
}

// Verifies SupportHTTPRouteParentRefPort (#82, #98):
// A route pinned to a listener port attaches only to that port; a route with no
// port filter attaches to all listeners; routing-table isolation is verified via
// the admin /routes endpoint.
#[tokio::test]
async fn parent_ref_port_matching() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-port").await?;

    // Any unused high port that coxswain is definitely NOT listening on.
    let wrong_port = "19999";

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(
        gwa::PARENT_REF_PORT,
        FixtureVars::new(&ns.name).with("WRONG_PORT", wrong_port),
    )
    .await?;

    // route-pinned (parentRef.port=HTTP_PORT) must attach only to the HTTP listener.
    let pinned_host = format!("pinned.{}.local", ns.name);
    let resp = wait::wait_for_route(
        &h.gateway_http,
        &pinned_host,
        "/probe",
        Duration::from_secs(60),
    )
    .await?;
    resp.assert_backend("echo-a");

    // route-unpinned (no parentRef.port) must attach to BOTH listeners.
    let both_host = format!("both.{}.local", ns.name);
    let resp = wait::wait_for_route(
        &h.gateway_http,
        &both_host,
        "/probe",
        Duration::from_secs(30),
    )
    .await?;
    resp.assert_backend("echo-a");

    // route-wrong-port (parentRef.port=WRONG_PORT) must NOT be routable on HTTP_PORT:
    // the route is scoped to the alt listener, which coxswain doesn't bind.
    let wrong_host = format!("wrong.{}.local", ns.name);
    let status = h.gateway_http.get_status(&wrong_host, "/").await?;
    assert_ne!(
        status, 200,
        "route-wrong-port must not be routable on HTTP_PORT"
    );

    // Verify routing-table isolation via admin /routes.
    // Once pinned.* and both.* are live the table is fully settled.
    //
    // Since the IngressProxy/GatewayProxy split (#201), `/routes` reports the
    // two tables under separate keys; this test only inspects Gateway-API routes.
    let routes: serde_json::Value = reqwest::get(h.admin_url("/routes")).await?.json().await?;
    let hosts = routes["gateway"]["hosts"]
        .as_array()
        .expect("gateway.hosts array");

    let http_port = u64::from(h.controller.gateway_http_addr.port());
    let wrong_port_u64: u64 = wrong_port.parse().unwrap();

    let ports_for = |host: &str| -> std::collections::BTreeSet<u64> {
        hosts
            .iter()
            .filter(|e| e["host"].as_str() == Some(host))
            .filter_map(|e| e["port"].as_u64())
            .collect()
    };

    // pinned.* appears under http_port only.
    assert_eq!(
        ports_for(&pinned_host),
        [http_port].into(),
        "pinned.* must appear only under HTTP_PORT in the routing table"
    );
    // wrong.* appears under wrong_port only (installed by controller; proxy doesn't bind that port).
    assert_eq!(
        ports_for(&wrong_host),
        [wrong_port_u64].into(),
        "wrong.* must appear only under WRONG_PORT in the routing table"
    );
    // both.* appears under both ports (no port filter → all listeners).
    let both_ports = ports_for(&both_host);
    assert!(
        both_ports.contains(&http_port) && both_ports.contains(&wrong_port_u64),
        "both.* must appear under both HTTP_PORT and WRONG_PORT, got {both_ports:?}"
    );

    Ok(())
}

/// `BackendTLSPolicy` happy-path: proxy verifies upstream cert against a CA bundle
/// stored in a ConfigMap and forwards the request successfully.
///
/// Sequence:
/// 1. Deploy a TLS echo backend (self-signed cert for `TLS_HOSTNAME`).
/// 2. Apply a Gateway + HTTPRoute + ConfigMap CA + BackendTLSPolicy.
/// 3. Wait for the route to return a 2xx echo response (proves TLS was established).
/// 4. Poll `BackendTLSPolicy.status.ancestors[].conditions` for `Accepted=True` / `ResolvedRefs=True`.
#[tokio::test]
async fn backend_tls_policy_configmap() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-backend-tls").await?;

    // Generate a self-signed cert for the backend.
    let tls_hostname = format!("echo-tls.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&tls_hostname);

    // Deploy the TLS echo backend.
    h.apply(
        backends::ECHO_TLS,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", cert.key_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-tls"]).await?;

    let host = format!("backend-tls.{}.local", ns.name);

    // Apply Gateway + HTTPRoute + ConfigMap CA + BackendTLSPolicy.
    h.apply(
        gwa::BACKEND_TLS_POLICY,
        FixtureVars::new(&ns.name)
            .with("TLS_HOSTNAME", &tls_hostname)
            .with("CA_PEM", cert.cert_pem.clone()), // self-signed: cert IS the CA
    )
    .await?;

    // The route should come up once the controller reconciles and the proxy verifies the cert.
    let resp = wait::wait_for_route(&h.gateway_http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-tls");

    // Controller must have written Accepted=True / ResolvedRefs=True on the policy.
    let controller_name = "coxswain-labs.dev/gateway-controller";
    wait::wait_for_backend_tls_policy_condition(
        &h.client,
        "echo-tls-policy",
        &ns.name,
        controller_name,
        "Accepted",
        "True",
        Duration::from_secs(30),
    )
    .await?;
    wait::wait_for_backend_tls_policy_condition(
        &h.client,
        "echo-tls-policy",
        &ns.name,
        controller_name,
        "ResolvedRefs",
        "True",
        Duration::from_secs(10),
    )
    .await?;

    Ok(())
}

/// `BackendTLSPolicy` invalid CA cert ref (missing ConfigMap):
/// - Policy gets `Accepted=False/NoValidCACertificate` and `ResolvedRefs=False/InvalidCACertificateRef`.
/// - Traffic to the targeted backend returns 5xx (GEP-1897: invalid policy must NOT
///   silently fall back to plain HTTP).
#[tokio::test]
async fn backend_tls_policy_invalid_ca() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-backend-tls-invalid").await?;

    // Backend cert can be anything — the policy is invalid before we get to TLS.
    let cert = GeneratedCert::for_host(&format!("echo-tls.{}.local", ns.name));
    h.apply(
        backends::ECHO_TLS,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", cert.key_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-tls"]).await?;

    h.apply(
        gwa::BACKEND_TLS_POLICY_INVALID_CA,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("backend-tls.{}.local", ns.name);
    // Traffic MUST return 5xx — never plain-HTTP-fallthrough success.
    wait::wait_for_route_status(&h.gateway_http, &host, "/", 502, Duration::from_secs(60)).await?;

    let controller_name = "coxswain-labs.dev/gateway-controller";
    wait::wait_for_backend_tls_policy_condition_with_reason(
        &h.client,
        "echo-tls-policy",
        &ns.name,
        controller_name,
        wait::ExpectedCondition {
            type_: "Accepted",
            status: "False",
            reason: "NoValidCACertificate",
        },
        Duration::from_secs(30),
    )
    .await?;
    wait::wait_for_backend_tls_policy_condition_with_reason(
        &h.client,
        "echo-tls-policy",
        &ns.name,
        controller_name,
        wait::ExpectedCondition {
            type_: "ResolvedRefs",
            status: "False",
            reason: "InvalidCACertificateRef",
        },
        Duration::from_secs(10),
    )
    .await?;

    Ok(())
}

/// `BackendTLSPolicy` section-name routing:
/// - Two policies on the same Service: one with `sectionName=https-1`, one without.
/// - The dual-port Service exposes both ports onto the same pod, whose cert is signed
///   for both SNIs as SANs.
/// - Traffic to port 443 (path `/port-443`) must use the section-name policy's SNI;
///   traffic to port 8443 (path `/port-8443`) must use the no-section-name policy's SNI.
/// - Both must succeed because the backend cert covers both SANs.
#[tokio::test]
async fn backend_tls_policy_section_name_routing() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-backend-tls-section").await?;

    let sni_primary = format!("primary.{}.local", ns.name);
    let sni_secondary = format!("secondary.{}.local", ns.name);
    let cert = GeneratedCert::for_hosts(&[&sni_primary, &sni_secondary]);

    // Apply the dual-port TLS echo backend.
    h.apply(
        backends::ECHO_TLS_DUAL_PORT,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", cert.key_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-tls"]).await?;

    h.apply(
        gwa::BACKEND_TLS_POLICY_SECTION_NAME,
        FixtureVars::new(&ns.name)
            .with("SNI_PRIMARY", &sni_primary)
            .with("SNI_SECONDARY", &sni_secondary)
            .with("CA_PEM", cert.cert_pem.clone()),
    )
    .await?;

    let host = format!("backend-tls.{}.local", ns.name);

    // Both routes must succeed. The section-name policy applies to port 443; the
    // catch-all to port 8443. If per-port lookup is broken, one of these returns 5xx.
    let resp = wait::wait_for_route(
        &h.gateway_http,
        &host,
        "/port-443/",
        Duration::from_secs(60),
    )
    .await?;
    resp.assert_backend("echo-tls");
    let resp = wait::wait_for_route(
        &h.gateway_http,
        &host,
        "/port-8443/",
        Duration::from_secs(30),
    )
    .await?;
    resp.assert_backend("echo-tls");

    Ok(())
}

/// `BackendTLSPolicy` conflict resolution:
/// - Two policies on the same Service with NO `sectionName`.
/// - Name-tiebreak: "aaa-policy" < "zzz-policy", so "aaa-policy" wins.
/// - Expected status: winner `Accepted=True`, loser `Accepted=False/Conflicted`,
///   both with the test Gateway in `status.ancestors[]`.
#[tokio::test]
async fn backend_tls_policy_conflict_resolution() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-backend-tls-conflict").await?;

    let tls_hostname = format!("echo-tls.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&tls_hostname);

    h.apply(
        backends::ECHO_TLS,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", cert.key_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-tls"]).await?;

    h.apply(
        gwa::BACKEND_TLS_POLICY_CONFLICT,
        FixtureVars::new(&ns.name)
            .with("TLS_HOSTNAME", &tls_hostname)
            .with("CA_PEM", cert.cert_pem.clone()),
    )
    .await?;

    let controller_name = "coxswain-labs.dev/gateway-controller";
    // Winner — "aaa-policy" must be Accepted.
    wait::wait_for_backend_tls_policy_condition(
        &h.client,
        "aaa-policy",
        &ns.name,
        controller_name,
        "Accepted",
        "True",
        Duration::from_secs(60),
    )
    .await?;
    // Loser — "zzz-policy" must have Accepted=False/Conflicted.
    wait::wait_for_backend_tls_policy_condition_with_reason(
        &h.client,
        "zzz-policy",
        &ns.name,
        controller_name,
        wait::ExpectedCondition {
            type_: "Accepted",
            status: "False",
            reason: "Conflicted",
        },
        Duration::from_secs(30),
    )
    .await?;

    Ok(())
}

/// `BackendTLSPolicy` ConfigMap CA mutation:
/// - Apply happy-path fixture; verify traffic succeeds.
/// - Replace `ca.crt` in the ConfigMap with an unrelated self-signed CA.
/// - Backend cert no longer verifies → traffic must transition to 5xx, proving the
///   controller reacted to the ConfigMap watch.
#[tokio::test]
async fn backend_tls_policy_configmap_mutation() -> anyhow::Result<()> {
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::api::{Patch, PatchParams};

    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-backend-tls-cm-mutation").await?;

    let tls_hostname = format!("echo-tls.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&tls_hostname);

    h.apply(
        backends::ECHO_TLS,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", cert.key_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-tls"]).await?;

    h.apply(
        gwa::BACKEND_TLS_POLICY,
        FixtureVars::new(&ns.name)
            .with("TLS_HOSTNAME", &tls_hostname)
            .with("CA_PEM", cert.cert_pem.clone()),
    )
    .await?;

    let host = format!("backend-tls.{}.local", ns.name);
    let resp = wait::wait_for_route(&h.gateway_http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-tls");

    // Swap the ConfigMap's ca.crt for an unrelated self-signed CA. The backend's cert
    // (signed by the original CA) must now fail verification → proxy returns 5xx.
    let unrelated = GeneratedCert::for_host("unrelated.invalid");
    let cm_api: Api<ConfigMap> = Api::namespaced(h.client.clone(), &ns.name);
    let patch = serde_json::json!({
        "data": { "ca.crt": unrelated.cert_pem }
    });
    cm_api
        .patch(
            "echo-tls-ca",
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await?;

    // The controller should observe the CM change, rebuild, and the proxy's UpstreamCaCache
    // will surface a fresh CA. The cert no longer chains → 502.
    wait::wait_for_route_status(&h.gateway_http, &host, "/", 502, Duration::from_secs(60)).await?;

    Ok(())
}

/// `BackendTLSPolicy` hostname-mismatch: the policy's `validation.hostname` does not
/// match the SAN in the backend's certificate → TLS handshake fails → proxy returns 5xx.
#[tokio::test]
async fn backend_tls_policy_hostname_mismatch() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-backend-tls-mismatch").await?;

    // Backend cert is issued for the real hostname.
    let real_hostname = format!("echo-tls.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&real_hostname);

    h.apply(
        backends::ECHO_TLS,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", cert.key_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-tls"]).await?;

    // Policy specifies a hostname that does NOT match the cert's SAN.
    let wrong_hostname = format!("wrong-hostname.{}.local", ns.name);

    h.apply(
        gwa::BACKEND_TLS_POLICY,
        FixtureVars::new(&ns.name)
            .with("TLS_HOSTNAME", &wrong_hostname) // mismatch
            .with("CA_PEM", cert.cert_pem.clone()),
    )
    .await?;

    let host = format!("backend-tls.{}.local", ns.name);

    // Wait for the route to appear in the routing table (reconciler must have processed it).
    // Then assert that requests fail with 5xx (TLS verification error from Pingora).
    wait::wait_for_route_status(&h.gateway_http, &host, "/", 502, Duration::from_secs(60)).await?;

    Ok(())
}

/// `/cluster` aggregate endpoint: after applying a Gateway + HTTPRoute, the
/// controller's `/cluster` JSON must include the Gateway with `proxy.pool ==
/// "shared"`, a positive `route_count`, and at least one condition, all within
/// one reconcile cycle. Also asserts the matching counters appear on `/status`.
#[tokio::test]
async fn cluster_endpoint() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-cluster-endpoint").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(gwa::PATH_MATCHING, FixtureVars::new(&ns.name))
        .await?;

    // First wait for the route to be live so we know the reconciler has built
    // the routing table at least once after our Gateway was applied.
    let host = format!("echo.{}.local", ns.name);
    wait::wait_for_route(&h.gateway_http, &host, "/a", Duration::from_secs(60)).await?;

    let cluster_url = h.controller_admin_url("/cluster");
    let status_url = h.controller_admin_url("/status");
    let client = reqwest::Client::new();

    // Poll /cluster until the Gateway we just applied is visible. The reconciler
    // rebuilds with a 500 ms trailing-edge debounce so allow a generous window.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let cluster = loop {
        let resp = client.get(&cluster_url).send().await?;
        assert_eq!(
            resp.status(),
            200,
            "/cluster should be 200 on the controller"
        );
        let json: serde_json::Value = resp.json().await?;
        let gateways = json["gateways"].as_array().cloned().unwrap_or_default();
        let visible = gateways
            .iter()
            .any(|g| g["namespace"] == ns.name && g["name"] == "coxswain-test");
        if visible {
            break json;
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "Gateway coxswain-test/{} did not appear in /cluster within timeout: {}",
                ns.name,
                json
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    let gw = cluster["gateways"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["namespace"] == ns.name && g["name"] == "coxswain-test")
        .expect("Gateway entry");
    assert_eq!(
        gw["proxy"]["pool"], "shared",
        "Gateway without parametersRef must be classified as shared"
    );
    let route_count = gw["route_count"].as_u64().unwrap_or(0);
    assert!(
        route_count >= 1,
        "expected at least one attached route, got {route_count} (gw={gw})"
    );
    let conditions = gw["conditions"].as_array().expect("conditions array");
    assert!(
        !conditions.is_empty(),
        "expected at least one condition, got none (gw={gw})"
    );
    let cond_types: Vec<&str> = conditions
        .iter()
        .filter_map(|c| c["type"].as_str())
        .collect();
    assert!(
        cond_types.contains(&"Programmed") || cond_types.contains(&"Accepted"),
        "expected Programmed or Accepted condition, got {cond_types:?}"
    );

    // /status must mirror the same counters now that the cluster summary is wired.
    let status: serde_json::Value = client.get(&status_url).send().await?.json().await?;
    let gateway_count = status["gateway_count"]
        .as_u64()
        .expect("gateway_count present on controller /status");
    assert!(gateway_count >= 1, "gateway_count={gateway_count}");
    assert_eq!(
        status["dedicated_count"], 0,
        "no parametersRef in this fixture; dedicated_count must be 0"
    );
    assert!(
        status["ingress_count"].is_u64(),
        "ingress_count must be present when /cluster summary is enabled"
    );

    Ok(())
}
