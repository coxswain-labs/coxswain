use coxswain_e2e::{
    fixtures::{
        self, BACKENDS_ECHO, INGRESS_DEFAULT_BACKEND, INGRESS_PATH_MATCHING,
        INGRESS_TLS_TERMINATION,
    },
    harness::{
        ControllerOptions, ControllerProcess, GeneratedCert, Harness, HttpClient, NamespaceGuard,
        bootstrap, http, wait,
    },
};
use std::time::Duration;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("coxswain_e2e=debug,warn")
        .try_init();
}

#[tokio::test]
async fn status_load_balancer_ip() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start_with_options(ControllerOptions {
        ingress_status_address: Some("203.0.113.1".to_string()),
        ..Default::default()
    })
    .await?;
    let ns = NamespaceGuard::create(&h.client, "ing-lb-status").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(INGRESS_PATH_MATCHING, &ns.name, &[]).await?;

    wait::wait_for_ingress_lb_ip(
        &h.client,
        "echo-ingress",
        &ns.name,
        "203.0.113.1",
        Duration::from_secs(30),
    )
    .await?;

    Ok(())
}

/// Tests both the per-Ingress spec.defaultBackend and the controller-wide
/// --ingress-default-backend flag. Backends are deployed before the controller
/// starts so that echo-c is already ready on the first routing-table rebuild.
#[tokio::test]
async fn default_backend() -> anyhow::Result<()> {
    init_tracing();

    // Bootstrap cluster connection and create the namespace before starting the
    // controller, so the default-backend endpoints are ready on first sync.
    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "ing-default").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;

    // Start the controller with the controller-wide default pointing at echo-c.
    let controller = ControllerProcess::start_with_options(ControllerOptions {
        ingress_default_backend: Some(format!("{}/echo-c:3000", ns.name)),
        ..Default::default()
    })
    .await?;
    wait::wait_for_ready(controller.health_addr, Duration::from_secs(30)).await?;
    let http = HttpClient::new(controller.proxy_addr);

    // Apply the fixture: rule /api → echo-a, spec.defaultBackend → echo-b.
    fixtures::apply_fixture(INGRESS_DEFAULT_BACKEND, &ns.name, &[]).await?;

    let host = format!("app.{}.local", ns.name);
    let unknown_host = format!("unknown.{}.local", ns.name);

    // Wait until the explicit rule is live, then test all three cases.
    let resp = wait::wait_for_route(&http, &host, "/api", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    // Per-Ingress defaultBackend catches path-miss on the rule's host.
    let resp = http.get(&host, "/other").await?;
    resp.assert_backend("echo-b");

    // Controller-wide default catches requests to an unknown host.
    let resp = http.get(&unknown_host, "/anything").await?;
    resp.assert_backend("echo-c");

    Ok(())
}

#[tokio::test]
async fn path_matching() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-path").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(INGRESS_PATH_MATCHING, &ns.name, &[]).await?;

    let host = format!("ingress.{}.local", ns.name);

    let resp = wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    let resp = h.http.get(&host, "/b").await?;
    resp.assert_backend("echo-b");

    Ok(())
}

/// Verifies SNI-driven TLS termination:
/// - Two Ingresses, each with a distinct self-signed cert, route to separate backends.
/// - Correct cert is selected by SNI for each host.
/// - Unknown SNI causes a TLS handshake error (no cert installed).
#[tokio::test]
async fn tls_termination_with_sni() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-tls").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host_a = format!("tls-a.{}.local", ns.name);
    let host_b = format!("tls-b.{}.local", ns.name);

    let cert_a = GeneratedCert::for_host(&host_a);
    let cert_b = GeneratedCert::for_host(&host_b);

    // Apply two independent TLS Ingresses (same fixture, different params).
    fixtures::apply_fixture(
        INGRESS_TLS_TERMINATION,
        &ns.name,
        &[
            ("INGRESS_NAME", "ingress-a"),
            ("SECRET_NAME", "cert-a"),
            ("TLS_HOST", &host_a),
            ("BACKEND_NAME", "echo-a"),
            ("TLS_CRT_B64", &cert_a.cert_b64()),
            ("TLS_KEY_B64", &cert_a.key_b64()),
        ],
    )
    .await?;
    fixtures::apply_fixture(
        INGRESS_TLS_TERMINATION,
        &ns.name,
        &[
            ("INGRESS_NAME", "ingress-b"),
            ("SECRET_NAME", "cert-b"),
            ("TLS_HOST", &host_b),
            ("BACKEND_NAME", "echo-b"),
            ("TLS_CRT_B64", &cert_b.cert_b64()),
            ("TLS_KEY_B64", &cert_b.key_b64()),
        ],
    )
    .await?;

    // Wait for both HTTPS routes to become live.
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
