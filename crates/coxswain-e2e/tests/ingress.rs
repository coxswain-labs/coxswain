use coxswain_e2e::{
    fixtures::{
        self, BACKENDS_ECHO, INGRESS_CERT_MANAGER, INGRESS_DEFAULT_BACKEND, INGRESS_PATH_MATCHING,
        INGRESS_TLS_TERMINATION,
    },
    harness::{
        ControllerOptions, ControllerProcess, GeneratedCert, Harness, HttpClient, NamespaceGuard,
        bootstrap, http, wait,
    },
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn init_tracing() {
    // Install the rustls crypto provider once for the process. reqwest uses
    // rustls internally, so this must happen before any client is created.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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

    // /b shares the same ingress as /a, so a short deadline is enough; use
    // wait_for_route rather than a bare get() to tolerate transient timeouts.
    let resp = wait::wait_for_route(&h.http, &host, "/b", Duration::from_secs(15)).await?;
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

/// Verifies that rotating a `kubernetes.io/tls` Secret causes the new certificate to be
/// served for subsequent TLS connections without a process restart:
/// 1. Apply an Ingress with `cert_old` — wait for it to be live and capture the leaf DER.
/// 2. Re-apply the same fixture with `cert_new` (same Secret name, different PEM data).
/// 3. Poll new handshakes until the served leaf DER changes — assert it matches `cert_new`.
/// 4. Assert that routing still works on the new certificate.
#[tokio::test]
async fn tls_certificate_hot_rotation() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-tls-rotate").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("tls-rotate.{}.local", ns.name);
    let cert_old = GeneratedCert::for_host(&host);
    let cert_new = GeneratedCert::for_host(&host);

    // Deploy with the original cert.
    fixtures::apply_fixture(
        INGRESS_TLS_TERMINATION,
        &ns.name,
        &[
            ("INGRESS_NAME", "ingress-rotate"),
            ("SECRET_NAME", "cert-rotate"),
            ("TLS_HOST", &host),
            ("BACKEND_NAME", "echo-a"),
            ("TLS_CRT_B64", &cert_old.cert_b64()),
            ("TLS_KEY_B64", &cert_old.key_b64()),
        ],
    )
    .await?;

    wait::wait_for_https_route(h.tls_addr, &host, "/", Duration::from_secs(60)).await?;
    let old_der = http::https_peer_leaf_der(&host, "/", h.tls_addr).await?;

    // Rotate: re-apply the same fixture with new PEM bytes. kubectl apply patches the Secret.
    fixtures::apply_fixture(
        INGRESS_TLS_TERMINATION,
        &ns.name,
        &[
            ("INGRESS_NAME", "ingress-rotate"),
            ("SECRET_NAME", "cert-rotate"),
            ("TLS_HOST", &host),
            ("BACKEND_NAME", "echo-a"),
            ("TLS_CRT_B64", &cert_new.cert_b64()),
            ("TLS_KEY_B64", &cert_new.key_b64()),
        ],
    )
    .await?;

    // Poll until the new leaf is served — covers debounce window + reflector propagation.
    wait::wait_for_tls_cert_rotation(h.tls_addr, &host, &old_der, Duration::from_secs(15)).await?;

    // Backend routing must still work after the swap.
    let resp = http::https_get(&host, "/", h.tls_addr).await?;
    assert!(
        resp.1.is_some(),
        "expected a successful response after cert rotation"
    );
    resp.1.unwrap().assert_backend("echo-a");

    Ok(())
}

/// Verifies cert-manager automatic certificate provisioning for Ingress:
/// 1. Apply an Ingress with cert-manager.io/cluster-issuer annotation.
/// 2. cert-manager (using the coxswain-e2e-selfsigned ClusterIssuer) provisions
///    the kubernetes.io/tls Secret named in spec.tls[].secretName.
/// 3. Coxswain picks up the Secret via its Secret watch and serves TLS.
/// 4. HTTPS request succeeds and routes to the expected backend.
#[tokio::test]
async fn cert_manager_ingress_provisioning() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-cert-mgr").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("tls-cm.{}.local", ns.name);
    let secret_name = "cert-manager-tls";

    fixtures::apply_fixture(
        INGRESS_CERT_MANAGER,
        &ns.name,
        &[
            ("INGRESS_NAME", "cm-ingress"),
            ("TLS_HOST", &host),
            ("SECRET_NAME", secret_name),
            ("BACKEND_NAME", "echo-a"),
        ],
    )
    .await?;

    // Wait for cert-manager to issue the certificate and populate the Secret.
    wait::wait_for_tls_secret(&h.client, secret_name, &ns.name, Duration::from_secs(120)).await?;

    // Coxswain picks up the Secret via its Secret watch; wait for HTTPS to become live.
    let resp = wait::wait_for_https_route(h.tls_addr, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    Ok(())
}

/// Verifies PROXY protocol v1 on the plain-HTTP listener:
/// - Controller started with --proxy-accept-proxy-protocol and 127.0.0.1/32 trusted.
/// - Raw TCP connection sends "PROXY TCP4 198.51.100.42 ... \r\n" then HTTP/1.1 GET.
/// - Echo response must include a `forwarded` header with `for="198.51.100.42:12345"`.
#[tokio::test]
async fn proxy_protocol_http_v1_forwarded() -> anyhow::Result<()> {
    init_tracing();

    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "pp-http-v1").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(INGRESS_PATH_MATCHING, &ns.name, &[]).await?;

    let controller = ControllerProcess::start_with_options(ControllerOptions {
        proxy_accept_proxy_protocol: true,
        proxy_trusted_sources: vec!["127.0.0.1/32".to_string()],
        ..Default::default()
    })
    .await?;
    wait::wait_for_ready(controller.health_addr, Duration::from_secs(30)).await?;

    let host = format!("ingress.{}.local", ns.name);

    // Send PROXY v1 header + HTTP/1.1 request over raw TCP.
    let proxy_line = "PROXY TCP4 198.51.100.42 10.0.0.1 12345 80\r\n";
    let http_req = format!("GET /a HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    // Retry until the route is live (controller may still be syncing).
    let body = wait_for_proxy_v1_route(
        controller.proxy_addr,
        proxy_line,
        &http_req,
        Duration::from_secs(60),
    )
    .await?;

    let echo: serde_json::Value = serde_json::from_str(&body)?;
    // echo-basic returns headers as Title-Case keys with array values.
    let forwarded = echo["headers"]["Forwarded"][0]
        .as_str()
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        forwarded.contains("198.51.100.42") && forwarded.contains("12345"),
        "expected forwarded header with 198.51.100.42:12345, got: {forwarded}"
    );
    assert!(
        forwarded.contains("proto=http"),
        "expected proto=http in forwarded, got: {forwarded}"
    );

    Ok(())
}

/// Verifies PROXY protocol v2 on the HTTPS listener:
/// - Raw TCP sends a v2 binary header (AF_INET, src=192.0.2.7:54321), then TLS handshake.
/// - Echo response must include `forwarded: for="192.0.2.7:54321";proto=https`.
#[tokio::test]
async fn proxy_protocol_https_v2_forwarded() -> anyhow::Result<()> {
    init_tracing();

    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "pp-https-v2").await?;

    fixtures::apply_fixture(BACKENDS_ECHO, &ns.name, &[]).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("tls-pp.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&host);

    fixtures::apply_fixture(
        INGRESS_TLS_TERMINATION,
        &ns.name,
        &[
            ("INGRESS_NAME", "pp-ingress"),
            ("SECRET_NAME", "pp-cert"),
            ("TLS_HOST", &host),
            ("BACKEND_NAME", "echo-a"),
            ("TLS_CRT_B64", &cert.cert_b64()),
            ("TLS_KEY_B64", &cert.key_b64()),
        ],
    )
    .await?;

    let controller = ControllerProcess::start_with_options(ControllerOptions {
        proxy_accept_proxy_protocol: true,
        proxy_trusted_sources: vec!["127.0.0.1/32".to_string()],
        ..Default::default()
    })
    .await?;
    wait::wait_for_ready(controller.health_addr, Duration::from_secs(30)).await?;

    // Build PROXY v2 binary header: src=192.0.2.7:54321, dst=10.0.0.1:443
    let mut v2_header = Vec::with_capacity(28);
    v2_header.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n"); // 12-byte signature
    v2_header.push(0x21); // version 2, command PROXY
    v2_header.push(0x11); // AF_INET, STREAM
    v2_header.extend_from_slice(&12u16.to_be_bytes()); // address block length
    v2_header.extend_from_slice(&[192, 0, 2, 7]); // src IP 192.0.2.7
    v2_header.extend_from_slice(&[10, 0, 0, 1]); // dst IP 10.0.0.1
    v2_header.extend_from_slice(&54321u16.to_be_bytes()); // src port
    v2_header.extend_from_slice(&443u16.to_be_bytes()); // dst port

    let http_req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    let body = wait_for_proxy_v2_tls_route(
        controller.tls_addr,
        &host,
        &v2_header,
        &http_req,
        Duration::from_secs(60),
    )
    .await?;

    let echo: serde_json::Value = serde_json::from_str(&body)?;
    // echo-basic returns headers as Title-Case keys with array values.
    let forwarded = echo["headers"]["Forwarded"][0]
        .as_str()
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        forwarded.contains("192.0.2.7") && forwarded.contains("54321"),
        "expected forwarded header with 192.0.2.7:54321, got: {forwarded}"
    );
    assert!(
        forwarded.contains("proto=https"),
        "expected proto=https in forwarded, got: {forwarded}"
    );

    Ok(())
}

/// Verifies strict mode: a connection from a trusted source that sends HTTP without a
/// PROXY preamble is dropped before any response is sent.
#[tokio::test]
async fn proxy_protocol_strict_drop() -> anyhow::Result<()> {
    init_tracing();

    let controller = ControllerProcess::start_with_options(ControllerOptions {
        proxy_accept_proxy_protocol: true,
        proxy_trusted_sources: vec!["127.0.0.1/32".to_string()],
        ..Default::default()
    })
    .await?;
    wait::wait_for_ready(controller.health_addr, Duration::from_secs(30)).await?;

    let mut tcp = tokio::net::TcpStream::connect(controller.proxy_addr).await?;
    // Send a plain HTTP request without any PROXY preamble.
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await?;
    tcp.flush().await?;

    // The controller should close the connection before sending any HTTP response.
    // Accept both clean EOF (n == 0) and a TCP RST (ConnectionReset / ConnectionAborted).
    let mut buf = vec![0u8; 256];
    match tcp.read(&mut buf).await {
        Ok(0) => {}
        Ok(n) => panic!("expected connection closed on missing PROXY header, got {n} bytes"),
        Err(e)
            if e.kind() == std::io::ErrorKind::ConnectionReset
                || e.kind() == std::io::ErrorKind::ConnectionAborted => {}
        Err(e) => return Err(e.into()),
    }

    Ok(())
}

// ── Raw-TCP helpers for PROXY protocol tests ──────────────────────────────────

/// Retry: send a v1 PROXY header + HTTP request over raw TCP until a 200 JSON response arrives.
async fn wait_for_proxy_v1_route(
    proxy_addr: std::net::SocketAddr,
    proxy_line: &str,
    http_req: &str,
    timeout: Duration,
) -> anyhow::Result<String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match try_raw_http(proxy_addr, proxy_line.as_bytes(), http_req).await {
            Ok(body) => return Ok(body),
            Err(_) => {
                if tokio::time::Instant::now() >= deadline {
                    anyhow::bail!("timed out waiting for PROXY v1 route");
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

/// Make one raw TCP request: write `preamble` bytes, then the HTTP request, read the response body.
async fn try_raw_http(
    addr: std::net::SocketAddr,
    preamble: &[u8],
    http_req: &str,
) -> anyhow::Result<String> {
    let mut tcp = tokio::net::TcpStream::connect(addr).await?;
    tcp.write_all(preamble).await?;
    tcp.write_all(http_req.as_bytes()).await?;
    tcp.flush().await?;

    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await?;
    let s = String::from_utf8_lossy(&response);

    // Split headers from body
    let body = s
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("no body in response"))?;

    // Assert HTTP 200
    anyhow::ensure!(
        s.starts_with("HTTP/1.1 200"),
        "unexpected status: {}",
        s.lines().next().unwrap_or("")
    );

    Ok(body.to_string())
}

/// Retry: send v2 PROXY header then TLS + HTTP request until a 200 JSON response arrives.
async fn wait_for_proxy_v2_tls_route(
    tls_addr: std::net::SocketAddr,
    host: &str,
    v2_header: &[u8],
    http_req: &str,
    timeout: Duration,
) -> anyhow::Result<String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match try_tls_after_proxy_v2(tls_addr, host, v2_header, http_req).await {
            Ok(body) => return Ok(body),
            Err(_) => {
                if tokio::time::Instant::now() >= deadline {
                    anyhow::bail!("timed out waiting for PROXY v2 TLS route");
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

/// Write v2 PROXY header bytes to a raw TCP stream, then perform TLS handshake,
/// then send the HTTP request, and read the response body.
async fn try_tls_after_proxy_v2(
    tls_addr: std::net::SocketAddr,
    host: &str,
    v2_header: &[u8],
    http_req: &str,
) -> anyhow::Result<String> {
    use rustls::ClientConfig;
    use std::sync::Arc;
    use tokio_rustls::TlsConnector;

    let mut tcp = tokio::net::TcpStream::connect(tls_addr).await?;
    tcp.write_all(v2_header).await?;
    tcp.flush().await?;

    // TLS config that accepts any certificate (self-signed certs in tests).
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?;
    let mut tls = connector.connect(server_name, tcp).await?;

    tls.write_all(http_req.as_bytes()).await?;
    tls.flush().await?;

    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;
    let s = String::from_utf8_lossy(&response);

    let body = s
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("no body in response"))?;

    anyhow::ensure!(
        s.starts_with("HTTP/1.1 200"),
        "unexpected status: {}",
        s.lines().next().unwrap_or("")
    );

    Ok(body.to_string())
}

/// A `ServerCertVerifier` that accepts any certificate.
/// For use only in test code against self-signed certs.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
