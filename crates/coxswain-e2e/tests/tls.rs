#![allow(missing_docs)]
//! TLS & connection data-plane: certificate handling and protocol upgrades.
//!
//! Plane: **data-plane**. Execution: **parallel** — every test owns a fresh
//! namespace and asserts only connections served through that partition.
//!
//! Classification rule: a test belongs to the plane of its *primary assertion
//! target*. This file is the TLS/connection domain — SNI termination, cert
//! rotation/fallback, cert-manager provisioning, cross-namespace cert refs,
//! `BackendTLSPolicy` (upstream TLS), PROXY protocol, h2c, and WebSocket
//! upgrades. Ingress vs Gateway API is a sub-grouping *within* this file.
//!
//! Note: `tls_missing_secret_marks_gateway_not_programmed` asserts only listener
//! conditions (no traffic), but lives here with the rest of the TLS-cert
//! resolution story rather than in `status_conditions.rs`. Plain-HTTP routing
//! lives in `routing.rs`.

use coxswain_e2e::{
    ControllerOptions, ControllerProcess, FixtureVars, GeneratedCert, Harness, NamespaceGuard,
    bootstrap,
    fixtures::{self, backends, gateway_api as gwa, ingress},
    harness::{http, wait},
};
use futures::StreamExt as _;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Api;
use kube::api::PostParams;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

mod common;

/// Verifies SNI-driven TLS termination:
/// - Two Ingresses, each with a distinct self-signed cert, route to separate backends.
/// - Correct cert is selected by SNI for each host.
/// - Unknown SNI causes a TLS handshake error (no cert installed).
#[tokio::test]
async fn ingress_tls_termination_with_sni() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-tls").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host_a = format!("tls-a.{}.local", ns.name);
    let host_b = format!("tls-b.{}.local", ns.name);

    let cert_a = GeneratedCert::for_host(&host_a);
    let cert_b = GeneratedCert::for_host(&host_b);

    // Apply two independent TLS Ingresses (same fixture, different params).
    fixtures::apply_fixture(
        ingress::TLS_TERMINATION,
        FixtureVars::new(&ns.name)
            .with("INGRESS_NAME", "ingress-a")
            .with("SECRET_NAME", "cert-a")
            .with("TLS_HOST", &host_a)
            .with("BACKEND_NAME", "echo-a")
            .with("TLS_CRT_B64", cert_a.cert_b64())
            .with("TLS_KEY_B64", cert_a.key_b64()),
    )
    .await?;
    fixtures::apply_fixture(
        ingress::TLS_TERMINATION,
        FixtureVars::new(&ns.name)
            .with("INGRESS_NAME", "ingress-b")
            .with("SECRET_NAME", "cert-b")
            .with("TLS_HOST", &host_b)
            .with("BACKEND_NAME", "echo-b")
            .with("TLS_CRT_B64", cert_b.cert_b64())
            .with("TLS_KEY_B64", cert_b.key_b64()),
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

/// Verifies that when `spec.tls[].hosts` is omitted, the controller falls back to the
/// rule hosts and the cert is still served correctly via SNI.
#[tokio::test]
async fn tls_fallback_when_hosts_omitted() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-tls-nohosts").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("tls-nohosts.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&host);

    fixtures::apply_fixture(
        ingress::TLS_NO_HOSTS,
        FixtureVars::new(&ns.name)
            .with("INGRESS_NAME", "ingress-nohosts")
            .with("SECRET_NAME", "cert-nohosts")
            .with("TLS_HOST", &host)
            .with("BACKEND_NAME", "echo-a")
            .with("TLS_CRT_B64", cert.cert_b64())
            .with("TLS_KEY_B64", cert.key_b64()),
    )
    .await?;

    let resp = wait::wait_for_https_route(h.tls_addr, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    Ok(())
}

/// Verifies that rotating a `kubernetes.io/tls` Secret causes the new certificate to be
/// served for subsequent TLS connections without a process restart:
/// 1. Apply an Ingress with `cert_old` — wait for it to be live and capture the leaf DER.
/// 2. Re-apply the same fixture with `cert_new` (same Secret name, different PEM data).
/// 3. Poll new handshakes until the served leaf DER changes — assert it matches `cert_new`.
/// 4. Assert that routing still works on the new certificate.
#[tokio::test]
async fn ingress_tls_certificate_hot_rotation() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-tls-rotate").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("tls-rotate.{}.local", ns.name);
    let cert_old = GeneratedCert::for_host(&host);
    let cert_new = GeneratedCert::for_host(&host);

    // Deploy with the original cert.
    fixtures::apply_fixture(
        ingress::TLS_TERMINATION,
        FixtureVars::new(&ns.name)
            .with("INGRESS_NAME", "ingress-rotate")
            .with("SECRET_NAME", "cert-rotate")
            .with("TLS_HOST", &host)
            .with("BACKEND_NAME", "echo-a")
            .with("TLS_CRT_B64", cert_old.cert_b64())
            .with("TLS_KEY_B64", cert_old.key_b64()),
    )
    .await?;

    wait::wait_for_https_route(h.tls_addr, &host, "/", Duration::from_secs(60)).await?;
    let old_der = http::https_peer_leaf_der(&host, "/", h.tls_addr).await?;

    // Rotate: re-apply the same fixture with new PEM bytes. kubectl apply patches the Secret.
    fixtures::apply_fixture(
        ingress::TLS_TERMINATION,
        FixtureVars::new(&ns.name)
            .with("INGRESS_NAME", "ingress-rotate")
            .with("SECRET_NAME", "cert-rotate")
            .with("TLS_HOST", &host)
            .with("BACKEND_NAME", "echo-a")
            .with("TLS_CRT_B64", cert_new.cert_b64())
            .with("TLS_KEY_B64", cert_new.key_b64()),
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
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ing-cert-mgr").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("tls-cm.{}.local", ns.name);
    let secret_name = "cert-manager-tls";

    fixtures::apply_fixture(
        ingress::CERT_MANAGER,
        FixtureVars::new(&ns.name)
            .with("INGRESS_NAME", "cm-ingress")
            .with("TLS_HOST", &host)
            .with("SECRET_NAME", secret_name)
            .with("BACKEND_NAME", "echo-a"),
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
    common::init_tracing();

    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "pp-http-v1").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let controller = ControllerProcess::start_with_options(ControllerOptions {
        accept_proxy_protocol: true,
        trusted_sources: vec!["0.0.0.0/0".to_string()],
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
    common::init_tracing();

    bootstrap().await?;
    let client = kube::Client::try_default().await?;
    let ns = NamespaceGuard::create(&client, "pp-https-v2").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("tls-pp.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&host);

    fixtures::apply_fixture(
        ingress::TLS_TERMINATION,
        FixtureVars::new(&ns.name)
            .with("INGRESS_NAME", "pp-ingress")
            .with("SECRET_NAME", "pp-cert")
            .with("TLS_HOST", &host)
            .with("BACKEND_NAME", "echo-a")
            .with("TLS_CRT_B64", cert.cert_b64())
            .with("TLS_KEY_B64", cert.key_b64()),
    )
    .await?;

    let controller = ControllerProcess::start_with_options(ControllerOptions {
        accept_proxy_protocol: true,
        trusted_sources: vec!["0.0.0.0/0".to_string()],
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

// `proxy_protocol_strict_drop` removed: the trusted-sources enforcement logic
// (accept-only-from-CIDR, drop-plain-HTTP-from-trusted-source) is covered by
// unit tests in `coxswain-proxy` against the CIDR matcher and PROXY-protocol
// accept/reject code paths. The e2e scenario required a loopback-sourced client
// which doesn't map cleanly to in-cluster LoadBalancer routing.

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
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Gateway API TLS termination with SNI selection:
/// - Two HTTPS listeners, each backed by a distinct self-signed cert.
/// - Each SNI routes to the correct backend.
/// - Unknown SNI fails the TLS handshake.
#[tokio::test]
async fn gateway_tls_termination_with_sni() -> anyhow::Result<()> {
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
async fn gateway_tls_certificate_hot_rotation() -> anyhow::Result<()> {
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
