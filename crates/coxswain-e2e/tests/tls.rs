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
    ControllerOptions, ControllerProcess, FixtureVars, GeneratedCert, Harness, MtlsCerts,
    NamespaceGuard, StaticRsaCert, bootstrap,
    fixtures::{self, backends, gateway_api as gwa, ingress},
    harness::{GATEWAY_HTTPS_PORT, GATEWAY_TLS_PASSTHROUGH_PORT, http, wait},
};
use futures::StreamExt as _;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Api;
use kube::api::PostParams;
use reqwest::Version;
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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-ing-tls").await?;

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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-ing-tls-nohosts").await?;

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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-ing-tls-rotate").await?;

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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-ing-cert-mgr").await?;

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
    wait::poll_until(
        timeout,
        wait::POLL,
        || async {
            match try_raw_http(proxy_addr, proxy_line.as_bytes(), http_req).await {
                Ok(_) => "PROXY v1 route to return a 200 body".to_string(),
                Err(e) => format!("PROXY v1 route to return 200; last attempt failed: {e}"),
            }
        },
        || async {
            try_raw_http(proxy_addr, proxy_line.as_bytes(), http_req)
                .await
                .ok()
        },
    )
    .await
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
    wait::poll_until(
        timeout,
        wait::POLL,
        || async {
            match try_tls_after_proxy_v2(tls_addr, host, v2_header, http_req).await {
                Ok(_) => "PROXY v2 + TLS route to return a 200 body".to_string(),
                Err(e) => format!("PROXY v2 + TLS route to return 200; last attempt failed: {e}"),
            }
        },
        || async {
            try_tls_after_proxy_v2(tls_addr, host, v2_header, http_req)
                .await
                .ok()
        },
    )
    .await
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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-tls-sni").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host_a = format!("tls-a.{}.local", ns.name);
    let host_b = format!("tls-b.{}.local", ns.name);
    let cert_a = GeneratedCert::for_host(&host_a);
    let cert_b = GeneratedCert::for_host(&host_b);

    fixtures::apply_fixture(
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

    // Shared-mode Gateways advertise their OWN VIP (#472) — resolve it from the
    // Gateway's status instead of using the shared proxy Service address.
    let gw_addr = wait::wait_for_gateway_address(
        &h.client,
        "coxswain-tls-test",
        &ns.name,
        GATEWAY_HTTPS_PORT,
        Duration::from_secs(120),
    )
    .await?;

    let resp_a = wait::wait_for_https_route(gw_addr, &host_a, "/", Duration::from_secs(60)).await?;
    resp_a.assert_backend("echo-a");

    let resp_b = wait::wait_for_https_route(gw_addr, &host_b, "/", Duration::from_secs(60)).await?;
    resp_b.assert_backend("echo-b");

    // Unknown SNI must cause a TLS handshake failure (no cert installed).
    let unknown = format!("unknown.{}.local", ns.name);
    let result = http::https_get(&unknown, "/", gw_addr).await;
    assert!(
        result.is_err(),
        "expected TLS error for unknown SNI, got: {result:?}"
    );

    Ok(())
}

/// Cross-Gateway TLS-termination isolation (#472): two shared-mode Gateways in
/// one namespace BOTH terminate the SAME hostname with DIFFERENT certs, each on
/// its OWN per-Gateway VIP. Because the proxy keys its terminate cert store by
/// the internal port each VIP maps to, the two Gateways never share a cert
/// namespace:
///   - A's VIP presents A's cert for the shared hostname and routes to echo-a.
///   - B's VIP presents B's (different) cert for the same hostname → echo-b.
///   - A's VIP cannot complete a handshake for a hostname only B serves, even
///     though B holds a valid cert for it — proving no cross-Gateway cert leak.
#[tokio::test]
async fn https_terminate_cert_isolated_per_gateway() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-iso").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let shared_host = format!("iso-shared.{}.local", ns.name);
    let b_only_host = format!("iso-b-only.{}.local", ns.name);
    // A and B both hold a cert for `shared_host`, but distinct key pairs — so a
    // served-leaf-DER comparison proves which Gateway answered.
    let cert_a = GeneratedCert::for_host(&shared_host);
    let cert_b = GeneratedCert::for_host(&shared_host);
    let cert_b2 = GeneratedCert::for_host(&b_only_host);

    fixtures::apply_fixture(
        gwa::TLS_ISOLATION_CROSS_GATEWAY,
        FixtureVars::new(&ns.name)
            .with("SHARED_HOSTNAME", &shared_host)
            .with("B_ONLY_HOSTNAME", &b_only_host)
            .with("SECRET_A_NAME", "iso-cert-a")
            .with("SECRET_B_NAME", "iso-cert-b")
            .with("SECRET_B2_NAME", "iso-cert-b-only")
            .with("TLS_CRT_A_B64", cert_a.cert_b64())
            .with("TLS_KEY_A_B64", cert_a.key_b64())
            .with("TLS_CRT_B_B64", cert_b.cert_b64())
            .with("TLS_KEY_B_B64", cert_b.key_b64())
            .with("TLS_CRT_B2_B64", cert_b2.cert_b64())
            .with("TLS_KEY_B2_B64", cert_b2.key_b64()),
    )
    .await?;

    // Each Gateway advertises its OWN VIP (#472) — resolve both from status.
    let a_vip = wait::wait_for_gateway_address(
        &h.client,
        "coxswain-iso-a",
        &ns.name,
        GATEWAY_HTTPS_PORT,
        Duration::from_secs(120),
    )
    .await?;
    let b_vip = wait::wait_for_gateway_address(
        &h.client,
        "coxswain-iso-b",
        &ns.name,
        GATEWAY_HTTPS_PORT,
        Duration::from_secs(120),
    )
    .await?;
    assert_ne!(
        a_vip.ip(),
        b_vip.ip(),
        "each shared-mode Gateway must get a distinct VIP, got A={a_vip} B={b_vip}"
    );

    // A's VIP serves the shared hostname → A's backend.
    let resp_a =
        wait::wait_for_https_route(a_vip, &shared_host, "/", Duration::from_secs(60)).await?;
    resp_a.assert_backend("echo-a");
    // B's VIP serves the same hostname → B's backend.
    let resp_b =
        wait::wait_for_https_route(b_vip, &shared_host, "/", Duration::from_secs(60)).await?;
    resp_b.assert_backend("echo-b");

    // The decisive assertion: SAME SNI, each VIP presents its OWN Gateway's cert.
    let der_a = http::https_peer_leaf_der(&shared_host, "/", a_vip).await?;
    let der_b = http::https_peer_leaf_der(&shared_host, "/", b_vip).await?;
    assert_eq!(
        der_a,
        cert_a.cert_der(),
        "Gateway A's VIP must present A's cert for the shared hostname"
    );
    assert_eq!(
        der_b,
        cert_b.cert_der(),
        "Gateway B's VIP must present B's cert for the shared hostname"
    );
    assert_ne!(
        der_a, der_b,
        "same SNI on the two VIPs must yield different certs — cert store is per-Gateway"
    );

    // B genuinely serves `b_only_host` on its VIP (positive control for the negative below).
    wait::wait_for_https_route(b_vip, &b_only_host, "/", Duration::from_secs(60)).await?;

    // Negative — no cross-Gateway leak: A's VIP must NOT complete a handshake for
    // a hostname only B holds a cert/listener for. A's port-scoped cert store
    // never sees B's cert.
    let leaked = http::https_get(&b_only_host, "/", a_vip).await;
    assert!(
        leaked.is_err(),
        "A's VIP must reject a hostname only Gateway B serves (no cross-Gateway cert leak), got: {leaked:?}"
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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-tls-missing").await?;

    let host = format!("tls-missing.{}.local", ns.name);
    let secret_name = "cert-missing";

    // Apply a Gateway with an HTTPS listener whose Secret does not exist yet.
    fixtures::apply_fixture(
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
async fn tls_cross_namespace_grant_serves_https() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-tls-xns").await?;
    let certs_ns = NamespaceGuard::create(&h.client, "tls-gw-tls-xns-certs").await?;

    // Deploy backend in the primary namespace.
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("tls-xns.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&host);
    let secret_name = "xns-cert";

    // Deploy Secret + ReferenceGrant into the certs namespace.
    fixtures::apply_fixture(
        gwa::TLS_CROSS_NAMESPACE_CERTS,
        FixtureVars::new(&certs_ns.name)
            .with("TESTNS", &ns.name)
            .with("SECRET_NAME", secret_name)
            .with("TLS_CRT_B64", cert.cert_b64())
            .with("TLS_KEY_B64", cert.key_b64()),
    )
    .await?;

    // Deploy Gateway + HTTPRoute into the primary namespace.
    fixtures::apply_fixture(
        gwa::TLS_CROSS_NAMESPACE_GW,
        FixtureVars::new(&ns.name)
            .with("CERTS_NS", &certs_ns.name)
            .with("LISTENER_HOSTNAME", &host)
            .with("SECRET_NAME", secret_name),
    )
    .await?;

    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    let resp = wait::wait_for_https_route(gw_tls, &host, "/", Duration::from_secs(60)).await?;
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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-tls-rotate").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host_a = format!("tls-rot-a.{}.local", ns.name);
    let host_b = format!("tls-rot-b.{}.local", ns.name);
    let cert_a_old = GeneratedCert::for_host(&host_a);
    let cert_a_new = GeneratedCert::for_host(&host_a);
    let cert_b = GeneratedCert::for_host(&host_b);

    // Deploy with original certs.
    fixtures::apply_fixture(
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

    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    wait::wait_for_https_route(gw_tls, &host_a, "/", Duration::from_secs(60)).await?;
    wait::wait_for_https_route(gw_tls, &host_b, "/", Duration::from_secs(60)).await?;

    let old_der_a = http::https_peer_leaf_der(&host_a, "/", gw_tls).await?;
    let old_der_b = http::https_peer_leaf_der(&host_b, "/", gw_tls).await?;

    // Rotate only Secret A; Secret B data is unchanged.
    fixtures::apply_fixture(
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
    wait::wait_for_tls_cert_rotation(gw_tls, &host_a, &old_der_a, Duration::from_secs(15)).await?;

    // Listener B must still serve the original cert (no spurious swap).
    let new_der_b = http::https_peer_leaf_der(&host_b, "/", gw_tls).await?;
    assert_eq!(old_der_b, new_der_b, "listener B cert must not change");

    // Both listeners must still route correctly.
    let resp_a = http::https_get(&host_a, "/", gw_tls).await?;
    assert!(
        resp_a.1.is_some(),
        "expected response from listener A after rotation"
    );
    resp_a.1.unwrap().assert_backend("echo-a");

    let resp_b = http::https_get(&host_b, "/", gw_tls).await?;
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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-cert-mgr").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("tls-cm.{}.local", ns.name);
    let secret_name = "cert-manager-tls";

    fixtures::apply_fixture(
        gwa::CERT_MANAGER,
        FixtureVars::new(&ns.name)
            .with("LISTENER_HOSTNAME", &host)
            .with("SECRET_NAME", secret_name),
    )
    .await?;

    // Wait for cert-manager to issue the certificate and populate the Secret.
    wait::wait_for_tls_secret(&h.client, secret_name, &ns.name, Duration::from_secs(120)).await?;

    // Coxswain picks up the Secret via its Secret watch; wait for HTTPS to become live.
    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    let resp = wait::wait_for_https_route(gw_tls, &host, "/", Duration::from_secs(60)).await?;
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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-ws").await?;

    fixtures::apply_fixture(backends::WEBSOCKET_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["ws-echo"]).await?;
    fixtures::apply_fixture(gwa::WEBSOCKET, FixtureVars::new(&ns.name)).await?;

    let host = format!("ws.{}.local", ns.name);
    let gw_http = h.gateway_http_addr(&ns.name).await?;

    // Poll until the proxy returns a 101 for this virtual host.
    wait::wait_for_ws_route(gw_http, &host, Duration::from_secs(60)).await?;

    // Open a fresh WebSocket connection and verify the echo round-trip.
    let uri = format!("ws://{gw_http}/");
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

/// Verifies the Gateway-API `appProtocol: kubernetes.io/h2c` path (GEP-1911, #367):
/// a Service port declaring h2c makes the proxy speak HTTP/2 cleartext on the
/// upstream leg (distinct from the Ingress annotation path in
/// [`annotation_backend_protocol_grpc_selects_h2c`]).
///
/// Two HTTPRoutes point at the same h2c-only port 3001 through two Services that
/// differ only in `appProtocol`, so the upstream wire protocol is governed solely
/// by the Service field — not the port:
/// - `appProtocol: kubernetes.io/h2c` → `BackendProtocol::H2c` → the proxy speaks
///   h2c → the port serves (2xx).
/// - no `appProtocol` → `BackendProtocol::Http1` → the proxy speaks HTTP/1.1 → the
///   h2c-only port rejects it (non-2xx). This is the negative that proves the
///   `appProtocol` field — not the Service identity — flipped the protocol.
#[tokio::test]
async fn backend_protocol_h2c() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-h2c").await?;

    fixtures::apply_fixture(backends::H2C_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["h2c-echo"]).await?;
    fixtures::apply_fixture(gwa::BACKEND_PROTOCOL_H2C, FixtureVars::new(&ns.name)).await?;

    // Positive: appProtocol h2c → h2c → the h2c-only port serves.
    let gw = h.gateway_http(&ns.name).await?;
    let host = format!("h2c.{}.local", ns.name);
    let resp = wait::wait_for_route(&gw, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("h2c-echo");

    // Negative: no appProtocol → HTTP/1.1 → the h2c-only port rejects the request.
    // The route is programmed (the positive proved the fixture reconciled); only the
    // wire protocol differs. The rejection surfaces as 400 or 502 depending on how the
    // h2c/HTTP-1.1 mismatch fails, so assert the rejection class rather than a single code.
    let plain_host = format!("h2c-plain.{}.local", ns.name);
    wait::wait_for_route_rejected(&gw, &plain_host, "/", Duration::from_secs(60)).await?;

    Ok(())
}

/// Verifies the Ingress `ingress.coxswain-labs.dev/backend-protocol` annotation
/// (distinct from the Gateway-API `appProtocol` path in [`backend_protocol_h2c`]).
///
/// Both Ingresses point at the same appProtocol-less Service on the h2c-only port
/// 3001, so the upstream wire protocol is governed solely by the annotation:
/// - `GRPC` → `BackendProtocol::H2c` → the proxy speaks h2c → the port serves (2xx).
/// - no annotation → `BackendProtocol::Http1` → the proxy speaks HTTP/1.1 → the
///   h2c-only port rejects it (non-2xx). This is the negative that proves the
///   annotation — not the Service — flipped the protocol.
///
/// The HTTPS value isn't exercised here: an Ingress `backend-protocol: HTTPS` makes
/// the proxy verify the upstream cert against the system trust store with no CA
/// injection path (Ingress has no `BackendTLSPolicy` equivalent), so a self-signed
/// e2e upstream can never complete the handshake. h2c needs no upstream cert.
#[tokio::test]
async fn annotation_backend_protocol_grpc_selects_h2c() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-ing-backend-protocol").await?;

    fixtures::apply_fixture(backends::H2C_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["h2c-echo"]).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_BACKEND_PROTOCOL,
        FixtureVars::new(&ns.name),
    )
    .await?;

    // Positive: GRPC annotation → h2c → the h2c-only port serves.
    let grpc_host = format!("backend-protocol-grpc.{}.local", ns.name);
    let resp = wait::wait_for_route(&h.http, &grpc_host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("h2c-echo");

    // Negative: no annotation → HTTP/1.1 → the h2c-only port rejects the request.
    // The route is programmed (the positive proved the fixture reconciled); only the
    // wire protocol differs. The rejection surfaces as 400 or 502 depending on how the
    // h2c/HTTP-1.1 mismatch fails (upstream protocol error vs. no valid upstream
    // response), so assert the rejection class rather than a single hardcoded code.
    let http1_host = format!("backend-protocol-http1.{}.local", ns.name);
    wait::wait_for_route_rejected(&h.http, &http1_host, "/", Duration::from_secs(60)).await?;

    Ok(())
}

/// An HTTPS listener with a RequestRedirect filter must produce a `Location` header
/// that uses the `https://` scheme, not the hardcoded `http://` that existed before
/// the redirect-scheme fix.
#[tokio::test]
async fn tls_redirect_preserves_https_scheme() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-tls-redirect").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("tls-redirect.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&host);
    let secret_name = "cert-tls-redirect";

    fixtures::apply_fixture(
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
    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    wait::wait_for_https_route(
        gw_tls,
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
        .resolve(&host, gw_tls)
        .build()?;

    let url = format!("https://{}:{}/tls-redirect", host, gw_tls.port());
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
async fn backend_tls_policy_configmap_ca_verifies_upstream() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-backend-tls").await?;

    // Generate a self-signed cert for the backend.
    let tls_hostname = format!("echo-tls.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&tls_hostname);

    // Deploy the TLS echo backend.
    fixtures::apply_fixture(
        backends::ECHO_TLS,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", cert.key_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-tls"]).await?;

    let host = format!("backend-tls.{}.local", ns.name);

    // Apply Gateway + HTTPRoute + ConfigMap CA + BackendTLSPolicy.
    fixtures::apply_fixture(
        gwa::BACKEND_TLS_POLICY,
        FixtureVars::new(&ns.name)
            .with("TLS_HOSTNAME", &tls_hostname)
            .with("CA_PEM", cert.cert_pem.clone()), // self-signed: cert IS the CA
    )
    .await?;

    // The route should come up once the controller reconciles and the proxy verifies the cert.
    let gw = h.gateway_http(&ns.name).await?;
    let resp = wait::wait_for_route(&gw, &host, "/", Duration::from_secs(60)).await?;
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
async fn backend_tls_policy_invalid_ca_rejects_with_502() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-backend-tls-invalid").await?;

    // Backend cert can be anything — the policy is invalid before we get to TLS.
    let cert = GeneratedCert::for_host(&format!("echo-tls.{}.local", ns.name));
    fixtures::apply_fixture(
        backends::ECHO_TLS,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", cert.key_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-tls"]).await?;

    fixtures::apply_fixture(
        gwa::BACKEND_TLS_POLICY_INVALID_CA,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let host = format!("backend-tls.{}.local", ns.name);
    // Traffic MUST return 5xx — never plain-HTTP-fallthrough success.
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route_status(&gw, &host, "/", 502, Duration::from_secs(60)).await?;

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
async fn backend_tls_policy_section_name_selects_per_port_sni() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-backend-tls-section").await?;

    let sni_primary = format!("primary.{}.local", ns.name);
    let sni_secondary = format!("secondary.{}.local", ns.name);
    let cert = GeneratedCert::for_hosts(&[&sni_primary, &sni_secondary]);

    // Apply the dual-port TLS echo backend.
    fixtures::apply_fixture(
        backends::ECHO_TLS_DUAL_PORT,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", cert.key_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-tls"]).await?;

    fixtures::apply_fixture(
        gwa::BACKEND_TLS_POLICY_SECTION_NAME,
        FixtureVars::new(&ns.name)
            .with("SNI_PRIMARY", &sni_primary)
            .with("SNI_SECONDARY", &sni_secondary)
            .with("CA_PEM", cert.cert_pem.clone()),
    )
    .await?;

    let host = format!("backend-tls.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;

    // Both routes must succeed. The section-name policy applies to port 443; the
    // catch-all to port 8443. If per-port lookup is broken, one of these returns 5xx.
    let resp = wait::wait_for_route(&gw, &host, "/port-443/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-tls");
    let resp = wait::wait_for_route(&gw, &host, "/port-8443/", Duration::from_secs(30)).await?;
    resp.assert_backend("echo-tls");

    Ok(())
}

/// `BackendTLSPolicy` conflict resolution:
/// - Two policies on the same Service with NO `sectionName`.
/// - Name-tiebreak: "aaa-policy" < "zzz-policy", so "aaa-policy" wins.
/// - Expected status: winner `Accepted=True`, loser `Accepted=False/Conflicted`,
///   both with the test Gateway in `status.ancestors[]`.
#[tokio::test]
async fn backend_tls_policy_conflict_resolves_by_name() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-backend-tls-conflict").await?;

    let tls_hostname = format!("echo-tls.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&tls_hostname);

    fixtures::apply_fixture(
        backends::ECHO_TLS,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", cert.key_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-tls"]).await?;

    fixtures::apply_fixture(
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
async fn backend_tls_policy_configmap_mutation_reloads_ca() -> anyhow::Result<()> {
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::api::{Patch, PatchParams};

    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-backend-tls-cm-mutation").await?;

    let tls_hostname = format!("echo-tls.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&tls_hostname);

    fixtures::apply_fixture(
        backends::ECHO_TLS,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", cert.key_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-tls"]).await?;

    fixtures::apply_fixture(
        gwa::BACKEND_TLS_POLICY,
        FixtureVars::new(&ns.name)
            .with("TLS_HOSTNAME", &tls_hostname)
            .with("CA_PEM", cert.cert_pem.clone()),
    )
    .await?;

    let host = format!("backend-tls.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    let resp = wait::wait_for_route(&gw, &host, "/", Duration::from_secs(60)).await?;
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
    wait::wait_for_route_status(&gw, &host, "/", 502, Duration::from_secs(60)).await?;

    Ok(())
}

/// `BackendTLSPolicy` hostname-mismatch: the policy's `validation.hostname` does not
/// match the SAN in the backend's certificate → TLS handshake fails → proxy returns 5xx.
#[tokio::test]
async fn backend_tls_policy_hostname_mismatch_fails_handshake() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-backend-tls-mismatch").await?;

    // Backend cert is issued for the real hostname.
    let real_hostname = format!("echo-tls.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&real_hostname);

    fixtures::apply_fixture(
        backends::ECHO_TLS,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", cert.key_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-tls"]).await?;

    // Policy specifies a hostname that does NOT match the cert's SAN.
    let wrong_hostname = format!("wrong-hostname.{}.local", ns.name);

    fixtures::apply_fixture(
        gwa::BACKEND_TLS_POLICY,
        FixtureVars::new(&ns.name)
            .with("TLS_HOSTNAME", &wrong_hostname) // mismatch
            .with("CA_PEM", cert.cert_pem.clone()),
    )
    .await?;

    let host = format!("backend-tls.{}.local", ns.name);

    // Wait for the route to appear in the routing table (reconciler must have processed it).
    // Then assert that requests fail with 5xx (TLS verification error from Pingora).
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route_status(&gw, &host, "/", 502, Duration::from_secs(60)).await?;

    Ok(())
}

/// Verifies that `ingress.coxswain-labs.dev/ssl-redirect: "true"` (with default code 308)
/// causes the HTTP listener to issue a 308 redirect whose Location starts with `https://`
/// and preserves the original host and path.
#[tokio::test]
async fn ingress_ssl_redirect_upgrades_http_to_https_308() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-ing-ssl-redir").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_SSL_REDIRECT,
        FixtureVars::new(&ns.name).with("SSL_REDIRECT_CODE", "308"),
    )
    .await?;

    let host = format!("ssl-redirect.{}.local", ns.name);

    let location = wait::wait_for_route_redirect(
        h.http.proxy_addr,
        &host,
        "/probe",
        308,
        Duration::from_secs(60),
    )
    .await?;

    assert!(
        location.starts_with("https://"),
        "ssl-redirect: Location must start with https://, got {location:?}"
    );
    assert!(
        location.contains(&host),
        "ssl-redirect: Location must preserve the original host {host:?}, got {location:?}"
    );
    assert!(
        location.ends_with("/probe"),
        "ssl-redirect: Location must preserve the original path /probe, got {location:?}"
    );

    Ok(())
}

/// Verifies that `ingress.coxswain-labs.dev/ssl-redirect-code: "301"` overrides the
/// default 308 status code for the HTTP→HTTPS redirect.
#[tokio::test]
async fn ingress_ssl_redirect_honors_custom_status_code() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-ing-ssl-301").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        ingress::ANNOTATION_SSL_REDIRECT,
        FixtureVars::new(&ns.name).with("SSL_REDIRECT_CODE", "301"),
    )
    .await?;

    let host = format!("ssl-redirect.{}.local", ns.name);

    let location =
        wait::wait_for_route_redirect(h.http.proxy_addr, &host, "/", 301, Duration::from_secs(60))
            .await?;

    assert!(
        location.starts_with("https://"),
        "ssl-redirect-code=301: Location must start with https://, got {location:?}"
    );

    Ok(())
}

/// Verifies that `ingress.coxswain-labs.dev/ssl-redirect` only applies to the HTTP listener:
/// - HTTP requests receive a 308 redirect to https://.
/// - HTTPS requests are served normally (200 from echo-a, no redirect).
///
/// This is the HTTP-port-scoping invariant: the `RequestRedirect` filter is prepended
/// only on the HTTP listener's route entry, leaving the TLS listener entry unmodified.
#[tokio::test]
async fn ingress_ssl_redirect_noop_on_https_listener() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-ing-ssl-noop").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("ssl-redirect-tls.{}.local", ns.name);
    let cert = GeneratedCert::for_host(&host);

    fixtures::apply_fixture(
        ingress::ANNOTATION_SSL_REDIRECT_TLS,
        FixtureVars::new(&ns.name)
            .with("SECRET_NAME", "ssl-redirect-cert")
            .with("TLS_CRT_B64", cert.cert_b64())
            .with("TLS_KEY_B64", cert.key_b64()),
    )
    .await?;

    // HTTP listener must redirect to HTTPS.
    let location =
        wait::wait_for_route_redirect(h.http.proxy_addr, &host, "/", 308, Duration::from_secs(60))
            .await?;
    assert!(
        location.starts_with("https://"),
        "ssl-redirect noop: HTTP redirect Location must start with https://, got {location:?}"
    );

    // HTTPS listener must NOT redirect — must serve 200 from echo-a.
    let resp = wait::wait_for_https_route(h.tls_addr, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    Ok(())
}

/// Tracking issue for cross-namespace `BackendTLSPolicy` CA certs.
/// Currently unsupported per `rbac.rs`. Test validates that we correctly hit the graceful failure mode
/// (or tracks when it magically starts working so we know to remove the ignore).
#[ignore = "Cross-namespace BackendTLSPolicy caCertificateRef is currently unsupported (#XXX)"]
#[tokio::test]
async fn backend_tls_policy_cross_namespace_ca_fails_gracefully() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns_primary = NamespaceGuard::create(&h.client, "btls-cross-primary").await?;
    let ns_tenant = NamespaceGuard::create(&h.client, "btls-cross-tenant").await?;

    let host = format!("backend-tls.{}.local", ns_primary.name);
    let cert = GeneratedCert::for_host(&host);

    // Apply the echo-tls backend in the primary namespace so it matches the policy target.
    fixtures::apply_fixture(
        backends::ECHO_TLS,
        FixtureVars::new(&ns_primary.name)
            .with("TLS_CRT_B64", cert.cert_b64())
            .with("TLS_KEY_B64", cert.key_b64()),
    )
    .await?;

    // Apply the ConfigMap CA + ReferenceGrant in the tenant namespace
    let ca_pem_indented = cert.cert_pem.replace("\n", "\n    ");
    fixtures::apply_fixture(
        gwa::BACKEND_TLS_POLICY_CROSS_NAMESPACE_TENANT,
        FixtureVars::new(&ns_tenant.name)
            .with("TESTNS", &ns_primary.name)
            .with("CA_PEM", &ca_pem_indented),
    )
    .await?;

    // Apply the Gateway, HTTPRoute, and BackendTLSPolicy in the primary namespace
    fixtures::apply_fixture(
        gwa::BACKEND_TLS_POLICY_CROSS_NAMESPACE_ROUTE,
        FixtureVars::new(&ns_primary.name)
            .with("TENANTNS", &ns_tenant.name)
            .with("TLS_HOSTNAME", &host),
    )
    .await?;

    // Once implemented, this test should assert a successful 200 response from echo-tls.
    // Right now, it'll fail or result in 502 Bad Gateway due to missing CA bundle resolution.
    let gw = h.gateway_http(&ns_primary.name).await?;
    let resp = wait::wait_for_route(&gw, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-tls");

    Ok(())
}

/// Verifies that HTTPS clients negotiate HTTP/2 via ALPN with the proxy (#32).
///
/// The proxy advertises `h2` and `http/1.1` in its TLS ALPN extension.  A
/// TLS client that supports h2 must receive an HTTP/2 response — confirmed by
/// `resp.version() == HTTP_2`.
#[tokio::test]
async fn h2_negotiated_over_tls_via_alpn() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-h2-alpn").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host_a = format!("h2-alpn-a.{}.local", ns.name);
    let host_b = format!("h2-alpn-b.{}.local", ns.name); // required by the two-listener fixture
    let cert_a = GeneratedCert::for_host(&host_a);
    let cert_b = GeneratedCert::for_host(&host_b);

    fixtures::apply_fixture(
        gwa::TLS_TERMINATION,
        FixtureVars::new(&ns.name)
            .with("LISTENER_A_HOSTNAME", &host_a)
            .with("LISTENER_B_HOSTNAME", &host_b)
            .with("SECRET_A_NAME", "cert-h2-a")
            .with("SECRET_B_NAME", "cert-h2-b")
            .with("TLS_CRT_A_B64", cert_a.cert_b64())
            .with("TLS_KEY_A_B64", cert_a.key_b64())
            .with("TLS_CRT_B_B64", cert_b.cert_b64())
            .with("TLS_KEY_B_B64", cert_b.key_b64()),
    )
    .await?;

    // Wait for the HTTPS route to be live (uses a plain h1 client internally).
    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    wait::wait_for_https_route(gw_tls, &host_a, "/", Duration::from_secs(60)).await?;

    // Build an h2-capable TLS client (no .http1_only()) — reqwest with rustls will
    // negotiate h2 via ALPN when the server offers it.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .resolve(&host_a, gw_tls)
        .build()?;
    let url = format!("https://{}:{}/", host_a, gw_tls.port());
    let resp = client.get(&url).send().await?;

    assert_eq!(
        resp.status().as_u16(),
        200,
        "HTTPS h2 request must return 200"
    );
    assert_eq!(
        resp.version(),
        Version::HTTP_2,
        "proxy must negotiate HTTP/2 via ALPN for a TLS client that offers h2"
    );

    Ok(())
}

/// Verifies that HTTPS clients that prefer HTTP/1.1 are still served correctly
/// after h2 ALPN is added (#32 backward compatibility).
///
/// A client calling `.http1_only()` sends no `h2` ALPN extension.  The proxy
/// must fall back to HTTP/1.1 and serve the request normally.
#[tokio::test]
async fn h1_over_tls_served_when_client_prefers_h1() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-h1-alpn").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host_a = format!("h1-alpn-a.{}.local", ns.name);
    let host_b = format!("h1-alpn-b.{}.local", ns.name);
    let cert_a = GeneratedCert::for_host(&host_a);
    let cert_b = GeneratedCert::for_host(&host_b);

    fixtures::apply_fixture(
        gwa::TLS_TERMINATION,
        FixtureVars::new(&ns.name)
            .with("LISTENER_A_HOSTNAME", &host_a)
            .with("LISTENER_B_HOSTNAME", &host_b)
            .with("SECRET_A_NAME", "cert-h1-a")
            .with("SECRET_B_NAME", "cert-h1-b")
            .with("TLS_CRT_A_B64", cert_a.cert_b64())
            .with("TLS_KEY_A_B64", cert_a.key_b64())
            .with("TLS_CRT_B_B64", cert_b.cert_b64())
            .with("TLS_KEY_B_B64", cert_b.key_b64()),
    )
    .await?;

    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    wait::wait_for_https_route(gw_tls, &host_a, "/", Duration::from_secs(60)).await?;

    // Force h1: the ALPN callback must not select h2 when the client doesn't offer it.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .http1_only()
        .resolve(&host_a, gw_tls)
        .build()?;
    let url = format!("https://{}:{}/", host_a, gw_tls.port());
    let resp = client.get(&url).send().await?;

    assert_eq!(
        resp.status().as_u16(),
        200,
        "HTTPS h1 request must return 200"
    );
    assert_eq!(
        resp.version(),
        Version::HTTP_11,
        "proxy must fall back to HTTP/1.1 when client does not offer h2 in ALPN"
    );

    Ok(())
}

// ── GEP-3567 misdirected-request helpers ─────────────────────────────────────

/// Connect to `proxy_addr` with TLS SNI = `sni`, then send a plain HTTP/1.1
/// GET with `Host: host_header`. Returns the HTTP response status code.
///
/// Uses a no-op certificate verifier so self-signed test certs are accepted.
/// This is the building block for GEP-3567 e2e tests: the SNI in the TLS
/// handshake deliberately differs from the `Host` request header to simulate
/// HTTP/2 connection coalescing across listener boundaries.
async fn https_get_with_sni(
    sni: &str,
    host_header: &str,
    path: &str,
    proxy_addr: std::net::SocketAddr,
) -> anyhow::Result<u16> {
    use anyhow::Context as _;
    use rustls::ClientConfig;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    #[derive(Debug)]
    struct NoVerifier;
    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let config = Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth(),
    );
    let connector = TlsConnector::from(config);
    let tcp = TcpStream::connect(proxy_addr)
        .await
        .context("TCP connect to proxy")?;
    let server_name = ServerName::try_from(sni.to_owned()).context("invalid SNI")?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake")?;

    let req = format!("GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes())
        .await
        .context("write HTTP request")?;

    // Pingora closes the connection without a TLS close_notify after an error
    // response (e.g. 421 Misdirected Request) and after any `Connection: close`
    // reply. rustls surfaces that as `UnexpectedEof`, which `read_to_end` treats
    // as fatal — masking the response bytes that already arrived. Real clients
    // (reqwest, curl, browsers) tolerate this; mirror that by reading chunks and
    // accepting `UnexpectedEof` as a clean end-of-stream once the bytes are in.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tls.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(anyhow::Error::new(e)).context("read HTTP response"),
        }
    }

    let text = String::from_utf8_lossy(&buf);
    text.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .with_context(|| format!("parse HTTP status from: {:.100}", text))
}

/// Verifies GEP-3567 misdirected-request detection on Gateway HTTPS listeners.
///
/// A Gateway with two HTTPS listeners on the same port (one exact-hostname, one
/// wildcard) must return 421 when the request's Host header resolves to a
/// *different* listener than the one selected by the TLS SNI.  Connections where
/// both SNI and Host resolve to the *same* listener (including the legitimate
/// coalescing case within a wildcard listener) must be served normally (200).
#[tokio::test]
async fn gateway_https_coalescing_returns_421_for_cross_listener_host() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-mdr421").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    // Two listener hostnames: one exact, one wildcard.
    let exact_host = format!("mdr-exact.{}.local", ns.name);
    let wild_pattern = format!("*.mdr.{}.local", ns.name);
    let wild_a = format!("a.mdr.{}.local", ns.name);
    let wild_b = format!("b.mdr.{}.local", ns.name);

    // One cert per listener; self-signed, accepted via NoVerifier in the test
    // client — no SAN validation needed.
    let cert_exact = GeneratedCert::for_host(&exact_host);
    let cert_wild = GeneratedCert::for_host(&wild_pattern);

    fixtures::apply_fixture(
        gwa::TLS_TERMINATION,
        FixtureVars::new(&ns.name)
            .with("LISTENER_A_HOSTNAME", &exact_host)
            .with("LISTENER_B_HOSTNAME", &wild_pattern)
            .with("SECRET_A_NAME", "cert-mdr-exact")
            .with("SECRET_B_NAME", "cert-mdr-wild")
            .with("TLS_CRT_A_B64", cert_exact.cert_b64())
            .with("TLS_KEY_A_B64", cert_exact.key_b64())
            .with("TLS_CRT_B_B64", cert_wild.cert_b64())
            .with("TLS_KEY_B_B64", cert_wild.key_b64()),
    )
    .await?;

    // Verify both routes are live with normal (matching SNI+Host) requests before
    // probing the mismatch cases.
    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    wait::wait_for_https_route(gw_tls, &exact_host, "/", Duration::from_secs(60)).await?;
    wait::wait_for_https_route(gw_tls, &wild_a, "/", Duration::from_secs(60)).await?;

    let proxy = gw_tls;

    // ── Sad paths: cross-listener → 421 ─────────────────────────────────────

    // SNI=exact listener, Host=wildcard-listener → different listeners → 421.
    let status = https_get_with_sni(&exact_host, &wild_a, "/", proxy).await?;
    assert_eq!(
        status, 421,
        "SNI={exact_host:?} Host={wild_a:?}: expected 421 Misdirected Request (cross-listener)"
    );

    // SNI=wildcard-listener, Host=exact-listener → different listeners → 421.
    let status = https_get_with_sni(&wild_a, &exact_host, "/", proxy).await?;
    assert_eq!(
        status, 421,
        "SNI={wild_a:?} Host={exact_host:?}: expected 421 Misdirected Request (cross-listener)"
    );

    // ── Happy coalescing path: same wildcard listener → 200 ─────────────────

    // SNI=wild_a and Host=wild_b both resolve to the *.mdr listener → not
    // misdirected; proxy routes by Host to echo-b and returns 200.
    let status = https_get_with_sni(&wild_a, &wild_b, "/", proxy).await?;
    assert_eq!(
        status, 200,
        "SNI={wild_a:?} Host={wild_b:?}: expected 200 (same *.mdr listener; coalescing is safe)"
    );

    Ok(())
}

/// GEP-851 dual-certificate listener — happy path:
/// - Gateway listener declares two `certificateRefs` (an ECDSA cert + a static RSA cert).
/// - Controller resolves both Secrets → listener `ResolvedRefs=True`.
/// - HTTPS routing succeeds; the proxy serves the ECDSA cert because
///   `TlsStoreBuilder::build()` sorts ECDSA ahead of RSA.
#[tokio::test]
async fn https_listener_serves_ecdsa_cert_when_dual_cert_configured() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-dual-cert-happy").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("dual.{}.local", ns.name);
    let ecdsa_cert = GeneratedCert::for_host(&host);

    fixtures::apply_fixture(
        gwa::TLS_DUAL_CERT,
        FixtureVars::new(&ns.name)
            .with("HOSTNAME", &host)
            .with("ECDSA_SECRET", "cert-ecdsa")
            .with("RSA_SECRET", "cert-rsa")
            .with("ECDSA_CRT_B64", ecdsa_cert.cert_b64())
            .with("ECDSA_KEY_B64", ecdsa_cert.key_b64())
            .with("RSA_CRT_B64", StaticRsaCert::cert_b64())
            .with("RSA_KEY_B64", StaticRsaCert::key_b64()),
    )
    .await?;

    // Both cert refs resolve → ResolvedRefs=True.
    wait::wait_for_gateway_listener_condition(
        &h.client,
        "coxswain-dual-cert-test",
        &ns.name,
        "https",
        "ResolvedRefs",
        "True",
        Duration::from_secs(30),
    )
    .await?;

    // HTTPS routing must work via the dual-cert listener.
    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    let resp = wait::wait_for_https_route(gw_tls, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    // The proxy must serve the ECDSA cert (sorted first by TlsStoreBuilder::build()).
    let served_der = http::https_peer_leaf_der(&host, "/", gw_tls).await?;
    assert_eq!(
        served_der,
        ecdsa_cert.cert_der(),
        "expected ECDSA cert to be served; TlsStoreBuilder sorts ECDSA ahead of RSA"
    );

    Ok(())
}

/// GEP-851 dual-certificate listener — partial-resolve sad path:
/// - Gateway listener declares two `certificateRefs`: one valid ECDSA Secret and
///   one that does not exist.
/// - Controller resolves one ref and fails the other →
///   listener `ResolvedRefs=False` (GEP-851: partial resolution must degrade, not succeed).
/// - HTTPS routing still works via the valid cert (best-effort serve).
#[tokio::test]
async fn https_listener_degrades_when_one_certificate_ref_is_invalid() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-dual-cert-sad").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    let host = format!("dual-sad.{}.local", ns.name);
    let ecdsa_cert = GeneratedCert::for_host(&host);

    // Apply the dual-cert fixture but supply only the ECDSA Secret.
    // The RSA Secret ("cert-rsa-missing") does not exist → partial resolution.
    fixtures::apply_fixture(
        gwa::TLS_DUAL_CERT,
        FixtureVars::new(&ns.name)
            .with("HOSTNAME", &host)
            .with("ECDSA_SECRET", "cert-ecdsa-sad")
            .with("RSA_SECRET", "cert-rsa-missing")
            .with("ECDSA_CRT_B64", ecdsa_cert.cert_b64())
            .with("ECDSA_KEY_B64", ecdsa_cert.key_b64())
            // RSA Secret values are irrelevant — the Secret itself is omitted below.
            .with("RSA_CRT_B64", StaticRsaCert::cert_b64())
            .with("RSA_KEY_B64", StaticRsaCert::key_b64()),
    )
    .await?;

    // The fixture creates both Secrets; delete the RSA one to simulate "missing".
    let secrets_api: Api<Secret> = Api::namespaced(h.client.clone(), &ns.name);
    secrets_api
        .delete("cert-rsa-missing", &Default::default())
        .await?;

    // Partial resolution → ResolvedRefs=False on the listener.
    wait::wait_for_gateway_listener_condition(
        &h.client,
        "coxswain-dual-cert-test",
        &ns.name,
        "https",
        "ResolvedRefs",
        "False",
        Duration::from_secs(30),
    )
    .await?;

    // The valid cert is still served → HTTPS routing must succeed (best-effort).
    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    let resp = wait::wait_for_https_route(gw_tls, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    Ok(())
}

// ── Gateway frontend client-certificate mTLS — GEP-91 (#86) ──────────────────

/// Gateway `spec.tls.frontend.default.validation` (AllowValidOnly): a TLS
/// connection presenting a valid client certificate signed by the configured CA
/// is admitted (200).  The CA is delivered via a ConfigMap with key `ca.crt`
/// (Core-support ref, GEP-91 happy path).
#[tokio::test]
async fn gateway_frontend_mtls_accepts_valid_client_cert() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-mtls-valid").await?;

    let mtls = MtlsCerts::generate();
    let server_cert = GeneratedCert::for_host(&format!("gw-mtls.{}.local", ns.name));
    let host = format!("gw-mtls.{}.local", ns.name);

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        gwa::FRONTEND_MTLS_CONFIGMAP,
        FixtureVars::new(&ns.name)
            .with("HOSTNAME", &host)
            .with("SECRET_NAME", "gw-mtls-server-cert")
            .with("TLS_CRT_B64", server_cert.cert_b64())
            .with("TLS_KEY_B64", server_cert.key_b64())
            .with("CA_CRT_PEM", &mtls.ca_cert_pem),
    )
    .await?;

    // Poll until the route is live and the CA is reconciled into the ClientCertStore:
    // a valid client cert must be admitted (200 echo body).
    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    let resp = wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async {
            format!(
                "GEP-91 AllowValidOnly route {host}/ to admit a valid client cert (200 echo body)"
            )
        },
        || async {
            match http::https_get_with_client_cert(
                &host,
                "/",
                gw_tls,
                &mtls.client_cert_pem,
                &mtls.client_key_pem,
            )
            .await
            {
                Ok((_, Some(body))) => Some(body),
                _ => None,
            }
        },
    )
    .await?;

    resp.assert_backend("echo-a");
    Ok(())
}

/// Gateway `spec.tls.frontend.default.validation` (AllowValidOnly): a TLS
/// connection presenting **no** client certificate is rejected at the TLS
/// handshake — the server aborts with `FAIL_IF_NO_PEER_CERT` before the HTTP
/// layer is reached (GEP-91 sad path — Istio MUTUAL model).
#[tokio::test]
async fn gateway_frontend_mtls_rejects_missing_client_cert() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-mtls-nocert").await?;

    let mtls = MtlsCerts::generate();
    let server_cert = GeneratedCert::for_host(&format!("gw-mtls.{}.local", ns.name));
    let host = format!("gw-mtls.{}.local", ns.name);

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        gwa::FRONTEND_MTLS_CONFIGMAP,
        FixtureVars::new(&ns.name)
            .with("HOSTNAME", &host)
            .with("SECRET_NAME", "gw-mtls-server-cert")
            .with("TLS_CRT_B64", server_cert.cert_b64())
            .with("TLS_KEY_B64", server_cert.key_b64())
            .with("CA_CRT_PEM", &mtls.ca_cert_pem),
    )
    .await?;

    // Pre-condition: wait until mTLS is active — a valid cert must be accepted.
    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async {
            format!("GEP-91 AllowValidOnly route {host}/ to be active (valid cert accepted)")
        },
        || async {
            match http::https_get_with_client_cert(
                &host,
                "/",
                gw_tls,
                &mtls.client_cert_pem,
                &mtls.client_key_pem,
            )
            .await
            {
                Ok((_, Some(_))) => Some(()),
                _ => None,
            }
        },
    )
    .await?;

    // Now attempt without a client certificate.  The server must abort the TLS
    // handshake (FAIL_IF_NO_PEER_CERT) so reqwest returns an error before any
    // HTTP response is decoded.
    let result = http::https_get(&host, "/", gw_tls).await;
    anyhow::ensure!(
        result.is_err(),
        "expected TLS handshake failure when no client cert is presented on \
         GEP-91 AllowValidOnly host {host}; got Ok: {:?}",
        result.ok()
    );

    Ok(())
}

/// Gateway `spec.tls.frontend.default.validation` referencing an absent
/// ConfigMap: the controller resolves to `Unavailable`, and the proxy
/// fail-closes every TLS handshake to the listener hostname
/// (GEP-91 sad path — fail-closed on unresolvable CA ref).
#[tokio::test]
async fn gateway_frontend_mtls_fails_closed_when_ca_configmap_missing() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-mtls-noca").await?;

    let mtls = MtlsCerts::generate();
    let server_cert = GeneratedCert::for_host(&format!("gw-mtls.{}.local", ns.name));
    let host = format!("gw-mtls.{}.local", ns.name);

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    // The fixture references ConfigMap `does-not-exist` which is absent — the
    // controller must produce `ClientCertConfigState::Unavailable` for this host.
    fixtures::apply_fixture(
        gwa::FRONTEND_MTLS_MISSING_CA,
        FixtureVars::new(&ns.name)
            .with("HOSTNAME", &host)
            .with("SECRET_NAME", "gw-mtls-server-cert")
            .with("TLS_CRT_B64", server_cert.cert_b64())
            .with("TLS_KEY_B64", server_cert.key_b64()),
    )
    .await?;

    // GEP-91: a Gateway-wide frontend CA ref that can't resolve drives the HTTPS
    // listener to ResolvedRefs=False / Programmed=False (the
    // GatewayFrontendInvalidDefaultClientCertificateValidation conformance
    // contract), even though the listener's own server cert is valid.
    wait::wait_for_gateway_listener_condition(
        &h.client,
        "coxswain-frontend-missing-ca",
        &ns.name,
        "https",
        "ResolvedRefs",
        "False",
        Duration::from_secs(60),
    )
    .await?;
    wait::wait_for_gateway_listener_condition(
        &h.client,
        "coxswain-frontend-missing-ca",
        &ns.name,
        "https",
        "Programmed",
        "False",
        Duration::from_secs(60),
    )
    .await?;

    // Every connection attempt must fail at the TLS layer — the CA is Unavailable
    // so the proxy installs PEER | FAIL_IF_NO_PEER_CERT with no CA store, which
    // causes BoringSSL to reject every cert (including valid ones).
    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    let with_cert = http::https_get_with_client_cert(
        &host,
        "/",
        gw_tls,
        &mtls.client_cert_pem,
        &mtls.client_key_pem,
    )
    .await;
    anyhow::ensure!(
        with_cert.is_err(),
        "expected TLS failure with a valid client cert when CA ConfigMap is missing \
         (proxy must fail-close); got Ok: {:?}",
        with_cert.ok()
    );

    let without_cert = http::https_get(&host, "/", gw_tls).await;
    anyhow::ensure!(
        without_cert.is_err(),
        "expected TLS failure without a client cert when CA ConfigMap is missing \
         (proxy must fail-close); got Ok: {:?}",
        without_cert.ok()
    );

    Ok(())
}

/// Gateway `spec.tls.frontend.default.validation` CA ConfigMap hot-reload:
/// rotate the CA ConfigMap to a new CA and confirm that certs signed by the new
/// CA are accepted and certs signed by the old CA are rejected
/// (GEP-91 hot-reload).
#[tokio::test]
async fn gateway_frontend_mtls_reloads_ca_on_configmap_change() -> anyhow::Result<()> {
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::api::{Patch as KubePatch, PatchParams as KubePP};

    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-mtls-rotate").await?;

    let old_mtls = MtlsCerts::generate();
    let new_mtls = MtlsCerts::generate();
    let server_cert = GeneratedCert::for_host(&format!("gw-mtls.{}.local", ns.name));
    let host = format!("gw-mtls.{}.local", ns.name);

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    // Start with the old CA.
    fixtures::apply_fixture(
        gwa::FRONTEND_MTLS_CONFIGMAP,
        FixtureVars::new(&ns.name)
            .with("HOSTNAME", &host)
            .with("SECRET_NAME", "gw-mtls-server-cert")
            .with("TLS_CRT_B64", server_cert.cert_b64())
            .with("TLS_KEY_B64", server_cert.key_b64())
            .with("CA_CRT_PEM", &old_mtls.ca_cert_pem),
    )
    .await?;

    // Wait until the old CA is active: old client cert is admitted.
    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async { format!("GEP-91 AllowValidOnly route {host}/ to accept old-CA client cert") },
        || async {
            match http::https_get_with_client_cert(
                &host,
                "/",
                gw_tls,
                &old_mtls.client_cert_pem,
                &old_mtls.client_key_pem,
            )
            .await
            {
                Ok((_, Some(_))) => Some(()),
                _ => None,
            }
        },
    )
    .await?;

    // Rotate the CA ConfigMap to the new CA.
    let cms_api: Api<ConfigMap> = Api::namespaced(h.client.clone(), &ns.name);
    let patch = serde_json::json!({
        "data": {
            "ca.crt": new_mtls.ca_cert_pem
        }
    });
    cms_api
        .patch(
            "frontend-ca",
            &KubePP::apply("coxswain-e2e"),
            &KubePatch::Merge(&patch),
        )
        .await?;

    // After rotation: new client cert must be accepted.
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async {
            format!(
                "GEP-91 AllowValidOnly route {host}/ to accept new-CA client cert after CA rotation"
            )
        },
        || async {
            match http::https_get_with_client_cert(
                &host,
                "/",
                gw_tls,
                &new_mtls.client_cert_pem,
                &new_mtls.client_key_pem,
            )
            .await
            {
                Ok((_, Some(_))) => Some(()),
                _ => None,
            }
        },
    )
    .await?;

    // Old client cert must now be rejected (signed by rotated-out CA).
    let old_result = http::https_get_with_client_cert(
        &host,
        "/",
        gw_tls,
        &old_mtls.client_cert_pem,
        &old_mtls.client_key_pem,
    )
    .await;
    anyhow::ensure!(
        old_result.is_err(),
        "expected TLS failure for cert signed by old (rotated-out) CA after CA rotation; \
         got Ok: {:?}",
        old_result.ok()
    );

    Ok(())
}

/// Gateway `spec.tls.frontend.default.validation.mode: AllowInsecureFallback`:
/// a connection presenting **no** client certificate is admitted (200) because
/// the handshake is never aborted (GEP-91 happy path — AllowInsecureFallback).
#[tokio::test]
async fn gateway_frontend_mtls_insecure_fallback_admits_missing_cert() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-mtls-fallback").await?;

    let mtls = MtlsCerts::generate();
    let server_cert = GeneratedCert::for_host(&format!("gw-mtls.{}.local", ns.name));
    let host = format!("gw-mtls.{}.local", ns.name);

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        gwa::FRONTEND_MTLS_INSECURE_FALLBACK,
        FixtureVars::new(&ns.name)
            .with("HOSTNAME", &host)
            .with("SECRET_NAME", "gw-mtls-server-cert")
            .with("TLS_CRT_B64", server_cert.cert_b64())
            .with("TLS_KEY_B64", server_cert.key_b64())
            .with("CA_CRT_PEM", &mtls.ca_cert_pem),
    )
    .await?;

    // AllowInsecureFallback: a plain HTTPS connection (no client cert) must reach
    // the backend — the proxy must not abort the handshake.
    let gw_tls = h.gateway_tls_addr(&ns.name).await?;
    let resp = wait::wait_for_https_route(gw_tls, &host, "/", Duration::from_secs(90)).await?;
    resp.assert_backend("echo-a");

    // A valid client cert must also be accepted (fallback ≠ cert rejection).
    let resp_with_cert = wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            format!("GEP-91 AllowInsecureFallback route {host}/ to also accept a valid client cert")
        },
        || async {
            match http::https_get_with_client_cert(
                &host,
                "/",
                gw_tls,
                &mtls.client_cert_pem,
                &mtls.client_key_pem,
            )
            .await
            {
                Ok((_, Some(body))) => Some(body),
                _ => None,
            }
        },
    )
    .await?;

    resp_with_cert.assert_backend("echo-a");
    Ok(())
}

// ── GEP-3155: Gateway backend client certificate ──────────────────────────────

/// GEP-3155 happy path: proxy presents client cert to mTLS upstream.
///
/// Sequence:
/// 1. Generate a server cert + a client CA + client cert (two independent CAs).
/// 2. Deploy `echo-mtls` backend (requires a client cert signed by the client CA).
/// 3. Apply Gateway with `spec.tls.backend.clientCertificateRef` + BackendTLSPolicy.
/// 4. Poll until the route returns 200 — proves the proxy presented a valid client cert.
/// 5. Verify Gateway `ResolvedRefs=True`.
#[tokio::test]
async fn backend_mtls_presents_client_cert_when_gateway_configures_ref() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-backend-cc").await?;

    // Server cert: TLS termination at the backend.
    let tls_hostname = format!("echo-mtls.{}.local", ns.name);
    let server_cert = GeneratedCert::for_host(&tls_hostname);

    // Client CA + leaf: proxy presents this to the mTLS backend.
    let client_certs = MtlsCerts::generate();

    // Deploy echo-mtls (requires client cert signed by the client CA).
    fixtures::apply_fixture(
        backends::ECHO_MTLS,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", server_cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", server_cert.key_b64())
            .with("TLS_CLIENT_CA_B64", client_certs.ca_cert_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-mtls"]).await?;

    let host = format!("backend-cc.{}.local", ns.name);

    // Apply Gateway (clientCertificateRef) + HTTPRoute + BackendTLSPolicy.
    fixtures::apply_fixture(
        gwa::BACKEND_CLIENT_CERT,
        FixtureVars::new(&ns.name)
            .with("TLS_HOSTNAME", &tls_hostname)
            .with("CA_PEM", server_cert.cert_pem.clone())
            .with("CLIENT_CERT_B64", client_certs.client_cert_b64())
            .with("CLIENT_KEY_B64", client_certs.client_key_b64()),
    )
    .await?;

    // Traffic must succeed: proxy presents the client cert, backend validates it.
    let gw = h.gateway_http(&ns.name).await?;
    let resp = wait::wait_for_route(&gw, &host, "/", Duration::from_secs(90)).await?;
    resp.assert_backend("echo-mtls");

    // Gateway must report ResolvedRefs=True (client cert Secret resolved OK).
    wait::wait_for_gateway_condition(
        &h.client,
        "backend-cc-gw",
        &ns.name,
        "ResolvedRefs",
        "True",
        Duration::from_secs(30),
    )
    .await?;

    Ok(())
}

/// GEP-3155 sad path: proxy presents a client cert the backend does NOT trust
/// → upstream mTLS handshake fails → 502.
///
/// `echo-mtls` (echo-basic) uses `VerifyClientCertIfGiven`: it accepts a
/// no-cert connection, but a cert that is presented MUST chain to its configured
/// client CA.  The backend trusts CA "A"; the Gateway's `clientCertificateRef`
/// presents a leaf from an independent CA "B".  The proxy presents B's cert →
/// echo-basic rejects it → handshake aborts → 502.
///
/// This is the load-bearing proof that the proxy actually presents the
/// configured cert: had it presented nothing, the connection would have
/// succeeded (200), not failed closed.  Paired with the happy path above (a
/// trusted cert → 200), the two together prove presentation + validation.
#[tokio::test]
async fn backend_mtls_rejects_untrusted_client_cert() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-backend-cc-untrusted").await?;

    let tls_hostname = format!("echo-mtls-ut.{}.local", ns.name);
    let server_cert = GeneratedCert::for_host(&tls_hostname);

    // Two independent client CAs. The backend trusts A; the proxy presents B.
    let backend_trusted_ca = MtlsCerts::generate();
    let proxy_untrusted = MtlsCerts::generate();

    fixtures::apply_fixture(
        backends::ECHO_MTLS,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", server_cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", server_cert.key_b64())
            .with("TLS_CLIENT_CA_B64", backend_trusted_ca.ca_cert_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-mtls"]).await?;

    let host = format!("backend-cc.{}.local", ns.name);

    // Gateway clientCertificateRef = a cert from the UNTRUSTED CA "B".  The
    // Secret itself is a valid kubernetes.io/tls Secret, so the controller
    // resolves it (ResolvedRefs=True) and pushes it to the proxy; the rejection
    // happens at the upstream TLS handshake, not at ref resolution.
    fixtures::apply_fixture(
        gwa::BACKEND_CLIENT_CERT,
        FixtureVars::new(&ns.name)
            .with("TLS_HOSTNAME", &tls_hostname)
            .with("CA_PEM", server_cert.cert_pem.clone())
            .with("CLIENT_CERT_B64", proxy_untrusted.client_cert_b64())
            .with("CLIENT_KEY_B64", proxy_untrusted.client_key_b64()),
    )
    .await?;

    // Proxy presents an untrusted client cert → backend aborts handshake → 502.
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route_status(&gw, &host, "/", 502, Duration::from_secs(60)).await?;

    Ok(())
}

/// GEP-3155 fail-closed: a configured-but-unresolvable `clientCertificateRef`
/// makes the proxy fail closed (502) on BackendTLSPolicy upstreams — it must not
/// silently connect without the operator-configured client identity.
///
/// The Gateway's `clientCertificateRef` points to a Secret that does not exist.
/// The controller surfaces `ResolvedRefs=False/InvalidClientCertificateRef`; the
/// proxy returns 502 for every request to the BackendTLSPolicy-selected backend,
/// matching the project's fail-closed posture for every other cert path (and the
/// GEP-1897 invalid-BackendTLSPolicy 502).
#[tokio::test]
async fn backend_mtls_invalid_client_cert_ref_fails_closed() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-gw-backend-cc-failclosed").await?;

    let tls_hostname = format!("echo-tls-fc.{}.local", ns.name);
    let server_cert = GeneratedCert::for_host(&tls_hostname);

    // Plain TLS backend — fail-closed returns 502 before the proxy ever connects.
    fixtures::apply_fixture(
        backends::ECHO_TLS,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", server_cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", server_cert.key_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-tls"]).await?;

    // Gateway clientCertificateRef → a Secret that does not exist.
    fixtures::apply_fixture(
        gwa::BACKEND_CLIENT_CERT_FAILS_CLOSED,
        FixtureVars::new(&ns.name)
            .with("TLS_HOSTNAME", &tls_hostname)
            .with("CA_PEM", server_cert.cert_pem.clone()),
    )
    .await?;

    // Unresolvable client cert ref → proxy fails closed → 502 (never connects).
    let host = format!("backend-tls.{}.local", ns.name);
    let gw = h.gateway_http(&ns.name).await?;
    wait::wait_for_route_status(&gw, &host, "/", 502, Duration::from_secs(60)).await?;

    // Controller surfaces the resolution failure on the Gateway.
    wait::wait_for_gateway_condition(
        &h.client,
        "backend-cc-fc-gw",
        &ns.name,
        "ResolvedRefs",
        "False",
        Duration::from_secs(30),
    )
    .await?;

    Ok(())
}

// ── TLS passthrough (TLSRoute / GEP-2643, #70) ────────────────────────────────

/// Happy path: TLSRoute on a `TLS/Passthrough` listener routes raw TLS by SNI.
///
/// The backend terminates TLS (proxy never sees plaintext). The TLS handshake
/// succeeds using the backend's cert as the trusted root — if the proxy were
/// terminating TLS itself, it would present a different cert not in our root
/// store, and the handshake would fail, causing the test to fail.
#[tokio::test]
async fn tls_passthrough_routes_by_sni_without_termination() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-passthrough-happy").await?;

    let hostname = format!("passthrough.{}.local", ns.name);
    let backend_cert = GeneratedCert::for_host(&hostname);

    // Deploy the TLS echo backend (terminates TLS itself using backend_cert).
    fixtures::apply_fixture(
        backends::ECHO_TLS,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", backend_cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", backend_cert.key_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-tls"]).await?;

    // Apply the passthrough Gateway + TLSRoute.
    fixtures::apply_fixture(
        gwa::TLS_PASSTHROUGH,
        FixtureVars::new(&ns.name)
            .with(
                "GATEWAY_TLS_PASSTHROUGH_PORT",
                &GATEWAY_TLS_PASSTHROUGH_PORT.to_string(),
            )
            .with("PASSTHROUGH_HOSTNAME", &hostname),
    )
    .await?;

    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-passthrough-gw",
        &ns.name,
        "Programmed",
        "True",
        Duration::from_secs(60),
    )
    .await?;

    // Open a raw TLS connection to the passthrough port using backend_cert's DER
    // as the trusted root.  If the proxy terminated TLS, it would present a
    // different cert that isn't in our root store, making the handshake fail.
    let passthrough_addr = h.gateway_passthrough_addr(&ns.name).await?;
    let trusted_ca_der = backend_cert.cert_der();
    let body = wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async { format!("TLS passthrough route for {hostname} to become live") },
        || async {
            try_tls_passthrough(
                &passthrough_addr,
                &hostname,
                &trusted_ca_der,
                "GET / HTTP/1.1\r\nHost: backend\r\nConnection: close\r\n\r\n",
            )
            .await
            .ok()
        },
    )
    .await?;

    assert!(
        body.contains("namespace"),
        "expected echo-tls JSON body with 'namespace' field, got: {body}",
    );

    Ok(())
}

/// Sad path: unknown SNI on a Passthrough listener → connection dropped, no backend reached.
///
/// The proxy has a TLSRoute for `hostname` but none for `unknown`. A TLS connect
/// with `unknown` as the SNI must fail — the proxy closes the connection before
/// the handshake can complete.
#[tokio::test]
async fn tls_passthrough_unknown_sni_is_rejected() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-passthrough-nosni").await?;

    let hostname = format!("passthrough.{}.local", ns.name);
    let backend_cert = GeneratedCert::for_host(&hostname);

    fixtures::apply_fixture(
        backends::ECHO_TLS,
        FixtureVars::new(&ns.name)
            .with("TLS_SERVER_CERT_B64", backend_cert.cert_b64())
            .with("TLS_SERVER_KEY_B64", backend_cert.key_b64()),
    )
    .await?;
    wait::wait_for_deployments(&ns.name, &["echo-tls"]).await?;

    fixtures::apply_fixture(
        gwa::TLS_PASSTHROUGH,
        FixtureVars::new(&ns.name)
            .with(
                "GATEWAY_TLS_PASSTHROUGH_PORT",
                &GATEWAY_TLS_PASSTHROUGH_PORT.to_string(),
            )
            .with("PASSTHROUGH_HOSTNAME", &hostname),
    )
    .await?;

    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-passthrough-gw",
        &ns.name,
        "Programmed",
        "True",
        Duration::from_secs(60),
    )
    .await?;

    // Pre-condition: confirm the happy-path hostname is routed before probing the
    // negative, so the test can't pass vacuously due to the proxy not being ready.
    let passthrough_addr = h.gateway_passthrough_addr(&ns.name).await?;
    let trusted_ca_der = backend_cert.cert_der();
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async { format!("TLS passthrough route for {hostname} to become live (pre-condition)") },
        || async {
            try_tls_passthrough(
                &passthrough_addr,
                &hostname,
                &trusted_ca_der,
                "GET / HTTP/1.1\r\nHost: backend\r\nConnection: close\r\n\r\n",
            )
            .await
            .ok()
        },
    )
    .await?;

    // Connect with an SNI that has no matching TLSRoute → proxy drops the connection.
    let unknown = format!("unknown.{}.local", ns.name);
    let result = try_tls_passthrough(
        &passthrough_addr,
        &unknown,
        &trusted_ca_der,
        "GET / HTTP/1.1\r\nHost: backend\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        result.is_err(),
        "expected connection error for unknown SNI, got success",
    );

    Ok(())
}

/// Sad path: `TLS/Passthrough` listener exists but zero TLSRoutes are attached.
///
/// The Gateway should still become `Programmed=True` (the listener configuration
/// is valid even with no routes attached), and any incoming connection is dropped
/// (no backend to forward to).
#[tokio::test]
async fn tls_passthrough_listener_without_route_is_programmed_but_drops() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "tls-passthrough-noroute").await?;

    let hostname = format!("passthrough.{}.local", ns.name);

    // Apply only the Gateway (no TLSRoute).
    fixtures::apply_fixture(
        gwa::TLS_PASSTHROUGH_GW_ONLY,
        FixtureVars::new(&ns.name)
            .with(
                "GATEWAY_TLS_PASSTHROUGH_PORT",
                &GATEWAY_TLS_PASSTHROUGH_PORT.to_string(),
            )
            .with("PASSTHROUGH_HOSTNAME", &hostname),
    )
    .await?;

    // Gateway should become Programmed even with no routes.
    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-passthrough-gw-only",
        &ns.name,
        "Programmed",
        "True",
        Duration::from_secs(60),
    )
    .await?;

    // Any TLS connection to the passthrough port is dropped (no backend to forward to).
    // We use a self-signed cert for the hostname, but verification is expected to
    // fail before the handshake completes — the proxy closes the connection.
    let dummy_cert = GeneratedCert::for_host(&hostname);
    let gw_pt = h.gateway_passthrough_addr(&ns.name).await?;
    let result = try_tls_passthrough(
        &gw_pt,
        &hostname,
        &dummy_cert.cert_der(),
        "GET / HTTP/1.1\r\nHost: backend\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        result.is_err(),
        "expected connection error with no TLSRoute attached, got success",
    );

    Ok(())
}

/// Open a raw TLS connection to `addr` with `sni` as the ClientHello server_name.
///
/// Verifies the TLS handshake against `trusted_ca_der` (the backend's cert in DER
/// form — use [`GeneratedCert::cert_der`] to obtain it).  Sends `http_req` through
/// the encrypted tunnel and returns the HTTP response body.
///
/// Returns an error if the TCP connect fails, the TLS handshake fails (e.g. the
/// proxy dropped the connection or presented an untrusted cert), or the HTTP
/// response status is not 200.
///
/// # Errors
///
/// Returns an error if the TCP connect, TLS handshake, write, or read fails, or
/// if the HTTP response status is not 200.
async fn try_tls_passthrough(
    addr: &std::net::SocketAddr,
    sni: &str,
    trusted_ca_der: &[u8],
    http_req: &str,
) -> anyhow::Result<String> {
    use anyhow::Context as _;
    use rustls::ClientConfig;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, ServerName};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsConnector;

    let mut roots = RootCertStore::empty();
    let cert_der = CertificateDer::from(trusted_ca_der.to_vec());
    roots
        .add(cert_der)
        .map_err(|e| anyhow::anyhow!("add root cert: {e}"))?;

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .context("TCP connect")?;
    let server_name =
        ServerName::try_from(sni.to_owned()).map_err(|e| anyhow::anyhow!("invalid SNI: {e}"))?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake")?;

    tls.write_all(http_req.as_bytes())
        .await
        .context("write HTTP request")?;
    tls.flush().await.context("flush")?;

    // Pingora closes the connection without a TLS close_notify — mirror what
    // the existing TLS helper tests do: accept UnexpectedEof as end-of-stream.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tls.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(anyhow::Error::new(e)).context("read HTTP response"),
        }
    }

    let text = String::from_utf8_lossy(&buf).to_string();
    anyhow::ensure!(
        text.starts_with("HTTP/1.1 200"),
        "unexpected HTTP status: {}",
        text.lines().next().unwrap_or("")
    );

    Ok(text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default())
}
