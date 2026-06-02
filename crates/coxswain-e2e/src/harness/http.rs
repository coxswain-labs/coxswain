use anyhow::Context as _;
use reqwest::Method;
use std::net::SocketAddr;

#[derive(Debug, serde::Deserialize)]
pub struct EchoResponse {
    pub path: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub namespace: Option<String>,
    pub pod: Option<String>,
    pub service: Option<String>,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, serde_json::Value>,
}

impl EchoResponse {
    pub fn assert_backend(&self, deployment_name: &str) {
        let pod = self.pod.as_deref().unwrap_or("");
        assert!(
            pod.starts_with(&format!("{deployment_name}-")),
            "expected backend pod starting with '{deployment_name}-', got '{pod}'"
        );
    }
}

pub struct HttpClient {
    inner: reqwest::Client,
    proxy_addr: SocketAddr,
}

impl HttpClient {
    pub fn new(proxy_addr: SocketAddr) -> Self {
        let inner = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("reqwest client");
        Self { inner, proxy_addr }
    }

    /// Send an arbitrary request. `path` may include a `?query=...` suffix.
    /// Returns `(status_code, Some(body))` when the response is JSON, or
    /// `(status_code, None)` for non-2xx or non-JSON responses.
    pub async fn request(
        &self,
        method: Method,
        host: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
    ) -> anyhow::Result<(u16, Option<EchoResponse>)> {
        let url = format!("http://{}{path}", self.proxy_addr);
        let mut req = self.inner.request(method, &url).header("Host", host);
        for (k, v) in extra_headers {
            req = req.header(*k, *v);
        }
        let resp = req.send().await.context("send request")?;
        let status = resp.status().as_u16();
        if resp.status().is_success() {
            let body = resp
                .json::<EchoResponse>()
                .await
                .context("parse echo response")?;
            Ok((status, Some(body)))
        } else {
            Ok((status, None))
        }
    }

    pub async fn get(&self, host: &str, path: &str) -> anyhow::Result<EchoResponse> {
        let (status, body) = self.request(Method::GET, host, path, &[]).await?;
        anyhow::ensure!(body.is_some(), "GET {host}{path} returned {status}");
        Ok(body.unwrap())
    }

    pub async fn get_status(&self, host: &str, path: &str) -> anyhow::Result<u16> {
        let (status, _) = self.request(Method::GET, host, path, &[]).await?;
        Ok(status)
    }

    /// Send a GET and return the response status, response headers, and optional body.
    pub async fn get_full(
        &self,
        host: &str,
        path: &str,
    ) -> anyhow::Result<(u16, reqwest::header::HeaderMap, Option<EchoResponse>)> {
        let url = format!("http://{}{path}", self.proxy_addr);
        let resp = self
            .inner
            .get(&url)
            .header("Host", host)
            .send()
            .await
            .context("send request")?;
        let status = resp.status().as_u16();
        let resp_headers = resp.headers().clone();
        let body = if resp.status().is_success() {
            Some(
                resp.json::<EchoResponse>()
                    .await
                    .context("parse echo response")?,
            )
        } else {
            None
        };
        Ok((status, resp_headers, body))
    }
}

/// Make a single HTTPS GET and return the peer's leaf certificate as DER bytes.
///
/// Requires `reqwest` built with `rustls-tls` (already the case in this crate).
/// Returns `Err` if the handshake fails or no peer certificate is presented.
pub async fn https_peer_leaf_der(
    host: &str,
    path: &str,
    tls_addr: SocketAddr,
) -> anyhow::Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .resolve(host, tls_addr)
        .tls_info(true)
        .build()
        .context("build https client for tls_info")?;

    let url = format!("https://{}:{}{path}", host, tls_addr.port());
    let resp = client.get(&url).send().await.context("https GET")?;
    let tls_info = resp
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .context("no TLS info on response")?;
    tls_info
        .peer_certificate()
        .context("no peer certificate in TLS info")
        .map(|der| der.to_vec())
}

/// Make a single HTTPS GET, routing `host` to `tls_addr` and skipping cert validation.
/// Returns `(status, Some(body))` on a 2xx JSON response, `(status, None)` otherwise.
/// Returns `Err` if the TLS handshake fails (e.g., unknown SNI).
pub async fn https_get(
    host: &str,
    path: &str,
    tls_addr: SocketAddr,
) -> anyhow::Result<(u16, Option<EchoResponse>)> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .resolve(host, tls_addr)
        .build()
        .context("build https client")?;

    let url = format!("https://{}:{}{path}", host, tls_addr.port());
    let resp = client.get(&url).send().await.context("https GET")?;
    let status = resp.status().as_u16();
    if resp.status().is_success() {
        let body = resp
            .json::<EchoResponse>()
            .await
            .context("parse echo response")?;
        Ok((status, Some(body)))
    } else {
        Ok((status, None))
    }
}
