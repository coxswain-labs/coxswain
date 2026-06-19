//! HTTP and HTTPS test clients, echo response deserialization, and backend-count helper.

use anyhow::Context as _;
use reqwest::Method;
use std::net::SocketAddr;

/// JSON body returned by the echo server on every request.
#[derive(Debug, serde::Deserialize)]
pub struct EchoResponse {
    /// Request path as seen by the echo server.
    pub path: Option<String>,
    /// `Host` header as seen by the echo server.
    pub host: Option<String>,
    /// HTTP method of the request.
    pub method: Option<String>,
    /// Kubernetes namespace of the pod that responded.
    pub namespace: Option<String>,
    /// Kubernetes pod name that responded.
    pub pod: Option<String>,
    /// Kubernetes service name that served the request.
    pub service: Option<String>,
    /// All request headers forwarded by the proxy.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, serde_json::Value>,
}

impl EchoResponse {
    /// Assert that the response came from a pod belonging to `deployment_name`.
    pub fn assert_backend(&self, deployment_name: &str) {
        let pod = self.pod.as_deref().unwrap_or("");
        assert!(
            pod.starts_with(&format!("{deployment_name}-")),
            "expected backend pod starting with '{deployment_name}-', got '{pod}'"
        );
    }
}

/// HTTP test client pre-configured to send requests to the coxswain proxy.
pub struct HttpClient {
    inner: reqwest::Client,
    /// Address of the proxy's HTTP listener.
    pub proxy_addr: SocketAddr,
}

impl HttpClient {
    /// Construct a client targeting `proxy_addr`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying `reqwest` client cannot be built.
    pub fn new(proxy_addr: SocketAddr) -> anyhow::Result<Self> {
        let inner = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .context("reqwest client")?;
        Ok(Self { inner, proxy_addr })
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

    /// Send `method` to `host``path` with a fixed in-memory body. `reqwest` derives a
    /// `Content-Length` header from the body length, so this exercises the proxy's
    /// up-front body-size check. Returns `(status, Some(body))` on a 2xx JSON response,
    /// `(status, None)` otherwise (e.g. a 413 rejection).
    pub async fn request_with_body(
        &self,
        method: Method,
        host: &str,
        path: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<(u16, Option<EchoResponse>)> {
        let url = format!("http://{}{path}", self.proxy_addr);
        let resp = self
            .inner
            .request(method, &url)
            .header("Host", host)
            .body(body)
            .send()
            .await
            .context("send request with body")?;
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

    /// Send `method` with an unknown-length streaming body. `reqwest` omits
    /// `Content-Length` and uses `Transfer-Encoding: chunked`, so this exercises the
    /// proxy's mid-stream body-size cap (the up-front Content-Length check cannot fire).
    /// `chunks` are streamed in order. Returns `(status, Some(body))` on a 2xx JSON
    /// response, `(status, None)` otherwise (e.g. a 413 rejection).
    pub async fn request_with_streamed_body(
        &self,
        method: Method,
        host: &str,
        path: &str,
        chunks: Vec<Vec<u8>>,
    ) -> anyhow::Result<(u16, Option<EchoResponse>)> {
        let url = format!("http://{}{path}", self.proxy_addr);
        let stream = futures::stream::iter(chunks.into_iter().map(Ok::<_, std::io::Error>));
        let resp = self
            .inner
            .request(method, &url)
            .header("Host", host)
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
            .context("send request with streamed body")?;
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

    /// GET `path` with `Host: host`. Returns the parsed echo body on 2xx, or an error.
    pub async fn get(&self, host: &str, path: &str) -> anyhow::Result<EchoResponse> {
        let (status, body) = self.request(Method::GET, host, path, &[]).await?;
        body.ok_or_else(|| anyhow::anyhow!("GET {host}{path} returned {status}"))
    }

    /// GET `path` and return only the HTTP status code.
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

    /// Send a GET with `extra_headers` and return the raw response bytes (not parsed JSON).
    ///
    /// Unlike [`Self::get_full_with_headers`] this method never attempts to
    /// parse the body as JSON, so it works correctly when the body is
    /// compressed (e.g. the caller sent `Accept-Encoding: gzip` and the proxy
    /// returned a `Content-Encoding: gzip` body). Use this for compression
    /// effect tests where you need to decompress and inspect the body manually.
    pub async fn get_full_raw(
        &self,
        host: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
    ) -> anyhow::Result<(u16, reqwest::header::HeaderMap, bytes::Bytes)> {
        use anyhow::Context as _;
        let url = format!("http://{}{path}", self.proxy_addr);
        let mut req = self.inner.get(&url).header("Host", host);
        for (k, v) in extra_headers {
            req = req.header(*k, *v);
        }
        let resp = req.send().await.context("send request")?;
        let status = resp.status().as_u16();
        let resp_headers = resp.headers().clone();
        let body = resp.bytes().await.context("read response bytes")?;
        Ok((status, resp_headers, body))
    }

    /// Like [`Self::get_full`], but sends `extra_headers` on the request.
    ///
    /// Used by caching tests to verify that a request carrying `Authorization`
    /// bypasses the response cache (no `Age` header on the reply).
    pub async fn get_full_with_headers(
        &self,
        host: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
    ) -> anyhow::Result<(u16, reqwest::header::HeaderMap, Option<EchoResponse>)> {
        let url = format!("http://{}{path}", self.proxy_addr);
        let mut req = self.inner.get(&url).header("Host", host);
        for (k, v) in extra_headers {
            req = req.header(*k, *v);
        }
        let resp = req.send().await.context("send request")?;
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

/// Send `n` GET requests to `path` and count how often each deployment prefix responded.
///
/// The returned map keys are deployment names (e.g. `"echo-a"`), derived by stripping the
/// pod's random suffix (`"echo-a-xxxx-yyyy"` → `"echo-a"`). Pods that cannot be identified
/// are counted under `"unknown"`.
pub async fn count_backends(
    http: &HttpClient,
    host: &str,
    path: &str,
    n: usize,
) -> anyhow::Result<std::collections::HashMap<String, usize>> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for _ in 0..n {
        let resp = http.get(host, path).await?;
        let pod = resp.pod.as_deref().unwrap_or("");
        // Pod name format: "<deployment>-<replicaset>-<random>" — take the first two segments.
        let key = pod.splitn(3, '-').take(2).collect::<Vec<_>>().join("-");
        let key = if key.is_empty() {
            "unknown".to_string()
        } else {
            key
        };
        *counts.entry(key).or_insert(0) += 1;
    }
    Ok(counts)
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
