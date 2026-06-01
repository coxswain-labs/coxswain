use anyhow::Context as _;
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

    pub async fn get(&self, host: &str, path: &str) -> anyhow::Result<EchoResponse> {
        let url = format!("http://{}{path}", self.proxy_addr);
        let resp = self
            .inner
            .get(&url)
            .header("Host", host)
            .send()
            .await
            .context("send request")?;

        let status = resp.status();
        anyhow::ensure!(
            status.is_success(),
            "GET {host}{path} returned {status}"
        );

        resp.json::<EchoResponse>().await.context("parse echo response")
    }

    pub async fn get_status(&self, host: &str, path: &str) -> anyhow::Result<u16> {
        let url = format!("http://{}{path}", self.proxy_addr);
        let resp = self
            .inner
            .get(&url)
            .header("Host", host)
            .send()
            .await
            .context("send request")?;
        Ok(resp.status().as_u16())
    }
}
