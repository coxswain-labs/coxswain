pub mod bootstrap;
pub mod controller;
pub mod http;
pub mod namespace;
pub mod tls;
pub mod wait;

use anyhow::Context as _;
pub use bootstrap::bootstrap;
pub use controller::{ControllerOptions, ControllerProcess};
pub use http::HttpClient;
pub use namespace::NamespaceGuard;
pub use tls::GeneratedCert;

pub struct Harness {
    pub client: kube::Client,
    pub controller: ControllerProcess,
    pub http: HttpClient,
    pub tls_addr: std::net::SocketAddr,
}

impl Harness {
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_with_options(ControllerOptions::default()).await
    }

    pub async fn start_with_options(opts: ControllerOptions) -> anyhow::Result<Self> {
        bootstrap().await.context("bootstrap")?;
        let client = kube::Client::try_default().await.context("kube client")?;
        let controller = ControllerProcess::start_with_options(opts)
            .await
            .context("spawn controller")?;
        wait::wait_for_ready(controller.health_addr, std::time::Duration::from_secs(30))
            .await
            .context("readyz timeout")?;
        let http = HttpClient::new(controller.proxy_addr);
        let tls_addr = controller.tls_addr;
        Ok(Self {
            client,
            controller,
            http,
            tls_addr,
        })
    }

    pub fn admin_url(&self, path: &str) -> String {
        format!("http://{}{path}", self.controller.admin_addr)
    }
}
