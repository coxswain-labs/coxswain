pub mod bootstrap;
pub mod controller;
pub mod http;
pub mod namespace;
pub mod wait;

use anyhow::Context as _;
pub use bootstrap::bootstrap;
pub use controller::ControllerProcess;
pub use http::HttpClient;
pub use namespace::NamespaceGuard;

pub struct Harness {
    pub client: kube::Client,
    pub controller: ControllerProcess,
    pub http: HttpClient,
}

impl Harness {
    pub async fn start() -> anyhow::Result<Self> {
        bootstrap().await.context("bootstrap")?;
        let client = kube::Client::try_default().await.context("kube client")?;
        let controller = ControllerProcess::start()
            .await
            .context("spawn controller")?;
        wait::wait_for_ready(controller.health_addr, std::time::Duration::from_secs(30))
            .await
            .context("readyz timeout")?;
        let http = HttpClient::new(controller.proxy_addr);
        Ok(Self {
            client,
            controller,
            http,
        })
    }

    pub fn admin_url(&self, path: &str) -> String {
        format!("http://{}{path}", self.controller.admin_addr)
    }
}
