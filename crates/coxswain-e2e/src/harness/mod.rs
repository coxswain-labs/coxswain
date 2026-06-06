//! E2E test harness: bootstraps the cluster, spawns a coxswain subprocess,
//! and provides HTTP/TLS client helpers and wait utilities.

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
pub use namespace::{IngressClassGuard, NamespaceGuard};
pub use tls::GeneratedCert;

/// Top-level test harness: wraps a running controller subprocess with a Kubernetes
/// client, an HTTP test client, and fixture application helpers.
pub struct Harness {
    /// Kubernetes client pre-configured from the default kubeconfig.
    pub client: kube::Client,
    /// Running coxswain subprocess (killed on drop).
    pub controller: ControllerProcess,
    /// HTTP test client pre-pointed at the controller's HTTP proxy port.
    pub http: HttpClient,
    /// Bound address of the controller's HTTPS/TLS proxy port.
    pub tls_addr: std::net::SocketAddr,
}

impl Harness {
    /// Bootstrap the cluster (if needed) and start a controller with default options.
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_with_options(ControllerOptions::default()).await
    }

    /// Bootstrap the cluster (if needed) and start a controller with custom options.
    pub async fn start_with_options(opts: ControllerOptions) -> anyhow::Result<Self> {
        bootstrap().await.context("bootstrap")?;
        let client = kube::Client::try_default().await.context("kube client")?;
        let controller = ControllerProcess::start_with_options(opts)
            .await
            .context("spawn controller")?;
        wait::wait_for_ready(controller.health_addr, std::time::Duration::from_secs(30))
            .await
            .context("readyz timeout")?;
        let http = HttpClient::new(controller.proxy_addr).context("http client")?;
        let tls_addr = controller.tls_addr;
        Ok(Self {
            client,
            controller,
            http,
            tls_addr,
        })
    }

    /// Build an admin endpoint URL (e.g. `admin_url("/routes")`).
    pub fn admin_url(&self, path: &str) -> String {
        format!("http://{}{path}", self.controller.admin_addr)
    }

    /// Apply a fixture YAML. Automatically substitutes `HTTP_PORT` and `HTTPS_PORT`
    /// from the controller's bound addresses; use `vars.with(key, val)` for extras.
    pub async fn apply(
        &self,
        path: impl AsRef<std::path::Path>,
        vars: crate::fixtures::FixtureVars,
    ) -> anyhow::Result<()> {
        let vars = crate::fixtures::FixtureVars {
            http_port: self.controller.proxy_addr.port(),
            https_port: self.tls_addr.port(),
            ..vars
        };
        crate::fixtures::apply_fixture(path, vars).await
    }
}
