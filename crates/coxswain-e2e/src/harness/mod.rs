//! E2E test harness: bootstraps the cluster, deploys coxswain via Helm,
//! and provides HTTP/TLS client helpers and wait utilities.

pub mod bootstrap;
pub mod controller;
pub mod http;
pub mod namespace;
pub mod tls;
pub mod wait;

use anyhow::Context as _;
pub use bootstrap::{GATEWAY_HTTP_PORT, GATEWAY_HTTPS_PORT, bootstrap};
pub use controller::{
    ControllerOptions, ControllerProcess, DedicatedRelease, INGRESS_HTTP_PORT, INGRESS_HTTPS_PORT,
};
pub use http::HttpClient;
pub use namespace::{IngressClassGuard, NamespaceGuard};
pub use tls::GeneratedCert;

/// Top-level test harness: wraps the in-cluster coxswain installation with a
/// Kubernetes client, an HTTP test client, and fixture application helpers.
///
/// `http` and `tls_addr` point at the Ingress data plane; `gateway_http` and
/// `gateway_tls_addr` point at the Gateway data plane. Both are backed by the
/// shared-proxy pod's LoadBalancer Service IP — the two listener sets simply
/// bind different ports on the same pod.
pub struct Harness {
    /// Kubernetes client pre-configured from the default kubeconfig.
    pub client: kube::Client,
    /// Handle to the in-cluster installation (port-forwards killed on drop).
    pub controller: ControllerProcess,
    /// HTTP test client pre-pointed at the Ingress HTTP proxy port (`<lb_ip>:80`).
    pub http: HttpClient,
    /// Address of the Ingress HTTPS/TLS proxy port (`<lb_ip>:443`).
    pub tls_addr: std::net::SocketAddr,
    /// HTTP test client pre-pointed at the Gateway HTTP port (`<lb_ip>:8000`).
    pub gateway_http: HttpClient,
    /// Address of the Gateway HTTPS port (`<lb_ip>:8443`).
    pub gateway_tls_addr: std::net::SocketAddr,
}

impl Harness {
    /// Bootstrap the cluster (if needed) and connect with default options.
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_with_options(ControllerOptions::default()).await
    }

    /// Bootstrap the cluster (if needed) and connect, applying any non-default
    /// Helm overrides before obtaining addresses.
    pub async fn start_with_options(opts: ControllerOptions) -> anyhow::Result<Self> {
        bootstrap().await.context("bootstrap")?;
        let client = kube::Client::try_default().await.context("kube client")?;
        let controller = ControllerProcess::start_with_options(opts)
            .await
            .context("controller install")?;
        wait::wait_for_ready(controller.health_addr, std::time::Duration::from_secs(60))
            .await
            .context("readyz timeout")?;
        let http = HttpClient::new(controller.proxy_addr).context("http client")?;
        let tls_addr = controller.tls_addr;
        let gateway_http =
            HttpClient::new(controller.gateway_http_addr).context("gateway http client")?;
        let gateway_tls_addr = controller.gateway_https_addr;
        Ok(Self {
            client,
            controller,
            http,
            tls_addr,
            gateway_http,
            gateway_tls_addr,
        })
    }

    /// Build an admin endpoint URL targeting the shared-proxy pod
    /// (e.g. `admin_url("/api/v1/routes")`).
    pub fn admin_url(&self, path: &str) -> String {
        format!("http://{}{path}", self.controller.admin_addr)
    }

    /// Build an admin endpoint URL targeting the controller pod.
    /// Use for controller-specific paths like `/api/v1/routing/gateways`.
    pub fn controller_admin_url(&self, path: &str) -> String {
        format!("http://{}{path}", self.controller.controller_admin_addr)
    }

    /// Apply a fixture YAML. Substitutes the four standard port placeholders
    /// with their fixed in-cluster values; use `vars.with(key, val)` for extras.
    pub async fn apply(
        &self,
        path: impl AsRef<std::path::Path>,
        vars: crate::fixtures::FixtureVars,
    ) -> anyhow::Result<()> {
        let vars = crate::fixtures::FixtureVars {
            http_port: INGRESS_HTTP_PORT,
            https_port: INGRESS_HTTPS_PORT,
            gateway_http_port: GATEWAY_HTTP_PORT,
            gateway_https_port: GATEWAY_HTTPS_PORT,
            ..vars
        };
        crate::fixtures::apply_fixture(path, vars).await
    }
}
