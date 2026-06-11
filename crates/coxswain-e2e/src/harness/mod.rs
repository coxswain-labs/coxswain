//! E2E test harness: bootstraps the cluster, spawns a coxswain subprocess,
//! and provides HTTP/TLS client helpers and wait utilities.

pub mod bootstrap;
pub mod controller;
pub mod dedicated_proxy_process;
pub mod http;
pub mod namespace;
pub mod tls;
pub mod wait;

use anyhow::Context as _;
pub use bootstrap::bootstrap;
pub use controller::{ControllerOptions, ControllerProcess};
pub use dedicated_proxy_process::DedicatedProxyProcess;
pub use http::HttpClient;
pub use namespace::{IngressClassGuard, NamespaceGuard};
pub use tls::GeneratedCert;

/// Top-level test harness: wraps a running controller subprocess with a Kubernetes
/// client, an HTTP test client, and fixture application helpers.
///
/// `http` and `tls_addr` point at the Ingress data plane; `gateway_http` and
/// `gateway_tls_addr` point at the Gateway data plane. Since the IngressProxy
/// / GatewayProxy split (#201) the two bind disjoint port sets, so tests must
/// pick the correct pair for the route under test.
pub struct Harness {
    /// Kubernetes client pre-configured from the default kubeconfig.
    pub client: kube::Client,
    /// Running coxswain subprocess (killed on drop).
    pub controller: ControllerProcess,
    /// HTTP test client pre-pointed at the Ingress HTTP proxy port.
    pub http: HttpClient,
    /// Bound address of the Ingress HTTPS/TLS proxy port.
    pub tls_addr: std::net::SocketAddr,
    /// HTTP test client pre-pointed at the Gateway HTTP listener port.
    pub gateway_http: HttpClient,
    /// Bound address of the Gateway HTTPS listener port.
    pub gateway_tls_addr: std::net::SocketAddr,
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

    /// Build an admin endpoint URL (e.g. `admin_url("/routes")`).
    pub fn admin_url(&self, path: &str) -> String {
        format!("http://{}{path}", self.controller.admin_addr)
    }

    /// Spawn a `serve proxy --dedicated` subprocess scoped to one Gateway,
    /// binding the same `GATEWAY_HTTP_PORT` / `GATEWAY_HTTPS_PORT` the fixture
    /// declared. The shared subprocess must have already released the listener
    /// (i.e. the Gateway is in dedicated mode and `DedicatedProxyReady=True`),
    /// otherwise the bind races and one of the two will fail.
    ///
    /// `watch_namespaces` is the per-namespace reflector set; must include the
    /// Gateway's own namespace, plus any tenant namespaces an HTTPRoute attached
    /// to the Gateway routes a backend into.
    pub async fn start_dedicated_proxy(
        &self,
        gateway_name: &str,
        gateway_namespace: &str,
        watch_namespaces: &[&str],
    ) -> anyhow::Result<DedicatedProxyProcess> {
        DedicatedProxyProcess::start(
            gateway_name,
            gateway_namespace,
            self.controller.gateway_http_addr,
            self.controller.gateway_https_addr,
            watch_namespaces,
        )
        .await
    }

    /// Apply a fixture YAML. Automatically substitutes the four port placeholders
    /// (`HTTP_PORT`, `HTTPS_PORT`, `GATEWAY_HTTP_PORT`, `GATEWAY_HTTPS_PORT`) from
    /// the controller's bound addresses; use `vars.with(key, val)` for extras.
    pub async fn apply(
        &self,
        path: impl AsRef<std::path::Path>,
        vars: crate::fixtures::FixtureVars,
    ) -> anyhow::Result<()> {
        let vars = crate::fixtures::FixtureVars {
            http_port: self.controller.proxy_addr.port(),
            https_port: self.tls_addr.port(),
            gateway_http_port: self.controller.gateway_http_addr.port(),
            gateway_https_port: self.controller.gateway_https_addr.port(),
            ..vars
        };
        crate::fixtures::apply_fixture(path, vars).await
    }
}
