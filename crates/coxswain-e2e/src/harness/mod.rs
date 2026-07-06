//! E2E test harness: bootstraps the cluster, deploys coxswain via Helm,
//! and provides HTTP/TLS client helpers and wait utilities.

pub mod bootstrap;
pub mod controller;
pub mod http;
pub mod leader;
pub mod namespace;
pub mod tls;
pub mod wait;

use anyhow::Context as _;
pub use bootstrap::{
    GATEWAY_HTTP_PORT, GATEWAY_HTTPS_PORT, GATEWAY_TLS_PASSTHROUGH_PORT, bootstrap,
    bootstrap_cluster,
};
pub use controller::{ControllerOptions, ControllerProcess, INGRESS_HTTP_PORT, INGRESS_HTTPS_PORT};
pub use http::HttpClient;
pub use namespace::{IngressClassGuard, NamespaceGuard};
pub use tls::{GeneratedCert, MtlsCerts, StaticRsaCert};

/// Top-level test harness: wraps the in-cluster coxswain installation with a
/// Kubernetes client, an HTTP test client, and fixture application helpers.
///
/// `http` and `tls_addr` point at the Ingress data plane (the shared-proxy
/// pod's fixed `80`/`443`). Gateway data-plane addresses are NOT fixed fields:
/// each shared-mode Gateway advertises its OWN per-Gateway VIP (#472), so a
/// Gateway test resolves its address from the Gateway's own `status.addresses`
/// via [`Harness::gateway_http`] / [`Harness::gateway_tls_addr`] /
/// [`Harness::gateway_passthrough_addr`] (single-Gateway namespaces) or
/// [`wait::wait_for_gateway_address`] (multi-Gateway namespaces).
pub struct Harness {
    /// Kubernetes client pre-configured from the default kubeconfig.
    pub client: kube::Client,
    /// Handle to the in-cluster installation (port-forwards killed on drop).
    pub controller: ControllerProcess,
    /// HTTP test client pre-pointed at the Ingress HTTP proxy port (`<lb_ip>:80`).
    pub http: HttpClient,
    /// Address of the Ingress HTTPS/TLS proxy port (`<lb_ip>:443`).
    pub tls_addr: std::net::SocketAddr,
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
        Ok(Self {
            client,
            controller,
            http,
            tls_addr,
        })
    }

    /// Resolve the per-Gateway VIP (#472) of the single Gateway in `namespace`
    /// and return an [`HttpClient`] bound to its HTTP listener
    /// ([`GATEWAY_HTTP_PORT`]).
    ///
    /// Shared-mode Gateways each advertise their own VIP rather than the fixed
    /// shared listeners, so a data-plane test addresses the Gateway it created.
    /// Use [`wait::wait_for_gateway_address`] for namespaces with >1 Gateway.
    ///
    /// # Errors
    ///
    /// Errors if the namespace holds zero or more than one Gateway, the VIP
    /// never gets an address, or the client cannot be built.
    pub async fn gateway_http(&self, namespace: &str) -> anyhow::Result<HttpClient> {
        let addr = self.gateway_vip(namespace, GATEWAY_HTTP_PORT).await?;
        HttpClient::new(addr).context("gateway http client")
    }

    /// Resolve the per-Gateway VIP (#472) of the single Gateway in `namespace`
    /// as a [`SocketAddr`] on its HTTP listener ([`GATEWAY_HTTP_PORT`]) — for
    /// callers that need the raw address (e.g. a `ws://` URL) rather than an
    /// [`HttpClient`].
    ///
    /// # Errors
    ///
    /// See [`Harness::gateway_http`].
    pub async fn gateway_http_addr(&self, namespace: &str) -> anyhow::Result<std::net::SocketAddr> {
        self.gateway_vip(namespace, GATEWAY_HTTP_PORT).await
    }

    /// Resolve the per-Gateway VIP (#472) of the single Gateway in `namespace`
    /// as a [`SocketAddr`] on its HTTPS listener ([`GATEWAY_HTTPS_PORT`]).
    ///
    /// # Errors
    ///
    /// See [`Harness::gateway_http`].
    pub async fn gateway_tls_addr(&self, namespace: &str) -> anyhow::Result<std::net::SocketAddr> {
        self.gateway_vip(namespace, GATEWAY_HTTPS_PORT).await
    }

    /// Resolve the per-Gateway VIP (#472) of the single Gateway in `namespace`
    /// as a [`SocketAddr`] on its TLS-passthrough listener
    /// ([`GATEWAY_TLS_PASSTHROUGH_PORT`], GEP-2643 / #70).
    ///
    /// # Errors
    ///
    /// See [`Harness::gateway_http`].
    pub async fn gateway_passthrough_addr(
        &self,
        namespace: &str,
    ) -> anyhow::Result<std::net::SocketAddr> {
        self.gateway_vip(namespace, GATEWAY_TLS_PASSTHROUGH_PORT)
            .await
    }

    /// Resolve the single owned Gateway's VIP in `namespace` on `port`, waiting
    /// up to 120 s for its `status.addresses` to populate.
    async fn gateway_vip(
        &self,
        namespace: &str,
        port: u16,
    ) -> anyhow::Result<std::net::SocketAddr> {
        wait::wait_for_single_gateway_address(
            &self.client,
            namespace,
            port,
            std::time::Duration::from_secs(120),
        )
        .await
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
}
