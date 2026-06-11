//! Handle to the in-cluster coxswain installation, with port-forwards to the
//! management (health + admin) endpoints.

use anyhow::Context as _;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::process::{Child, Command};

use crate::harness::bootstrap::{
    COXSWAIN_NAMESPACE, E2E_IMAGE, GATEWAY_HTTP_PORT, GATEWAY_HTTPS_PORT, HelmOverrides,
    helm_install, workspace_root,
};

/// Fixed port the Helm chart sets for HTTP ingress (`proxy.http.port`).
pub const INGRESS_HTTP_PORT: u16 = 80;
/// Fixed port the Helm chart sets for HTTPS ingress (`proxy.https.port`).
pub const INGRESS_HTTPS_PORT: u16 = 443;

/// Name of the shared-proxy external LoadBalancer Service as rendered by the
/// chart when the release name is `coxswain` (i.e. `coxswain-shared-proxy`).
const SHARED_PROXY_SVC: &str = "coxswain-shared-proxy";
/// Name of the shared-proxy internal ClusterIP Service (health + admin).
const SHARED_PROXY_INTERNAL_SVC: &str = "coxswain-shared-proxy-internal";

/// Optional parameters for tests that need non-default proxy configuration.
///
/// Each non-default field triggers a `helm upgrade --install` to reconfigure
/// the release before the test runs.
#[derive(Default)]
pub struct ControllerOptions {
    /// Sets `controller.statusAddress`. Needed by the conformance suite so
    /// `Gateway.status.addresses` carries a reachable IP.
    pub status_address: Option<String>,
    /// Sets `proxy.shared.ingressDefaultBackend`.
    /// Format: `<namespace>/<service>:<port>`.
    pub ingress_default_backend: Option<String>,
    /// Sets `proxy.shared.acceptProxyProtocol`.
    pub accept_proxy_protocol: bool,
    /// Sets `proxy.shared.trustedSources` (CIDR list).
    /// Only meaningful when `accept_proxy_protocol` is true.
    pub trusted_sources: Vec<String>,
    /// Sets `proxy.shared.accessLog`. `None` leaves the chart default.
    pub access_log: Option<bool>,
    /// Sets `proxy.shared.accessLogPathMode` (`"full"` / `"pattern"` / `"none"`).
    /// `None` leaves the chart default.
    pub access_log_path_mode: Option<String>,
}

/// Handle to the in-cluster coxswain installation for one test.
///
/// The shared-proxy data-plane is reachable at `proxy_addr` (HTTP),
/// `tls_addr` (HTTPS), `gateway_http_addr`, and `gateway_https_addr` — all
/// are addresses on the Service's LoadBalancer IP. Health and admin are
/// port-forwarded to `127.0.0.1:<ephemeral>` for the duration of the test.
pub struct ControllerProcess {
    /// LoadBalancer IP assigned to the shared-proxy external Service.
    pub lb_ip: IpAddr,
    /// Bound address for Ingress HTTP traffic (`<lb_ip>:80`).
    pub proxy_addr: SocketAddr,
    /// Bound address for Ingress HTTPS/TLS traffic (`<lb_ip>:443`).
    pub tls_addr: SocketAddr,
    /// Bound address for Gateway HTTP traffic (`<lb_ip>:GATEWAY_HTTP_PORT`).
    pub gateway_http_addr: SocketAddr,
    /// Bound address for Gateway HTTPS traffic (`<lb_ip>:GATEWAY_HTTPS_PORT`).
    pub gateway_https_addr: SocketAddr,
    /// Local port-forwarded address for `/healthz` / `/readyz`.
    pub health_addr: SocketAddr,
    /// Local port-forwarded address for `/metrics` / `/routes` / `/status` on
    /// the shared-proxy pod.
    pub admin_addr: SocketAddr,
    /// Local port-forwarded address for the controller pod's admin endpoint.
    /// Serves `/cluster`, `/status`, `/routes` (controller reconciler view).
    pub controller_admin_addr: SocketAddr,
    health_pf: Child,
    admin_pf: Child,
    controller_admin_pf: Child,
}

impl ControllerProcess {
    /// Connect to the existing in-cluster installation with default options.
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_with_options(ControllerOptions::default()).await
    }

    /// Connect to the existing in-cluster installation, applying any non-default
    /// Helm overrides first (triggers a `helm upgrade --wait`).
    ///
    /// # Errors
    ///
    /// Returns an error if the Helm upgrade, LB-IP lookup, or port-forward
    /// setup fails.
    pub async fn start_with_options(opts: ControllerOptions) -> anyhow::Result<Self> {
        // Always reconcile the Helm release with the requested overrides so the
        // chart never carries leftover state from a previous test in the same
        // binary (e.g. test N flipping `accessLog=false` would leak into test
        // N+1 if N+1 passed `ControllerOptions::default()` and we skipped the
        // upgrade). When the values match the live release Helm short-circuits
        // — the cost is one helm-upgrade decision plus `wait_for_leader_ready`.
        let overrides = HelmOverrides {
            status_address: opts.status_address,
            ingress_default_backend: opts.ingress_default_backend,
            accept_proxy_protocol: opts.accept_proxy_protocol,
            trusted_sources: opts.trusted_sources,
            access_log: opts.access_log,
            access_log_path_mode: opts.access_log_path_mode,
        };
        let root = workspace_root().context("workspace root")?;
        helm_install(&root, &overrides)
            .await
            .context("helm upgrade with overrides")?;

        let lb_ip = wait_for_lb_ip().await.context("shared-proxy LB IP")?;

        let health_port = free_port()?;
        let admin_port = free_port()?;

        let controller_admin_port = free_port()?;

        let health_pf = start_port_forward(SHARED_PROXY_INTERNAL_SVC, health_port, 8081).await?;
        let admin_pf = start_port_forward(SHARED_PROXY_INTERNAL_SVC, admin_port, 8082).await?;
        let controller_admin_pf =
            start_port_forward(CONTROLLER_SVC, controller_admin_port, 8082).await?;

        let health_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), health_port);
        let admin_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), admin_port);
        let controller_admin_addr = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            controller_admin_port,
        );

        // After every helm upgrade, poll the controller's own /readyz via a
        // temporary port-forward until it's synced. The proxy's /readyz (polled
        // by Harness::start_with_options) returns immediately since the proxy
        // wasn't necessarily restarted — but the controller may still be
        // running its initial informer sync and hasn't written any status yet.
        wait_for_controller_ready()
            .await
            .context("controller readyz")?;

        Ok(Self {
            lb_ip,
            proxy_addr: SocketAddr::new(lb_ip, INGRESS_HTTP_PORT),
            tls_addr: SocketAddr::new(lb_ip, INGRESS_HTTPS_PORT),
            gateway_http_addr: SocketAddr::new(lb_ip, GATEWAY_HTTP_PORT),
            gateway_https_addr: SocketAddr::new(lb_ip, GATEWAY_HTTPS_PORT),
            health_addr,
            admin_addr,
            controller_admin_addr,
            health_pf,
            admin_pf,
            controller_admin_pf,
        })
    }
}

impl ControllerProcess {
    /// Read every shared-proxy pod's stdout in the coxswain namespace and
    /// return only the JSON-formatted access-log lines (i.e. tracing events
    /// emitted on the `coxswain_proxy::access` target).
    ///
    /// Helm-installed pods run with `--log-format=json`. Lines that fail to
    /// parse as JSON or don't carry `"target":"coxswain_proxy::access"` are
    /// skipped. The shared-proxy Deployment may have multiple replicas — the
    /// returned vector is the concatenation across them.
    ///
    /// # Errors
    ///
    /// Returns an error if listing the pods or reading their logs fails.
    pub async fn shared_proxy_access_logs(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        let out = Command::new("kubectl")
            .args([
                "logs",
                "-n",
                COXSWAIN_NAMESPACE,
                "-l",
                "app.kubernetes.io/name=coxswain,app.kubernetes.io/component=shared-proxy",
                "--tail=-1",
            ])
            .output()
            .await
            .context("kubectl logs shared-proxy")?;
        if !out.status.success() {
            anyhow::bail!(
                "kubectl logs shared-proxy exit {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let stdout = String::from_utf8(out.stdout).context("decode kubectl logs stdout")?;
        let mut access = Vec::new();
        for line in stdout.lines() {
            let Ok(json) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if json.get("target").and_then(|v| v.as_str()) == Some("coxswain_proxy::access") {
                access.push(json);
            }
        }
        Ok(access)
    }
}

impl Drop for ControllerProcess {
    fn drop(&mut self) {
        let _ = self.health_pf.start_kill();
        let _ = self.admin_pf.start_kill();
        let _ = self.controller_admin_pf.start_kill();
    }
}

/// Poll `Service.status.loadBalancer.ingress[0].ip` for the shared-proxy external
/// Service until an IP is assigned or the timeout expires.
///
/// OrbStack assigns IPs within ~150 ms; cloud-provider-kind on kind takes ~5-10 s.
///
/// # Errors
///
/// Returns an error if no IP is assigned within 60 s.
async fn wait_for_lb_ip() -> anyhow::Result<IpAddr> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let out = Command::new("kubectl")
            .args([
                "get",
                "svc",
                SHARED_PROXY_SVC,
                "-n",
                COXSWAIN_NAMESPACE,
                "-o",
                "jsonpath={.status.loadBalancer.ingress[0].ip}",
            ])
            .output()
            .await
            .context("kubectl get svc")?;
        let ip_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !ip_str.is_empty() {
            return ip_str
                .parse::<IpAddr>()
                .with_context(|| format!("parse LB IP: {ip_str}"));
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("shared-proxy Service has no LoadBalancer IP after 60s");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Spawn a `kubectl port-forward` tunnel from `127.0.0.1:<local_port>` to
/// `<svc_name>:<remote_port>` in the coxswain namespace.
///
/// The returned [`Child`] must be kept alive for the lifetime of the tunnel;
/// dropping it kills the forward.
///
/// # Errors
///
/// Returns an error if `kubectl port-forward` fails to spawn.
async fn start_port_forward(
    svc_name: &str,
    local_port: u16,
    remote_port: u16,
) -> anyhow::Result<Child> {
    let child = Command::new("kubectl")
        .args([
            "port-forward",
            "-n",
            COXSWAIN_NAMESPACE,
            &format!("svc/{svc_name}"),
            &format!("{local_port}:{remote_port}"),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("kubectl port-forward {svc_name} {local_port}:{remote_port}"))?;
    // Actively poll the loopback port until kubectl has actually bound it AND
    // the underlying pod accepts connections. A fixed sleep races with helm
    // upgrades that briefly leave no Ready endpoint for the Service. Cap the
    // wait at 30 s — anything longer is a real bring-up failure.
    let local_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), local_port);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if tokio::time::timeout(
            Duration::from_millis(250),
            tokio::net::TcpStream::connect(local_addr),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .is_some()
        {
            return Ok(child);
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "port-forward {svc_name} {local_port}:{remote_port} never accepted connections within 30s"
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Allocate a free loopback TCP port by binding and immediately releasing it.
///
/// There is a small race window between release and reuse; acceptable for tests.
fn free_port() -> anyhow::Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").context("bind ephemeral port")?;
    Ok(listener.local_addr().context("local_addr")?.port())
}

/// Name of the controller ClusterIP Service (health + admin).
const CONTROLLER_SVC: &str = "coxswain-controller";

/// Poll the controller pod's `/readyz` via a temporary port-forward until it
/// returns 200 or 60 s elapses.
///
/// Used after a `helm upgrade` that restarts only the controller pod; the
/// proxy's `/readyz` returns immediately (proxy is unchanged) so the caller
/// can't rely on the existing health forward to detect controller readiness.
///
/// # Errors
///
/// Returns an error if the port-forward cannot be started or readyz doesn't
/// return 200 within 60 s.
async fn wait_for_controller_ready() -> anyhow::Result<()> {
    let port = free_port()?;
    let mut pf = start_port_forward(CONTROLLER_SVC, port, 8081).await?;
    let addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port);
    let result = crate::harness::wait::wait_for_ready(addr, Duration::from_secs(60))
        .await
        .context("controller readyz timeout");
    let _ = pf.start_kill();
    result
}

/// Returns the coxswain image name used for dedicated-mode proxy Deployments.
///
/// Tests that assert the provisioned Deployment's image should compare against
/// this value.
pub fn dedicated_proxy_image() -> &'static str {
    E2E_IMAGE
}
