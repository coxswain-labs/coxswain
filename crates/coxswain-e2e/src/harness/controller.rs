//! Handle to the in-cluster coxswain installation, with port-forwards to the
//! management (health + admin) endpoints.

use anyhow::Context as _;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::process::{Child, Command};

use crate::harness::bootstrap::{
    COXSWAIN_NAMESPACE, E2E_IMAGE, GATEWAY_HTTP_PORT, HelmOverrides, helm_install, workspace_root,
};

/// Fixed port the Helm chart sets for HTTP ingress (`proxy.ingress.http.port`).
pub const INGRESS_HTTP_PORT: u16 = 80;
/// Fixed port the Helm chart sets for HTTPS ingress (`proxy.ingress.https.port`).
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
    /// Sets `discovery.svidTtl` (#423). Short values (e.g. `"10s"`) drive rapid
    /// SVID rotation for resilience tests. `None` leaves the chart default (24h).
    pub discovery_svid_ttl: Option<String>,
    /// Sets `controller.gatewayApi.enabled`. `None` leaves the chart default
    /// (`true`). Use `Some(false)` to test Ingress-only installs.
    pub gateway_api_enabled: Option<bool>,
    /// Sets `controller.ingress.enabled`. `None` leaves the chart default
    /// (`true`). Use `Some(false)` to test Gateway-API-only installs.
    pub ingress_enabled: Option<bool>,
}

/// Handle to the in-cluster coxswain installation for one test.
///
/// The shared-proxy Ingress data-plane is reachable at `proxy_addr` (HTTP) and
/// `tls_addr` (HTTPS) on the Service's LoadBalancer IP. Gateway data-plane
/// addresses are NOT fixed here: each shared-mode Gateway advertises its OWN
/// per-Gateway VIP (#472), resolved per-test via `Harness::gateway_*`. Health
/// and admin are port-forwarded to `127.0.0.1:<ephemeral>` for the test.
pub struct ControllerProcess {
    /// LoadBalancer IP assigned to the shared-proxy external Service.
    pub lb_ip: IpAddr,
    /// Bound address for Ingress HTTP traffic (`<lb_ip>:80`).
    pub proxy_addr: SocketAddr,
    /// Bound address for Ingress HTTPS/TLS traffic (`<lb_ip>:443`).
    pub tls_addr: SocketAddr,
    /// Local port-forwarded address for `/healthz` / `/readyz`.
    pub health_addr: SocketAddr,
    /// Local port-forwarded address for `/metrics` / `/api/v1/routes` /
    /// `/api/v1/health` on the shared-proxy pod.
    pub admin_addr: SocketAddr,
    /// Local port-forwarded address for the controller pod's admin endpoint.
    /// Serves `/api/v1/health` and the aggregator surface
    /// `/api/v1/{fleet,routing}/*` plus `/api/v1/{problems,manifests/*}`.
    /// `/api/v1/routes` returns 404 on the controller — use the proxy
    /// admin (`admin_addr`) for the raw per-pod routing table.
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
        // Only upgrade the shared Helm release when the caller requests non-default
        // overrides. Bootstrap already installed the release with default settings,
        // so the many tests that call start_with_options(default) never touch Helm
        // and never race on its lock; only the global-config mutator tests (which
        // pass non-default overrides and run in the serial pass) reconfigure it.
        let overrides = HelmOverrides {
            status_address: opts.status_address,
            ingress_default_backend: opts.ingress_default_backend,
            accept_proxy_protocol: opts.accept_proxy_protocol,
            trusted_sources: opts.trusted_sources,
            access_log: opts.access_log,
            access_log_path_mode: opts.access_log_path_mode,
            discovery_svid_ttl: opts.discovery_svid_ttl,
            gateway_api_enabled: opts.gateway_api_enabled,
            ingress_enabled: opts.ingress_enabled,
        };
        if overrides != HelmOverrides::default() {
            let root = workspace_root().context("workspace root")?;
            helm_install(&root, &overrides)
                .await
                .context("helm upgrade with overrides")?;
        }

        // When ingress is disabled the chart omits the external LoadBalancer Service
        // (shared-proxy-service.yaml is gated on `controller.ingress.enabled`). The
        // internal ClusterIP service used for health/admin port-forwards is always
        // present. Use the unspecified address as a sentinel; tests that disable ingress
        // must not send traffic through proxy_addr / tls_addr.
        let lb_ip = if overrides.ingress_enabled == Some(false) {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            wait_for_lb_ip(SHARED_PROXY_SVC, COXSWAIN_NAMESPACE)
                .await
                .context("shared-proxy LB IP")?
        };

        let health_port = free_port()?;
        let admin_port = free_port()?;

        let controller_admin_port = free_port()?;

        let health_pf = start_port_forward(
            &format!("svc/{SHARED_PROXY_INTERNAL_SVC}"),
            health_port,
            8081,
            COXSWAIN_NAMESPACE,
        )
        .await?;
        let admin_pf = start_port_forward(
            &format!("svc/{SHARED_PROXY_INTERNAL_SVC}"),
            admin_port,
            8082,
            COXSWAIN_NAMESPACE,
        )
        .await?;
        let controller_admin_pf = start_port_forward(
            &format!("svc/{CONTROLLER_SVC}"),
            controller_admin_port,
            8082,
            COXSWAIN_NAMESPACE,
        )
        .await?;

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
        wait_for_controller_ready(CONTROLLER_SVC, COXSWAIN_NAMESPACE)
            .await
            .context("controller readyz")?;

        Ok(Self {
            lb_ip,
            proxy_addr: SocketAddr::new(lb_ip, INGRESS_HTTP_PORT),
            tls_addr: SocketAddr::new(lb_ip, INGRESS_HTTPS_PORT),
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

/// RAII guard for a `kubectl port-forward` tunnel to a Gateway listener port
/// on the shared-proxy pod.
///
/// Dropping this kills the tunnel.
pub struct GatewayPortForward {
    child: Child,
    /// Local loopback address the tunnel is bound to.
    pub addr: SocketAddr,
}

impl Drop for GatewayPortForward {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

impl ControllerProcess {
    /// Open a `kubectl port-forward` tunnel to the shared-proxy Deployment's
    /// `GATEWAY_HTTP_PORT` listener and return an RAII [`GatewayPortForward`].
    ///
    /// Dedicated-mode Gateways have no per-Gateway VIP Service (#472), so a
    /// direct pod port-forward is the only way to reach the shared pool's
    /// Gateway HTTP listener for the dedicated-crash-loop resilience test.
    ///
    /// # Errors
    ///
    /// Returns an error if `kubectl port-forward` fails to start or the tunnel
    /// does not accept connections within 30 s.
    pub async fn gateway_http_forward(&self) -> anyhow::Result<GatewayPortForward> {
        let local_port = free_port()?;
        let child = start_port_forward(
            "deployment/coxswain-shared-proxy",
            local_port,
            GATEWAY_HTTP_PORT,
            COXSWAIN_NAMESPACE,
        )
        .await?;
        Ok(GatewayPortForward {
            child,
            addr: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), local_port),
        })
    }
}

/// Poll `Service.status.loadBalancer.ingress[0].ip` for `svc_name` in `namespace`
/// until an IP is assigned or 60 s elapses.
///
/// OrbStack assigns IPs within ~150 ms; cloud-provider-kind on kind takes ~5-10 s.
///
/// # Errors
///
/// Returns an error if no IP is assigned within 60 s.
async fn wait_for_lb_ip(svc_name: &str, namespace: &str) -> anyhow::Result<IpAddr> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let out = Command::new("kubectl")
            .args([
                "get",
                "svc",
                svc_name,
                "-n",
                namespace,
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
            anyhow::bail!("{svc_name} Service has no LoadBalancer IP after 60s");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Spawn a `kubectl port-forward` tunnel from `127.0.0.1:<local_port>` to
/// `<target>:<remote_port>` in `namespace`.
///
/// `target` is passed verbatim to `kubectl port-forward` and may be any valid
/// resource designator: `svc/<name>`, `deployment/<name>`, `pod/<name>`, etc.
///
/// The returned [`Child`] must be kept alive for the lifetime of the tunnel;
/// dropping it kills the forward.
///
/// # Errors
///
/// Returns an error if `kubectl port-forward` fails to spawn or the tunnel does
/// not accept connections within 30 s.
async fn start_port_forward(
    target: &str,
    local_port: u16,
    remote_port: u16,
    namespace: &str,
) -> anyhow::Result<Child> {
    let child = Command::new("kubectl")
        .args([
            "port-forward",
            "-n",
            namespace,
            target,
            &format!("{local_port}:{remote_port}"),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("kubectl port-forward {target} {local_port}:{remote_port}"))?;
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
                "port-forward {target} {local_port}:{remote_port} never accepted connections within 30s"
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
async fn wait_for_controller_ready(controller_svc: &str, namespace: &str) -> anyhow::Result<()> {
    let port = free_port()?;
    let mut pf =
        start_port_forward(&format!("svc/{controller_svc}"), port, 8081, namespace).await?;
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
