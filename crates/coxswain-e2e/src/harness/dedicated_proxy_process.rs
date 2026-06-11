//! Spawns a `coxswain serve proxy --dedicated` subprocess on ephemeral
//! management ports and tears it down on drop.
//!
//! The dedicated-proxy role doesn't accept `--ingress-*-port` or `--gateway-*-port`
//! flags — its listener set is driven by the watched Gateway's listener spec, so the
//! subprocess binds whichever ports the fixture declared via the
//! `GATEWAY_HTTP_PORT` / `GATEWAY_HTTPS_PORT` substitution tokens (which the
//! [`crate::harness::Harness`] pre-allocates). The wrapper only needs ephemeral
//! ports for `/healthz` + `/readyz` and the admin endpoint.

use anyhow::Context as _;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use std::os::unix::process::CommandExt as _;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::process::{Child, Command};

use crate::harness::HttpClient;
use crate::harness::controller::coxswain_bin;

const BIND_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Handle to a `coxswain serve proxy --dedicated` subprocess for e2e tests.
///
/// The `gateway_http_addr` / `gateway_https_addr` fields mirror the Gateway
/// listener ports the subprocess binds — they are passed in by the caller so
/// tests can `GET` against the dedicated subprocess on the same loopback port
/// the fixture declared in the Gateway spec.
pub struct DedicatedProxyProcess {
    child: Option<Child>,
    /// Bound address of the Gateway HTTP listener — the port the fixture
    /// declared via `GATEWAY_HTTP_PORT`.
    pub gateway_http_addr: SocketAddr,
    /// Bound address of the Gateway HTTPS listener — the port the fixture
    /// declared via `GATEWAY_HTTPS_PORT`.
    pub gateway_https_addr: SocketAddr,
    /// Bound address of the `/healthz`/`/readyz` endpoint.
    pub health_addr: SocketAddr,
    /// Bound address of the `/metrics`/`/routes`/`/status` endpoint.
    pub admin_addr: SocketAddr,
    /// Name of the Gateway the subprocess is scoped to.
    pub gateway_name: String,
    /// Namespace of the Gateway the subprocess is scoped to.
    pub gateway_namespace: String,
}

impl DedicatedProxyProcess {
    /// Spawn a dedicated-proxy subprocess scoped to one Gateway. `gateway_http_addr`
    /// and `gateway_https_addr` must match the listener ports the fixture
    /// rendered into the Gateway spec — the subprocess will bind them dynamically
    /// once its first reconcile cycle picks up the Gateway.
    ///
    /// `watch_namespaces` is the per-namespace reflector set passed via
    /// `--proxy-watch-namespaces` (required by clap when `--dedicated` is set;
    /// must at least include `gateway_namespace`). For cross-namespace
    /// HTTPRoute backends, also include the tenant namespaces.
    pub async fn start(
        gateway_name: &str,
        gateway_namespace: &str,
        gateway_http_addr: SocketAddr,
        gateway_https_addr: SocketAddr,
        watch_namespaces: &[&str],
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !watch_namespaces.is_empty(),
            "watch_namespaces must include at least the Gateway's namespace"
        );
        let health_port = free_port()?;
        let admin_port = free_port()?;
        let health_addr = SocketAddr::new(BIND_ADDR, health_port);
        let admin_addr = SocketAddr::new(BIND_ADDR, admin_port);

        // Distinct pod-name per subprocess so structured logs are
        // disambiguatable when multiple dedicated proxies run in one test.
        let pod_name = format!(
            "coxswain-e2e-dedicated-{}-{gateway_name}",
            std::process::id()
        );

        let binary = coxswain_bin()?;
        let args = vec![
            "serve".to_string(),
            "proxy".to_string(),
            "--dedicated".to_string(),
            "--gateway-name".to_string(),
            gateway_name.to_string(),
            "--gateway-namespace".to_string(),
            gateway_namespace.to_string(),
            "--proxy-watch-namespaces".to_string(),
            watch_namespaces.join(","),
            "--proxy-bind-address".to_string(),
            BIND_ADDR.to_string(),
            "--health-port".to_string(),
            health_port.to_string(),
            "--admin-port".to_string(),
            admin_port.to_string(),
            "--log-format".to_string(),
            "console".to_string(),
            "--pod-name".to_string(),
            pod_name,
            "--pod-namespace".to_string(),
            "coxswain-system".to_string(),
        ];

        let mut cmd = Command::new(&binary);
        cmd.args(&args);
        cmd.as_std_mut().process_group(0);
        let child = cmd
            .spawn()
            .with_context(|| format!("spawn {}", binary.display()))?;

        Ok(Self {
            child: Some(child),
            gateway_http_addr,
            gateway_https_addr,
            health_addr,
            admin_addr,
            gateway_name: gateway_name.to_string(),
            gateway_namespace: gateway_namespace.to_string(),
        })
    }

    /// Build an HTTP client pre-pointed at the dedicated subprocess's Gateway
    /// HTTP listener.
    pub fn http_client(&self) -> anyhow::Result<HttpClient> {
        HttpClient::new(self.gateway_http_addr).context("dedicated http client")
    }

    /// Build an admin endpoint URL (e.g. `admin_url("/routes")`).
    pub fn admin_url(&self, path: &str) -> String {
        format!("http://{}{path}", self.admin_addr)
    }

    /// Kill the subprocess and wait briefly for the OS to release its
    /// listener ports. Migration tests use this between cutover and re-binding
    /// on the shared subprocess.
    pub async fn shutdown(mut self) {
        if let Some(child) = self.child.take() {
            kill_child(child).await;
        }
    }
}

impl Drop for DedicatedProxyProcess {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            kill_child_sync(child);
        }
    }
}

async fn kill_child(mut child: Child) {
    if let Some(pid) = child.id() {
        let _ = killpg(Pid::from_raw(pid as i32), Signal::SIGKILL);
    }
    let _ = child.start_kill();
    let _ = child.wait().await;
    // Brief settle to let the kernel reap the listener sockets before the
    // next bind attempt.
    tokio::time::sleep(Duration::from_millis(200)).await;
}

fn kill_child_sync(mut child: Child) {
    if let Some(pid) = child.id() {
        let _ = killpg(Pid::from_raw(pid as i32), Signal::SIGKILL);
    }
    let _ = child.start_kill();
}

#[must_use = "port allocation result must be used"]
fn free_port() -> anyhow::Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").context("bind ephemeral port")?;
    Ok(listener.local_addr().context("local_addr")?.port())
}
