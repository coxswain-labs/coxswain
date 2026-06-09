//! Spawns a coxswain subprocess on ephemeral ports and tears it down on drop.

use anyhow::Context as _;
use ipnet::IpNet;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use std::os::unix::process::CommandExt as _;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};
use tokio::process::{Child, Command};

const BIND_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Handle to a running coxswain subprocess spawned for e2e tests.
///
/// Since the IngressProxy / GatewayProxy split (issue #201), Ingress and
/// Gateway traffic bind disjoint port sets. `proxy_addr` / `tls_addr` are the
/// Ingress entry points and are passed to coxswain via `--proxy-http-port` /
/// `--proxy-https-port`. `gateway_http_addr` / `gateway_https_addr` are
/// pre-allocated for Gateway listeners — tests apply Gateway resources whose
/// listeners declare these ports, and the controller's HotReloader detects
/// them and binds them on restart.
pub struct ControllerProcess {
    child: Child,
    /// Bound address of the Ingress HTTP proxy listener (`--proxy-http-port`).
    pub proxy_addr: SocketAddr,
    /// Bound address of the Ingress HTTPS/TLS proxy listener (`--proxy-https-port`).
    pub tls_addr: SocketAddr,
    /// Pre-allocated address for tests that need a Gateway HTTP listener port.
    /// Not passed as a CLI flag; tests declare it in their Gateway specs.
    pub gateway_http_addr: SocketAddr,
    /// Pre-allocated address for tests that need a Gateway HTTPS listener port.
    pub gateway_https_addr: SocketAddr,
    /// Bound address of the `/healthz`/`/readyz` endpoint.
    pub health_addr: SocketAddr,
    /// Bound address of the `/metrics`/`/routes`/`/status` endpoint.
    pub admin_addr: SocketAddr,
}

/// Optional parameters for `ControllerProcess::start_with_options`.
#[derive(Default)]
pub struct ControllerOptions {
    /// When set, passed as `--status-address` to the controller.
    pub status_address: Option<IpAddr>,
    /// When set, passed as `--ingress-default-backend` to the controller.
    /// Format: `<namespace>/<service>:<port>`.
    pub ingress_default_backend: Option<String>,
    /// When true, passes `--proxy-accept-proxy-protocol` to the controller.
    pub proxy_accept_proxy_protocol: bool,
    /// CIDR ranges passed to `--proxy-trusted-sources`.
    pub proxy_trusted_sources: Vec<IpNet>,
}

impl ControllerProcess {
    /// Spawn a controller with default options.
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_with_options(ControllerOptions::default()).await
    }

    /// Spawn a controller with the given options, binding ephemeral ports for all listeners.
    pub async fn start_with_options(opts: ControllerOptions) -> anyhow::Result<Self> {
        let http_port = free_port()?;
        let https_port = free_port()?;
        let gateway_http_port = free_port()?;
        let gateway_https_port = free_port()?;
        let health_port = free_port()?;
        let admin_port = free_port()?;

        let proxy_addr = SocketAddr::new(BIND_ADDR, http_port);
        let tls_addr = SocketAddr::new(BIND_ADDR, https_port);
        let gateway_http_addr = SocketAddr::new(BIND_ADDR, gateway_http_port);
        let gateway_https_addr = SocketAddr::new(BIND_ADDR, gateway_https_port);
        let health_addr = SocketAddr::new(BIND_ADDR, health_port);
        let admin_addr = SocketAddr::new(BIND_ADDR, admin_port);

        // Use the test process's PID as pod-name: if the lease is still held by
        // a prior test's controller (same pod-name), renewal succeeds immediately
        // instead of waiting out the TTL.
        let pod_name = format!("coxswain-e2e-{}", std::process::id());

        let binary = coxswain_bin()?;
        let mut args = vec![
            "serve".to_string(),
            "--proxy-bind-address".to_string(),
            BIND_ADDR.to_string(),
            "--proxy-http-port".to_string(),
            http_port.to_string(),
            "--proxy-https-port".to_string(),
            https_port.to_string(),
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
            "--controller-lease-ttl".to_string(),
            "3s".to_string(),
            "--controller-lease-renew-interval".to_string(),
            "1s".to_string(),
        ];
        if let Some(addr) = opts.status_address {
            args.push("--status-address".to_string());
            args.push(addr.to_string());
        }
        if let Some(db) = opts.ingress_default_backend {
            args.push("--ingress-default-backend".to_string());
            args.push(db);
        }
        if opts.proxy_accept_proxy_protocol {
            args.push("--proxy-accept-proxy-protocol".to_string());
        }
        if !opts.proxy_trusted_sources.is_empty() {
            args.push("--proxy-trusted-sources".to_string());
            args.push(
                opts.proxy_trusted_sources
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }

        // Make the spawned coxswain its own process-group leader so we can reap
        // any restart-children together with the original child on Drop. The bin
        // implements port-rebinding by `fork+exec` of a restart-child then exiting
        // the parent (`coxswain-bin::hot_reload`); the restart-child inherits the
        // group, so killing the group covers both.
        let mut cmd = Command::new(&binary);
        cmd.args(&args);
        cmd.as_std_mut().process_group(0);
        let child = cmd
            .spawn()
            .with_context(|| format!("spawn {}", binary.display()))?;

        Ok(Self {
            child,
            proxy_addr,
            tls_addr,
            gateway_http_addr,
            gateway_https_addr,
            health_addr,
            admin_addr,
        })
    }
}

impl Drop for ControllerProcess {
    fn drop(&mut self) {
        // The HotReloader's restart model is fork+exec of a child followed by the
        // parent calling `process::exit(0)`. The restart-child is in the same
        // process group as the parent (we set `process_group(0)` at spawn), so
        // killing the group sweeps every coxswain instance the test ever produced.
        // `start_kill` on the directly-tracked child remains as a belt-and-braces
        // fallback in case the group setup failed.
        if let Some(pid) = self.child.id() {
            let _ = killpg(Pid::from_raw(pid as i32), Signal::SIGKILL);
        }
        let _ = self.child.start_kill();
    }
}

#[must_use = "port allocation result must be used"]
fn free_addr() -> anyhow::Result<SocketAddr> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").context("bind ephemeral port")?;
    let addr = listener.local_addr().context("local_addr")?;
    Ok(addr)
    // listener drops here, releasing the port; small race window is acceptable
}

#[must_use = "port allocation result must be used"]
fn free_port() -> anyhow::Result<u16> {
    free_addr().map(|a| a.port())
}

fn coxswain_bin() -> anyhow::Result<PathBuf> {
    if let Ok(p) = std::env::var("COXSWAIN_BIN") {
        let path = PathBuf::from(p);
        anyhow::ensure!(path.exists(), "COXSWAIN_BIN not found: {}", path.display());
        return Ok(path);
    }
    // Test binary lives at target/{profile}/deps/<name>-<hash>.
    // The coxswain binary is at target/{profile}/coxswain.
    let exe = std::env::current_exe().context("current_exe")?;
    let target_dir = exe
        .parent()
        .and_then(|p| p.parent())
        .context("unexpected test binary path")?;
    let bin = target_dir.join("coxswain");
    anyhow::ensure!(
        bin.exists(),
        "coxswain binary not found at {}. Run: cargo build --bin coxswain",
        bin.display()
    );
    Ok(bin)
}
