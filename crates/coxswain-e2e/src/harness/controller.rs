use anyhow::Context as _;
use std::{net::SocketAddr, path::PathBuf};
use tokio::process::{Child, Command};

pub struct ControllerProcess {
    child: Child,
    pub proxy_addr: SocketAddr,
    pub tls_addr: SocketAddr,
    pub health_addr: SocketAddr,
    pub admin_addr: SocketAddr,
}

/// Optional parameters for `ControllerProcess::start_with_options`.
#[derive(Default)]
pub struct ControllerOptions {
    /// When set, passed as `--ingress-status-address` to the controller.
    pub ingress_status_address: Option<String>,
    /// When set, passed as `--ingress-default-backend` to the controller.
    /// Format: `<namespace>/<service>:<port>`.
    pub ingress_default_backend: Option<String>,
}

impl ControllerProcess {
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_with_options(ControllerOptions::default()).await
    }

    pub async fn start_with_options(opts: ControllerOptions) -> anyhow::Result<Self> {
        let proxy_addr = free_addr()?;
        let tls_addr = free_addr()?;
        let health_addr = free_addr()?;
        let admin_addr = free_addr()?;

        // Use the test process's PID as pod-name: if the lease is still held by
        // a prior test's controller (same pod-name), renewal succeeds immediately
        // instead of waiting out the TTL.
        let pod_name = format!("coxswain-e2e-{}", std::process::id());

        let binary = coxswain_bin()?;
        let mut args = vec![
            "serve".to_string(),
            "--proxy-addr".to_string(),
            proxy_addr.to_string(),
            "--proxy-tls-addr".to_string(),
            tls_addr.to_string(),
            "--health-addr".to_string(),
            health_addr.to_string(),
            "--admin-addr".to_string(),
            admin_addr.to_string(),
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
        if let Some(addr) = opts.ingress_status_address {
            args.push("--ingress-status-address".to_string());
            args.push(addr);
        }
        if let Some(db) = opts.ingress_default_backend {
            args.push("--ingress-default-backend".to_string());
            args.push(db);
        }

        let child = Command::new(&binary)
            .args(&args)
            .spawn()
            .with_context(|| format!("spawn {}", binary.display()))?;

        Ok(Self {
            child,
            proxy_addr,
            tls_addr,
            health_addr,
            admin_addr,
        })
    }
}

impl Drop for ControllerProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

fn free_addr() -> anyhow::Result<SocketAddr> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").context("bind ephemeral port")?;
    let addr = listener.local_addr().context("local_addr")?;
    Ok(addr)
    // listener drops here, releasing the port; small race window is acceptable
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
