use anyhow::Context as _;
use std::{net::SocketAddr, path::PathBuf};
use tokio::process::{Child, Command};

pub struct ControllerProcess {
    child: Child,
    pub proxy_addr: SocketAddr,
    pub health_addr: SocketAddr,
    pub admin_addr: SocketAddr,
}

impl ControllerProcess {
    pub async fn start() -> anyhow::Result<Self> {
        let proxy_addr = free_addr()?;
        let health_addr = free_addr()?;
        let admin_addr = free_addr()?;

        // Use the test process's PID as pod-name: if the lease is still held by
        // a prior test's controller (same pod-name), renewal succeeds immediately
        // instead of waiting out the TTL.
        let pod_name = format!("coxswain-e2e-{}", std::process::id());

        let binary = coxswain_bin()?;
        let child = Command::new(&binary)
            .args([
                "serve",
                "--proxy-addr",
                &proxy_addr.to_string(),
                "--health-addr",
                &health_addr.to_string(),
                "--admin-addr",
                &admin_addr.to_string(),
                "--log-format",
                "console",
                "--pod-name",
                &pod_name,
                "--pod-namespace",
                "coxswain-system",
                "--controller-lease-ttl",
                "3s",
                "--controller-lease-renew-interval",
                "1s",
            ])
            .spawn()
            .with_context(|| format!("spawn {}", binary.display()))?;

        Ok(Self {
            child,
            proxy_addr,
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
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").context("bind ephemeral port")?;
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
