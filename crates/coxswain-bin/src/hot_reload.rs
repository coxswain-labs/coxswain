use coxswain_controller::tls::SharedGatewayListenerHealth;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::HashSet;

/// Background service that watches for Gateway listener port changes and restarts
/// the process to rebind sockets when new ports are required.
///
/// # Restart handshake
///
/// When new ports are detected:
/// 1. The parent spawns a child with `COXSWAIN_RESTART_CHILD=1` and
///    `COXSWAIN_RESTART_PARENT_PID=<pid>`.
/// 2. The parent calls `process::exit(0)`, releasing its listening sockets
///    immediately. (Graceful drain is intentionally skipped — the child serves
///    the same routes within seconds and a slow drain would delay port rebinding.)
/// 3. The child polls `kill(<parent_pid>, 0)` every 100 ms (max 30 s) until the
///    parent process is gone, then binds the full updated port set.
///
/// Ports that disappear (e.g. a Gateway is deleted) do NOT trigger a restart; the
/// socket stays open but routes no traffic.
pub struct HotReloader {
    tls_health: SharedGatewayListenerHealth,
    currently_bound: HashSet<u16>,
    cli_ports: HashSet<u16>,
}

impl HotReloader {
    pub fn new(
        tls_health: SharedGatewayListenerHealth,
        currently_bound: HashSet<u16>,
        cli_ports: HashSet<u16>,
    ) -> Self {
        Self {
            tls_health,
            currently_bound,
            cli_ports,
        }
    }

    fn desired_ports(&self) -> HashSet<u16> {
        let mut ports = self.cli_ports.clone();
        let health = self.tls_health.load();
        for gw in health.values() {
            for &port in gw.listener_ports.values() {
                ports.insert(port);
            }
        }
        ports
    }
}

#[async_trait::async_trait]
impl BackgroundService for HotReloader {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        loop {
            // Wait for any health-map update.
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = self.tls_health.notified() => {}
            }
            // Trailing-edge 2 s debounce: absorb burst updates and give the Controller
            // a window to write Programmed=True before we exit.
            loop {
                tokio::select! {
                    _ = shutdown.changed() => return,
                    _ = self.tls_health.notified() => {}
                    _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => break,
                }
            }

            let desired = self.desired_ports();
            if desired.is_subset(&self.currently_bound) {
                continue;
            }

            let mut new_ports: Vec<u16> =
                desired.difference(&self.currently_bound).copied().collect();
            new_ports.sort_unstable();

            tracing::info!(
                ?new_ports,
                "New listener ports required; restarting to rebind"
            );

            if let Err(e) = spawn_restart_child() {
                tracing::error!(
                    error = %e,
                    "Failed to spawn restart child; new ports will not be served until next restart"
                );
                continue;
            }

            // Exit immediately so the OS closes our listening sockets and the child
            // can bind the full updated port set as soon as we disappear.
            // Graceful drain is intentionally skipped: the child inherits all routes
            // and will serve traffic within seconds; a slow drain would prevent the
            // child from binding the new ports within the conformance test window.
            std::process::exit(0);
        }
    }
}

fn spawn_restart_child() -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let child = std::process::Command::new(&exe)
        .args(&args)
        .env("COXSWAIN_RESTART_CHILD", "1")
        .env(
            "COXSWAIN_RESTART_PARENT_PID",
            std::process::id().to_string(),
        )
        .spawn()?;
    tracing::info!(pid = child.id(), "Spawned restart child process");
    Ok(())
}
