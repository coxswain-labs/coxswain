use coxswain_controller::tls::SharedGatewayListenerHealth;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::HashSet;
use std::sync::Arc;

/// Background service that watches for Gateway listener port changes and restarts
/// the process to rebind sockets when new ports are required.
///
/// On each routing-table rebuild, compares the set of ports declared across all
/// owned Gateway listeners (plus the CLI-configured defaults) against the ports
/// that were actually bound at startup. If any new port is needed, spawns a new
/// child process with `COXSWAIN_RESTART_CHILD=1` and calls `process::exit(0)`
/// so the parent releases its sockets and the child can bind the full updated set.
///
/// Ports that disappear (e.g. a Gateway is deleted) do NOT trigger a restart;
/// the socket stays open but routes no traffic (the routing table has no entries
/// for that port, so every request returns 404/503 as appropriate).
pub struct HotReloader {
    tls_health: SharedGatewayListenerHealth,
    currently_bound: Arc<HashSet<u16>>,
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
            currently_bound: Arc::new(currently_bound),
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
            if desired.is_subset(&*self.currently_bound) {
                continue;
            }

            let mut new_ports: Vec<u16> = desired
                .difference(&*self.currently_bound)
                .copied()
                .collect();
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
        .spawn()?;
    tracing::info!(pid = child.id(), "Spawned restart child process");
    Ok(())
}
