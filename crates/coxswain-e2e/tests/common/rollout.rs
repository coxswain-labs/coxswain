#![allow(missing_docs)]
//! Generic `kubectl rollout restart` helper for a namespace-scoped Deployment.
//!
//! Generalizes the deployment-specific restart helpers already in this crate
//! (`dedicated::restart_controller`, `shared_proxy::rollout_restart_shared_proxy`)
//! for tests that churn a fixture-owned backend Deployment they exclusively own
//! within their own namespace — safe to run in the parallel `e2e` pass, unlike
//! the shared-infrastructure restarts those helpers cover.

use tokio::process::Command;

/// Restart `deployment/{name}` in `namespace` and wait for the rollout to
/// settle (new pod(s) pass their readiness probe).
///
/// # Errors
///
/// Returns an error if either `kubectl` invocation fails or the rollout does
/// not complete within 90s.
pub async fn rollout_restart_deployment(namespace: &str, name: &str) -> anyhow::Result<()> {
    let deployment = format!("deployment/{name}");
    let status = Command::new("kubectl")
        .args(["rollout", "restart", &deployment, "-n", namespace])
        .status()
        .await?;
    anyhow::ensure!(
        status.success(),
        "kubectl rollout restart {deployment} -n {namespace} failed"
    );
    let status = Command::new("kubectl")
        .args([
            "rollout",
            "status",
            &deployment,
            "-n",
            namespace,
            "--timeout=90s",
        ])
        .status()
        .await?;
    anyhow::ensure!(
        status.success(),
        "{deployment} -n {namespace} rollout did not settle within 90s"
    );
    Ok(())
}
