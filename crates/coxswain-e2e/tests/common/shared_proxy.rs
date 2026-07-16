#![allow(missing_docs)]
//! Shared-proxy pool lifecycle helpers (#531).
//!
//! Scaling or restarting `coxswain-shared-proxy` breaks every tenant's data
//! plane, so tests using these helpers are only legal in whole-binary-serial
//! suites (`status_conditions`, `discovery`, `resilience` — see
//! `.config/nextest.toml`).
//!
//! Since #604 the pool is controller-owned: its replica count is config-driven
//! and re-asserted via server-side apply, so a direct `kubectl scale` is reverted
//! within a reconcile. [`scale_shared_proxy`] therefore drives the count through
//! a Helm upgrade of `proxy.shared.replicas`. Panic-safety no longer needs an
//! explicit restore guard — a leaked non-default override is detected and
//! restored by the harness's `ensure_default_release` on the next default-options
//! test. A `rollout restart` (churn without a replica change) still goes through
//! `kubectl`, since the controller does not fight it.

use tokio::process::Command;

const DEPLOYMENT: &str = "coxswain-shared-proxy";
const NAMESPACE: &str = "coxswain-system";

/// Scale the controller-owned shared proxy pool to `replicas` and block until it
/// converges (including 0). Drives the count through `proxy.shared.replicas` — a
/// direct `kubectl scale` would be reverted by the install reconciler.
pub async fn scale_shared_proxy(replicas: u32) -> anyhow::Result<()> {
    coxswain_e2e::harness::set_shared_proxy_replicas(replicas).await
}

/// `kubectl rollout restart` the shared proxy — the churn source for the #531
/// anti-flap test: the replacement pod connects with an empty bound set while
/// the old one drains. The replica count is unchanged, so the controller does
/// not fight it.
pub async fn rollout_restart_shared_proxy() -> anyhow::Result<()> {
    let status = Command::new("kubectl")
        .args([
            "rollout",
            "restart",
            &format!("deployment/{DEPLOYMENT}"),
            "-n",
            NAMESPACE,
        ])
        .status()
        .await?;
    anyhow::ensure!(
        status.success(),
        "kubectl rollout restart shared proxy failed"
    );
    Ok(())
}

/// `(status.replicas, status.readyReplicas)` of the shared-proxy Deployment,
/// with absent fields read as 0 (the fields are pruned at zero).
async fn deployment_counts() -> Option<(u32, u32)> {
    let out = Command::new("kubectl")
        .args([
            "get",
            "deployment",
            DEPLOYMENT,
            "-n",
            NAMESPACE,
            "-o",
            "jsonpath={.status.replicas}/{.status.readyReplicas}",
        ])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut parts = text.split('/');
    let total = parts.next()?.trim();
    let ready = parts.next().unwrap_or("").trim();
    Some((total.parse().unwrap_or(0), ready.parse().unwrap_or(0)))
}

/// Whether the shared-proxy Deployment has fully settled at `replicas` after a
/// rollout: `kubectl rollout status --watch=false` accounts for the observed
/// generation and updated/ready replica counts, so a not-yet-started rollout
/// (template just patched) correctly reads as unsettled.
pub async fn shared_proxy_settled(replicas: u32) -> anyhow::Result<bool> {
    let out = Command::new("kubectl")
        .args([
            "rollout",
            "status",
            &format!("deployment/{DEPLOYMENT}"),
            "-n",
            NAMESPACE,
            "--watch=false",
        ])
        .output()
        .await?;
    let rolled_out = out.status.success()
        && String::from_utf8_lossy(&out.stdout).contains("successfully rolled out");
    if !rolled_out {
        return Ok(false);
    }
    Ok(deployment_counts()
        .await
        .is_some_and(|(total, ready)| total == replicas && ready == replicas))
}
