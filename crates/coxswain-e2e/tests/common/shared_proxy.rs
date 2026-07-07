#![allow(missing_docs)]
//! Shared-proxy Deployment lifecycle helpers (#531).
//!
//! Scaling or restarting `coxswain-shared-proxy` breaks every tenant's data
//! plane, so tests using these helpers are only legal in whole-binary-serial
//! suites (`status_conditions`, `discovery`, `resilience` — see
//! `.config/nextest.toml`). [`SharedProxyScaleGuard`] restores `replicas=1`
//! on drop (panic-safe) via a synchronous `kubectl` invocation — no runtime
//! is needed in `Drop`, sidestepping the current-thread-runtime teardown trap
//! that async cleanup would hit.

use std::time::Duration;

use coxswain_e2e::harness::wait;
use tokio::process::Command;

const DEPLOYMENT: &str = "coxswain-shared-proxy";
const NAMESPACE: &str = "coxswain-system";

/// Scale the shared-proxy Deployment and wait for the real post-condition:
/// zero pods remaining (scale to 0) or all replicas Ready (scale up).
pub async fn scale_shared_proxy(replicas: u32) -> anyhow::Result<()> {
    let status = Command::new("kubectl")
        .args([
            "scale",
            &format!("deployment/{DEPLOYMENT}"),
            "-n",
            NAMESPACE,
            &format!("--replicas={replicas}"),
        ])
        .status()
        .await?;
    anyhow::ensure!(
        status.success(),
        "kubectl scale shared proxy to {replicas} failed"
    );
    wait_for_shared_proxy_replicas(replicas).await
}

/// Wait until the Deployment reports exactly `replicas` ready replicas and no
/// surplus pods (`kubectl scale` returns at spec-update time, not settle time).
pub async fn wait_for_shared_proxy_replicas(replicas: u32) -> anyhow::Result<()> {
    wait::poll_until(
        Duration::from_secs(120),
        wait::POLL,
        || async move {
            format!(
                "shared proxy Deployment to settle at {replicas} ready replica(s); \
                 current: {:?}",
                deployment_counts().await
            )
        },
        || async move {
            let (total, ready) = deployment_counts().await?;
            (total == replicas && ready == replicas).then_some(())
        },
    )
    .await
}

/// `kubectl rollout restart` the shared proxy — the churn source for the #531
/// anti-flap test: the replacement pod connects with an empty bound set while
/// the old one drains.
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

/// Panic-safe restoration of the single-replica shared proxy.
///
/// Construct before scaling down; drop runs a *synchronous* `kubectl scale
/// --replicas=1` so the fixture is restored even when the test body panics
/// mid-assertion. Tests should still scale back up explicitly and assert the
/// recovery — the guard is the backstop, not the assertion.
pub struct SharedProxyScaleGuard;

impl Drop for SharedProxyScaleGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new("kubectl")
            .args([
                "scale",
                &format!("deployment/{DEPLOYMENT}"),
                "-n",
                NAMESPACE,
                "--replicas=1",
            ])
            .status();
    }
}
