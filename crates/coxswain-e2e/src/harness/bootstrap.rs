use anyhow::Context as _;
use std::path::{Path, PathBuf};
use tokio::process::Command;

pub async fn bootstrap() -> anyhow::Result<()> {
    let root = workspace_root();

    // Purge any namespaces left over from a previous interrupted run.
    // --wait=false: don't block; the counter-based names ensure no collision with
    // Terminating namespaces within the same run.
    let _ = Command::new("kubectl")
        .args([
            "delete",
            "ns",
            "-l",
            "coxswain-e2e=true",
            "--ignore-not-found",
            "--wait=false",
        ])
        .status()
        .await;

    if !gateway_v1_crds_installed().await {
        tracing::info!("Gateway API CRDs absent or pre-v1, installing v1.5.1");
        kubectl_apply_url(
            "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.1/standard-install.yaml",
        )
        .await
        .context("install Gateway API CRDs")?;
        wait_for_crds_established()
            .await
            .context("Gateway API CRDs not established")?;
    }

    let manifests = root.join("deploy/manifests");
    kubectl_apply(&manifests.join("namespace.yaml")).await?;
    kubectl_apply(&manifests.join("rbac.yaml")).await?;
    kubectl_apply(&manifests.join("gateway-class.yaml")).await?;
    kubectl_apply(&manifests.join("ingress-class.yaml")).await?;

    Ok(())
}

/// Returns true only if ReferenceGrant is served at v1 (requires Gateway API >= v1.0.0 CRDs).
/// We need v1 because the `gateway-api` Rust crate targets the v1 API group.
async fn gateway_v1_crds_installed() -> bool {
    Command::new("kubectl")
        .args([
            "get",
            "crd",
            "referencegrants.gateway.networking.k8s.io",
            "-o",
            "jsonpath={.spec.versions[*].name}",
            "--ignore-not-found",
        ])
        .output()
        .await
        .map(|o| {
            let out = String::from_utf8_lossy(&o.stdout);
            out.split_whitespace().any(|v| v == "v1")
        })
        .unwrap_or(false)
}

async fn kubectl_apply(path: &Path) -> anyhow::Result<()> {
    let status = Command::new("kubectl")
        .args(["apply", "-f"])
        .arg(path)
        .status()
        .await
        .context("kubectl")?;
    anyhow::ensure!(status.success(), "kubectl apply failed: {}", path.display());
    Ok(())
}

async fn wait_for_crds_established() -> anyhow::Result<()> {
    let status = Command::new("kubectl")
        .args([
            "wait",
            "--for=condition=Established",
            "--timeout=60s",
            "crd/gateways.gateway.networking.k8s.io",
            "crd/httproutes.gateway.networking.k8s.io",
            "crd/referencegrants.gateway.networking.k8s.io",
        ])
        .status()
        .await
        .context("kubectl wait CRDs")?;
    anyhow::ensure!(
        status.success(),
        "Gateway API CRDs not established within 60s"
    );
    Ok(())
}

async fn kubectl_apply_url(url: &str) -> anyhow::Result<()> {
    let status = Command::new("kubectl")
        .args(["apply", "-f", url])
        .status()
        .await
        .context("kubectl")?;
    anyhow::ensure!(status.success(), "kubectl apply -f {url} failed");
    Ok(())
}

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}
