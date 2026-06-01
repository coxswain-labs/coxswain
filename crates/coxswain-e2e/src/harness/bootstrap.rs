use anyhow::Context as _;
use std::path::{Path, PathBuf};
use tokio::process::Command;

pub async fn bootstrap() -> anyhow::Result<()> {
    let root = workspace_root();

    if !gateway_crds_installed().await {
        tracing::info!("Gateway API CRDs absent, installing");
        kubectl_apply_url(
            "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml",
        )
        .await
        .context("install Gateway API CRDs")?;
    }

    let manifests = root.join("deploy/manifests");
    kubectl_apply(&manifests.join("namespace.yaml")).await?;
    kubectl_apply(&manifests.join("rbac.yaml")).await?;
    kubectl_apply(&manifests.join("gateway-class.yaml")).await?;
    kubectl_apply(&manifests.join("ingress-class.yaml")).await?;

    Ok(())
}

async fn gateway_crds_installed() -> bool {
    Command::new("kubectl")
        .args([
            "get",
            "crd",
            "gateways.gateway.networking.k8s.io",
            "--ignore-not-found",
            "-o",
            "name",
        ])
        .output()
        .await
        .map(|o| !o.stdout.is_empty())
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
