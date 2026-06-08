//! Cluster bootstrapping: installs Gateway API CRDs, cert-manager, and Coxswain manifests.

use anyhow::Context as _;
use std::path::{Path, PathBuf};
use tokio::process::Command;

/// Single source of truth for the Gateway API CRD version installed in tests.
/// To bump: change `.gateway-api-version` at the repo root and update
/// `gateway-api` in workspace `Cargo.toml`. See `docs/gateway-api-support.md`.
const GATEWAY_API_VERSION: &str = include_str!("../../../../.gateway-api-version").trim_ascii();

/// Ensure the cluster is ready for e2e tests: installs Gateway API CRDs (once),
/// cert-manager (once), and applies the Coxswain service manifests.
///
/// Idempotent — safe to call multiple times; subsequent calls skip already-installed
/// components in under 200 ms.
///
/// # Errors
///
/// Returns an error if any `kubectl apply` step fails or a required component
/// does not become available within its timeout.
pub async fn bootstrap() -> anyhow::Result<()> {
    // reqwest 0.13 uses `rustls-no-provider`; install ring explicitly so the
    // process has exactly one crypto provider regardless of transitive deps.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let root = workspace_root().context("workspace root")?;

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
        tracing::info!("Gateway API CRDs absent or pre-v1, installing {GATEWAY_API_VERSION}");
        kubectl_apply_url(
            &format!("https://github.com/kubernetes-sigs/gateway-api/releases/download/{GATEWAY_API_VERSION}/standard-install.yaml"),
        )
        .await
        .context("install Gateway API CRDs")?;
        wait_for_crds_established()
            .await
            .context("Gateway API CRDs not established")?;
    }

    install_cert_manager_if_missing()
        .await
        .context("install cert-manager")?;

    let manifests = root.join("deploy/manifests");
    kubectl_apply(&manifests.join("namespace.yaml")).await?;
    kubectl_apply(&manifests.join("rbac.yaml")).await?;
    kubectl_apply(&manifests.join("gateway-class.yaml")).await?;
    kubectl_apply(&manifests.join("ingress-class.yaml")).await?;
    kubectl_apply(&manifests.join("pdb.yaml")).await?;

    Ok(())
}

/// Install cert-manager v1.18.0 if not already present, then ensure the
/// `coxswain-e2e-selfsigned` ClusterIssuer exists.  Both steps are idempotent
/// via `kubectl apply`.
async fn install_cert_manager_if_missing() -> anyhow::Result<()> {
    if !cert_manager_installed().await {
        tracing::info!("cert-manager not found, installing v1.18.0");
        kubectl_apply_url(
            "https://github.com/cert-manager/cert-manager/releases/download/v1.18.0/cert-manager.yaml",
        )
        .await
        .context("install cert-manager")?;

        // Wait for all three cert-manager Deployments to be Available.
        let status = Command::new("kubectl")
            .args([
                "wait",
                "--for=condition=Available",
                "--timeout=120s",
                "deployment/cert-manager",
                "deployment/cert-manager-webhook",
                "deployment/cert-manager-cainjector",
                "-n",
                "cert-manager",
            ])
            .status()
            .await
            .context("kubectl wait cert-manager")?;
        anyhow::ensure!(
            status.success(),
            "cert-manager deployments not ready within 120s"
        );
    }

    // Always apply the ClusterIssuer — `kubectl apply` is idempotent so this is
    // safe on subsequent bootstrap calls when cert-manager was already installed.
    let issuer_yaml = r#"
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: coxswain-e2e-selfsigned
spec:
  selfSigned: {}
"#;
    let mut child = tokio::process::Command::new("kubectl")
        .args(["apply", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("kubectl apply ClusterIssuer")?;
    if let Some(stdin) = child.stdin.as_mut() {
        tokio::io::AsyncWriteExt::write_all(stdin, issuer_yaml.as_bytes())
            .await
            .context("write ClusterIssuer yaml")?;
    }
    drop(child.stdin.take());
    let status = child
        .wait()
        .await
        .context("kubectl apply ClusterIssuer wait")?;
    anyhow::ensure!(status.success(), "kubectl apply ClusterIssuer failed");

    Ok(())
}

/// Returns true if cert-manager CRDs are present at v1.
async fn cert_manager_installed() -> bool {
    Command::new("kubectl")
        .args([
            "get",
            "crd",
            "certificates.cert-manager.io",
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

/// Returns the absolute path to the Cargo workspace root.
///
/// # Errors
///
/// Returns an error if [`std::fs::canonicalize`] fails (e.g. the path does not exist).
pub fn workspace_root() -> anyhow::Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .context("canonicalize workspace root")
}
