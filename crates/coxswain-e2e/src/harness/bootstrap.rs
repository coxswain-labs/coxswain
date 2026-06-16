//! Cluster bootstrapping: builds the coxswain image, loads it into the cluster,
//! and installs the Helm release with the settings needed for e2e tests.

use anyhow::Context as _;
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tokio::sync::OnceCell;

/// Guards the heavy one-time cluster setup within a single process (fallback
/// for non-nextest execution). Under nextest with the `e2e-setup` setup
/// script, `COXSWAIN_E2E_BOOTSTRAPPED=1` is injected and tests short-circuit
/// without touching this cell.
static CLUSTER_SETUP: OnceCell<()> = OnceCell::const_new();

/// Single source of truth for the Gateway API CRD version installed in tests.
/// To bump: change `.gateway-api-version` at the repo root and update
/// `gateway-api` in workspace `Cargo.toml`. See `docs/gateway-api-support.md`.
const GATEWAY_API_VERSION: &str = include_str!("../../../../.gateway-api-version").trim_ascii();

/// Local Docker image tag used for all e2e runs.
pub(crate) const E2E_IMAGE: &str = "coxswain:e2e";
/// Helm release name.
pub(crate) const HELM_RELEASE: &str = "coxswain";
/// Kubernetes namespace coxswain is installed into.
pub(crate) const COXSWAIN_NAMESPACE: &str = "coxswain-system";

/// Fixed port the shared-proxy Service exposes for Gateway HTTP listeners.
pub const GATEWAY_HTTP_PORT: u16 = 8000;
/// Fixed port the shared-proxy Service exposes for Gateway HTTPS listeners.
pub const GATEWAY_HTTPS_PORT: u16 = 8443;

/// The local Kubernetes cluster distribution detected from the current context.
#[derive(Debug, Clone)]
pub(crate) enum ClusterKind {
    /// OrbStack-managed Kubernetes — ships its own LB controller; Docker images
    /// visible to containerd automatically via the shared OrbStack daemon.
    Orbstack,
    /// kind cluster — needs `kind load docker-image` and cloud-provider-kind for
    /// LoadBalancer IP assignment.
    Kind {
        /// The kind cluster name (context is `kind-<name>`).
        name: String,
    },
}

impl ClusterKind {
    /// Detect the cluster distribution from the current kubeconfig context.
    ///
    /// # Errors
    ///
    /// Returns an error if `kubectl config current-context` fails.
    pub(crate) async fn detect() -> anyhow::Result<Self> {
        let out = Command::new("kubectl")
            .args(["config", "current-context"])
            .output()
            .await
            .context("kubectl config current-context")?;
        let ctx = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if ctx == "orbstack" || ctx.starts_with("orb/") {
            Ok(Self::Orbstack)
        } else if let Some(name) = ctx.strip_prefix("kind-") {
            Ok(Self::Kind {
                name: name.to_string(),
            })
        } else {
            // Unknown context — treat like kind (explicit image load required).
            tracing::warn!(context = %ctx, "unrecognised cluster context, treating as kind");
            Ok(Self::Kind { name: ctx })
        }
    }
}

/// Ensure the cluster is ready for e2e tests.
///
/// Under `cargo nextest run --profile e2e` the `e2e-setup` setup script runs
/// [`bootstrap_cluster`] once before any test starts and injects
/// `COXSWAIN_E2E_BOOTSTRAPPED=1`; this function returns immediately in that
/// case. Without the setup script (direct `cargo test` or other paths) it
/// falls back to calling [`bootstrap_cluster`] inline.
///
/// # Errors
///
/// Returns an error if bootstrap fails.
pub async fn bootstrap() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if std::env::var("COXSWAIN_E2E_BOOTSTRAPPED").is_ok() {
        return Ok(());
    }
    bootstrap_cluster().await
}

/// Run the full one-time cluster setup: build image, install CRDs,
/// cert-manager, and the coxswain Helm release.
///
/// Called directly by the `e2e-setup` nextest setup-script binary so the
/// heavy work happens once, serially, before any test process starts. Also
/// used as the inline fallback by [`bootstrap`] when the env var is absent.
///
/// Cold path (fresh cluster, no Docker cache): ~10 min for the BoringSSL build.
/// Warm path (image cached, Helm release deployed): < 1 s.
///
/// # Errors
///
/// Returns an error if any setup step fails or a required component does not
/// become available within its timeout.
pub async fn bootstrap_cluster() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    CLUSTER_SETUP
        .get_or_try_init(|| async {
            // Purge leftover e2e namespaces from a previous interrupted run.
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

            let root = workspace_root().context("workspace root")?;
            let cluster = ClusterKind::detect().await.context("detect cluster kind")?;

            build_image(&root).await.context("docker build")?;

            match &cluster {
                ClusterKind::Kind { name } => {
                    kind_load_image(name).await.context("kind load")?;
                    install_cloud_provider_kind_if_missing()
                        .await
                        .context("cloud-provider-kind")?;
                }
                ClusterKind::Orbstack => {}
            }

            if !gateway_v1_crds_installed().await {
                tracing::info!(
                    "Gateway API CRDs absent or pre-v1, installing {GATEWAY_API_VERSION}"
                );
                kubectl_apply_url(&format!(
                    "https://github.com/kubernetes-sigs/gateway-api/releases/download/{GATEWAY_API_VERSION}/standard-install.yaml"
                ))
                .await
                .context("install Gateway API CRDs")?;
                wait_for_crds_established()
                    .await
                    .context("Gateway API CRDs not established")?;
            }

            install_cert_manager_if_missing()
                .await
                .context("install cert-manager")?;

            // Pre-apply coxswain CRDs with SSA before helm so the field manager
            // is consistent across fresh and pre-existing clusters.
            let crd_dir = root.join("charts/coxswain/crds");
            let status = Command::new("kubectl")
                .args([
                    "apply",
                    "--server-side",
                    "--force-conflicts",
                    "-f",
                    crd_dir.to_string_lossy().as_ref(),
                ])
                .status()
                .await
                .context("kubectl apply crds")?;
            anyhow::ensure!(status.success(), "kubectl apply --server-side crds failed");

            helm_install(&root, &HelmOverrides::default())
                .await
                .context("helm install")?;

            Ok(())
        })
        .await?;

    Ok(())
}

/// Additional Helm `--set` overrides for tests that need non-default proxy config.
///
/// All fields default to the chart's own defaults (empty / false).
#[derive(Debug, Default, PartialEq)]
pub(crate) struct HelmOverrides {
    /// Passed as `controller.statusAddress`. Used by the conformance suite so
    /// `Gateway.status.addresses` is populated with a reachable LB IP.
    pub status_address: Option<String>,
    /// Passed as `proxy.shared.ingressDefaultBackend`.
    /// Format: `<namespace>/<service>:<port>`.
    pub ingress_default_backend: Option<String>,
    /// Passed as `proxy.shared.acceptProxyProtocol`.
    pub accept_proxy_protocol: bool,
    /// Passed as `proxy.shared.trustedSources` (comma-joined CIDR list).
    /// Only meaningful when `accept_proxy_protocol` is true.
    pub trusted_sources: Vec<String>,
    /// Passed as `proxy.shared.accessLog`. `None` leaves the chart default
    /// (currently `true`).
    pub access_log: Option<bool>,
    /// Passed as `proxy.shared.accessLogPathMode`. `None` leaves the chart
    /// default (currently `"full"`).
    pub access_log_path_mode: Option<String>,
}

/// Install or upgrade the coxswain Helm release with e2e-specific overrides.
///
/// Uses `helm upgrade --install --wait` so the call blocks until both pods are
/// `Ready`. Idempotent: if the release is already deployed and the rendered
/// manifests are unchanged, Helm returns immediately.
///
/// # Errors
///
/// Returns an error if `helm upgrade` exits non-zero or times out.
pub(crate) async fn helm_install(root: &Path, overrides: &HelmOverrides) -> anyhow::Result<()> {
    let chart = root.join("charts/coxswain");
    let mut args: Vec<String> = vec![
        "upgrade".into(),
        "--install".into(),
        HELM_RELEASE.into(),
        chart.to_string_lossy().into_owned(),
        "--namespace".into(),
        COXSWAIN_NAMESPACE.into(),
        // --create-namespace tells Helm to create the target namespace if absent.
        // namespace.create=false disables the chart's own Namespace template so
        // the two don't conflict when the namespace doesn't exist yet.
        "--create-namespace".into(),
        "--set".into(),
        "namespace.create=false".into(),
        "--set".into(),
        format!("image.repository={}", image_repository()),
        "--set".into(),
        format!("image.tag={}", image_tag()),
        "--set".into(),
        "image.pullPolicy=Never".into(),
        "--set".into(),
        "service.gateway.type=LoadBalancer".into(),
        "--set".into(),
        format!("controller.coxswainImage={E2E_IMAGE}"),
        // Pre-declare the fixed gateway ports on the Service so they're reachable
        // via the LoadBalancer in addition to the standard 80/443.
        "--set".into(),
        format!(
            "service.gateway.additionalPorts[0].name=gw-http,service.gateway.additionalPorts[0].port={GATEWAY_HTTP_PORT},service.gateway.additionalPorts[0].targetPort={GATEWAY_HTTP_PORT},service.gateway.additionalPorts[0].protocol=TCP"
        ),
        "--set".into(),
        format!(
            "service.gateway.additionalPorts[1].name=gw-https,service.gateway.additionalPorts[1].port={GATEWAY_HTTPS_PORT},service.gateway.additionalPorts[1].targetPort={GATEWAY_HTTPS_PORT},service.gateway.additionalPorts[1].protocol=TCP"
        ),
        "--skip-crds".into(), // CRDs are pre-applied with SSA above
        "--wait".into(),
        "--timeout".into(),
        "120s".into(),
    ];

    if let Some(addr) = &overrides.status_address {
        args.push("--set".into());
        args.push(format!("controller.statusAddress={addr}"));
    }
    if let Some(db) = &overrides.ingress_default_backend {
        args.push("--set".into());
        args.push(format!("proxy.shared.ingressDefaultBackend={db}"));
    }
    if overrides.accept_proxy_protocol {
        args.push("--set".into());
        args.push("proxy.shared.acceptProxyProtocol=true".into());
    }
    if !overrides.trusted_sources.is_empty() {
        args.push("--set".into());
        args.push(format!(
            "proxy.shared.trustedSources={{{}}}",
            overrides.trusted_sources.join("\\,")
        ));
    }
    if let Some(enabled) = overrides.access_log {
        args.push("--set".into());
        args.push(format!("proxy.shared.accessLog={enabled}"));
    }
    if let Some(mode) = &overrides.access_log_path_mode {
        args.push("--set".into());
        args.push(format!("proxy.shared.accessLogPathMode={mode}"));
    }

    let status = Command::new("helm")
        .args(&args)
        .status()
        .await
        .context("helm upgrade")?;
    anyhow::ensure!(status.success(), "helm upgrade --install failed");

    // `helm --wait` returns when the new controller pod is Ready, but for a
    // ~15 s window (the lease TTL) the OLD controller pod can still hold the
    // leader-election lease. During that window the new pod sees ingresses /
    // gateways via `InitApply` events with `is_leader=false`, so it never
    // patches their status. Once it later becomes leader, no event re-fires
    // for already-known objects — they stay un-reconciled until something
    // else mutates them. Block until the new (sole) controller pod has the
    // lease so callers can assume status writes will happen.
    wait_for_leader_ready()
        .await
        .context("controller leader handover")?;
    Ok(())
}

/// Poll the `coxswain-leader-lock` Lease until its `holderIdentity` is one of
/// the currently-running controller pods AND no extra (terminating) controller
/// pods remain. This guarantees the new leader from a rolling update has fully
/// taken over before tests proceed.
///
/// # Errors
///
/// Returns an error if handover does not complete within 60 s.
async fn wait_for_leader_ready() -> anyhow::Result<()> {
    wait_for_leader_ready_in(COXSWAIN_NAMESPACE).await
}

/// Poll `coxswain-leader-lock` in `namespace` until the sole running
/// controller pod holds the lease.
///
/// # Errors
///
/// Returns an error if handover does not complete within 60 s.
async fn wait_for_leader_ready_in(namespace: &str) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let pods_out = Command::new("kubectl")
            .args([
                "get",
                "pods",
                "-n",
                namespace,
                "-l",
                "app.kubernetes.io/component=controller",
                "-o",
                "jsonpath={.items[*].metadata.name}",
            ])
            .output()
            .await
            .context("kubectl get pods")?;
        let pods: Vec<String> = String::from_utf8_lossy(&pods_out.stdout)
            .split_whitespace()
            .map(str::to_string)
            .collect();

        let lease_out = Command::new("kubectl")
            .args([
                "get",
                "lease",
                "coxswain-leader-lock",
                "-n",
                namespace,
                "-o",
                "jsonpath={.spec.holderIdentity}",
                "--ignore-not-found",
            ])
            .output()
            .await
            .context("kubectl get lease")?;
        let holder = String::from_utf8_lossy(&lease_out.stdout)
            .trim()
            .to_string();

        if pods.len() == 1 && pods.contains(&holder) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "leader handover timeout: pods={pods:?}, holder={holder:?} (expected exactly one controller pod holding the lease)"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Split `E2E_IMAGE` (`repo:tag`) into the repository part.
fn image_repository() -> &'static str {
    E2E_IMAGE
        .rsplit_once(':')
        .map(|(repo, _)| repo)
        .unwrap_or(E2E_IMAGE)
}

/// Split `E2E_IMAGE` (`repo:tag`) into the tag part.
fn image_tag() -> &'static str {
    E2E_IMAGE
        .rsplit_once(':')
        .map(|(_, tag)| tag)
        .unwrap_or("latest")
}

/// Build the coxswain Docker image tagged `coxswain:e2e`.
///
/// Two paths depending on host OS:
///
/// - **Linux host (typical CI runner)**: uses `Dockerfile.e2e` — a 2-line
///   `COPY target/release/coxswain` over a distroless Linux base. Requires
///   the host binary to be a Linux ELF; `cargo build --release --bin
///   coxswain` on Ubuntu satisfies that. ~5 s build.
/// - **Non-Linux host (developer macOS via OrbStack)**: uses the full
///   multi-stage production `Dockerfile`. The host can't produce a Linux
///   ELF without a cross-compile toolchain, and the Mach-O the macOS
///   compiler emits crashes with "Exec format error" inside the container.
///   The production multi-stage build sidesteps this by compiling inside
///   the container itself. First build is ~5–10 min (BoringSSL is the
///   dominant cost); cached after that.
///
/// Set `COXSWAIN_E2E_SKIP_BUILD=1` to skip the build entirely when the image
/// has already been loaded into the Docker daemon (e.g. from a CI artifact).
///
/// # Errors
///
/// Returns an error if `docker build` exits non-zero, or, on Linux hosts,
/// if the coxswain binary has not been compiled yet
/// (`target/release/coxswain` is absent).
async fn build_image(root: &Path) -> anyhow::Result<()> {
    if std::env::var("COXSWAIN_E2E_SKIP_BUILD").is_ok() {
        tracing::info!("COXSWAIN_E2E_SKIP_BUILD set; skipping docker build");
        return Ok(());
    }

    let use_e2e_dockerfile = cfg!(target_os = "linux");
    let dockerfile = if use_e2e_dockerfile {
        "Dockerfile.e2e"
    } else {
        "Dockerfile"
    };

    if use_e2e_dockerfile {
        // Fail fast with a clear message if the binary hasn't been compiled yet.
        let binary = root.join("target/release/coxswain");
        anyhow::ensure!(
            binary.exists(),
            "target/release/coxswain not found — run `cargo build --release --bin coxswain` first"
        );
    }

    tracing::info!("building Docker image {E2E_IMAGE} via {dockerfile}");
    let status = Command::new("docker")
        .args(["build", "-f", dockerfile, "-t", E2E_IMAGE, "."])
        .current_dir(root)
        .status()
        .await
        .context("docker build")?;
    anyhow::ensure!(
        status.success(),
        "docker build -f {dockerfile} failed",
        dockerfile = dockerfile
    );
    Ok(())
}

/// Load the e2e image into the named kind cluster.
///
/// # Errors
///
/// Returns an error if `kind load docker-image` exits non-zero.
async fn kind_load_image(cluster_name: &str) -> anyhow::Result<()> {
    tracing::info!(cluster = %cluster_name, "loading image into kind cluster");
    let status = Command::new("kind")
        .args(["load", "docker-image", E2E_IMAGE, "--name", cluster_name])
        .status()
        .await
        .context("kind load docker-image")?;
    anyhow::ensure!(status.success(), "kind load docker-image failed");
    Ok(())
}

/// Ensure [cloud-provider-kind](https://github.com/kubernetes-sigs/cloud-provider-kind)
/// is running as a host process so LoadBalancer Services get real IPs on kind.
///
/// cloud-provider-kind must run on the Docker host — it watches the Docker socket
/// and assigns IPs from the kind Docker bridge network. An in-cluster DaemonSet
/// does NOT work because kind nodes are Docker containers that lack their own
/// Docker socket.
///
/// In CI, the `setup-kind-cluster` composite action pre-starts cloud-provider-kind
/// before the tests run, so this function only starts it when the binary is on PATH
/// and no process is already running. If neither condition is met, a warning is
/// logged and the function returns `Ok(())` — tests that need LoadBalancer IPs
/// will fail when they poll for the address.
///
/// # Errors
///
/// Returns an error if `spawn` fails after finding the binary.
async fn install_cloud_provider_kind_if_missing() -> anyhow::Result<()> {
    // Check if already running as a host process.
    let already_running = Command::new("pgrep")
        .args(["-x", "cloud-provider-kind"])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);

    if already_running {
        return Ok(());
    }

    // Try to locate the binary on PATH.
    let which = Command::new("which")
        .arg("cloud-provider-kind")
        .output()
        .await;

    let binary = match which {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => {
            tracing::warn!(
                "cloud-provider-kind not found on PATH; LoadBalancer Services may not \
                 receive IPs — install with: go install sigs.k8s.io/cloud-provider-kind@latest"
            );
            return Ok(());
        }
    };

    tracing::info!(%binary, "starting cloud-provider-kind for LoadBalancer support on kind");
    // Spawn detached — the child outlives the test binary and is reparented to
    // init when the test process exits. stdout/stderr are suppressed to avoid
    // polluting the test output.
    Command::new(&binary)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawn cloud-provider-kind")?;

    // Poll until the spawned process is actually running rather than blind-
    // sleeping: `pgrep` only matches once the child is up, so this both confirms
    // registration and surfaces an immediate startup crash as a timeout. (We
    // returned early above if one was already running, so any match here is ours.)
    crate::harness::wait::poll_until(
        std::time::Duration::from_secs(10),
        crate::harness::wait::POLL_FAST,
        || async { "cloud-provider-kind process to start".to_string() },
        || async {
            Command::new("pgrep")
                .args(["-x", "cloud-provider-kind"])
                .status()
                .await
                .ok()
                .filter(|s| s.success())
                .map(|_| ())
        },
    )
    .await?;
    Ok(())
}

/// Install cert-manager v1.18.0 if not already present, then ensure the
/// `coxswain-e2e-selfsigned` ClusterIssuer exists. Both steps are idempotent
/// via `kubectl apply`.
async fn install_cert_manager_if_missing() -> anyhow::Result<()> {
    if !cert_manager_installed().await {
        tracing::info!("cert-manager not found, installing v1.18.0");
        kubectl_apply_url(
            "https://github.com/cert-manager/cert-manager/releases/download/v1.18.0/cert-manager.yaml",
        )
        .await
        .context("install cert-manager")?;

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

    // Always apply the ClusterIssuer — idempotent. Retried with backoff because
    // cert-manager's validating admission webhook can return transient errors
    // for ~10–30 s after the Deployment goes Ready (the apiserver needs to
    // observe the CA bundle injected by cainjector before webhook calls
    // succeed). A single apply will fail intermittently on freshly-installed
    // cert-manager; retrying makes the bootstrap deterministic.
    let issuer_yaml = r#"
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: coxswain-e2e-selfsigned
spec:
  selfSigned: {}
"#;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut backoff = std::time::Duration::from_secs(1);
    loop {
        let mut child = tokio::process::Command::new("kubectl")
            .args(["apply", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("kubectl apply ClusterIssuer")?;
        if let Some(stdin) = child.stdin.as_mut() {
            tokio::io::AsyncWriteExt::write_all(stdin, issuer_yaml.as_bytes())
                .await
                .context("write ClusterIssuer yaml")?;
        }
        drop(child.stdin.take());
        let output = child
            .wait_with_output()
            .await
            .context("kubectl apply ClusterIssuer wait")?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("kubectl apply ClusterIssuer failed after 60s: {stderr}");
        }
        tracing::debug!(
            retry_in_s = backoff.as_secs(),
            "ClusterIssuer apply transient failure, retrying: {stderr}"
        );
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(5));
    }
}

/// Returns `true` if cert-manager CRDs are present at v1.
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

/// Returns `true` only if `ReferenceGrant` is served at v1 (Gateway API >= v1.0.0).
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

async fn kubectl_apply_url(url: &str) -> anyhow::Result<()> {
    let status = Command::new("kubectl")
        .args(["apply", "-f", url])
        .status()
        .await
        .context("kubectl")?;
    anyhow::ensure!(status.success(), "kubectl apply -f {url} failed");
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
