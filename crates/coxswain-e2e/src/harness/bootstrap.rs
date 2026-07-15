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
/// To bump: change `.gateway-api-version` at the repo root, then regenerate
/// `gateway-api-types` with `cargo run -p xtask -- gateway-api-types`
/// (#510) — that's the whole loop; there's no second version string to keep
/// in sync (`gateway-api-types` is an in-workspace crate, not an external
/// dependency pinned separately in `Cargo.toml`).
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
/// Port pre-declared in the gateway Service for TLS-passthrough listeners (TLSRoute, GEP-2643).
pub const GATEWAY_TLS_PASSTHROUGH_PORT: u16 = 8444;
/// Port pre-declared in the gateway Service for raw TCP-proxy listeners (TCPRoute, GEP-1901, #505).
pub const GATEWAY_TCP_PROXY_PORT: u16 = 8445;
/// Port pre-declared in the gateway Service for UDP-proxy listeners (UDPRoute, GEP-2645, #506).
pub const GATEWAY_UDP_PROXY_PORT: u16 = 8446;

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

    /// Service type for the per-Gateway shared-mode VIPs (#472), chosen by
    /// reachability from the host the test process runs on.
    ///
    /// - **kind** (CI): `LoadBalancer`. cloud-provider-kind assigns each
    ///   LoadBalancer Service a distinct, host-reachable IP, so per-Gateway VIPs
    ///   sharing an advertised port (e.g. `443`) never collide. ClusterIPs
    ///   (`10.96.0.0/12`) are NOT routable from the kind host, so a ClusterIP VIP
    ///   would make every Gateway test time out.
    /// - **OrbStack** (local): `ClusterIP`. OrbStack's klipper-lb host-binds each
    ///   LoadBalancer Service's port, so two VIPs sharing a port stay `<pending>`
    ///   forever — but OrbStack routes ClusterIPs straight to the host, so a
    ///   distinct in-cluster VIP per Gateway is reachable and collision-free.
    pub(crate) fn vip_service_type(&self) -> &'static str {
        match self {
            Self::Kind { .. } => "LoadBalancer",
            Self::Orbstack => "ClusterIP",
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
    // Process-global, idempotent test-process setup. `bootstrap` is the one
    // entry every test reaches — directly or via `Harness::start` — so the
    // crypto provider and the tracing subscriber are installed here once per
    // process rather than re-stated in each test. Both `try`/`let _ =` forms
    // no-op if already installed (e.g. under `cargo test`, where the suite
    // shares one process). Placed before the early-return so CI test processes
    // (which set `COXSWAIN_E2E_BOOTSTRAPPED`) still get logging.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("coxswain_e2e=debug,warn")
        .try_init();
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
    /// Passed as `discovery.svidTtl` (#423). A short value (e.g. `"10s"`) makes
    /// the proxy bootstrap loop refresh its SVID quickly so a test can observe a
    /// rotation cycle without waiting the 24 h default. `None` leaves the chart
    /// default.
    pub discovery_svid_ttl: Option<String>,
    /// Passed as `controller.gatewayApi.enabled`. `None` leaves the chart
    /// default (`true`). Use `Some(false)` to test Ingress-only installs.
    pub gateway_api_enabled: Option<bool>,
    /// Passed as `controller.ingress.enabled`. `None` leaves the chart
    /// default (`true`). Use `Some(false)` to test Gateway-API-only installs.
    pub ingress_enabled: Option<bool>,
    /// Passed as `relay.dedicated.enabled` (#584): enables controller-provisioned
    /// namespace relays. `false` leaves the chart default (off).
    pub relay_dedicated_enabled: bool,
    /// Passed as `relay.dedicated.minProxyReplicas` (#584): the break-even relay
    /// provisioning threshold. `None` leaves the chart default (8).
    pub relay_min_proxy_replicas: Option<u32>,
    /// Passed as `watchNamespace` (#59): the controller's namespaced watch scope.
    /// A comma-separated list (`ns1,ns2`) scopes the controller to those
    /// namespaces. `None` leaves the chart default (cluster-wide).
    pub watch_namespace: Option<String>,
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
    // Runtime enforcement of the mutator-serialization invariant, at the
    // mutation site (defends every call path — test body, harness helper, or
    // future wrapper — where the static gate `check-e2e-mutators-serialized.sh`
    // only sees literals it can grep). A non-default override reconfigures the
    // ONE shared release and rolls the proxy; running that in the PARALLEL `e2e`
    // pass corrupts every concurrent test (the security-suite "cliff", #529).
    // The serial pass exports COXSWAIN_E2E_SERIAL=1 (see .config/nextest.toml);
    // its absence under a nextest test process means this mutator escaped the
    // serial pass. Fail THIS test loudly and immediately rather than 20 tests
    // downstream. Scoped to nextest (`NEXTEST` env) so conformance/other tooling
    // that legitimately overrides values outside the parallel pass is unaffected.
    if *overrides != HelmOverrides::default()
        && std::env::var_os("NEXTEST").is_some()
        && std::env::var("COXSWAIN_E2E_SERIAL").as_deref() != Ok("1")
    {
        panic!(
            "global-config mutator (non-default HelmOverrides) ran outside the serial \
             e2e pass — it rolls the shared proxy and corrupts concurrent tests. Move \
             the test to the e2e-serial profile (see .config/nextest.toml and \
             scripts/check-e2e-mutators-serialized.sh)."
        );
    }
    let chart = root.join("charts/coxswain");
    // Per-Gateway shared-mode VIP Service type (#472) is reachability-dependent on
    // the cluster distribution — LoadBalancer on kind/CI, ClusterIP on OrbStack.
    let vip_service_type = ClusterKind::detect()
        .await
        .context("detect cluster kind for VIP service type")?
        .vip_service_type();
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
        // Per-Gateway shared-mode VIP Service type (#472), reachability-selected
        // per cluster distribution — see `ClusterKind::vip_service_type`.
        "--set".into(),
        format!("proxy.shared.vipServiceType={vip_service_type}"),
        "--set".into(),
        format!("controller.coxswainImage={E2E_IMAGE}"),
        // E2E-only rollout acceleration (#570 follow-up). The production
        // defaults (5s/10s readiness probe, 15s/5s lease) put a ~57s floor
        // under every helm mutation — and under the restore the NEXT
        // default-options test pays — measured as three mutation+restore
        // pairs costing ~350s of the status_conditions serial pass alone
        // (2-replica controller rolls serially at probe cadence, then
        // wait_for_leader_ready sits out the lease handover). Faster probes
        // bound pod-Ready detection at ~3s and the short lease bounds
        // handover at one renew tick after the old leader's step-down
        // (2s × 3 ≤ 6s satisfies the controller's lease-ratio validation).
        // Production values.yaml is untouched; resilience tests poll real
        // post-conditions, not lease timings.
        "--set".into(),
        "readinessProbe.initialDelaySeconds=1".into(),
        "--set".into(),
        "readinessProbe.periodSeconds=2".into(),
        "--set".into(),
        "controller.leaseTtl=6s".into(),
        "--set".into(),
        "controller.leaseRenewInterval=2s".into(),
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
    if let Some(ttl) = &overrides.discovery_svid_ttl {
        args.push("--set".into());
        args.push(format!("discovery.svidTtl={ttl}"));
    }
    if let Some(ns) = &overrides.watch_namespace {
        args.push("--set".into());
        // Escape commas so Helm passes the whole namespace list as one string
        // value instead of splitting it into a list (#59 multi-namespace watch).
        args.push(format!("watchNamespace={}", ns.replace(',', "\\,")));
    }
    if let Some(enabled) = overrides.gateway_api_enabled {
        args.push("--set".into());
        args.push(format!("controller.gatewayApi.enabled={enabled}"));
    }
    if let Some(enabled) = overrides.ingress_enabled {
        args.push("--set".into());
        args.push(format!("controller.ingress.enabled={enabled}"));
    }
    if overrides.relay_dedicated_enabled {
        args.push("--set".into());
        args.push("relay.dedicated.enabled=true".into());
    }
    if let Some(min) = overrides.relay_min_proxy_replicas {
        args.push("--set".into());
        args.push(format!("relay.dedicated.minProxyReplicas={min}"));
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

/// Helm-values paths only a non-default [`HelmOverrides`] can set. Returns the
/// paths present in `values` (helm's user-supplied values as JSON) — i.e. the
/// evidence that a global-config mutator's configuration is still deployed.
///
/// Drift guard: the destructure below makes adding a field to [`HelmOverrides`]
/// (and its `--set` arm in [`helm_install`]) a COMPILE error here until a
/// matching dirty-path check is added. Without it the three sites — the struct,
/// the `--set` arms, and this function — drift silently and a leaked override
/// escapes leak detection, reintroducing the security-suite "cliff".
fn dirty_override_paths(values: &serde_json::Value) -> Vec<String> {
    let HelmOverrides {
        status_address: _,
        ingress_default_backend: _,
        accept_proxy_protocol: _,
        trusted_sources: _,
        access_log: _,
        access_log_path_mode: _,
        discovery_svid_ttl: _,
        gateway_api_enabled: _,
        ingress_enabled: _,
        relay_dedicated_enabled: _,
        relay_min_proxy_replicas: _,
        watch_namespace: _,
    } = HelmOverrides::default();
    let mut dirty = Vec::new();
    let mut check = |path: &[&str], is_dirty: bool| {
        if is_dirty {
            dirty.push(path.join("."));
        }
    };
    let get = |path: &[&str]| {
        let mut v = values;
        for seg in path {
            v = v.get(seg)?;
        }
        Some(v)
    };
    check(
        &["controller", "statusAddress"],
        get(&["controller", "statusAddress"]).is_some(),
    );
    check(
        &["proxy", "shared", "ingressDefaultBackend"],
        get(&["proxy", "shared", "ingressDefaultBackend"]).is_some(),
    );
    check(
        &["proxy", "shared", "acceptProxyProtocol"],
        get(&["proxy", "shared", "acceptProxyProtocol"]).and_then(serde_json::Value::as_bool)
            == Some(true),
    );
    check(
        &["proxy", "shared", "trustedSources"],
        get(&["proxy", "shared", "trustedSources"])
            .and_then(serde_json::Value::as_array)
            .is_some_and(|a| !a.is_empty()),
    );
    check(
        &["proxy", "shared", "accessLog"],
        get(&["proxy", "shared", "accessLog"]).is_some(),
    );
    check(
        &["proxy", "shared", "accessLogPathMode"],
        get(&["proxy", "shared", "accessLogPathMode"]).is_some(),
    );
    check(
        &["discovery", "svidTtl"],
        get(&["discovery", "svidTtl"]).is_some(),
    );
    check(
        &["controller", "gatewayApi", "enabled"],
        get(&["controller", "gatewayApi", "enabled"]).is_some(),
    );
    check(
        &["controller", "ingress", "enabled"],
        get(&["controller", "ingress", "enabled"]).is_some(),
    );
    check(
        &["relay", "dedicated", "enabled"],
        get(&["relay", "dedicated", "enabled"]).and_then(serde_json::Value::as_bool) == Some(true),
    );
    check(
        &["relay", "dedicated", "minProxyReplicas"],
        get(&["relay", "dedicated", "minProxyReplicas"]).is_some(),
    );
    check(&["watchNamespace"], get(&["watchNamespace"]).is_some());
    dirty
}

/// Read the deployed release's user-supplied Helm values as JSON.
async fn deployed_values() -> anyhow::Result<serde_json::Value> {
    let out = Command::new("helm")
        .args([
            "get",
            "values",
            HELM_RELEASE,
            "--namespace",
            COXSWAIN_NAMESPACE,
            "--output",
            "json",
        ])
        .output()
        .await
        .context("helm get values")?;
    anyhow::ensure!(
        out.status.success(),
        "helm get values failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).context("parse helm values JSON")
}

/// Reclaim a restore lock only if this process still owns it (its PID is still
/// the file's content), then remove it. A lock stolen as stale by another
/// waiter must NOT be deleted by the original owner's `Drop`, or a third waiter
/// could be admitted concurrently. Best-effort on every drop path.
struct RestoreLock {
    path: PathBuf,
    pid: u32,
}
impl Drop for RestoreLock {
    fn drop(&mut self) {
        if std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            == Some(self.pid)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Longer than any legitimate holder's critical section (helm get values +
/// `helm upgrade --wait` ≤120 s + `wait_for_leader_ready` ≤60 s ≈ 185 s), so a
/// live holder is never reclaimed as stale; a crashed holder is reclaimable
/// after this.
const RESTORE_LOCK_STALE: std::time::Duration = std::time::Duration::from_secs(240);
/// Strictly greater than [`RESTORE_LOCK_STALE`] so a waiter blocked on a crashed
/// holder's lock reaches the stale-reclaim path instead of failing first.
const RESTORE_LOCK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(360);

/// Guarantee the shared release runs with DEFAULT configuration before a
/// default-options test proceeds.
///
/// A global-config mutator (serial pass) leaves its `helm upgrade` deployed
/// when it finishes — nothing restores defaults. Any later default-options
/// test would then run against a proxy in e.g. PROXY-protocol-required mode
/// and fail with opaque 60–90 s connection-reset timeouts (the security-suite
/// "cliff"). This makes the harness self-healing and the failure mode
/// self-diagnosing: detect the leaked overrides by inspecting the deployed
/// values, log exactly which keys leaked, and restore defaults.
///
/// Concurrency: parallel-pass tests may all detect the same leak at once, and
/// concurrent `helm upgrade`s on one release fail with "another operation in
/// progress". A PID-stamped cross-process lock file serializes the restore;
/// waiters block on it and re-check the values after the holder finishes.
/// The fast "already clean" return is gated on the lock being ABSENT: while a
/// restore is in flight helm has already recorded the new (clean-looking)
/// user-values but the proxy Deployment is still rolling, so a test that saw
/// "clean" and skipped the lock would drive traffic mid-rollout — the exact
/// flake this exists to prevent. Rendezvousing on the lock makes the waiter
/// return only after the holder's `helm upgrade --wait` + leader handover.
///
/// # Errors
///
/// Returns an error if Helm cannot be queried/upgraded or the lock cannot be
/// acquired within the deadline.
pub(crate) async fn ensure_default_release(root: &Path) -> anyhow::Result<()> {
    let lock_path = std::env::temp_dir().join("coxswain-e2e-helm-restore.lock");

    // Fast path: truly clean AND no restore in flight. The lock-absent check
    // closes the mid-rollout window (see doc above).
    if !lock_path.exists() && dirty_override_paths(&deployed_values().await?).is_empty() {
        return Ok(());
    }

    // Cross-process lock (nextest runs one process per test). PID-stamped so a
    // stolen-then-reclaimed lock is never deleted by its original owner.
    let pid = std::process::id();
    let deadline = std::time::Instant::now() + RESTORE_LOCK_DEADLINE;
    let _lock = loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(mut f) => {
                use std::io::Write as _;
                let _ = write!(f, "{pid}");
                break RestoreLock {
                    path: lock_path.clone(),
                    pid,
                };
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Stale-lock recovery: a killed test process cannot clean up.
                if let Ok(meta) = std::fs::metadata(&lock_path)
                    && let Ok(modified) = meta.modified()
                    && modified.elapsed().unwrap_or_default() > RESTORE_LOCK_STALE
                {
                    let _ = std::fs::remove_file(&lock_path);
                    continue;
                }
                anyhow::ensure!(
                    std::time::Instant::now() < deadline,
                    "timed out waiting for another test's helm restore \
                     (lock {lock_path:?})"
                );
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e).context("create helm restore lock"),
        }
    };

    // Re-check under the lock: another process may have restored while we
    // waited (its `helm upgrade --wait` + leader handover already completed, so
    // the release is fully rolled out, not merely recorded).
    let dirty = dirty_override_paths(&deployed_values().await?);
    if dirty.is_empty() {
        return Ok(());
    }
    tracing::warn!(
        leaked = %dirty.join(", "),
        "shared Helm release has non-default config leaked by a global-config \
         mutator test; restoring defaults (see scripts/check-e2e-mutators-serialized.sh)"
    );
    helm_install(root, &HelmOverrides::default())
        .await
        .context("helm restore to default values")
}

/// Poll the `coxswain-leader-lock` Lease until its `holderIdentity` is one of
/// the currently-running controller pods, the controller Deployment's rollout
/// has fully settled (no extra terminating pods surviving a rolling update),
/// and exactly one pod holds the lease. This guarantees the new leader from a
/// rolling update has fully taken over before tests proceed.
///
/// The HA default runs the controller at `replicas: 2`, so the settle signal
/// is the Deployment's own status (`status.replicas == status.readyReplicas ==
/// spec.replicas`) rather than a hardcoded single-pod assumption — among those
/// ready replicas, leader election elects exactly one lease holder.
///
/// # Errors
///
/// Returns an error if handover does not complete within 60 s.
async fn wait_for_leader_ready() -> anyhow::Result<()> {
    wait_for_leader_ready_in(COXSWAIN_NAMESPACE).await
}

/// Poll `coxswain-leader-lock` in `namespace` until the controller Deployment
/// rollout has settled and one of its ready pods holds the lease.
///
/// # Errors
///
/// Returns an error if handover does not complete within 60 s.
async fn wait_for_leader_ready_in(namespace: &str) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        // Deployment rollout status: desired replicas, total non-terminated
        // replicas (old + new during a rolling update), and ready replicas.
        // The rollout is settled only when all three agree — any terminating
        // old pod from a rolling update keeps `status.replicas` above desired.
        let deploy_out = Command::new("kubectl")
            .args([
                "get",
                "deploy",
                "-n",
                namespace,
                "-l",
                "app.kubernetes.io/component=controller",
                "-o",
                "jsonpath={.items[0].spec.replicas}/{.items[0].status.replicas}/{.items[0].status.readyReplicas}",
            ])
            .output()
            .await
            .context("kubectl get deploy")?;
        let deploy_status = String::from_utf8_lossy(&deploy_out.stdout);
        let mut fields = deploy_status.split('/');
        // Absent numeric status fields render empty; treat them as 0 so an
        // un-rolled-out Deployment never spuriously satisfies the predicate.
        let desired: u32 = fields.next().unwrap_or("").trim().parse().unwrap_or(0);
        let total: u32 = fields.next().unwrap_or("").trim().parse().unwrap_or(0);
        let ready: u32 = fields.next().unwrap_or("").trim().parse().unwrap_or(0);
        let settled = desired > 0 && total == desired && ready == desired;

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

        // Settled rollout (desired == total == ready pods, no terminating
        // surplus) with the lease held by one of those ready pods.
        if settled && pods.len() == desired as usize && pods.contains(&holder) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "leader handover timeout: desired={desired}, total={total}, ready={ready}, pods={pods:?}, holder={holder:?} (expected a settled controller rollout with exactly one pod holding the lease)"
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
    // Check if already running as a host process. Match with `-f` (full command
    // line): the process name `cloud-provider-kind` is 19 chars, and Linux
    // `pgrep -x` matches the 15-char-truncated `comm`, so `-x` never matches it.
    let already_running = Command::new("pgrep")
        .args(["-f", "cloud-provider-kind"])
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
    // sleeping: `pgrep -f` only matches once the child is up, so this both
    // confirms registration and surfaces an immediate startup crash as a timeout.
    // (`-f` for the same 15-char-truncation reason as the `already_running` check.)
    crate::harness::wait::poll_until(
        std::time::Duration::from_secs(10),
        crate::harness::wait::POLL_FAST,
        || async { "cloud-provider-kind process to start".to_string() },
        || async {
            Command::new("pgrep")
                .args(["-f", "cloud-provider-kind"])
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
///
/// Version source: the `v1.18.0` release tag in the install URL below. This is a
/// multi-document manifest applied by URL (not a single image), so it is pinned by
/// release tag rather than `@sha256:` — bump the tag here to upgrade. The
/// Gateway-API CRDs are likewise tag-pinned via `.gateway-api-version`
/// ([`GATEWAY_API_VERSION`]).
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

/// Gateway API CRDs the harness depends on being present at v1 before it can trust
/// [`gateway_v1_crds_installed`]'s "already installed, skip reinstall" verdict, and
/// that [`wait_for_crds_established`] blocks on before returning.
///
/// Keep this in sync with the resource kinds the reflector actually watches
/// (`crates/coxswain-reflector/src/reconciler/proxy.rs`) — a CRD missing from this
/// list is invisible to both checks, so a cluster carrying an older Gateway API CRD
/// set (missing the newest addition) is wrongly treated as fully provisioned. See
/// the `gateway_v1_crds_installed` doc comment for the incident this guards against.
const REQUIRED_GATEWAY_API_CRDS: [&str; 5] = [
    "gateways.gateway.networking.k8s.io",
    "httproutes.gateway.networking.k8s.io",
    "referencegrants.gateway.networking.k8s.io",
    "tcproutes.gateway.networking.k8s.io",
    "udproutes.gateway.networking.k8s.io",
];

/// Returns `true` only if every CRD in [`REQUIRED_GATEWAY_API_CRDS`] is served at v1.
///
/// Checking a single "has Gateway API been installed at all" indicator (historically
/// just `ReferenceGrant`) is not sufficient: a cluster can carry an older Gateway API
/// CRD set — with `ReferenceGrant` at v1 since well before this repo adopted it — while
/// missing a resource added by a *later* spec bump (`TCPRoute` landed in v1.6.0, #505).
/// That mismatch trips this check as "already installed", skips the reinstall, and
/// leaves the new resource's CRD absent — the reflector then 404s on it forever and
/// `/readyz` never turns healthy (#505 CI incident: every e2e suite timed out at the
/// Helm install step, not just the ones exercising `TCPRoute`).
async fn gateway_v1_crds_installed() -> bool {
    for crd in REQUIRED_GATEWAY_API_CRDS {
        let served_v1 = Command::new("kubectl")
            .args([
                "get",
                "crd",
                crd,
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
            .unwrap_or(false);
        if !served_v1 {
            return false;
        }
    }
    true
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
    let crd_args: Vec<String> = REQUIRED_GATEWAY_API_CRDS
        .iter()
        .map(|c| format!("crd/{c}"))
        .collect();
    let status = Command::new("kubectl")
        .args(["wait", "--for=condition=Established", "--timeout=60s"])
        .args(&crd_args)
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
