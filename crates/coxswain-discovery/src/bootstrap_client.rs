//! Proxy-side bootstrap loop: acquire an SVID from the controller via the
//! `Bootstrap` RPC and keep it refreshed before expiry.
//!
//! # Lifecycle
//!
//! Generate a process-lifetime rcgen keypair once at startup, then loop:
//!
//! 1. Read the SA token from the projected volume path.
//! 2. Read the CA bundle from the trust-bundle ConfigMap mount.
//! 3. Connect to the bootstrap endpoint with server-auth-only TLS (verifying the
//!    controller's SPIFFE cert against the CA bundle).
//! 4. Send `Bootstrap { sa_token, csr_pem, wire_version }`.
//! 5. Store the returned `{ cert_pem, key_pem, ca_bundle_pem, not_after_unix }`
//!    in a [`SharedSvid`] cell.
//! 6. Broadcast a rotation tick on the [`tokio::sync::watch`] channel so the
//!    discovery supervisor reconnects with the fresh SVID.
//! 7. Sleep until ~50 % of the SVID TTL has elapsed, then repeat.
//!
//! Failures back off with jitter (250 ms → 30 s) so a transient controller
//! outage does not saturate the bootstrap listener.  The routing cells are
//! **never zeroed**: the last-good snapshot continues to be served until a
//! fresh SVID allows the supervisor to reconnect.

use std::time::Duration;

use rcgen::{CertificateParams, KeyPair};
use tokio::sync::watch;
use tonic::transport::Endpoint;
use tracing::{debug, info, warn};

use crate::auth::{DiscoveryBootstrapClientTls, SpiffeMatcher};
use crate::proto::v1::{BootstrapRequest, discovery_client::DiscoveryClient as TonicClient};
use crate::svid::{SharedSvid, SvidMaterial};
use crate::version::WIRE_VERSION;

// ── BootstrapClientConfig ─────────────────────────────────────────────────────

/// Configuration for the proxy-side bootstrap loop.
// intentionally open: field-literal constructed by coxswain-bin
pub struct BootstrapClientConfig {
    /// Endpoint for the bootstrap gRPC service (server-auth-only TLS).
    ///
    /// Must be an `https://` URI; the controller's SPIFFE cert is verified
    /// against the CA bundle from the trust-bundle ConfigMap mount.
    pub endpoint: String,
    /// Filesystem path to the projected ServiceAccount token.
    ///
    /// Standard location: `/var/run/secrets/coxswain/discovery-token/token`.
    pub sa_token_path: String,
    /// Filesystem path to the CA bundle from the trust-bundle ConfigMap.
    ///
    /// Standard location: `/var/run/secrets/coxswain/trust-bundle/ca.crt`.
    pub ca_bundle_path: String,
    /// SPIFFE trust domain (e.g. `"cluster.local"`).
    pub trust_domain: String,
    /// Pod namespace; used to form the controller's expected SPIFFE ID.
    pub controller_namespace: String,
    /// Initial backoff duration (default: 250 ms).
    pub backoff_base: Duration,
    /// Maximum backoff ceiling (default: 30 s).
    pub backoff_cap: Duration,
}

impl BootstrapClientConfig {
    /// Construct with required fields and sensible backoff defaults.
    #[must_use]
    pub fn new(
        endpoint: impl Into<String>,
        sa_token_path: impl Into<String>,
        ca_bundle_path: impl Into<String>,
        trust_domain: impl Into<String>,
        controller_namespace: impl Into<String>,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            sa_token_path: sa_token_path.into(),
            ca_bundle_path: ca_bundle_path.into(),
            trust_domain: trust_domain.into(),
            controller_namespace: controller_namespace.into(),
            backoff_base: Duration::from_millis(250),
            backoff_cap: Duration::from_secs(30),
        }
    }
}

// ── BootstrapClientHandle ─────────────────────────────────────────────────────

/// Handle returned by [`BootstrapClient::spawn`].
#[non_exhaustive]
pub struct BootstrapClientHandle {
    /// The latest SVID, or `None` until the first successful bootstrap.
    pub svid: SharedSvid,
    /// Receives a new generation counter each time the SVID is refreshed.
    pub rotation_rx: watch::Receiver<u64>,
}

// ── BootstrapRunner ───────────────────────────────────────────────────────────

/// The (not-yet-running) bootstrap loop returned by [`BootstrapClient::new`].
///
/// Drive it by awaiting [`BootstrapRunner::run`] — typically from a Pingora
/// background service so it runs on a Pingora runtime. `run` never returns under
/// normal operation (it loops across SVID refreshes for the process lifetime).
#[non_exhaustive]
pub struct BootstrapRunner {
    config: BootstrapClientConfig,
    svid_cell: SharedSvid,
    rotation_tx: watch::Sender<u64>,
}

impl BootstrapRunner {
    /// Run the bootstrap/refresh loop until the process exits.
    pub async fn run(self) {
        run_bootstrap(self.config, self.svid_cell, self.rotation_tx).await;
    }
}

// ── BootstrapClient ───────────────────────────────────────────────────────────

/// Proxy-side bootstrap loop. Zero-sized namespace for the `build`/`spawn`
/// constructors; never instantiated as a value.
#[non_exhaustive]
pub struct BootstrapClient;

impl BootstrapClient {
    /// Build the SVID cell + rotation channel and the (not-yet-running)
    /// [`BootstrapRunner`], without spawning a task.
    ///
    /// Use this when the caller is **not** already inside a Tokio runtime (the
    /// synchronous `coxswain-bin` startup path): wire the returned handle's
    /// `svid` cell into the discovery client config, then drive the
    /// [`BootstrapRunner`] from a Pingora background service. Use
    /// [`BootstrapClient::spawn`] when a runtime is already active.
    ///
    /// The handle's `svid` cell is `None` until the first successful bootstrap.
    #[must_use]
    pub fn build(config: BootstrapClientConfig) -> (BootstrapClientHandle, BootstrapRunner) {
        let svid = SharedSvid::new();
        let (rotation_tx, rotation_rx) = watch::channel(0u64);

        let handle = BootstrapClientHandle {
            svid: svid.clone(),
            rotation_rx,
        };
        let runner = BootstrapRunner {
            config,
            svid_cell: svid,
            rotation_tx,
        };
        (handle, runner)
    }

    /// Spawn the bootstrap loop and return a handle to the SVID cell.
    ///
    /// Convenience wrapper over [`BootstrapClient::new`] that immediately
    /// `tokio::spawn`s the loop — **requires an active Tokio runtime**.
    #[must_use]
    pub fn spawn(
        config: BootstrapClientConfig,
    ) -> (BootstrapClientHandle, tokio::task::JoinHandle<()>) {
        let (handle, runner) = Self::build(config);
        let task = tokio::spawn(runner.run());
        (handle, task)
    }
}

// ── private: bootstrap loop ───────────────────────────────────────────────────

async fn run_bootstrap(
    config: BootstrapClientConfig,
    svid_cell: SharedSvid,
    rotation_tx: watch::Sender<u64>,
) {
    // Generate a process-lifetime keypair. This keypair is reused across every
    // bootstrap call; only the cert changes (signed by the controller CA).
    let keypair = match KeyPair::generate() {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "bootstrap: failed to generate process keypair; loop will not start");
            return;
        }
    };

    let mut generation: u64 = 0;
    let mut attempt: u32 = 0;
    let mut refresh_after = Duration::ZERO; // first iteration fires immediately

    loop {
        tokio::time::sleep(refresh_after).await;

        let not_after = match do_bootstrap(&config, &keypair).await {
            Ok((material, not_after_unix)) => {
                generation = generation.saturating_add(1);
                svid_cell.store(std::sync::Arc::new(Some(material)));
                // Ignore send errors: if all receivers are gone, this task is orphaned.
                let _ = rotation_tx.send(generation);
                attempt = 0;
                not_after_unix
            }
            Err(()) => {
                attempt = attempt.saturating_add(1);
                let delay = backoff_jitter(attempt, config.backoff_base, config.backoff_cap);
                warn!(
                    attempt,
                    delay_ms = delay.as_millis(),
                    "bootstrap: retrying after backoff"
                );
                refresh_after = delay;
                continue;
            }
        };

        // Refresh at ~50% of the remaining TTL.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let remaining_secs = (not_after - now_unix).max(0) as u64;
        refresh_after = Duration::from_secs(remaining_secs / 2).max(Duration::from_secs(1));

        debug!(
            generation,
            not_after,
            refresh_in_secs = refresh_after.as_secs(),
            "bootstrap: SVID issued; scheduled refresh"
        );
    }
}

async fn do_bootstrap(
    config: &BootstrapClientConfig,
    keypair: &KeyPair,
) -> Result<(SvidMaterial, i64), ()> {
    // Read SA token.
    let sa_token = match tokio::fs::read_to_string(&config.sa_token_path).await {
        Ok(t) => t.trim().to_owned(),
        Err(e) => {
            warn!(error = %e, path = %config.sa_token_path, "bootstrap: failed to read SA token");
            return Err(());
        }
    };

    // Read CA bundle.
    let ca_bundle_pem = match tokio::fs::read(&config.ca_bundle_path).await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, path = %config.ca_bundle_path, "bootstrap: failed to read CA bundle");
            return Err(());
        }
    };

    // Generate a CSR from the process-lifetime keypair.
    let csr_pem = match build_csr(keypair) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "bootstrap: failed to generate CSR");
            return Err(());
        }
    };

    // Expected controller SPIFFE ID:
    // spiffe://<trust-domain>/ns/<controller-ns>/sa/coxswain-controller
    let expected_server = SpiffeMatcher::Exact(format!(
        "spiffe://{}/ns/{}/sa/coxswain-controller",
        config.trust_domain, config.controller_namespace
    ));

    let bootstrap_tls = DiscoveryBootstrapClientTls {
        server_ca_pem: ca_bundle_pem.clone(),
        expected_server,
    };

    let ep = Endpoint::from_shared(config.endpoint.clone())
        .map_err(|e| {
            warn!(error = %e, "bootstrap: invalid endpoint URI");
        })?
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_timeout(Duration::from_secs(5))
        .keep_alive_while_idle(true);

    let ep = bootstrap_tls.apply(ep).map_err(|e| {
        warn!(error = %e, "bootstrap: failed to configure TLS");
    })?;

    let channel = ep.connect_lazy();
    let mut grpc = TonicClient::new(channel);

    let req = BootstrapRequest {
        sa_token: sa_token.clone(),
        csr_pem: csr_pem.clone(),
        wire_version: WIRE_VERSION,
    };

    let resp = match grpc.bootstrap(tonic::Request::new(req)).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            warn!(error = %e, "bootstrap: RPC failed");
            return Err(());
        }
    };

    info!(
        not_after = resp.not_after_unix,
        "bootstrap: SVID issued by controller"
    );

    let key_pem = keypair.serialize_pem().into_bytes();

    let material = SvidMaterial {
        cert_pem: resp.svid_cert_pem,
        key_pem,
        ca_bundle_pem,
        not_after_unix: resp.not_after_unix,
    };

    Ok((material, resp.not_after_unix))
}

/// Build a minimal CSR PEM from the process-lifetime keypair.
fn build_csr(keypair: &KeyPair) -> Result<Vec<u8>, String> {
    let params = CertificateParams::new(vec![]).map_err(|e| e.to_string())?;
    let csr = params
        .serialize_request(keypair)
        .map_err(|e| e.to_string())?;
    csr.pem().map(|p| p.into_bytes()).map_err(|e| e.to_string())
}

/// Full-jitter exponential backoff (same algorithm as the discovery supervisor).
fn backoff_jitter(attempt: u32, base: Duration, cap: Duration) -> Duration {
    let base_ms = base.as_millis() as u64;
    let cap_ms = cap.as_millis() as u64;
    let ceiling = cap_ms.min(base_ms.saturating_mul(1u64 << attempt.min(7)));
    if ceiling == 0 {
        return Duration::ZERO;
    }
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    let ms = splitmix64(seq ^ nanos) % (ceiling + 1);
    Duration::from_millis(ms)
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}
