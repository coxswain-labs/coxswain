//! Leader pod label management for the discovery stream Service (#531).
//!
//! The discovery stream Service (`coxswain-controller-discovery`) selects on
//! [`DISCOVERY_LEADER_LABEL`] so its endpoints are exactly the current leader
//! pod — proxy dials deterministically reach the leader instead of round-
//! robining across standbys. A dedicated task drives [`LeaderLabel::ensure`] on
//! every leadership flip, retries on failure, and re-affirms periodically while
//! leading (so a stripped label heals without a flip — see [`run`]):
//!
//! - **promotion** — label own pod, strip any stale copy from other pods (a
//!   crashed ex-leader whose pod object survived cannot un-label itself);
//! - **demotion / step-down / startup** — remove own label (a crash-restarted
//!   container comes back as standby and must not attract streams).
//!
//! Label propagation into Service endpoints is asynchronous, so this is the
//! *routing* layer only; correctness is guaranteed by the discovery server's
//! not-leader stream rejection (the proxy fast-retries the rare stale dial).

use std::time::Duration;

use k8s_openapi::api::core::v1::Pod;
use kube::Client;
use kube::api::{Api, ListParams, Patch, PatchParams};
use tokio::sync::watch;

/// Retry cadence for a failed label convergence.
const RETRY: Duration = Duration::from_secs(5);

/// Re-affirm cadence for a *converged* label. Even after a clean convergence the
/// leader re-asserts its label state periodically so external tampering heals
/// without a leadership flip — see the dual-leader race note on [`run`].
const REAFFIRM: Duration = Duration::from_secs(15);

/// Drive label convergence off the leadership watch, decoupled from the lease
/// renewal loop (#531): label I/O (an own-pod PATCH, plus a LIST + strip
/// PATCHes on promotion) must never delay the next renew attempt — a stalled
/// apiserver would otherwise erode the renew-before-TTL fencing margin.
///
/// Converges on every leadership flip, retries every [`RETRY`] while unconverged,
/// and re-affirms every [`REAFFIRM`] while converged. The periodic re-affirm is
/// load-bearing, not belt-and-braces: at startup both replicas can briefly
/// co-acquire the lease, and the transient co-leader's [`LeaderLabel::ensure`]`(true)`
/// runs [`LeaderLabel::strip_others`], removing the *real* leader's label **after**
/// the real leader's own one-shot convergence. The real leader's watch value
/// never changes again (it stays leader), so without re-affirming it would never
/// restore its label and the discovery Service would stay endpoint-less until a
/// pod restart. `ensure` is idempotent, so re-affirming is cheap and self-healing.
/// Exits when the sender (the lease loop) is dropped.
pub(crate) async fn run(mut label: LeaderLabel, mut rx: watch::Receiver<bool>) {
    loop {
        let leading = *rx.borrow_and_update();
        let converged = label.ensure(leading).await;
        // Wake on either a leadership flip or the timer, then re-run `ensure`.
        // A converged leader re-affirms on the slower cadence; an unconverged
        // pass retries faster.
        let wait = if converged { REAFFIRM } else { RETRY };
        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// Pod label carried by the current leader; the discovery stream Service
/// selects on `discovery.coxswain-labs.dev/leader: "true"`.
pub(crate) const DISCOVERY_LEADER_LABEL: &str = "discovery.coxswain-labs.dev/leader";

/// Namespaced handle that converges the leader label onto the lease holder.
pub(crate) struct LeaderLabel {
    pods: Api<Pod>,
    pod_name: String,
    /// Set when the own-pod patch 404s: the process is not running as a Pod
    /// (local dev against a remote cluster). Labeling is permanently disabled
    /// for the process lifetime; the not-leader rejection still gates streams.
    disabled: bool,
}

impl LeaderLabel {
    pub(crate) fn new(client: Client, namespace: &str, pod_name: String) -> Self {
        Self {
            pods: Api::namespaced(client, namespace),
            pod_name,
            disabled: false,
        }
    }

    /// Converge the label to `leading`. Returns `true` when converged (or
    /// permanently disabled); `false` when an API call failed and the caller
    /// should retry on its next renewal tick.
    pub(crate) async fn ensure(&mut self, leading: bool) -> bool {
        if self.disabled {
            return true;
        }
        let own_ok = self.set_own_label(leading).await;
        let others_ok = if leading {
            self.strip_others().await
        } else {
            true
        };
        own_ok && others_ok
    }

    /// Add (`leading`) or remove (`!leading`) the label on this replica's pod.
    async fn set_own_label(&mut self, leading: bool) -> bool {
        let value = if leading {
            serde_json::json!("true")
        } else {
            serde_json::Value::Null
        };
        let patch = serde_json::json!({
            "metadata": { "labels": { DISCOVERY_LEADER_LABEL: value } }
        });
        match self
            .pods
            .patch(
                &self.pod_name,
                &PatchParams::default(),
                &Patch::Merge(&patch),
            )
            .await
        {
            Ok(_) => true,
            Err(kube::Error::Api(e)) if e.code == 404 => {
                tracing::info!(
                    pod = %self.pod_name,
                    "own pod not found; not running as a Pod — disabling discovery leader labeling \
                     (the not-leader stream rejection still gates standbys)"
                );
                self.disabled = true;
                true
            }
            Err(e) => {
                tracing::warn!(
                    pod = %self.pod_name,
                    leading,
                    error = %e,
                    "failed to update discovery leader label; will retry on the next renewal tick"
                );
                false
            }
        }
    }

    /// Remove stale leader labels from every *other* pod in the namespace.
    ///
    /// Heals the crashed-ex-leader case: the pod object survives a container
    /// crash with its label intact, and only the new leader can clear it.
    async fn strip_others(&self) -> bool {
        let lp = ListParams::default().labels(&format!("{DISCOVERY_LEADER_LABEL}=true"));
        let labeled = match self.pods.list(&lp).await {
            Ok(list) => list,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to list pods carrying the discovery leader label; will retry"
                );
                return false;
            }
        };
        let mut ok = true;
        for pod in labeled {
            let name = pod.metadata.name.as_deref().unwrap_or_default();
            if name.is_empty() || name == self.pod_name {
                continue;
            }
            let patch = serde_json::json!({
                "metadata": { "labels": { DISCOVERY_LEADER_LABEL: serde_json::Value::Null } }
            });
            if let Err(e) = self
                .pods
                .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
                .await
            {
                tracing::warn!(
                    stale_pod = %name,
                    error = %e,
                    "failed to strip a stale discovery leader label; will retry"
                );
                ok = false;
            } else {
                tracing::info!(
                    stale_pod = %name,
                    "stripped stale discovery leader label from ex-leader pod"
                );
            }
        }
        ok
    }
}
