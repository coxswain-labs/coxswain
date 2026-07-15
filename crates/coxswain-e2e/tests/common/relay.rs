#![allow(missing_docs)]
//! Relay-tier (#583/#585) data-plane assertion helpers.
//!
//! Since #601 a relay-fronted leaf is a controller-**provisioned** dedicated
//! proxy (the controller delivers its upstream at bootstrap and repoints it live),
//! so the relay-tier e2e no longer hand-builds a relay + a pinned leaf — it drives
//! the real provisioning path (see `discovery.rs`). What survives here is the
//! last-good continuity assertion these tests share.

use std::time::Duration;

use anyhow::Context as _;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ListParams};

use coxswain_e2e::harness::wait;

/// Assert that at least one pod matching `label_selector` in `ns` **stays**
/// `Ready=True` for the whole `window` — the last-good invariant under an
/// upstream outage. Polls every [`wait::POLL`]; the first check fires at t=0.
///
/// # Errors
///
/// Returns an error if no matching pod is Ready at any poll during the window
/// (a flip to NotReady, or the pod vanishing).
pub async fn assert_pod_stays_ready(
    client: &kube::Client,
    ns: &str,
    label_selector: &str,
    window: Duration,
) -> anyhow::Result<()> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), ns);
    let deadline = tokio::time::Instant::now() + window;
    let mut tick = tokio::time::interval(wait::POLL);
    loop {
        tick.tick().await;
        let list = pods
            .list(&ListParams::default().labels(label_selector))
            .await
            .with_context(|| format!("listing pods '{label_selector}' in '{ns}'"))?;
        let ready = list.items.iter().any(pod_is_ready);
        anyhow::ensure!(
            ready,
            "expected a pod matching '{label_selector}' in '{ns}' to stay Ready=True \
             for the whole last-good window, but none was Ready at this poll"
        );
        if tokio::time::Instant::now() >= deadline {
            return Ok(());
        }
    }
}

/// Whether the pod's `Ready` status condition is `"True"`.
fn pod_is_ready(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == "Ready"))
        .is_some_and(|c| c.status == "True")
}
