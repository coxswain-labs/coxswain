//! Leader-election introspection helpers (#531).
//!
//! The controller's HA truth-source is the `coordination.k8s.io` Lease
//! `coxswain-leader-lock` in the install namespace: `spec.holderIdentity` is
//! the leader pod's name. These helpers let e2e tests find the leader, kill it
//! deterministically, wait for a warm standby to take over, and scrape a
//! *specific* controller pod's metrics — the harness's Service-level
//! port-forwards pin an arbitrary Ready pod and are useless for asserting
//! per-replica behaviour like the leader-gated discovery stream.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::Context as _;
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::api::core::v1::Pod;
use kube::api::ListParams;
use kube::{Api, Client};

use super::controller::{free_port, start_port_forward};
use super::wait;

/// The leader-election Lease name (mirrors the controller's `LEASE_NAME`).
pub const LEASE_NAME: &str = "coxswain-leader-lock";

/// Namespace the harness installs coxswain into.
pub const SYSTEM_NAMESPACE: &str = "coxswain-system";

/// Remote admin port on controller pods, serving `/metrics` and `/api/v1`.
const CONTROLLER_ADMIN_PORT: u16 = 8082;

/// Current lease holder's pod name.
///
/// # Errors
///
/// Fails when the Lease is missing or carries no `holderIdentity` (no leader
/// elected yet).
#[must_use = "the leader pod name identifies which pod to target or kill"]
pub async fn leader_pod_name(client: &Client) -> anyhow::Result<String> {
    let api: Api<Lease> = Api::namespaced(client.clone(), SYSTEM_NAMESPACE);
    let lease = api
        .get(LEASE_NAME)
        .await
        .with_context(|| format!("get Lease {SYSTEM_NAMESPACE}/{LEASE_NAME}"))?;
    lease
        .spec
        .and_then(|s| s.holder_identity)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Lease {LEASE_NAME} has no holderIdentity (no leader)"))
}

/// Resolve the name of a live shared-proxy pod (#537).
///
/// Needed to target the controller's per-proxy routes view
/// (`fleet/proxies/{pod}/routes`) — the proxy no longer serves its own
/// `/api/v1/routes`, so tests that used to hit it directly via `admin_url`
/// now go through the controller and need a pod name to ask about. Returns
/// the first matching pod; the harness's default install runs one shared-proxy
/// replica, so there is no ambiguity to resolve.
///
/// # Errors
///
/// Fails if the pod list request errors, or if no shared-proxy pod exists.
#[must_use = "the pod name is needed to build the controller's per-proxy routes URL"]
pub async fn shared_proxy_pod_name(client: &Client) -> anyhow::Result<String> {
    let api: Api<Pod> = Api::namespaced(client.clone(), SYSTEM_NAMESPACE);
    let list = api
        .list(&ListParams::default().labels("app.kubernetes.io/component=shared-proxy"))
        .await
        .context("list shared-proxy pods")?;
    list.items
        .into_iter()
        .find_map(|p| p.metadata.name)
        .ok_or_else(|| anyhow::anyhow!("no shared-proxy pod found in {SYSTEM_NAMESPACE}"))
}

/// Wait until the Lease is held by a pod other than `old_holder` AND that pod
/// exists and reports `Ready=True`. Returns the new holder's name.
///
/// # Errors
///
/// Times out when no different Ready holder appears within `timeout`.
#[must_use = "the new leader pod name is needed for pod-targeted assertions"]
pub async fn wait_for_new_leader(
    client: &Client,
    old_holder: &str,
    timeout: Duration,
) -> anyhow::Result<String> {
    let lease_api: Api<Lease> = Api::namespaced(client.clone(), SYSTEM_NAMESPACE);
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), SYSTEM_NAMESPACE);
    wait::poll_until(
        timeout,
        wait::POLL,
        || {
            let lease_api = lease_api.clone();
            async move {
                let holder = lease_api
                    .get(LEASE_NAME)
                    .await
                    .ok()
                    .and_then(|l| l.spec.and_then(|s| s.holder_identity));
                format!("a Ready leader other than {old_holder}; current holder: {holder:?}")
            }
        },
        || {
            let lease_api = lease_api.clone();
            let pods_api = pods_api.clone();
            async move {
                let holder = lease_api
                    .get(LEASE_NAME)
                    .await
                    .ok()?
                    .spec?
                    .holder_identity
                    .filter(|h| !h.is_empty() && h != old_holder)?;
                let pod = pods_api.get(&holder).await.ok()?;
                pod_is_ready(&pod).then_some(holder)
            }
        },
    )
    .await
}

/// Per-tick ceiling on establishing the admin port-forward in
/// [`wait_for_leader_reconciled`].
///
/// [`pod_admin_forward`] polls up to 30 s for the local port to bind, which is
/// right for a one-shot caller and wrong inside a poll loop: one bad tick would
/// consume half a 60 s budget. Capping it keeps the tick cost near the poll
/// interval, so the wait actually gets the ~120 attempts its interval implies.
const FORWARD_TICK_BUDGET: Duration = Duration::from_secs(4);

/// Wait until the CURRENT Lease holder reports `leader=1` plus at least one
/// successful reconcile — the post-restart convergence gate for HA installs.
///
/// Re-resolves the holder and opens a fresh one-shot forward on every tick.
/// That per-tick cost buys the two properties a held forward cannot provide:
/// the wait survives a holder change mid-window, and it survives `kubectl
/// port-forward` wedging permanently when it dials the admin port in the
/// window where the pod is Ready but the admin listener isn't up yet (the
/// forward accepts the local connection, fails the upstream dial once, and
/// never recovers — starving the entire wait on a dead tunnel).
///
/// The per-tick forward is capped at [`FORWARD_TICK_BUDGET`]. Without that cap
/// the defence starves itself: [`pod_admin_forward`] waits up to 30 s for the
/// port to bind, so in exactly the post-outage window this gate exists for — the
/// pod Ready before its admin listener is up — a 60 s budget is two attempts
/// deep, not the ~120 the 500 ms poll interval suggests.
///
/// # Errors
///
/// Returns an error when no Ready Lease holder reports a leading, reconciled
/// state within `timeout`.
pub async fn wait_for_leader_reconciled(client: &Client, timeout: Duration) -> anyhow::Result<()> {
    let lease_api: Api<Lease> = Api::namespaced(client.clone(), SYSTEM_NAMESPACE);
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), SYSTEM_NAMESPACE);
    wait::poll_until(
        timeout,
        wait::POLL,
        || {
            let lease_api = lease_api.clone();
            let pods_api = pods_api.clone();
            async move {
                // Render what was actually observed, not just what was wanted:
                // "the leader never reconciled" and "we never managed to scrape
                // it" are different failures and the holder name alone
                // distinguished neither.
                let holder = lease_api
                    .get(LEASE_NAME)
                    .await
                    .ok()
                    .and_then(|l| l.spec.and_then(|s| s.holder_identity));
                let Some(holder) = holder.filter(|h| !h.is_empty()) else {
                    return "a Lease holder to exist; the Lease has no holder_identity".to_string();
                };
                let ready = match pods_api.get(&holder).await {
                    Ok(p) => {
                        if pod_is_ready(&p) {
                            "Ready=True"
                        } else {
                            "Ready!=True"
                        }
                    }
                    Err(_) => "<holder pod not found>",
                };
                let scrape =
                    match tokio::time::timeout(FORWARD_TICK_BUDGET, pod_admin_forward(&holder))
                        .await
                    {
                        Ok(Ok(pf)) => {
                            match reqwest::get(format!("{}/metrics", pf.base_url)).await {
                                Ok(r) => match r.text().await {
                                    Ok(body) => format!(
                                        "leader={:?} reconcile_ok_total={:?}",
                                        wait::parse_metric_value(
                                            &body,
                                            "coxswain_controller_leader"
                                        ),
                                        wait::reconcile_ok_total(&body),
                                    ),
                                    Err(e) => format!("<metrics body unreadable: {e}>"),
                                },
                                Err(e) => format!("<metrics scrape failed: {e}>"),
                            }
                        }
                        Ok(Err(e)) => format!("<admin port-forward failed: {e}>"),
                        Err(_) => format!(
                            "<admin port-forward did not bind within {FORWARD_TICK_BUDGET:?} — \
                         the admin listener is not accepting yet>"
                        ),
                    };
                format!(
                    "the current Lease holder to report leader=1 with a successful reconcile; \
                     holder={holder} ({ready}); last scrape: {scrape}"
                )
            }
        },
        || {
            let lease_api = lease_api.clone();
            let pods_api = pods_api.clone();
            async move {
                let holder = lease_api
                    .get(LEASE_NAME)
                    .await
                    .ok()?
                    .spec?
                    .holder_identity
                    .filter(|h| !h.is_empty())?;
                let pod = pods_api.get(&holder).await.ok()?;
                if !pod_is_ready(&pod) {
                    return None;
                }
                // Bounded: a tick that cannot bind costs one poll interval, not
                // half the caller's budget. See FORWARD_TICK_BUDGET.
                let pf = tokio::time::timeout(FORWARD_TICK_BUDGET, pod_admin_forward(&holder))
                    .await
                    .ok()?
                    .ok()?;
                let body = reqwest::get(format!("{}/metrics", pf.base_url))
                    .await
                    .ok()?
                    .text()
                    .await
                    .ok()?;
                let leading =
                    wait::parse_metric_value(&body, "coxswain_controller_leader") == Some(1.0);
                let reconciled = wait::reconcile_ok_total(&body).is_some_and(|v| v >= 1.0);
                (leading && reconciled).then_some(())
            }
        },
    )
    .await
}

/// Whether `pod` reports the `Ready=True` pod condition.
pub fn pod_is_ready(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .is_some_and(|conds| {
            conds
                .iter()
                .any(|c| c.type_ == "Ready" && c.status == "True")
        })
}

/// RAII port-forward to one specific controller pod's admin port.
///
/// Dropping kills the `kubectl port-forward` child. Hold ONE of these across a
/// poll loop and scrape through it — establishing a fresh forward per scrape
/// costs a kubectl subprocess plus its bind-readiness wait every tick.
pub struct PodAdminForward {
    child: tokio::process::Child,
    /// Local base URL, e.g. `http://127.0.0.1:49213`.
    pub base_url: String,
}

impl Drop for PodAdminForward {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

impl PodAdminForward {
    /// Scrape `/metrics` through this forward and return the first sample of
    /// `metric` (bare or labelled), `None` when the series is absent — which
    /// for lazily-registered gauges reads as 0.
    ///
    /// # Errors
    ///
    /// Fails when the scrape HTTP call fails (e.g. the forwarded pod died).
    #[must_use = "the scraped value is the assertion input"]
    pub async fn metric_value(&self, metric: &str) -> anyhow::Result<Option<f64>> {
        let body = reqwest::get(format!("{}/metrics", self.base_url))
            .await
            .context("GET /metrics through the pod forward")?
            .text()
            .await?;
        Ok(wait::parse_metric_value(&body, metric))
    }
}

/// Open a port-forward to `pod`'s admin port (serving `/metrics`).
///
/// # Errors
///
/// Fails when no free local port is available or the forward cannot bind
/// within the helper's internal deadline.
#[must_use = "dropping the forward closes the tunnel"]
pub async fn pod_admin_forward(pod: &str) -> anyhow::Result<PodAdminForward> {
    let local = free_port()?;
    let child = start_port_forward(
        &format!("pod/{pod}"),
        local,
        CONTROLLER_ADMIN_PORT,
        SYSTEM_NAMESPACE,
    )
    .await
    .with_context(|| format!("port-forward to pod/{pod}"))?;
    let addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), local);
    Ok(PodAdminForward {
        child,
        base_url: format!("http://{addr}"),
    })
}

/// One-shot convenience: forward to `pod`, scrape one `metric`, tear down.
/// For repeated scrapes (poll loops) hold a [`PodAdminForward`] instead.
///
/// # Errors
///
/// Fails when the forward cannot be established or the scrape HTTP call fails.
#[must_use = "the scraped value is the assertion input"]
pub async fn pod_metric_value(pod: &str, metric: &str) -> anyhow::Result<Option<f64>> {
    let pf = pod_admin_forward(pod).await?;
    pf.metric_value(metric).await
}
