//! Shared test-orchestration helpers for the dedicated-mode Gateway suite.
//!
//! The dedicated-proxy tests are classified by behavior plane across
//! `provisioning_rbac.rs`, `status_conditions.rs`, and `resilience.rs`, but they
//! share a common vocabulary: the fixture-coupled resource names, the
//! provision-then-poll setup, and the condition/address accessors. These live
//! here (DAMP test support) rather than in the library so the read-only-proxy
//! crate boundary stays clean.

use coxswain_e2e::{
    Harness, NamespaceGuard,
    fixtures::{FixtureVars, dedicated_proxy as dedicated},
    harness::wait,
};
use gateway_api::apis::standard::gateways::Gateway;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Service, ServiceAccount};
use kube::api::Api;
use std::time::Duration;
use tokio::process::Command;

/// Gateway `metadata.name` declared in the fixture — chosen to keep the
/// rendered resource name (`<gw>-<class>`) stable across test runs without
/// TESTNS substitution leaking into it. See
/// `crates/coxswain-e2e/fixtures/dedicated_proxy/dedicated_gateway.yaml`.
pub const GATEWAY_NAME: &str = "dedicated-gw";
/// Rendered resource name per GEP-1762 — `<gateway-name>-<gateway-class>`.
pub const RESOURCE_NAME: &str = "dedicated-gw-coxswain";
/// Condition type the operator writes when the dedicated pod is Ready and the
/// shared pool must stop serving the Gateway (#210).
pub const CUT_OVER_CONDITION: &str = "gateway.coxswain-labs.dev/DedicatedProxyReady";

/// `RoleBinding` name pattern: `coxswain-<gateway-namespace>-<gateway-name>`
/// (see `coxswain_controller::operator::rbac`). Constructed at runtime from
/// the test namespace.
pub fn binding_name(ns: &str) -> String {
    format!("coxswain-{ns}-{GATEWAY_NAME}")
}

/// Returns the ClusterRoleBinding name the controller creates for a
/// `from: All` listener — mirrors `cluster_binding_name` in
/// `coxswain_controller::operator::rbac`.
pub fn cluster_route_binding_name(gw_ns: &str, gw_name: &str) -> String {
    format!("coxswain-{gw_ns}-{gw_name}-cluster-wide-routes")
}

/// Apply the dedicated-mode Gateway fixture, then wait for the controller's
/// provisioning operator to land the three resources. Returns the apis
/// scoped to `ns` for follow-up assertions.
pub async fn apply_and_wait(
    h: &Harness,
    ns: &NamespaceGuard,
) -> anyhow::Result<(
    Api<Deployment>,
    Api<Service>,
    Api<ServiceAccount>,
    Deployment,
    Service,
    ServiceAccount,
)> {
    h.apply(dedicated::DEDICATED_GATEWAY, FixtureVars::new(&ns.name))
        .await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    let sas: Api<ServiceAccount> = Api::namespaced(h.client.clone(), &ns.name);

    let deploy =
        wait::wait_for_resource(&deployments, RESOURCE_NAME, Duration::from_secs(15)).await?;
    let svc = wait::wait_for_resource(&services, RESOURCE_NAME, Duration::from_secs(15)).await?;
    let sa = wait::wait_for_resource(&sas, RESOURCE_NAME, Duration::from_secs(15)).await?;

    Ok((deployments, services, sas, deploy, svc, sa))
}

/// Returns the Gateway's `status.conditions[type=...]` `(status, reason)`
/// pair, or `None` if the condition isn't present yet.
pub fn gateway_condition(gw: &Gateway, type_: &str) -> Option<(String, String)> {
    gw.status
        .as_ref()?
        .conditions
        .as_ref()?
        .iter()
        .find(|c| c.type_ == type_)
        .map(|c| (c.status.clone(), c.reason.clone()))
}

/// Returns the Gateway's `status.addresses` as a sorted vec of
/// `(type, value)` tuples for deterministic comparison.
pub fn gateway_addresses(gw: &Gateway) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = gw
        .status
        .as_ref()
        .and_then(|s| s.addresses.as_ref())
        .map(|addrs| {
            addrs
                .iter()
                .map(|a| (a.r#type.clone().unwrap_or_default(), a.value.clone()))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Wait until the controller flips the cutover condition to `True` — i.e. the
/// dedicated pod is Ready and the shared pool has dropped the Gateway from its
/// routing table.
pub async fn wait_for_cut_over(
    gateways: &Api<Gateway>,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    wait::poll_until(
        timeout,
        wait::POLL,
        || async {
            let conds = gateways
                .get(name)
                .await
                .ok()
                .and_then(|gw| gw.status.and_then(|s| s.conditions))
                .map(|cs| {
                    cs.iter()
                        .map(|c| format!("{}={}", c.type_, c.status))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            format!("Gateway '{name}' to flip {CUT_OVER_CONDITION}=True; conditions={conds:?}")
        },
        || async {
            let gw = gateways.get(name).await.ok()?;
            let conds = gw.status.as_ref()?.conditions.as_ref()?;
            conds
                .iter()
                .find(|c| c.type_ == CUT_OVER_CONDITION)
                .filter(|c| c.status == "True")
                .map(|_| ())
        },
    )
    .await
}

/// Restart the in-cluster controller Deployment and wait for rollout.
///
/// Used by `lifecycle_controller_restart_is_idempotent` to verify that the
/// controller's SSA output is stable across a full pod restart.
pub async fn restart_controller() -> anyhow::Result<()> {
    let status = Command::new("kubectl")
        .args([
            "rollout",
            "restart",
            "deployment/coxswain-controller",
            "-n",
            "coxswain-system",
        ])
        .status()
        .await?;
    anyhow::ensure!(status.success(), "kubectl rollout restart failed");
    let status = Command::new("kubectl")
        .args([
            "rollout",
            "status",
            "deployment/coxswain-controller",
            "-n",
            "coxswain-system",
            "--timeout=60s",
        ])
        .status()
        .await?;
    anyhow::ensure!(status.success(), "controller restart timed out");
    Ok(())
}
