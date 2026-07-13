//! Shared test-orchestration helpers for the dedicated-mode Gateway suite.
//!
//! The dedicated-proxy tests are classified by behavior plane across
//! `provisioning.rs`, `status_conditions.rs`, and `resilience.rs`, but they
//! share a common vocabulary: the fixture-coupled resource names, the
//! provision-then-poll setup, and the condition/address accessors. These live
//! here (DAMP test support) rather than in the library so the read-only-proxy
//! crate boundary stays clean.

use coxswain_e2e::{
    Harness, NamespaceGuard,
    fixtures::{self, FixtureVars, dedicated_proxy as dedicated},
    harness::wait,
};
use gateway_api_types::apis::standard::gateways::Gateway;
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
    fixtures::apply_fixture(dedicated::DEDICATED_GATEWAY, FixtureVars::new(&ns.name)).await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    let sas: Api<ServiceAccount> = Api::namespaced(h.client.clone(), &ns.name);

    let deploy =
        wait::wait_for_resource(&deployments, RESOURCE_NAME, Duration::from_secs(15)).await?;
    let svc = wait::wait_for_resource(&services, RESOURCE_NAME, Duration::from_secs(15)).await?;
    let sa = wait::wait_for_resource(&sas, RESOURCE_NAME, Duration::from_secs(15)).await?;

    Ok((deployments, services, sas, deploy, svc, sa))
}

/// Assert the GEP-1762 provisioning contract every dedicated-proxy resource
/// shares: each of the Deployment, Service, and ServiceAccount carries the
/// `gateway-name`, `managed-by`, and `name` labels, exactly one owner reference
/// back to the Gateway (`controller=true`, `blockOwnerDeletion=true`,
/// `gateway.networking.k8s.io/*` apiVersion), and the Deployment's SSA field
/// manager is `coxswain-controller`. Fixture-specific extras (e.g. merged
/// `infrastructure.labels`/`annotations`) are asserted by the caller.
pub fn assert_provisioning_contract(deploy: &Deployment, svc: &Service, sa: &ServiceAccount) {
    for (kind, meta) in [
        ("Deployment", &deploy.metadata),
        ("Service", &svc.metadata),
        ("ServiceAccount", &sa.metadata),
    ] {
        let labels = meta
            .labels
            .as_ref()
            .unwrap_or_else(|| panic!("{kind}: labels missing"));
        assert_eq!(
            labels
                .get("gateway.networking.k8s.io/gateway-name")
                .map(String::as_str),
            Some(GATEWAY_NAME),
            "{kind}: GEP-1762 gateway-name label missing/wrong"
        );
        assert_eq!(
            labels
                .get("app.kubernetes.io/managed-by")
                .map(String::as_str),
            Some("coxswain"),
            "{kind}: managed-by label missing/wrong"
        );
        assert_eq!(
            labels.get("app.kubernetes.io/name").map(String::as_str),
            Some("coxswain"),
            "{kind}: name label missing/wrong"
        );

        let refs = meta
            .owner_references
            .as_ref()
            .unwrap_or_else(|| panic!("{kind}: owner references missing"));
        assert_eq!(refs.len(), 1, "{kind}: expected exactly one owner ref");
        let r = &refs[0];
        assert_eq!(r.kind, "Gateway", "{kind}: owner ref kind");
        assert_eq!(r.name, GATEWAY_NAME, "{kind}: owner ref name");
        assert_eq!(r.controller, Some(true), "{kind}: owner ref controller");
        assert_eq!(
            r.block_owner_deletion,
            Some(true),
            "{kind}: owner ref blockOwnerDeletion"
        );
        assert!(
            r.api_version.starts_with("gateway.networking.k8s.io/"),
            "{kind}: owner ref api_version = {}",
            r.api_version
        );
    }

    let managers = deploy
        .metadata
        .managed_fields
        .as_ref()
        .unwrap_or_else(|| panic!("Deployment managedFields missing"));
    assert!(
        managers
            .iter()
            .any(|f| f.manager.as_deref() == Some("coxswain-controller")),
        "expected a managedFields entry with manager = 'coxswain-controller'"
    );
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

/// Scale the in-cluster controller Deployment to `replicas` and wait for the
/// change to take effect. Scaling to `0` then back to `1` gives a deterministic
/// controller-downtime window: this helper does not return for `replicas == 0`
/// until the controller pods are actually gone, so a mutation applied next is
/// guaranteed to land while nothing is watching.
///
/// # Errors
///
/// Returns an error if the `kubectl scale` invocation fails, or if the
/// controller does not reach the requested replica count within 60s.
pub async fn scale_controller(replicas: u32) -> anyhow::Result<()> {
    let status = Command::new("kubectl")
        .args([
            "scale",
            "deployment/coxswain-controller",
            "-n",
            "coxswain-system",
            &format!("--replicas={replicas}"),
        ])
        .status()
        .await?;
    anyhow::ensure!(
        status.success(),
        "kubectl scale controller to {replicas} failed"
    );

    if replicas == 0 {
        // Wait until no replicas remain — `kubectl scale` returns once the spec
        // is updated, not once the pod has terminated. Poll the real state so a
        // catch-up test's mutation lands with the controller genuinely down.
        wait::poll_until(
            Duration::from_secs(60),
            wait::POLL,
            || async { "controller Deployment to report 0 running replicas".to_string() },
            || async {
                let out = Command::new("kubectl")
                    .args([
                        "get",
                        "deployment",
                        "coxswain-controller",
                        "-n",
                        "coxswain-system",
                        "-o",
                        "jsonpath={.status.replicas}",
                    ])
                    .output()
                    .await
                    .ok()?;
                let raw = String::from_utf8_lossy(&out.stdout);
                let raw = raw.trim();
                // `.status.replicas` is omitted (empty) or "0" once all pods are gone.
                (raw.is_empty() || raw == "0").then_some(())
            },
        )
        .await?;
    } else {
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
        anyhow::ensure!(status.success(), "controller scale-up rollout timed out");
    }
    Ok(())
}

/// Read the controller Deployment's configured replica count (`spec.replicas`).
///
/// Tests that scale the controller down for an outage window MUST capture this
/// first and restore the exact count afterwards — the shared install runs HA
/// (two replicas by default) and the leader-election tests assert a standby
/// exists. Restoring a hardcoded `1` silently degrades every later test in the
/// serial pass.
///
/// # Errors
///
/// Returns an error if `kubectl get` fails or the field is not a number.
#[must_use = "the captured count is what the outage test must restore"]
pub async fn controller_replicas() -> anyhow::Result<u32> {
    let out = Command::new("kubectl")
        .args([
            "get",
            "deployment",
            "coxswain-controller",
            "-n",
            "coxswain-system",
            "-o",
            "jsonpath={.spec.replicas}",
        ])
        .output()
        .await?;
    anyhow::ensure!(
        out.status.success(),
        "kubectl get controller replicas failed"
    );
    let raw = String::from_utf8_lossy(&out.stdout);
    raw.trim()
        .parse::<u32>()
        .map_err(|e| anyhow::anyhow!("controller spec.replicas {raw:?} is not a number: {e}"))
}
