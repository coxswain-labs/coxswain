#![allow(missing_docs)]
//! E2E coverage for the Step 9 (#208) provisioning operator.
//!
//! Three scenarios — apply→assert, delete→assert GC, restart→assert
//! resourceVersion stability. The dedicated proxy pod is intentionally
//! non-functional in this PR (its SA has no per-namespace RBAC bindings yet;
//! those land in #209), so these tests assert **resource provisioning only**,
//! never traffic flow.

use coxswain_e2e::{
    FixtureVars, Harness, NamespaceGuard, fixtures::dedicated_gateway as dedicated,
};
use gateway_api::apis::standard::gateways::Gateway;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Service, ServiceAccount};
use kube::api::{Api, DeleteParams};
use std::time::Duration;
use tokio::time;

mod common;

/// Gateway `metadata.name` declared in the fixture — chosen to keep the
/// rendered resource name (`<gw>-<class>`) stable across test runs without
/// TESTNS substitution leaking into it. See
/// `crates/coxswain-e2e/fixtures/dedicated_gateway/dedicated_gateway.yaml`.
const GATEWAY_NAME: &str = "dedicated-gw";
/// Rendered resource name per GEP-1762 — `<gateway-name>-<gateway-class>`.
const RESOURCE_NAME: &str = "dedicated-gw-coxswain";

/// Apply the dedicated-mode Gateway fixture, then wait for the controller's
/// provisioning operator to land the three resources. Returns the apis
/// scoped to `ns` for follow-up assertions.
async fn apply_and_wait(
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

    let deploy = poll_until(Duration::from_secs(15), || async {
        deployments.get(RESOURCE_NAME).await.ok()
    })
    .await?;
    let svc = poll_until(Duration::from_secs(15), || async {
        services.get(RESOURCE_NAME).await.ok()
    })
    .await?;
    let sa = poll_until(Duration::from_secs(15), || async {
        sas.get(RESOURCE_NAME).await.ok()
    })
    .await?;

    Ok((deployments, services, sas, deploy, svc, sa))
}

/// Poll `check` every 500 ms until it returns `Some(T)` or `timeout` elapses.
async fn poll_until<T, F, Fut>(timeout: Duration, mut check: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = time::Instant::now() + timeout;
    loop {
        if let Some(val) = check().await {
            return Ok(val);
        }
        if time::Instant::now() >= deadline {
            anyhow::bail!("poll_until timed out after {timeout:?}");
        }
        time::sleep(Duration::from_millis(500)).await;
    }
}

/// 1. Apply a dedicated-mode Gateway → assert all three resources are created
///    with the GEP-1762 labels (including merged infrastructure labels), the
///    correct owner reference back to the Gateway, and the SSA field manager
///    set to `"coxswain-controller"`.
#[tokio::test]
async fn provisions_resources_for_dedicated_gateway() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "dedgw-create").await?;

    let (_, _, _, deploy, svc, sa) = apply_and_wait(&h, &ns).await?;

    // Reserved-set + merged user labels on each resource.
    for (kind, meta) in [
        ("Deployment", &deploy.metadata),
        ("Service", &svc.metadata),
        ("ServiceAccount", &sa.metadata),
    ] {
        let labels = meta.labels.as_ref().unwrap_or_else(|| {
            panic!("{kind}: labels missing");
        });
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
        assert_eq!(
            labels.get("team").map(String::as_str),
            Some("platform"),
            "{kind}: infrastructure.labels.team should merge"
        );
    }

    // Annotation merged from infrastructure.annotations.
    for (kind, meta) in [
        ("Deployment", &deploy.metadata),
        ("Service", &svc.metadata),
        ("ServiceAccount", &sa.metadata),
    ] {
        let annotations = meta.annotations.as_ref().unwrap_or_else(|| {
            panic!("{kind}: annotations missing");
        });
        assert_eq!(
            annotations
                .get("coxswain.example/owner")
                .map(String::as_str),
            Some("tenant-team"),
            "{kind}: infrastructure.annotations.owner should merge"
        );
    }

    // Owner reference back to the Gateway with controller=true,
    // blockOwnerDeletion=true.
    for (kind, meta) in [
        ("Deployment", &deploy.metadata),
        ("Service", &svc.metadata),
        ("ServiceAccount", &sa.metadata),
    ] {
        let refs = meta.owner_references.as_ref().unwrap_or_else(|| {
            panic!("{kind}: owner references missing");
        });
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

    // SSA field manager (acceptance criterion).
    let managers = deploy
        .metadata
        .managed_fields
        .as_ref()
        .expect("Deployment managedFields missing");
    assert!(
        managers
            .iter()
            .any(|f| f.manager.as_deref() == Some("coxswain-controller")),
        "expected a managedFields entry with manager = 'coxswain-controller'"
    );

    Ok(())
}

/// 2. Delete the Gateway → assert all three resources are garbage-collected
///    within 30 s via the owner-ref cascade. No explicit deletion of the
///    provisioned resources; K8s GC drives it from the owner reference.
#[tokio::test]
async fn gateway_deletion_garbage_collects_resources() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "dedgw-gc").await?;

    let (deployments, services, sas, _, _, _) = apply_and_wait(&h, &ns).await?;

    // Delete the Gateway and wait for GC to cascade.
    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    gateways
        .delete(GATEWAY_NAME, &DeleteParams::default())
        .await?;

    poll_until(Duration::from_secs(30), || async {
        let deploy_gone = deployments.get(RESOURCE_NAME).await.is_err();
        let svc_gone = services.get(RESOURCE_NAME).await.is_err();
        let sa_gone = sas.get(RESOURCE_NAME).await.is_err();
        if deploy_gone && svc_gone && sa_gone {
            Some(())
        } else {
            None
        }
    })
    .await?;

    Ok(())
}

/// 3. Restart the controller after the resources are provisioned → assert
///    the SSA path is idempotent: `resourceVersion` stays stable across the
///    restart because the operator's same-content SSA produces no server-side
///    write.
#[tokio::test]
async fn restart_controller_does_not_bump_resource_version() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "dedgw-idempotent").await?;

    let (_deployments, _services, _sas, deploy, svc, sa) = apply_and_wait(&h, &ns).await?;

    let rv_deploy_before = deploy
        .metadata
        .resource_version
        .clone()
        .expect("Deployment resourceVersion");
    let rv_svc_before = svc
        .metadata
        .resource_version
        .clone()
        .expect("Service resourceVersion");
    let rv_sa_before = sa
        .metadata
        .resource_version
        .clone()
        .expect("ServiceAccount resourceVersion");

    // Restart: drop the harness (kills controller) and re-spawn. Bootstrap is
    // idempotent so the second start only re-spawns the binary, and the
    // 3-second lease TTL means the new pod-name re-claims leadership quickly.
    drop(h);
    let h2 = Harness::start().await?;

    // Give the new leader's operator a few reconcile cycles to send the
    // idempotent SSAs. SSA on identical content does not bump
    // `resourceVersion`; if it does, the operator emitted a write that
    // should have been a no-op.
    time::sleep(Duration::from_secs(15)).await;

    let deploy_after: Api<Deployment> = Api::namespaced(h2.client.clone(), &ns.name);
    let svc_after: Api<Service> = Api::namespaced(h2.client.clone(), &ns.name);
    let sa_after: Api<ServiceAccount> = Api::namespaced(h2.client.clone(), &ns.name);

    let d2 = deploy_after.get(RESOURCE_NAME).await?;
    let s2 = svc_after.get(RESOURCE_NAME).await?;
    let a2 = sa_after.get(RESOURCE_NAME).await?;

    assert_eq!(
        d2.metadata.resource_version.as_deref(),
        Some(rv_deploy_before.as_str()),
        "Deployment resourceVersion changed across restart (SSA was not idempotent)"
    );
    assert_eq!(
        s2.metadata.resource_version.as_deref(),
        Some(rv_svc_before.as_str()),
        "Service resourceVersion changed across restart (SSA was not idempotent)"
    );
    assert_eq!(
        a2.metadata.resource_version.as_deref(),
        Some(rv_sa_before.as_str()),
        "ServiceAccount resourceVersion changed across restart (SSA was not idempotent)"
    );

    Ok(())
}
