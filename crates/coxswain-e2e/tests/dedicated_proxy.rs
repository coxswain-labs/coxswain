#![allow(missing_docs)]
//! E2E coverage for the Step 9 (#208) provisioning operator.
//!
//! Three scenarios — apply→assert, delete→assert GC, restart→assert
//! resourceVersion stability. The dedicated proxy pod is intentionally
//! non-functional in this PR (its SA has no per-namespace RBAC bindings yet;
//! those land in #209), so these tests assert **resource provisioning only**,
//! never traffic flow.

use coxswain_e2e::{FixtureVars, Harness, NamespaceGuard, fixtures::dedicated_proxy as dedicated};
use gateway_api::apis::standard::gateways::Gateway;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Service, ServiceAccount};
use k8s_openapi::api::rbac::v1::RoleBinding;
use kube::api::{Api, DeleteParams, ListParams};
use std::time::Duration;
use tokio::time;

mod common;

/// Gateway `metadata.name` declared in the fixture — chosen to keep the
/// rendered resource name (`<gw>-<class>`) stable across test runs without
/// TESTNS substitution leaking into it. See
/// `crates/coxswain-e2e/fixtures/dedicated_proxy/dedicated_gateway.yaml`.
const GATEWAY_NAME: &str = "dedicated-gw";
/// Rendered resource name per GEP-1762 — `<gateway-name>-<gateway-class>`.
const RESOURCE_NAME: &str = "dedicated-gw-coxswain";

/// `RoleBinding` name pattern: `coxswain-<gateway-namespace>-<gateway-name>`
/// (see `coxswain_controller::operator::rbac`). Constructed at runtime from
/// the test namespace.
fn binding_name(ns: &str) -> String {
    format!("coxswain-{ns}-{GATEWAY_NAME}")
}

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
async fn provisions_resources_for_dedicated_proxy() -> anyhow::Result<()> {
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
    // Persistent namespace: the bootstrap purge runs on every
    // `Harness::start()`, including the second one below. A regular
    // `NamespaceGuard::create` would label this namespace `coxswain-e2e=true`
    // and the second bootstrap would delete it before we could verify the
    // SSA idempotency — defeating the test. The persistent variant skips
    // the label; the `Drop` still cleans up at end-of-test.
    let ns = NamespaceGuard::create_persistent(&h.client, "dedgw-idempotent").await?;

    let (_deployments, _services, _sas, deploy, _svc, _sa) = apply_and_wait(&h, &ns).await?;

    // Use `metadata.generation`, not `metadata.resourceVersion`, for the
    // idempotency check. `resourceVersion` bumps on every write — including
    // status updates emitted by the K8s Deployment controller while the
    // proxy pod scales / becomes Ready — so it drifts naturally in the 15 s
    // observation window and is not a clean signal of "the operator wrote a
    // new spec". `generation` only bumps on spec changes, which is exactly
    // the property SSA idempotency is supposed to preserve.
    //
    // We check Deployment only: it's the load-bearing resource (rollouts
    // are triggered by spec changes here), it reliably carries
    // `.metadata.generation`, and the proxy pod's lifecycle is what would
    // be most visibly disrupted by a spurious SSA write. Service and
    // ServiceAccount don't consistently populate `.generation` (Service's
    // generation isn't set in all K8s versions; ServiceAccount has no
    // spec), so checking them via `.generation` would itself be flaky.
    let gen_deploy_before = deploy.metadata.generation.expect("Deployment generation");

    // Restart: drop the harness (kills controller) and re-spawn. Bootstrap is
    // idempotent so the second start only re-spawns the binary, and the
    // 3-second lease TTL means the new pod-name re-claims leadership quickly.
    drop(h);
    let h2 = Harness::start().await?;

    // Give the new leader's operator a few reconcile cycles to send the
    // idempotent SSAs. SSA on identical content does not bump `.generation`;
    // if it does, the operator emitted a spec write that should have been a
    // no-op.
    time::sleep(Duration::from_secs(15)).await;

    let deploy_after: Api<Deployment> = Api::namespaced(h2.client.clone(), &ns.name);
    let d2 = deploy_after.get(RESOURCE_NAME).await?;

    assert_eq!(
        d2.metadata.generation,
        Some(gen_deploy_before),
        "Deployment .metadata.generation changed across restart (SSA wrote a new spec)"
    );

    Ok(())
}

// =============================================================================
// #209 — per-namespace RBAC narrowing.
// =============================================================================

/// 4. Apply a dedicated-mode Gateway with a same-namespace HTTPRoute → assert
///    the controller creates a `RoleBinding` `coxswain-<ns>-<gw-name>` in the
///    Gateway's own namespace, with the discovery labels set and bound to the
///    `coxswain-gateway-proxy-reader` ClusterRole.
#[tokio::test]
async fn provisions_role_binding_in_gateway_namespace() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "dedgw-rbac-own").await?;

    h.apply(
        dedicated::DEDICATED_GATEWAY_WITH_ROUTE,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let bindings: Api<RoleBinding> = Api::namespaced(h.client.clone(), &ns.name);
    let want_name = binding_name(&ns.name);
    let rb = poll_until(Duration::from_secs(15), || async {
        bindings.get(&want_name).await.ok()
    })
    .await?;

    // RoleRef points at the static permission-template ClusterRole.
    assert_eq!(rb.role_ref.kind, "ClusterRole");
    assert_eq!(rb.role_ref.name, "coxswain-gateway-proxy-reader");

    // Subject is the rendered proxy ServiceAccount in the Gateway's own ns.
    let subjects = rb.subjects.as_ref().expect("subjects set");
    assert_eq!(subjects.len(), 1);
    assert_eq!(subjects[0].kind, "ServiceAccount");
    assert_eq!(subjects[0].name, RESOURCE_NAME);
    assert_eq!(subjects[0].namespace.as_deref(), Some(ns.name.as_str()));

    // Discovery labels — reconcile lists by these to compute drift.
    let labels = rb
        .metadata
        .labels
        .as_ref()
        .expect("RoleBinding labels missing");
    assert_eq!(
        labels
            .get("app.kubernetes.io/managed-by")
            .map(String::as_str),
        Some("coxswain")
    );
    assert_eq!(
        labels
            .get("gateway.networking.k8s.io/gateway-name")
            .map(String::as_str),
        Some(GATEWAY_NAME)
    );
    assert_eq!(
        labels
            .get("gateway.coxswain-labs.dev/gateway-namespace")
            .map(String::as_str),
        Some(ns.name.as_str())
    );

    // No owner references — cleanup is reconcile-driven via the labels above
    // (cross-namespace owner refs are unsupported by K8s GC).
    assert!(
        rb.metadata.owner_references.is_none()
            || rb.metadata.owner_references.as_ref().unwrap().is_empty(),
        "RoleBinding must not carry owner references; cleanup is reconcile-driven"
    );

    Ok(())
}

/// 5. Delete the Gateway → finalizer drives synchronous cleanup of every
///    managed `RoleBinding` for that Gateway. Verifies the binding list (by
///    the managed-by label selector) is empty within 30 s, and the Gateway
///    itself disappears (finalizer is removed).
#[tokio::test]
async fn gateway_deletion_drives_role_binding_cleanup() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "dedgw-rbac-gc").await?;

    h.apply(
        dedicated::DEDICATED_GATEWAY_WITH_ROUTE,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let bindings: Api<RoleBinding> = Api::namespaced(h.client.clone(), &ns.name);
    let want_name = binding_name(&ns.name);

    // Wait for the binding to be present before we delete the Gateway, so the
    // subsequent "binding gone" assertion is meaningful.
    poll_until(Duration::from_secs(15), || async {
        bindings.get(&want_name).await.ok()
    })
    .await?;

    // Delete the Gateway. The finalizer keeps it alive until the controller
    // clears bindings + removes the finalizer.
    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    gateways
        .delete(GATEWAY_NAME, &DeleteParams::default())
        .await?;

    poll_until(Duration::from_secs(30), || async {
        // The binding must be gone, and listing by the managed-by selector
        // for this Gateway must return zero objects.
        let binding_gone = bindings.get(&want_name).await.is_err();
        let selector = format!(
            "app.kubernetes.io/managed-by=coxswain,\
             gateway.networking.k8s.io/gateway-name={GATEWAY_NAME},\
             gateway.coxswain-labs.dev/gateway-namespace={}",
            ns.name
        );
        let leftover = bindings
            .list(&ListParams::default().labels(&selector))
            .await
            .map(|l| l.items.len())
            .unwrap_or(usize::MAX);
        let gateway_gone = gateways.get(GATEWAY_NAME).await.is_err();
        if binding_gone && leftover == 0 && gateway_gone {
            Some(())
        } else {
            None
        }
    })
    .await?;

    Ok(())
}

/// 6. Drift detection: out-of-band delete of a managed `RoleBinding` triggers
///    the controller to re-create it within ~5 s via the RoleBinding
///    cross-watch (`watches(... managed-by=coxswain ...)`).
#[tokio::test]
async fn out_of_band_binding_deletion_is_recreated() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "dedgw-rbac-drift").await?;

    h.apply(
        dedicated::DEDICATED_GATEWAY_WITH_ROUTE,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let bindings: Api<RoleBinding> = Api::namespaced(h.client.clone(), &ns.name);
    let want_name = binding_name(&ns.name);
    let original = poll_until(Duration::from_secs(15), || async {
        bindings.get(&want_name).await.ok()
    })
    .await?;
    let original_rv = original
        .metadata
        .resource_version
        .clone()
        .expect("RoleBinding resourceVersion");

    bindings
        .delete(&want_name, &DeleteParams::default())
        .await?;

    // Wait for the controller to observe the deletion via the cross-watch and
    // SSA the binding back. `resourceVersion` strictly increases on K8s
    // writes; a new binding with the same name will have a higher one.
    let recreated = poll_until(Duration::from_secs(15), || async {
        bindings.get(&want_name).await.ok()
    })
    .await?;
    let new_rv = recreated
        .metadata
        .resource_version
        .expect("recreated RoleBinding resourceVersion");
    assert_ne!(
        new_rv, original_rv,
        "drift detection should produce a new binding (resourceVersion bumped)"
    );
    Ok(())
}

/// 7. Container-args rendering: the Deployment the controller provisions
///    carries `--proxy-watch-namespaces=<ns>` matching the desired-namespace
///    set the binding reconciler computed for this Gateway.
#[tokio::test]
async fn deployment_container_carries_watch_namespaces_arg() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "dedgw-rbac-args").await?;

    h.apply(
        dedicated::DEDICATED_GATEWAY_WITH_ROUTE,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let deploy = poll_until(Duration::from_secs(15), || async {
        deployments.get(RESOURCE_NAME).await.ok()
    })
    .await?;

    let want_arg = format!("--proxy-watch-namespaces={}", ns.name);
    let containers = deploy
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .map(|s| s.containers.as_slice())
        .unwrap_or_default();
    let coxswain = containers
        .iter()
        .find(|c| c.name == "coxswain")
        .expect("coxswain container present");
    let args = coxswain.args.as_ref().expect("args set");
    assert!(
        args.iter().any(|a| a == &want_arg),
        "expected {want_arg} in container args; got {args:?}"
    );
    Ok(())
}

// =============================================================================
// #211 — dedicated-mode Gateway status writer.
// =============================================================================

/// Helper: returns the Gateway's `status.conditions[type=...]` `(status, reason)`
/// pair, or `None` if the condition isn't present yet.
fn gateway_condition(gw: &Gateway, type_: &str) -> Option<(String, String)> {
    gw.status
        .as_ref()?
        .conditions
        .as_ref()?
        .iter()
        .find(|c| c.type_ == type_)
        .map(|c| (c.status.clone(), c.reason.clone()))
}

/// Helper: returns the Gateway's `status.addresses` as a sorted vec of
/// `(type, value)` tuples for deterministic comparison.
fn gateway_addresses(gw: &Gateway) -> Vec<(String, String)> {
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

/// 8 — Scenario A (#211, ClusterIP happy path): apply a dedicated Gateway with
/// `serviceType: ClusterIP` (the existing fixture), wait for pod Ready, then
/// assert the operator writes `Accepted=True`, `Programmed=True`,
/// `gateway.coxswain-labs.dev/DedicatedProxyReady=True/Ready`, and
/// `status.addresses[0]` matching the provisioned Service's `spec.clusterIP`.
#[tokio::test]
async fn writes_clusterip_address_and_programmed_true_when_pod_ready() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "dedgw-status-clusterip").await?;

    let (_, services, _, _, _, _) = apply_and_wait(&h, &ns).await?;

    // Read the rendered Service to learn its clusterIP — apiserver assigns
    // it synchronously on Service creation.
    let svc = services.get(RESOURCE_NAME).await?;
    let cluster_ip = svc
        .spec
        .as_ref()
        .and_then(|s| s.cluster_ip.clone())
        .expect("provisioned Service should have a clusterIP");
    assert!(
        !cluster_ip.is_empty() && cluster_ip != "None",
        "ClusterIP fixture expects a non-headless clusterIP, got {cluster_ip}"
    );

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    // Programmed=True takes a moment: we wait for both pod readiness and
    // the operator's reconcile to propagate. 60s window accommodates image
    // pull and pod startup on a cold local cluster.
    let gw = poll_until(Duration::from_secs(60), || async {
        let gw = gateways.get(GATEWAY_NAME).await.ok()?;
        let accepted = gateway_condition(&gw, "Accepted")?;
        let programmed = gateway_condition(&gw, "Programmed")?;
        let cut_over = gateway_condition(&gw, "gateway.coxswain-labs.dev/DedicatedProxyReady")?;
        let addresses = gateway_addresses(&gw);
        if accepted == ("True".to_string(), "Accepted".to_string())
            && programmed == ("True".to_string(), "Programmed".to_string())
            && cut_over == ("True".to_string(), "Ready".to_string())
            && !addresses.is_empty()
        {
            Some(gw)
        } else {
            None
        }
    })
    .await?;

    // Address came from the Service's clusterIP, type=IPAddress.
    let addresses = gateway_addresses(&gw);
    assert_eq!(addresses.len(), 1, "ClusterIP yields exactly one address");
    assert_eq!(
        addresses[0],
        ("IPAddress".to_string(), cluster_ip.clone()),
        "Gateway.status.addresses must mirror Service.spec.clusterIP"
    );
    Ok(())
}

/// 9 — Scenario B (#211, LoadBalancer with synthetic status patch): local
/// clusters don't run an LB controller, so we apply a `serviceType:
/// LoadBalancer` Gateway, assert `Programmed=False, reason=AddressNotAssigned`,
/// then manually patch the Service's `/status` subresource with a synthetic
/// LB ingress and confirm the operator flips `Programmed=True` with the
/// injected IP showing in `status.addresses`.
#[tokio::test]
async fn loadbalancer_status_patch_drives_addresses_and_programmed_true() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "dedgw-status-lb").await?;

    h.apply(
        dedicated::DEDICATED_GATEWAY_LOADBALANCER,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    poll_until(Duration::from_secs(15), || async {
        services.get(RESOURCE_NAME).await.ok()
    })
    .await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);

    // Before the synthetic status patch: the Service has no LB ingress (no
    // LB controller in the local cluster), so the operator must surface
    // Programmed=False, reason=AddressNotAssigned. Pod readiness is not
    // required for this assertion — the precedence ladder yields
    // AddressNotAssigned when a Ready pod is present and addresses are
    // still empty (and Pending otherwise — both are False so we only assert
    // status=False here to avoid coupling to pod startup timing).
    poll_until(Duration::from_secs(45), || async {
        let gw = gateways.get(GATEWAY_NAME).await.ok()?;
        let programmed = gateway_condition(&gw, "Programmed")?;
        if programmed.0 == "False"
            && (programmed.1 == "AddressNotAssigned" || programmed.1 == "Pending")
        {
            Some(())
        } else {
            None
        }
    })
    .await?;

    // Patch the Service's /status subresource with a synthetic LB ingress.
    // Plain `.patch()` would target the spec subresource — we MUST go
    // through `.patch_status()` to write `status.loadBalancer.ingress`.
    let synthetic_lb_ip = "203.0.113.7";
    let status_patch = serde_json::json!({
        "status": {
            "loadBalancer": {
                "ingress": [{"ip": synthetic_lb_ip}]
            }
        }
    });
    services
        .patch_status(
            RESOURCE_NAME,
            &kube::api::PatchParams::default(),
            &kube::api::Patch::Merge(&status_patch),
        )
        .await?;

    // The operator's Service cross-watch should pick this up and re-reconcile
    // the owning Gateway. Wait for Programmed=True with the injected IP.
    let gw = poll_until(Duration::from_secs(60), || async {
        let gw = gateways.get(GATEWAY_NAME).await.ok()?;
        let programmed = gateway_condition(&gw, "Programmed")?;
        let addresses = gateway_addresses(&gw);
        if programmed == ("True".to_string(), "Programmed".to_string())
            && addresses
                .iter()
                .any(|(t, v)| t == "IPAddress" && v == synthetic_lb_ip)
        {
            Some(gw)
        } else {
            None
        }
    })
    .await?;
    let _ = gw;
    Ok(())
}

/// 10 — Scenario C (#211, InvalidParameters): apply a dedicated Gateway whose
/// `parametersRef.name` targets a missing `CoxswainGatewayParameters` object,
/// and assert the operator writes `Accepted=False, reason=InvalidParameters`
/// + `Programmed=False, reason=Invalid` directly — no shared
/// `AcceptedOverrides` channel.
#[tokio::test]
async fn invalid_parameters_yields_accepted_false_invalid_parameters() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "dedgw-status-invalid").await?;

    h.apply(
        dedicated::DEDICATED_GATEWAY_INVALID_PARAMS,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    poll_until(Duration::from_secs(30), || async {
        let gw = gateways.get(GATEWAY_NAME).await.ok()?;
        let accepted = gateway_condition(&gw, "Accepted")?;
        let programmed = gateway_condition(&gw, "Programmed")?;
        if accepted == ("False".to_string(), "InvalidParameters".to_string())
            && programmed == ("False".to_string(), "Invalid".to_string())
        {
            Some(())
        } else {
            None
        }
    })
    .await?;

    // No Deployment/Service/SA should have been provisioned — the
    // InvalidParameters branch returns before render+apply.
    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    let sas: Api<ServiceAccount> = Api::namespaced(h.client.clone(), &ns.name);
    assert!(
        deployments.get(RESOURCE_NAME).await.is_err(),
        "no Deployment should be provisioned on the InvalidParameters path"
    );
    assert!(
        services.get(RESOURCE_NAME).await.is_err(),
        "no Service should be provisioned on the InvalidParameters path"
    );
    assert!(
        sas.get(RESOURCE_NAME).await.is_err(),
        "no ServiceAccount should be provisioned on the InvalidParameters path"
    );
    Ok(())
}
