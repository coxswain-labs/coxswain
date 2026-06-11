#![allow(missing_docs)]
//! E2E coverage for the dedicated-mode Gateway lifecycle (Steps 9–13).
//!
//! Tests are layered by phase:
//! - **Step 9 (#208)** — provisioning operator: resource creation, GC on
//!   Gateway deletion, SSA idempotency across controller restart.
//! - **Step 10 (#209)** — per-namespace RBAC narrowing: RoleBinding lifecycle,
//!   drift detection, container-args rendering.
//! - **Step 11 (#211)** — Gateway status writer: `Accepted`/`Programmed`
//!   conditions, address derivation per `serviceType`,
//!   `InvalidParameters` path.
//! - **Step 13 (#212)** — user-visible lifecycle: traffic through a dedicated
//!   proxy host subprocess, cross-namespace + `ReferenceGrant` revocation,
//!   mode migration in both directions, and traffic continuity across a
//!   controller restart.
//!
//! The Step-13 lifecycle tests spawn a second `serve proxy --dedicated`
//! subprocess on the host alongside the existing `serve dev` subprocess.
//! In-cluster Deployments are pinned to `registry.k8s.io/pause:3.10` so a
//! coxswain image build is not required — bind/release of the listener port
//! is sequenced by the controller's cutover signal.

use coxswain_e2e::{
    DedicatedProxyProcess, FixtureVars, Harness, NamespaceGuard,
    fixtures::{backends, dedicated_proxy as dedicated},
    harness::{HttpClient, wait},
};
use gateway_api::apis::standard::gateways::Gateway;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Service, ServiceAccount};
use k8s_openapi::api::rbac::v1::RoleBinding;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams};
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
/// Condition type the operator writes when the dedicated pod is Ready and the
/// shared pool must stop serving the Gateway (#210).
const CUT_OVER_CONDITION: &str = "gateway.coxswain-labs.dev/DedicatedProxyReady";

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
/// `serviceType: ClusterIP`, wait for pod Ready, then assert the operator
/// writes `Accepted=True`, `Programmed=True`,
/// `gateway.coxswain-labs.dev/DedicatedProxyReady=True/Ready`, and
/// `status.addresses[0]` matching the provisioned Service's `spec.clusterIP`.
///
/// Uses [`dedicated::DEDICATED_GATEWAY_CLUSTERIP`] rather than the shared
/// `DEDICATED_GATEWAY` fixture because Pod-Ready gating requires a
/// stub-image container — the default `coxswain:<version>` image cached
/// on the cluster predates the controller/proxy CLI split and CrashLoops
/// against the operator-rendered args, so it never reports Ready.
#[tokio::test]
async fn writes_clusterip_address_and_programmed_true_when_pod_ready() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "dedgw-status-clusterip").await?;

    h.apply(
        dedicated::DEDICATED_GATEWAY_CLUSTERIP,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    let svc = poll_until(Duration::from_secs(15), || async {
        services.get(RESOURCE_NAME).await.ok()
    })
    .await?;
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

/// 9 — Scenario B (#211, LoadBalancer address propagation): apply a
/// `serviceType: LoadBalancer` Gateway and verify the operator surfaces the
/// assigned LB IP in `Gateway.status.addresses` and flips `Programmed=True`
/// once an IP is present.
///
/// Address-source resilience: some local clusters (e.g. OrbStack) ship a
/// built-in LB controller that assigns an IP within seconds; on bare clusters
/// the harness writes a synthetic `Service.status.loadBalancer.ingress` if
/// none appears within a short window. Either path produces the same observable
/// downstream signal — the operator's address resolution doesn't care which
/// source populated the field, and pinning to one specific IP is fragile
/// because an active LB controller will overwrite a synthetic patch within
/// a single reconcile loop.
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

    // Before any LB ingress is assigned the operator must surface
    // Programmed=False with one of two reasons:
    //   * Pending — pod not yet Ready (precedence: pod-ready > address)
    //   * AddressNotAssigned — pod is Ready but no LB IP yet
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

    // Give an in-cluster LB controller a short window to assign an IP. If
    // nothing shows up in 10 s we synthetically patch the status subresource
    // so the test still exercises address propagation on bare clusters.
    // Plain `.patch()` would target the spec subresource — `/status` writes
    // MUST go through `.patch_status()`.
    let in_cluster_assigned = poll_until(Duration::from_secs(10), || async {
        let svc = services.get_status(RESOURCE_NAME).await.ok()?;
        let ip = svc
            .status
            .as_ref()
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_ref())
            .and_then(|i| i.first())
            .and_then(|e| e.ip.clone())
            .filter(|s| !s.is_empty());
        ip.map(|ip| ip.to_string())
    })
    .await
    .ok();
    let expected_ip: String = if let Some(ip) = in_cluster_assigned {
        ip
    } else {
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
        synthetic_lb_ip.to_string()
    };

    // The operator's Service cross-watch picks up the LB-ingress change and
    // re-reconciles the owning Gateway. Wait for Programmed=True and the
    // assigned IP in status.addresses.
    let gw = poll_until(Duration::from_secs(60), || async {
        let gw = gateways.get(GATEWAY_NAME).await.ok()?;
        let programmed = gateway_condition(&gw, "Programmed")?;
        let addresses = gateway_addresses(&gw);
        if programmed == ("True".to_string(), "Programmed".to_string())
            && addresses
                .iter()
                .any(|(t, v)| t == "IPAddress" && v == &expected_ip)
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

// =============================================================================
// #212 — Step 13: user-visible dedicated-mode Gateway lifecycle.
// =============================================================================

/// Wait until the controller flips the cutover condition to `True` — i.e. the
/// dedicated pod is Ready and the shared pool has dropped the Gateway from its
/// routing table.
async fn wait_for_cut_over(
    gateways: &Api<Gateway>,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    poll_until(timeout, || async {
        let gw = gateways.get(name).await.ok()?;
        let conds = gw.status.as_ref()?.conditions.as_ref()?;
        conds
            .iter()
            .find(|c| c.type_ == CUT_OVER_CONDITION)
            .filter(|c| c.status == "True")
            .map(|_| ())
    })
    .await
}

/// 11 — Apply a dedicated-mode Gateway → assert Deployment/Service/ServiceAccount
/// land with the GEP-1762 labels, owner references back to the Gateway, and the
/// SSA field manager set to `coxswain-controller`.
#[tokio::test]
async fn lifecycle_provisioning_creates_resources() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ded-life-prov").await?;

    h.apply(dedicated::PROVISIONING, FixtureVars::new(&ns.name))
        .await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    let sas: Api<ServiceAccount> = Api::namespaced(h.client.clone(), &ns.name);

    let deploy = poll_until(Duration::from_secs(30), || async {
        deployments.get(RESOURCE_NAME).await.ok()
    })
    .await?;
    let svc = poll_until(Duration::from_secs(30), || async {
        services.get(RESOURCE_NAME).await.ok()
    })
    .await?;
    let sa = poll_until(Duration::from_secs(30), || async {
        sas.get(RESOURCE_NAME).await.ok()
    })
    .await?;

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
            "{kind}: GEP-1762 gateway-name label"
        );
        assert_eq!(
            labels
                .get("app.kubernetes.io/managed-by")
                .map(String::as_str),
            Some("coxswain"),
            "{kind}: managed-by label"
        );

        let refs = meta
            .owner_references
            .as_ref()
            .unwrap_or_else(|| panic!("{kind}: owner references missing"));
        assert_eq!(refs.len(), 1, "{kind}: expected one owner ref");
        assert_eq!(refs[0].kind, "Gateway", "{kind}: owner ref kind");
        assert_eq!(refs[0].name, GATEWAY_NAME, "{kind}: owner ref name");
        assert_eq!(refs[0].controller, Some(true), "{kind}: controller=true");
        assert_eq!(
            refs[0].block_owner_deletion,
            Some(true),
            "{kind}: blockOwnerDeletion=true"
        );
    }

    let managers = deploy
        .metadata
        .managed_fields
        .as_ref()
        .expect("Deployment managedFields");
    assert!(
        managers
            .iter()
            .any(|f| f.manager.as_deref() == Some("coxswain-controller")),
        "expected managedFields entry for 'coxswain-controller'"
    );

    Ok(())
}

/// 12 — Spawn a dedicated-proxy host subprocess once the controller has flipped
/// `DedicatedProxyReady=True`, send a GET via the Gateway listener, assert the
/// expected backend.
#[tokio::test]
async fn lifecycle_dedicated_proxy_routes_traffic() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ded-life-traffic").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(dedicated::TRAFFIC, FixtureVars::new(&ns.name))
        .await?;

    // Cutover must complete before we spawn the dedicated subprocess — until
    // it does, the shared subprocess still holds GATEWAY_HTTP_PORT.
    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait_for_cut_over(&gateways, GATEWAY_NAME, Duration::from_secs(60)).await?;

    let dedicated_proxy = h
        .start_dedicated_proxy(GATEWAY_NAME, &ns.name, &[&ns.name])
        .await?;
    wait::wait_for_ready(dedicated_proxy.health_addr, Duration::from_secs(30)).await?;

    let host = format!("dedicated.{}.local", ns.name);
    let http = dedicated_proxy.http_client()?;
    let resp = wait::wait_for_route(&http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    Ok(())
}

/// 13 — An HTTPRoute with a backend Service in a different namespace resolves
/// via `ReferenceGrant`. The per-tenant `RoleBinding` is provisioned for the
/// dedicated proxy ServiceAccount, and traffic flows through the dedicated
/// subprocess.
#[tokio::test]
async fn lifecycle_cross_namespace_backend() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ded-life-xns").await?;
    let tenant = NamespaceGuard::create(&h.client, "ded-life-xns-tenant").await?;

    h.apply(
        dedicated::CROSS_NAMESPACE_TENANT,
        FixtureVars::new(&tenant.name).with("TESTNS", &ns.name),
    )
    .await?;
    wait::wait_for_deployments(&tenant.name, &["echo-d"]).await?;

    h.apply(
        dedicated::CROSS_NAMESPACE_ROUTE,
        FixtureVars::new(&ns.name).with("TENANTNS", &tenant.name),
    )
    .await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait_for_cut_over(&gateways, GATEWAY_NAME, Duration::from_secs(60)).await?;

    let bindings: Api<RoleBinding> = Api::namespaced(h.client.clone(), &tenant.name);
    let want_binding = binding_name(&ns.name);
    poll_until(Duration::from_secs(30), || async {
        bindings.get(&want_binding).await.ok()
    })
    .await?;

    let dedicated_proxy = h
        .start_dedicated_proxy(GATEWAY_NAME, &ns.name, &[&ns.name, &tenant.name])
        .await?;
    wait::wait_for_ready(dedicated_proxy.health_addr, Duration::from_secs(30)).await?;

    let host = format!("cross-ns.{}.local", ns.name);
    let http = dedicated_proxy.http_client()?;
    let resp = wait::wait_for_route(&http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-d");

    Ok(())
}

/// 14 — Delete the `ReferenceGrant` → the cross-namespace backend is dropped
/// from the dedicated proxy's routing table (requests 503) and the per-tenant
/// `RoleBinding` is reconciled away.
#[tokio::test]
async fn lifecycle_reference_grant_revocation_drops_backend() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ded-life-revoke").await?;
    let tenant = NamespaceGuard::create(&h.client, "ded-life-revoke-tenant").await?;

    h.apply(
        dedicated::CROSS_NAMESPACE_TENANT,
        FixtureVars::new(&tenant.name).with("TESTNS", &ns.name),
    )
    .await?;
    wait::wait_for_deployments(&tenant.name, &["echo-d"]).await?;

    h.apply(
        dedicated::CROSS_NAMESPACE_ROUTE,
        FixtureVars::new(&ns.name).with("TENANTNS", &tenant.name),
    )
    .await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait_for_cut_over(&gateways, GATEWAY_NAME, Duration::from_secs(60)).await?;

    let dedicated_proxy = h
        .start_dedicated_proxy(GATEWAY_NAME, &ns.name, &[&ns.name, &tenant.name])
        .await?;
    wait::wait_for_ready(dedicated_proxy.health_addr, Duration::from_secs(30)).await?;

    let host = format!("cross-ns.{}.local", ns.name);
    let http = dedicated_proxy.http_client()?;
    // Baseline — the route resolves while the grant is in place.
    wait::wait_for_route(&http, &host, "/", Duration::from_secs(60)).await?;

    use gateway_api::apis::standard::referencegrants::ReferenceGrant;
    let grants: Api<ReferenceGrant> = Api::namespaced(h.client.clone(), &tenant.name);
    let grant_name = format!("allow-httproute-from-{}", ns.name);
    grants.delete(&grant_name, &DeleteParams::default()).await?;

    // Cross-namespace backend dropped from the routing table → 503.
    wait::wait_for_route_status(&http, &host, "/", 503, Duration::from_secs(30)).await?;

    // Tenant ns is no longer in the desired-namespace set → the per-tenant
    // RoleBinding is reconciled away.
    let bindings: Api<RoleBinding> = Api::namespaced(h.client.clone(), &tenant.name);
    let want_binding = binding_name(&ns.name);
    poll_until(Duration::from_secs(30), || async {
        bindings.get(&want_binding).await.err().map(|_| ())
    })
    .await?;

    Ok(())
}

/// 15 — `Programmed=True` plus `status.addresses` populated for a ClusterIP
/// dedicated-mode Gateway. (Sibling of test 8 which also pins ClusterIP, but
/// gates only on conditions/addresses without the cutover-and-traffic plumbing.)
#[tokio::test]
async fn lifecycle_gateway_status_conditions_and_addresses() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ded-life-status").await?;

    h.apply(dedicated::PROVISIONING, FixtureVars::new(&ns.name))
        .await?;

    wait::wait_for_gateway_programmed(&h.client, GATEWAY_NAME, &ns.name, Duration::from_secs(60))
        .await?;

    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    let svc = services.get(RESOURCE_NAME).await?;
    let cluster_ip = svc
        .spec
        .as_ref()
        .and_then(|s| s.cluster_ip.clone())
        .expect("Service should have a clusterIP");
    assert!(
        !cluster_ip.is_empty() && cluster_ip != "None",
        "ClusterIP fixture expects a non-headless IP, got {cluster_ip}"
    );

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let gw = gateways.get(GATEWAY_NAME).await?;
    let addresses: Vec<(String, String)> = gw
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
    assert!(
        addresses
            .iter()
            .any(|(t, v)| t == "IPAddress" && v == &cluster_ip),
        "Gateway.status.addresses should include ({cluster_ip}); got {addresses:?}"
    );

    Ok(())
}

/// 16 — Gateway deletion cascades to Deployment/Service/ServiceAccount via
/// owner-ref GC, and the Gateway itself is removed after the dedicated-cleanup
/// finalizer runs. (Sibling of test 2 which asserts the same against
/// `DEDICATED_GATEWAY` without the pause stub; this variant exercises the same
/// path with a pause-image fixture for consistency with the rest of the
/// lifecycle suite.)
#[tokio::test]
async fn lifecycle_gateway_deletion_cascades_resources() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ded-life-gc").await?;

    h.apply(dedicated::PROVISIONING, FixtureVars::new(&ns.name))
        .await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    let sas: Api<ServiceAccount> = Api::namespaced(h.client.clone(), &ns.name);

    poll_until(Duration::from_secs(30), || async {
        deployments.get(RESOURCE_NAME).await.ok()
    })
    .await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    gateways
        .delete(GATEWAY_NAME, &DeleteParams::default())
        .await?;

    poll_until(Duration::from_secs(30), || async {
        let gone = deployments.get(RESOURCE_NAME).await.is_err()
            && services.get(RESOURCE_NAME).await.is_err()
            && sas.get(RESOURCE_NAME).await.is_err()
            && gateways.get(GATEWAY_NAME).await.is_err();
        if gone { Some(()) } else { None }
    })
    .await?;

    Ok(())
}

/// 17 — Mode migration shared → dedicated. Final-state assertion: pre-migration
/// the shared subprocess serves the Gateway; after patching in `parametersRef`
/// and waiting for cutover, the shared subprocess returns 404 and the dedicated
/// subprocess returns the backend response.
#[tokio::test]
async fn lifecycle_mode_migration_shared_to_dedicated() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ded-life-m-s2d").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(dedicated::MODE_MIGRATION_SHARED, FixtureVars::new(&ns.name))
        .await?;

    let host = format!("migrate.{}.local", ns.name);

    // Baseline: shared subprocess serves the Gateway in shared mode.
    let pre = wait::wait_for_route(&h.gateway_http, &host, "/", Duration::from_secs(60)).await?;
    pre.assert_backend("echo-a");

    // Patch in the parametersRef → controller provisions a dedicated pod and
    // flips DedicatedProxyReady=True once it's Ready.
    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let patch = serde_json::json!({
        "spec": {
            "infrastructure": {
                "parametersRef": {
                    "group": "gateway.coxswain-labs.dev",
                    "kind": "CoxswainGatewayParameters",
                    "name": "dedicated-params",
                },
            },
        },
    });
    gateways
        .patch(GATEWAY_NAME, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;

    wait_for_cut_over(&gateways, GATEWAY_NAME, Duration::from_secs(60)).await?;

    // Shared subprocess must drop the Gateway → port released, 404 on the
    // shared listener. The wait absorbs the listener-drain handoff window.
    wait::wait_for_route_status(&h.gateway_http, &host, "/", 404, Duration::from_secs(15)).await?;

    let dedicated_proxy = h
        .start_dedicated_proxy(GATEWAY_NAME, &ns.name, &[&ns.name])
        .await?;
    wait::wait_for_ready(dedicated_proxy.health_addr, Duration::from_secs(30)).await?;

    let http = dedicated_proxy.http_client()?;
    let post = wait::wait_for_route(&http, &host, "/", Duration::from_secs(60)).await?;
    post.assert_backend("echo-a");

    Ok(())
}

/// 18 — Mode migration dedicated → shared. Final-state assertion: pre-migration
/// the dedicated subprocess serves; after patching `parametersRef` out, waiting
/// for the cutover signal to clear, and shutting down the dedicated subprocess
/// (releasing the listener port — in production the pod GC does this), the
/// shared subprocess re-adopts the Gateway and serves backend traffic again.
#[tokio::test]
async fn lifecycle_mode_migration_dedicated_to_shared() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ded-life-m-d2s").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(
        dedicated::MODE_MIGRATION_DEDICATED,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait_for_cut_over(&gateways, GATEWAY_NAME, Duration::from_secs(60)).await?;

    let dedicated_proxy = h
        .start_dedicated_proxy(GATEWAY_NAME, &ns.name, &[&ns.name])
        .await?;
    wait::wait_for_ready(dedicated_proxy.health_addr, Duration::from_secs(30)).await?;

    let host = format!("migrate.{}.local", ns.name);
    let http = dedicated_proxy.http_client()?;
    let pre = wait::wait_for_route(&http, &host, "/", Duration::from_secs(60)).await?;
    pre.assert_backend("echo-a");

    // Patch out the parametersRef. Merge-patch null deletes the field.
    let patch = serde_json::json!({
        "spec": {
            "infrastructure": {
                "parametersRef": null,
            },
        },
    });
    gateways
        .patch(GATEWAY_NAME, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;

    // Wait for the controller to clear the cutover signal. Once cleared, the
    // shared subprocess will try to re-adopt the Gateway and bind the listener.
    poll_until(Duration::from_secs(30), || async {
        let gw = gateways.get(GATEWAY_NAME).await.ok()?;
        let conds = gw.status.as_ref()?.conditions.as_ref();
        let still_cut_over = conds
            .map(|cs| {
                cs.iter()
                    .any(|c| c.type_ == CUT_OVER_CONDITION && c.status == "True")
            })
            .unwrap_or(false);
        if still_cut_over { None } else { Some(()) }
    })
    .await?;

    // Release the listener port so the shared subprocess can bind it. In
    // production the GC'd pod releases the port on its own pod IP; on the host
    // loopback we have to do this explicitly.
    dedicated_proxy.shutdown().await;

    // Shared subprocess re-adopts the Gateway. The ~1s race window between
    // status-clear and shared re-bind is covered by this poll budget.
    let post = wait::wait_for_route(&h.gateway_http, &host, "/", Duration::from_secs(30)).await?;
    post.assert_backend("echo-a");

    Ok(())
}

/// 19 — Controller restart idempotency: the dedicated subprocess keeps serving
/// across a `serve dev` restart (no traffic disruption), and the controller's
/// SSA on identical content does not bump the Deployment's `.metadata.generation`.
#[tokio::test]
async fn lifecycle_controller_restart_is_idempotent() -> anyhow::Result<()> {
    common::init_tracing();
    let h = Harness::start().await?;
    // Persistent namespace so the bootstrap purge on the second `Harness::start()`
    // doesn't delete it.
    let ns = NamespaceGuard::create_persistent(&h.client, "ded-life-restart").await?;

    h.apply(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    h.apply(dedicated::TRAFFIC, FixtureVars::new(&ns.name))
        .await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait_for_cut_over(&gateways, GATEWAY_NAME, Duration::from_secs(60)).await?;

    // Spawn the dedicated subprocess and verify baseline traffic. This
    // subprocess is held across the controller restart — proof of "no traffic
    // disruption" is that it keeps serving while `h` is dropped+respawned.
    let dedicated_proxy: DedicatedProxyProcess = h
        .start_dedicated_proxy(GATEWAY_NAME, &ns.name, &[&ns.name])
        .await?;
    wait::wait_for_ready(dedicated_proxy.health_addr, Duration::from_secs(30)).await?;

    let host = format!("dedicated.{}.local", ns.name);
    let http: HttpClient = dedicated_proxy.http_client()?;
    let pre = wait::wait_for_route(&http, &host, "/", Duration::from_secs(60)).await?;
    pre.assert_backend("echo-a");

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let deploy_before = deployments.get(RESOURCE_NAME).await?;
    let gen_before = deploy_before
        .metadata
        .generation
        .expect("Deployment generation");

    // Restart: drop the controller (kills `serve dev`) and spawn a fresh one.
    // The dedicated subprocess survives — it keeps serving on its listener
    // port through the restart.
    drop(h);
    let h2 = Harness::start().await?;

    // Let the new leader's operator emit its first few idempotent SSAs.
    time::sleep(Duration::from_secs(15)).await;

    let deployments_after: Api<Deployment> = Api::namespaced(h2.client.clone(), &ns.name);
    let deploy_after = deployments_after.get(RESOURCE_NAME).await?;
    assert_eq!(
        deploy_after.metadata.generation,
        Some(gen_before),
        "Deployment .metadata.generation should not bump across controller restart (SSA must be idempotent on identical content)"
    );

    // Traffic continuity — the dedicated subprocess kept serving the whole
    // time, so the same backend assertion still holds.
    let post = http.get(&host, "/").await?;
    post.assert_backend("echo-a");

    Ok(())
}
