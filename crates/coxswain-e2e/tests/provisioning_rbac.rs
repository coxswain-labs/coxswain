#![allow(missing_docs)]
//! Provisioning & RBAC control-plane: the dedicated-proxy operator and its
//! ServiceAccount surface.
//!
//! Plane: **control-plane**. Execution: **mixed** — most tests own a fresh
//! namespace and a fresh dedicated Gateway (parallel-safe); the read-only-proxy
//! audit reads cluster-scoped RBAC.
//!
//! Classification rule: a test belongs to the plane of its *primary assertion
//! target*. "A resource is provisioned / GC'd / a binding exists" is
//! control-plane even if it sends a probe. Covers dedicated-proxy resource
//! provisioning (GEP-1762 labels, owner refs, SSA), garbage collection,
//! per-namespace + cluster-wide RBAC RoleBinding lifecycle + drift recovery,
//! `--proxy-watch-namespaces` rendering, ReferenceGrant-gated cross-namespace
//! backends, the dedicated proxy serving traffic end-to-end, and the structural
//! read-only-proxy ServiceAccount audit (zero write verbs).
//!
//! Note: `lifecycle_dedicated_proxy_routes_traffic` and
//! `lifecycle_cross_namespace_backend` assert traffic, but are kept here with the
//! dedicated-provisioning lifecycle they validate (and share its helper set)
//! rather than in `routing.rs`. Controller-restart and mode-migration lifecycle
//! tests live in `resilience.rs`; the #211 status-writer tests in
//! `status_conditions.rs`. Shared dedicated helpers live in `common::dedicated`.

use coxswain_e2e::{
    FixtureVars, Harness, NamespaceGuard,
    fixtures::{self, backends, dedicated_proxy as dedicated, ingress},
    harness::{HttpClient, wait},
};
use gateway_api::apis::standard::gateways::Gateway;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Secret, Service, ServiceAccount};
use k8s_openapi::api::events::v1::Event;
use k8s_openapi::api::rbac::v1::{ClusterRoleBinding, RoleBinding};
use kube::api::{Api, DeleteParams, ListParams, ObjectMeta, Patch, PatchParams, PostParams};
use serde_json::json;
use std::collections::HashSet;
use std::process::Command;
use std::time::Duration;

mod common;
use common::dedicated::{
    GATEWAY_NAME, RESOURCE_NAME, apply_and_wait, assert_provisioning_contract, binding_name,
    cluster_route_binding_name, wait_for_cut_over,
};

/// 1. Apply a dedicated-mode Gateway → assert all three resources are created
///    with the GEP-1762 labels (including merged infrastructure labels), the
///    correct owner reference back to the Gateway, and the SSA field manager
///    set to `"coxswain-controller"`.
#[tokio::test]
async fn provisions_resources_for_dedicated_proxy() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-dedgw-create").await?;

    let (_, _, _, deploy, svc, sa) = apply_and_wait(&h, &ns).await?;

    // GEP-1762 labels + owner reference + SSA field manager (shared contract).
    assert_provisioning_contract(&deploy, &svc, &sa);

    // Fixture-specific: this fixture sets `infrastructure.labels`/`annotations`,
    // which must merge onto every provisioned resource.
    for (kind, meta) in [
        ("Deployment", &deploy.metadata),
        ("Service", &svc.metadata),
        ("ServiceAccount", &sa.metadata),
    ] {
        let labels = meta.labels.as_ref().unwrap_or_else(|| {
            panic!("{kind}: labels missing");
        });
        assert_eq!(
            labels.get("team").map(String::as_str),
            Some("platform"),
            "{kind}: infrastructure.labels.team should merge"
        );
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

    Ok(())
}

/// 2. Delete the Gateway → assert all three resources are garbage-collected
///    within 30 s via the owner-ref cascade. No explicit deletion of the
///    provisioned resources; K8s GC drives it from the owner reference.
#[tokio::test]
async fn gateway_deletion_garbage_collects_resources() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-dedgw-gc").await?;

    let (deployments, services, sas, _, _, _) = apply_and_wait(&h, &ns).await?;

    // Delete the Gateway and wait for GC to cascade.
    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    gateways
        .delete(GATEWAY_NAME, &DeleteParams::default())
        .await?;

    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            format!("Deployment/Service/ServiceAccount '{RESOURCE_NAME}' to be garbage-collected")
        },
        || async {
            let deploy_gone = deployments.get(RESOURCE_NAME).await.is_err();
            let svc_gone = services.get(RESOURCE_NAME).await.is_err();
            let sa_gone = sas.get(RESOURCE_NAME).await.is_err();
            (deploy_gone && svc_gone && sa_gone).then_some(())
        },
    )
    .await?;

    Ok(())
}

/// 4. Apply a dedicated-mode Gateway with a same-namespace HTTPRoute → assert
///    the controller creates a `RoleBinding` `coxswain-<ns>-<gw-name>` in the
///    Gateway's own namespace, with the discovery labels set and bound to the
///    `coxswain-gateway-proxy-reader` ClusterRole.
#[tokio::test]
async fn provisions_role_binding_in_gateway_namespace() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-dedgw-rbac-own").await?;

    fixtures::apply_fixture(
        dedicated::DEDICATED_GATEWAY_WITH_ROUTE,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let bindings: Api<RoleBinding> = Api::namespaced(h.client.clone(), &ns.name);
    let want_name = binding_name(&ns.name);
    let rb = wait::wait_for_resource(&bindings, &want_name, Duration::from_secs(15)).await?;

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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-dedgw-rbac-gc").await?;

    fixtures::apply_fixture(
        dedicated::DEDICATED_GATEWAY_WITH_ROUTE,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let bindings: Api<RoleBinding> = Api::namespaced(h.client.clone(), &ns.name);
    let want_name = binding_name(&ns.name);

    // Wait for the binding to be present before we delete the Gateway, so the
    // subsequent "binding gone" assertion is meaningful.
    wait::wait_for_resource(&bindings, &want_name, Duration::from_secs(15)).await?;

    // Delete the Gateway. The finalizer keeps it alive until the controller
    // clears bindings + removes the finalizer.
    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    gateways
        .delete(GATEWAY_NAME, &DeleteParams::default())
        .await?;

    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            format!(
                "RoleBinding {want_name} + all managed bindings + Gateway {GATEWAY_NAME} to be cleaned up"
            )
        },
        || async {
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
            (binding_gone && leftover == 0 && gateway_gone).then_some(())
        },
    )
    .await?;

    Ok(())
}

/// 6. Drift detection: out-of-band delete of a managed `RoleBinding` triggers
///    the controller to re-create it within ~5 s via the RoleBinding
///    cross-watch (`watches(... managed-by=coxswain ...)`).
#[tokio::test]
async fn out_of_band_binding_deletion_is_recreated() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-dedgw-rbac-drift").await?;

    fixtures::apply_fixture(
        dedicated::DEDICATED_GATEWAY_WITH_ROUTE,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let bindings: Api<RoleBinding> = Api::namespaced(h.client.clone(), &ns.name);
    let want_name = binding_name(&ns.name);
    let original = wait::wait_for_resource(&bindings, &want_name, Duration::from_secs(15)).await?;
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
    let recreated = wait::wait_for_resource(&bindings, &want_name, Duration::from_secs(15)).await?;
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
///    carries the discovery SVID-bootstrap wiring (#423) — bootstrap endpoint,
///    projected-token path, CA-bundle path, trust domain — so the dedicated
///    proxy can authenticate to the controller and open the mTLS Stream.
///
/// (`--proxy-watch-namespaces` was retired in #424 when the proxy became a pure
/// discovery client: it no longer watches namespaces, the controller pushes
/// pre-scoped routing snapshots, and namespace-read RBAC is provisioned
/// controller-side as RoleBindings — covered by the lifecycle tests below.)
#[tokio::test]
async fn deployment_container_carries_discovery_bootstrap_args() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-dedgw-rbac-args").await?;

    fixtures::apply_fixture(
        dedicated::DEDICATED_GATEWAY_WITH_ROUTE,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let deploy =
        wait::wait_for_resource(&deployments, RESOURCE_NAME, Duration::from_secs(15)).await?;

    let pod_spec = deploy
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .expect("dedicated proxy pod spec present");
    let coxswain = pod_spec
        .containers
        .iter()
        .find(|c| c.name == "coxswain")
        .expect("coxswain container present");
    let args = coxswain.args.as_ref().expect("args set");
    for needle in [
        "--discovery-bootstrap-endpoint=",
        "--discovery-sa-token-path=",
        "--discovery-ca-bundle-path=",
        "--discovery-trust-domain=",
    ] {
        assert!(
            args.iter().any(|a| a.starts_with(needle)),
            "dedicated proxy must render {needle} for SVID bootstrap; got {args:?}"
        );
    }

    // The projected SA-token and trust-bundle volumes must be mounted, else the
    // bootstrap args point at empty paths and the proxy can never get an SVID.
    let mounts = coxswain
        .volume_mounts
        .as_ref()
        .expect("coxswain container must mount the discovery token + trust volumes");
    for vol in ["discovery-token", "trust-bundle"] {
        assert!(
            mounts.iter().any(|m| m.name == vol),
            "dedicated proxy must mount the '{vol}' volume; got {mounts:?}"
        );
    }

    Ok(())
}

// ── Per-field CoxswainGatewayParameters coverage (#333) ──────────────────────
//
// The happy-path provisioning tests assert only the GEP-1762 contract (labels,
// owner refs, SSA manager), never the individual tunables. Each parameter field
// is an independent mapping with its own failure mode, so it gets one atomic
// test (charter #2) — a failure names the exact field that stopped rendering.
// All five share the `DEDICATED_GATEWAY_FIELDS` fixture (every knob set) and
// assert their own field against the rendered objects.

/// Provision the all-fields dedicated Gateway in `ns` and return the rendered
/// Deployment + Service for the per-field assertions below.
async fn provision_field_gateway(
    h: &Harness,
    ns: &NamespaceGuard,
) -> anyhow::Result<(Deployment, Service)> {
    fixtures::apply_fixture(
        dedicated::DEDICATED_GATEWAY_FIELDS,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    let deploy =
        wait::wait_for_resource(&deployments, RESOURCE_NAME, Duration::from_secs(15)).await?;
    let svc = wait::wait_for_resource(&services, RESOURCE_NAME, Duration::from_secs(15)).await?;
    Ok((deploy, svc))
}

/// The `coxswain` container of the rendered dedicated-proxy Deployment.
fn coxswain_container(deploy: &Deployment) -> &k8s_openapi::api::core::v1::Container {
    deploy
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .map(|s| s.containers.as_slice())
        .unwrap_or_default()
        .iter()
        .find(|c| c.name == "coxswain")
        .unwrap_or_else(|| panic!("coxswain container present"))
}

/// #333 — `replicas` renders to `Deployment.spec.replicas`.
#[tokio::test]
async fn params_replicas_sets_deployment_replicas() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-dedgw-replicas").await?;
    let (deploy, _) = provision_field_gateway(&h, &ns).await?;
    assert_eq!(
        deploy.spec.as_ref().and_then(|s| s.replicas),
        Some(3),
        "replicas should render to Deployment.spec.replicas"
    );
    Ok(())
}

/// #333 — `image` renders to the `coxswain` container image.
#[tokio::test]
async fn params_image_sets_container_image() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-dedgw-image").await?;
    let (deploy, _) = provision_field_gateway(&h, &ns).await?;
    assert_eq!(
        coxswain_container(&deploy).image.as_deref(),
        Some("registry.invalid/custom-proxy:v9"),
        "image override should render to the coxswain container image"
    );
    Ok(())
}

/// #333 — `resources` render to the `coxswain` container requests/limits.
#[tokio::test]
async fn params_resources_set_container_resources() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-dedgw-resources").await?;
    let (deploy, _) = provision_field_gateway(&h, &ns).await?;
    let resources = coxswain_container(&deploy)
        .resources
        .as_ref()
        .expect("container resources");
    let requests = resources.requests.as_ref().expect("resource requests");
    assert_eq!(
        requests.get("cpu").map(|q| q.0.as_str()),
        Some("125m"),
        "cpu request should render"
    );
    assert_eq!(
        requests.get("memory").map(|q| q.0.as_str()),
        Some("64Mi"),
        "memory request should render"
    );
    let limits = resources.limits.as_ref().expect("resource limits");
    assert_eq!(
        limits.get("cpu").map(|q| q.0.as_str()),
        Some("250m"),
        "cpu limit should render"
    );
    assert_eq!(
        limits.get("memory").map(|q| q.0.as_str()),
        Some("128Mi"),
        "memory limit should render"
    );
    Ok(())
}

/// #333 — `podTemplate` merges onto the rendered pod template (label + nodeSelector).
#[tokio::test]
async fn params_pod_template_merges_onto_template() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-dedgw-podtemplate").await?;
    let (deploy, _) = provision_field_gateway(&h, &ns).await?;
    let tmpl = &deploy.spec.as_ref().expect("Deployment spec").template;
    let labels = tmpl
        .metadata
        .as_ref()
        .and_then(|m| m.labels.as_ref())
        .expect("pod template labels");
    assert_eq!(
        labels.get("tier").map(String::as_str),
        Some("edge"),
        "podTemplate label should merge onto the rendered pod template"
    );
    let node_selector = tmpl
        .spec
        .as_ref()
        .and_then(|s| s.node_selector.as_ref())
        .expect("podTemplate nodeSelector");
    assert_eq!(
        node_selector
            .get("coxswain-labs.dev/pool")
            .map(String::as_str),
        Some("edge"),
        "podTemplate nodeSelector should merge onto the rendered pod template"
    );
    Ok(())
}

/// #333 — `serviceType: NodePort` renders to `Service.spec.type`.
#[tokio::test]
async fn params_service_type_sets_service_type() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-dedgw-svctype").await?;
    let (_, svc) = provision_field_gateway(&h, &ns).await?;
    assert_eq!(
        svc.spec.as_ref().and_then(|s| s.type_.as_deref()),
        Some("NodePort"),
        "serviceType should render to Service.spec.type"
    );
    Ok(())
}

/// 11 — Apply a dedicated-mode Gateway → assert Deployment/Service/ServiceAccount
/// land with the GEP-1762 labels, owner references back to the Gateway, and the
/// SSA field manager set to `coxswain-controller`.
#[tokio::test]
async fn lifecycle_provisioning_creates_resources() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-ded-life-prov").await?;

    fixtures::apply_fixture(dedicated::PROVISIONING, FixtureVars::new(&ns.name)).await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    let sas: Api<ServiceAccount> = Api::namespaced(h.client.clone(), &ns.name);

    let deploy =
        wait::wait_for_resource(&deployments, RESOURCE_NAME, Duration::from_secs(30)).await?;
    let svc = wait::wait_for_resource(&services, RESOURCE_NAME, Duration::from_secs(30)).await?;
    let sa = wait::wait_for_resource(&sas, RESOURCE_NAME, Duration::from_secs(30)).await?;

    // GEP-1762 labels + owner reference + SSA field manager (shared contract).
    assert_provisioning_contract(&deploy, &svc, &sa);

    Ok(())
}

/// 12 — Spawn a dedicated-proxy host subprocess once the controller has flipped
/// `DedicatedProxyReady=True`, send a GET via the Gateway listener, assert the
/// expected backend.
#[tokio::test]
#[ignore = "dedicated-over-discovery clobbers shared routing cells under concurrent provisioning; unignore when per-proxy scope filtering lands (#426)"]
async fn lifecycle_dedicated_proxy_routes_traffic() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-ded-life-traffic").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(dedicated::TRAFFIC, FixtureVars::new(&ns.name)).await?;

    // Wait for the controller to flip DedicatedProxyReady=True (cutover).
    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait_for_cut_over(&gateways, GATEWAY_NAME, Duration::from_secs(60)).await?;

    // The operator provisions a LoadBalancer Service for the dedicated pod;
    // wait for it to get a real IP then verify traffic flows through it.
    let dedicated_addr =
        wait::wait_for_dedicated_proxy_endpoint(&ns.name, GATEWAY_NAME, Duration::from_secs(60))
            .await?;
    let http = HttpClient::new(dedicated_addr)?;

    let host = format!("dedicated.{}.local", ns.name);
    let resp = wait::wait_for_route(&http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    // Negative (#210 cut-over): once DedicatedProxyReady=True the shared pool must
    // relinquish the Gateway — without this the shared pool could double-serve the
    // same Gateway the dedicated pod now owns.
    //
    // Assert this against the shared proxy's OWN routing table, not by probing its
    // listener for a 404: Gateway listener ports are bound dynamically and the
    // socket is released once no shared Gateway uses the port (see
    // docs/src/guides/running-in-production.md — "removed ports … socket is
    // released"). With this the only Gateway, the shared proxy unbinds the gateway
    // port entirely, so a data-plane probe is TCP-refused, never a 404. The
    // relinquish is faithfully observed as the host leaving `/api/v1/routes`.
    let routes_url = h.admin_url("/api/v1/routes");
    let client = reqwest::Client::new();
    let still_serving = |json: &serde_json::Value, host: &str| -> bool {
        json["gateway"]["hosts"]
            .as_array()
            .is_some_and(|hosts| hosts.iter().any(|e| e["host"].as_str() == Some(host)))
    };
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            let state = match client.get(&routes_url).send().await {
                Ok(r) => match r.json::<serde_json::Value>().await {
                    Ok(j) => format!("still serving = {}", still_serving(&j, &host)),
                    Err(e) => format!("routes body parse error: {e}"),
                },
                Err(e) => format!("routes request error: {e}"),
            };
            format!("shared proxy to drop '{host}' from its gateway routing table; {state}")
        },
        || async {
            let json = client
                .get(&routes_url)
                .send()
                .await
                .ok()?
                .json::<serde_json::Value>()
                .await
                .ok()?;
            (!still_serving(&json, &host)).then_some(())
        },
    )
    .await?;

    Ok(())
}

/// 13 — An HTTPRoute with a backend Service in a different namespace resolves
/// via `ReferenceGrant`. The per-tenant `RoleBinding` is provisioned for the
/// dedicated proxy ServiceAccount, and traffic flows through the dedicated
/// subprocess.
#[tokio::test]
#[ignore = "dedicated-over-discovery clobbers shared routing cells under concurrent provisioning; unignore when per-proxy scope filtering lands (#426)"]
async fn lifecycle_cross_namespace_backend() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-ded-life-xns").await?;
    let tenant = NamespaceGuard::create(&h.client, "prov-ded-life-xns-tenant").await?;

    fixtures::apply_fixture(
        dedicated::CROSS_NAMESPACE_TENANT,
        FixtureVars::new(&tenant.name).with("TESTNS", &ns.name),
    )
    .await?;
    wait::wait_for_deployments(&tenant.name, &["echo-d"]).await?;

    fixtures::apply_fixture(
        dedicated::CROSS_NAMESPACE_ROUTE,
        FixtureVars::new(&ns.name).with("TENANTNS", &tenant.name),
    )
    .await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait_for_cut_over(&gateways, GATEWAY_NAME, Duration::from_secs(60)).await?;

    let bindings: Api<RoleBinding> = Api::namespaced(h.client.clone(), &tenant.name);
    let want_binding = binding_name(&ns.name);
    wait::wait_for_resource(&bindings, &want_binding, Duration::from_secs(30)).await?;

    let dedicated_addr =
        wait::wait_for_dedicated_proxy_endpoint(&ns.name, GATEWAY_NAME, Duration::from_secs(60))
            .await?;
    let http = HttpClient::new(dedicated_addr)?;

    let host = format!("cross-ns.{}.local", ns.name);
    let resp = wait::wait_for_route(&http, &host, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-d");

    Ok(())
}

/// 14 — Delete the `ReferenceGrant` → the cross-namespace backend is dropped
/// from the dedicated proxy's routing table (requests 503) and the per-tenant
/// `RoleBinding` is reconciled away.
#[tokio::test]
#[ignore = "dedicated-over-discovery clobbers shared routing cells under concurrent provisioning; unignore when per-proxy scope filtering lands (#426)"]
async fn lifecycle_reference_grant_revocation_drops_backend() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-ded-life-revoke").await?;
    let tenant = NamespaceGuard::create(&h.client, "prov-ded-life-revoke-tenant").await?;

    fixtures::apply_fixture(
        dedicated::CROSS_NAMESPACE_TENANT,
        FixtureVars::new(&tenant.name).with("TESTNS", &ns.name),
    )
    .await?;
    wait::wait_for_deployments(&tenant.name, &["echo-d"]).await?;

    fixtures::apply_fixture(
        dedicated::CROSS_NAMESPACE_ROUTE,
        FixtureVars::new(&ns.name).with("TENANTNS", &tenant.name),
    )
    .await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait_for_cut_over(&gateways, GATEWAY_NAME, Duration::from_secs(60)).await?;

    let dedicated_addr =
        wait::wait_for_dedicated_proxy_endpoint(&ns.name, GATEWAY_NAME, Duration::from_secs(60))
            .await?;
    let http = HttpClient::new(dedicated_addr)?;

    let host = format!("cross-ns.{}.local", ns.name);
    // Baseline — the route resolves while the grant is in place.
    wait::wait_for_route(&http, &host, "/", Duration::from_secs(60)).await?;

    use gateway_api::apis::standard::referencegrants::ReferenceGrant;
    let grants: Api<ReferenceGrant> = Api::namespaced(h.client.clone(), &tenant.name);
    let grant_name = format!("allow-httproute-from-{}", ns.name);
    grants.delete(&grant_name, &DeleteParams::default()).await?;

    // Cross-namespace backend dropped from the routing table → reflector
    // installs an "error route" returning 500 ("No ready endpoints for rule —
    // installing error route (500)"; see `gateway_api::reconcile`).
    wait::wait_for_route_status(&http, &host, "/", 500, Duration::from_secs(30)).await?;

    // Tenant ns is no longer in the desired-namespace set → the per-tenant
    // RoleBinding is reconciled away.
    let bindings: Api<RoleBinding> = Api::namespaced(h.client.clone(), &tenant.name);
    let want_binding = binding_name(&ns.name);
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async { format!("per-tenant RoleBinding {want_binding} to be reconciled away") },
        || async { bindings.get(&want_binding).await.err().map(|_| ()) },
    )
    .await?;

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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-ded-life-gc").await?;

    fixtures::apply_fixture(dedicated::PROVISIONING, FixtureVars::new(&ns.name)).await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    let sas: Api<ServiceAccount> = Api::namespaced(h.client.clone(), &ns.name);

    wait::wait_for_resource(&deployments, RESOURCE_NAME, Duration::from_secs(30)).await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    gateways
        .delete(GATEWAY_NAME, &DeleteParams::default())
        .await?;

    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            format!(
                "Deployment/Service/ServiceAccount '{RESOURCE_NAME}' and Gateway {GATEWAY_NAME} to be garbage-collected"
            )
        },
        || async {
            let gone = deployments.get(RESOURCE_NAME).await.is_err()
                && services.get(RESOURCE_NAME).await.is_err()
                && sas.get(RESOURCE_NAME).await.is_err()
                && gateways.get(GATEWAY_NAME).await.is_err();
            gone.then_some(())
        },
    )
    .await?;

    Ok(())
}

/// 21. `from: All` listener → controller auto-provisions a `ClusterRoleBinding`
///     for cluster-wide `HTTPRoute` reads. Flipping the listener back to
///     `from: Same` removes the binding on the next reconcile.
///
/// The cluster-wide-read decision moved controller-side in #424 (the proxy is a
/// pure discovery client and no longer reads routes, so `--allow-cluster-wide-
/// route-read` was retired); the controller still derives the flag and
/// provisions/removes the `ClusterRoleBinding` — which is what this verifies.
#[tokio::test]
async fn cluster_wide_binding_created_and_removed_with_listener_mode() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-dedgw-clusterwide-toggle").await?;

    // Gateway fixture with from: All.
    fixtures::apply_fixture(
        dedicated::DEDICATED_GATEWAY_FROM_ALL,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let gw_name = "dedicated-gw-from-all";
    let crb_name = cluster_route_binding_name(&ns.name, gw_name);

    let crbs: Api<ClusterRoleBinding> = Api::all(h.client.clone());

    // 1. ClusterRoleBinding appears within 15 s.
    wait::wait_for_resource(&crbs, &crb_name, Duration::from_secs(15)).await?;

    // 2. Patch the listener to from: Same — the binding must disappear.
    // SSA requires apiVersion + kind in the payload.
    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let patch = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": gw_name, "namespace": &ns.name },
        "spec": {
            "gatewayClassName": "coxswain",
            "infrastructure": {
                "parametersRef": {
                    "group": "gateway.coxswain-labs.dev",
                    "kind": "CoxswainGatewayParameters",
                    "name": "dedicated-params-from-all"
                }
            },
            "listeners": [{
                "name": "http",
                "port": 8200,
                "protocol": "HTTP",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]
        }
    });
    gateways
        .patch(
            gw_name,
            &PatchParams::apply("e2e-test").force(),
            &Patch::Apply(patch),
        )
        .await?;

    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            format!("ClusterRoleBinding {crb_name} to be removed after reverting the listener to from: Same")
        },
        || async { crbs.get(&crb_name).await.is_err().then_some(()) },
    )
    .await?;

    Ok(())
}

/// 22. Gateway deletion drives `ClusterRoleBinding` cleanup: the finalizer
///     keeps the Gateway alive until the controller removes both per-namespace
///     `RoleBinding`s and any cluster-wide `ClusterRoleBinding`s, then removes
///     the finalizer.
#[tokio::test]
async fn cluster_wide_binding_deleted_on_gateway_deletion() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-dedgw-clusterwide-gc").await?;

    fixtures::apply_fixture(
        dedicated::DEDICATED_GATEWAY_FROM_ALL,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let gw_name = "dedicated-gw-from-all";
    let crb_name = cluster_route_binding_name(&ns.name, gw_name);

    let crbs: Api<ClusterRoleBinding> = Api::all(h.client.clone());
    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);

    // Wait for the binding to exist before deleting — makes the "binding gone"
    // assertion below meaningful.
    wait::wait_for_resource(&crbs, &crb_name, Duration::from_secs(15)).await?;

    gateways.delete(gw_name, &DeleteParams::default()).await?;

    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            format!("ClusterRoleBinding {crb_name} and Gateway {gw_name} to be cleaned up after deletion")
        },
        || async {
            let crb_gone = crbs.get(&crb_name).await.is_err();
            let gw_gone = gateways.get(gw_name).await.is_err();
            (crb_gone && gw_gone).then_some(())
        },
    )
    .await?;

    Ok(())
}

// ===========================================================================
// Discovery control-plane bootstrap (#423).
//
// The shared proxy ships with ZERO pre-provisioned cert material: it acquires
// its SVID at runtime by presenting its projected ServiceAccount token to the
// controller's bootstrap listener (server-auth-only TLS), receiving a CA-signed
// SVID, then opening the mandatory-mTLS Stream to receive routing snapshots.
//
// Because the e2e harness installs via `helm --wait`, the shared-proxy pod only
// reaches Ready once that whole bootstrap chain has succeeded — so a served
// route is end-to-end proof that controller-as-CA + SA-token bootstrap +
// SVID-over-channel all work. The first test asserts the CA artifacts exist and
// that routing flows; the read-only audit below confirms the bootstrap volumes
// added no write verbs to the proxy SA.
// ===========================================================================

/// The discovery control-plane namespace (matches the harness Helm install and
/// `deploy/manifests`). CA Secret + trust ConfigMap live here.
const DISCOVERY_NAMESPACE: &str = "coxswain-system";

/// Happy path: a proxy with no pre-provisioned cert bootstraps its SVID, opens
/// the mTLS Stream, and serves a route — and the controller-as-CA artifacts
/// (CA Secret + published trust-bundle ConfigMap) exist.
#[tokio::test]
async fn zero_cert_proxy_bootstraps_and_serves_routes() -> anyhow::Result<()> {
    let h = Harness::start().await?;

    // The controller self-generated (mode=auto) the CA Secret and published the
    // public trust bundle ConfigMap proxies mount. Assert both exist with the
    // expected keys — these are the controller-as-CA artifacts the bootstrap
    // chain depends on.
    let secrets: Api<Secret> = Api::namespaced(h.client.clone(), DISCOVERY_NAMESPACE);
    let ca = secrets.get("coxswain-discovery-ca").await.map_err(|e| {
        anyhow::anyhow!("CA Secret coxswain-discovery-ca must exist in {DISCOVERY_NAMESPACE}: {e}")
    })?;
    let ca_data = ca.data.unwrap_or_default();
    assert!(
        ca_data.contains_key("tls.crt") && ca_data.contains_key("tls.key"),
        "CA Secret must carry tls.crt + tls.key, got keys: {:?}",
        ca_data.keys().collect::<Vec<_>>()
    );

    let cms: Api<ConfigMap> = Api::namespaced(h.client.clone(), DISCOVERY_NAMESPACE);
    let trust = cms.get("coxswain-discovery-trust").await.map_err(|e| {
        anyhow::anyhow!(
            "trust-bundle ConfigMap coxswain-discovery-trust must be published in \
             {DISCOVERY_NAMESPACE} (the controller publisher writes it): {e}"
        )
    })?;
    let trust_data = trust.data.unwrap_or_default();
    let bundle = trust_data.get("ca.crt").ok_or_else(|| {
        anyhow::anyhow!(
            "trust ConfigMap must carry the ca.crt key, got: {:?}",
            trust_data.keys().collect::<Vec<_>>()
        )
    })?;
    assert!(
        bundle.contains("BEGIN CERTIFICATE"),
        "trust bundle ca.crt must be PEM, got {} bytes without a PEM header",
        bundle.len()
    );

    // End-to-end proof: the bootstrapped proxy serves a route over the mTLS
    // stream it could only have opened with a valid SVID.
    let ns = NamespaceGuard::create(&h.client, "boot-serves").await?;
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("ingress.{}.local", ns.name);
    let resp = wait::wait_for_route(&h.http, &host, "/a", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    Ok(())
}

/// Sum the *occurrences* of `BootstrapRejected` Warning Events in the discovery
/// namespace.
///
/// The kube `Recorder` coalesces every same-key event into ONE Event object: its
/// key is `(type, action, reason, reportingController, reportingInstance,
/// regarding)` — the note is NOT part of the key. Every bootstrap rejection
/// shares that key (regarding is always the controller Pod, reason is always
/// `BootstrapRejected`), so the first rejection in the controller's lifetime
/// creates the object and every later one only PATCHes its `series.count`.
/// Counting event *objects* therefore stays pinned at 1 no matter how many
/// proxies are rejected — and in a shared suite another test's dedicated proxy
/// routinely emits the first `BootstrapRejected` before this test runs, so an
/// object-count delta never moves.
///
/// Summing `series.count` (an Event with no series == 1 occurrence) yields a
/// total that increments on EVERY rejection, so the before/after delta reliably
/// captures the rogue proxy's reject regardless of coalescing. Coalescing is the
/// correct production behaviour (it prevents event spam from a proxy retrying on
/// a backoff loop), so the robustness lives here in the test, not the controller.
async fn count_bootstrap_rejected(events: &Api<Event>) -> anyhow::Result<usize> {
    let list = events.list(&ListParams::default()).await?;
    Ok(list
        .items
        .iter()
        .filter(|e| e.reason.as_deref() == Some("BootstrapRejected"))
        .map(|e| {
            e.series
                .as_ref()
                .and_then(|s| usize::try_from(s.count).ok())
                .unwrap_or(1)
        })
        .sum())
}

/// Sad path: a proxy that presents a ServiceAccount token minted for the WRONG
/// audience is rejected at bootstrap. TokenReview (which the controller scopes
/// to the `coxswain-discovery` audience) fails, so no SVID is issued, the rogue
/// proxy never reaches Ready, and the controller — the sole diagnostic emitter —
/// records a `BootstrapRejected` Warning Event.
#[tokio::test]
async fn invalid_sa_token_is_rejected_with_event() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "boot-reject").await?;

    // The rogue proxy must verify the controller's server cert before it can
    // send its (bad) token, so it needs the public trust bundle. Copy the
    // controller-published ConfigMap into the rogue namespace (cross-namespace
    // ConfigMap mounts are not allowed).
    let src_cms: Api<ConfigMap> = Api::namespaced(h.client.clone(), DISCOVERY_NAMESPACE);
    let trust = src_cms.get("coxswain-discovery-trust").await.map_err(|e| {
        anyhow::anyhow!("trust ConfigMap must exist before the sad-path test can run: {e}")
    })?;
    let dst_cms: Api<ConfigMap> = Api::namespaced(h.client.clone(), &ns.name);
    dst_cms
        .create(
            &PostParams::default(),
            &ConfigMap {
                metadata: ObjectMeta {
                    name: Some("coxswain-discovery-trust".to_owned()),
                    namespace: Some(ns.name.clone()),
                    ..Default::default()
                },
                data: trust.data.clone(),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("copy trust bundle into {}: {e}", ns.name))?;

    let events: Api<Event> = Api::namespaced(h.client.clone(), DISCOVERY_NAMESPACE);
    let before = count_bootstrap_rejected(&events).await?;

    // A rogue proxy whose projected token is minted for the WRONG audience.
    // Everything else mirrors a normal shared proxy.
    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let rogue: Deployment = serde_json::from_value(json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": { "name": "rogue-proxy", "namespace": ns.name },
        "spec": {
            "replicas": 1,
            "selector": { "matchLabels": { "app": "rogue-proxy" } },
            "template": {
                "metadata": { "labels": { "app": "rogue-proxy" } },
                "spec": {
                    "containers": [{
                        "name": "coxswain",
                        "image": "coxswain:e2e",
                        "imagePullPolicy": "Never",
                        "args": ["serve", "proxy", "--shared"],
                        "env": [
                            { "name": "POD_NAME", "valueFrom": { "fieldRef": { "fieldPath": "metadata.name" } } },
                            { "name": "POD_NAMESPACE", "valueFrom": { "fieldRef": { "fieldPath": "metadata.namespace" } } },
                            { "name": "COXSWAIN_DISCOVERY_ENDPOINT", "value": "https://coxswain-controller-discovery.coxswain-system.svc:50051" },
                            { "name": "COXSWAIN_DISCOVERY_BOOTSTRAP_ENDPOINT", "value": "https://coxswain-controller-discovery.coxswain-system.svc:50052" },
                            { "name": "COXSWAIN_DISCOVERY_SA_TOKEN_PATH", "value": "/var/run/secrets/coxswain/discovery-token/token" },
                            { "name": "COXSWAIN_DISCOVERY_CA_BUNDLE_PATH", "value": "/var/run/secrets/coxswain/trust-bundle/ca.crt" },
                            { "name": "COXSWAIN_DISCOVERY_TRUST_DOMAIN", "value": "cluster.local" }
                        ],
                        "volumeMounts": [
                            { "name": "discovery-token", "mountPath": "/var/run/secrets/coxswain/discovery-token", "readOnly": true },
                            { "name": "trust-bundle", "mountPath": "/var/run/secrets/coxswain/trust-bundle", "readOnly": true }
                        ]
                    }],
                    "volumes": [
                        {
                            "name": "discovery-token",
                            "projected": {
                                "sources": [{
                                    "serviceAccountToken": {
                                        "path": "token",
                                        // Deliberately WRONG: the controller requires `coxswain-discovery`.
                                        "audience": "wrong-audience",
                                        "expirationSeconds": 3600
                                    }
                                }]
                            }
                        },
                        {
                            "name": "trust-bundle",
                            "configMap": { "name": "coxswain-discovery-trust", "optional": false }
                        }
                    ]
                }
            }
        }
    }))?;
    deployments.create(&PostParams::default(), &rogue).await?;

    // The bootstrap loop retries with backoff, so a rejection event appears
    // shortly after the rogue pod schedules.
    wait::poll_until(
        Duration::from_secs(120),
        wait::POLL,
        || async {
            "controller to emit a BootstrapRejected Warning Event for the wrong-audience token"
                .to_string()
        },
        || async {
            let now = count_bootstrap_rejected(&events).await.unwrap_or(before);
            (now > before).then_some(())
        },
    )
    .await?;

    Ok(())
}

// ===========================================================================
// Read-only-proxy ServiceAccount audit (from rbac_read_only_proxy.rs).
//
// write verbs.
//
// This is the load-bearing invariant of v0.2's controller/proxy split: a
// compromised proxy must not be able to write to Kubernetes. The chart
// enforces it by not granting any write rules in `shared-proxy-rbac.yaml`;
// this test enforces it by asking the API server.
//
// Mechanism: parse `kubectl auth can-i --list --as=<sa>` and assert that
// every verb in the right-hand column belongs to `{get, list, watch}`. The
// check is structural — it doesn't depend on which resources show up, only
// on which verbs are bound. Adding a `create` / `patch` / `update` /
// `delete` / `deletecollection` rule to the proxy ClusterRole, even on an
// unrelated resource, regresses the invariant.
//
// Two baseline-grant carve-outs:
// - `selfsubjectaccessreviews` / `selfsubjectrulesreviews` (api group
//   `authorization.k8s.io`) — every authenticated user holds `create` on
//   these via the cluster-default `system:basic-user` ClusterRoleBinding;
//   that's not the proxy's RBAC, it's Kubernetes plumbing.
// - Non-resource URLs (`/healthz`, `/version`, `/.well-known/*`) — same
//   reason, `system:public-info-viewer` grants `get` on these to every
//   authenticated user.
//
// The test skips when no cluster is reachable (kubectl unavailable, no
// kubeconfig context) so it remains runnable locally without infrastructure.
// In CI it runs against the same cluster the rest of the e2e suite targets.
// ===========================================================================

/// The ServiceAccount under audit. Matches the name rendered by both the
/// raw manifests in `deploy/manifests/shared-proxy-rbac.yaml` and the Helm
/// chart's default release-name convention (`<release>-coxswain-shared-proxy`).
const PROXY_SA_CANDIDATES: &[&str] = &[
    "coxswain-shared-proxy",
    "release-name-coxswain-shared-proxy",
];

/// Verbs the proxy is allowed to hold. Anything outside this set is a
/// regression of the read-only-proxy invariant.
const ALLOWED_VERBS: &[&str] = &["get", "list", "watch"];

/// Resource prefixes whose verbs come from baseline cluster grants
/// (`system:basic-user`, `system:public-info-viewer`), not from the
/// `coxswain-shared-proxy` ClusterRole. Excluded from the audit so the test
/// fails only on real regressions.
///
/// Every `selfsubject*` resource (under both `authorization.k8s.io` and
/// `authentication.k8s.io`) grants `create` to every authenticated principal
/// via cluster-default bindings; that's K8s plumbing, not coxswain.
const BASELINE_RESOURCE_PREFIXES: &[&str] = &["selfsubject"];

#[test]
fn shared_proxy_sa_has_only_read_verbs() {
    let Some(output) = try_auth_can_i_list() else {
        eprintln!(
            "rbac_read_only_proxy: no reachable cluster — skipping. Run against a cluster \
             with coxswain installed (helm or manifests) to enforce the invariant."
        );
        return;
    };

    let rows = parse_auth_can_i(&output);
    assert!(
        !rows.is_empty(),
        "auth can-i --list returned no rows — is the ServiceAccount actually bound? \
         Output was:\n{output}"
    );

    let allowed: HashSet<&str> = ALLOWED_VERBS.iter().copied().collect();
    let mut violations: Vec<String> = Vec::new();

    for row in &rows {
        if is_baseline_grant(row) {
            continue;
        }
        for verb in &row.verbs {
            if !allowed.contains(verb.as_str()) {
                violations.push(format!("resource={}, verb={}", row.resource, verb));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "shared-proxy ServiceAccount has write verbs — read-only invariant regressed!\n\
         {}\n\
         full kubectl output:\n{output}",
        violations.join("\n")
    );
}

/// Try each candidate SA name; return the first kubectl output that succeeded.
/// Returns `None` when no cluster is reachable or no candidate SA exists.
fn try_auth_can_i_list() -> Option<String> {
    let namespace =
        std::env::var("COXSWAIN_E2E_NAMESPACE").unwrap_or_else(|_| "coxswain-system".to_string());

    for sa in PROXY_SA_CANDIDATES {
        let principal = format!("system:serviceaccount:{namespace}:{sa}");
        let output = Command::new("kubectl")
            .args(["auth", "can-i", "--list", "--as", &principal])
            .output()
            .ok()?;
        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("rbac_read_only_proxy: candidate `{sa}` failed: {stderr}");
    }
    None
}

/// One parsed row of `kubectl auth can-i --list` output.
#[derive(Debug, Default)]
struct AuthRow {
    /// Resource cell (first column). Empty when the row is a non-resource URL.
    resource: String,
    /// Verbs from the rightmost bracketed segment.
    verbs: Vec<String>,
    /// True when the row's non-resource URL column is non-empty.
    is_non_resource_url: bool,
}

/// Parse the kubectl table into [`AuthRow`]s. The output is column-aligned
/// whitespace; columns are: Resources, Non-Resource URLs, Resource Names,
/// Verbs. We split on whitespace runs, then re-assemble: the last bracketed
/// segment is verbs; segments preceding it are the first three columns.
fn parse_auth_can_i(output: &str) -> Vec<AuthRow> {
    let mut rows = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Resources") {
            continue;
        }
        let Some(open) = trimmed.rfind('[') else {
            continue;
        };
        let Some(close) = trimmed.rfind(']') else {
            continue;
        };
        if close <= open {
            continue;
        }

        // Verbs.
        let mut verbs = Vec::new();
        for verb in trimmed[open + 1..close].split(|c: char| c.is_whitespace() || c == ',') {
            let v = verb.trim();
            if !v.is_empty() {
                verbs.push(v.to_string());
            }
        }

        // Everything before the verbs bracket is the first three columns.
        let prefix = trimmed[..open].trim_end();
        let first_col = prefix.split_whitespace().next().unwrap_or("").to_string();

        let is_non_resource_url = first_col.starts_with('[') || first_col.is_empty();

        rows.push(AuthRow {
            resource: if is_non_resource_url {
                String::new()
            } else {
                first_col
            },
            verbs,
            is_non_resource_url,
        });
    }
    rows
}

fn is_baseline_grant(row: &AuthRow) -> bool {
    if row.is_non_resource_url {
        return true;
    }
    BASELINE_RESOURCE_PREFIXES
        .iter()
        .any(|p| row.resource == *p || row.resource.starts_with(p))
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    const SAMPLE_READ_ONLY: &str = "\
Resources                          Non-Resource URLs   Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []   []   [create]
selfsubjectrulesreviews.authorization.k8s.io    []   []   [create]
services                                        []   []   [get list watch]
secrets                                         []   []   [get,list,watch]
gateways.gateway.networking.k8s.io              []   []   [get list watch]
                                                [/.well-known/openid-configuration]   []   [get]
                                                [/.well-known/openid/v1/jwks]         []   [get]
";

    const SAMPLE_HAS_WRITE: &str = "\
Resources                          Non-Resource URLs   Resource Names   Verbs
services                                        []   []   [get list watch]
gateways/status.gateway.networking.k8s.io       []   []   [patch update]
";

    #[test]
    fn read_only_sample_passes_audit() {
        let rows = parse_auth_can_i(SAMPLE_READ_ONLY);
        let allowed: HashSet<&str> = ALLOWED_VERBS.iter().copied().collect();
        for row in &rows {
            if is_baseline_grant(row) {
                continue;
            }
            for verb in &row.verbs {
                assert!(
                    allowed.contains(verb.as_str()),
                    "real read-only sample should not yield disallowed verbs; got {verb} on {}",
                    row.resource
                );
            }
        }
    }

    #[test]
    fn write_sample_yields_violation() {
        let rows = parse_auth_can_i(SAMPLE_HAS_WRITE);
        let allowed: HashSet<&str> = ALLOWED_VERBS.iter().copied().collect();
        let mut violations = 0;
        for row in &rows {
            if is_baseline_grant(row) {
                continue;
            }
            for verb in &row.verbs {
                if !allowed.contains(verb.as_str()) {
                    violations += 1;
                }
            }
        }
        assert!(
            violations >= 2,
            "write sample must produce at least two violations (patch + update); got {violations}"
        );
    }

    #[test]
    fn parse_ignores_header() {
        let rows = parse_auth_can_i("Resources Non-Resource URLs Resource Names Verbs\n");
        assert!(rows.is_empty(), "header line must not produce rows");
    }

    #[test]
    fn parse_handles_empty_output() {
        let rows = parse_auth_can_i("");
        assert!(rows.is_empty());
    }
}
