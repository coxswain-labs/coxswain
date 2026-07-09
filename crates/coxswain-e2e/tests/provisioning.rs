#![allow(missing_docs)]
//! Provisioning control-plane: the dedicated-proxy operator.
//!
//! Plane: **control-plane**. Execution: **parallel** — every test owns a fresh
//! namespace and a fresh dedicated Gateway.
//!
//! Classification rule: a test belongs to the plane of its *primary assertion
//! target*. "A resource is provisioned / GC'd" is control-plane even if it
//! sends a probe. Covers dedicated-proxy resource provisioning (GEP-1762
//! labels, owner refs, SSA), garbage collection, per-field
//! `CoxswainGatewayParameters` rendering, ReferenceGrant-gated cross-namespace
//! backends, the dedicated proxy serving traffic end-to-end, and per-proxy
//! scope isolation.
//!
//! Note: `lifecycle_dedicated_proxy_routes_traffic` and
//! `lifecycle_cross_namespace_backend` assert traffic, but are kept here with the
//! dedicated-provisioning lifecycle they validate (and share its helper set)
//! rather than in `routing.rs`. Controller-restart and mode-migration lifecycle
//! tests live in `resilience.rs`; the #211 status-writer tests in
//! `status_conditions.rs`. Discovery bootstrap-credential tests and the
//! read-only-proxy ServiceAccount audit live in `discovery.rs`. Shared dedicated
//! helpers live in `common::dedicated`.

use coxswain_e2e::{
    ControllerOptions, FixtureVars, Harness, NamespaceGuard,
    fixtures::{self, backends, dedicated_proxy as dedicated, gateway_api as gwa, ingress as ing},
    harness::{HttpClient, wait},
};
use gateway_api_types::apis::standard::gateways::Gateway;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::core::v1::{Service, ServiceAccount};
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams};
use std::net::SocketAddr;
use std::time::Duration;

mod common;
use common::dedicated::{
    GATEWAY_NAME, RESOURCE_NAME, apply_and_wait, assert_provisioning_contract, wait_for_cut_over,
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
        assert_eq!(
            labels
                .get("app.kubernetes.io/component")
                .map(String::as_str),
            Some("dedicated-proxy"),
            "{kind}: dedicated-proxy component label survives the infra overlay"
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

// ── GEP-1867 infrastructure propagation, shared mode (#482) ──────────────────
//
// In shared mode the proxy pod and per-Gateway VIP Service both live in the
// controller's namespace, so the controller provisions a per-Gateway identity
// ServiceAccount in the Gateway's OWN namespace as the GEP-1867 carrier (the
// upstream GatewayInfrastructure conformance test lists SA/Pod/Service in the
// Gateway namespace by the gateway-name label). Its name is hashed, so tests
// locate it by that label rather than by a fixed name.

const SHARED_INFRA_GATEWAY: &str = "shared-infra-gw";
const GATEWAY_NAME_LABEL: &str = "gateway.networking.k8s.io/gateway-name";

/// List ServiceAccounts in `ns` carrying the gateway-name label for
/// `SHARED_INFRA_GATEWAY`. Mirrors the conformance lister's filter.
async fn list_identity_sas(h: &Harness, ns: &str) -> anyhow::Result<Vec<ServiceAccount>> {
    let sas: Api<ServiceAccount> = Api::namespaced(h.client.clone(), ns);
    let lp = ListParams::default().labels(&format!("{GATEWAY_NAME_LABEL}={SHARED_INFRA_GATEWAY}"));
    Ok(sas.list(&lp).await?.items)
}

/// Poll until exactly one identity SA exists for the shared Gateway, returning it.
async fn wait_for_identity_sa(h: &Harness, ns: &str) -> anyhow::Result<ServiceAccount> {
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async { format!("a per-Gateway identity ServiceAccount labelled {GATEWAY_NAME_LABEL}={SHARED_INFRA_GATEWAY} in {ns}") },
        || async { list_identity_sas(h, ns).await.ok().and_then(|v| v.into_iter().next()) },
    )
    .await
}

/// 482a — A shared Gateway with `infrastructure.{labels,annotations}` provisions
/// an identity ServiceAccount in its own namespace carrying the gateway-name
/// label, the propagated infra label/annotation, the shared-gateway-sa
/// component, and an owner reference back to the Gateway.
#[tokio::test]
async fn shared_gateway_provisions_identity_service_account_when_infra_set() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-shared-infra-sa").await?;
    fixtures::apply_fixture(dedicated::SHARED_GATEWAY_INFRA, FixtureVars::new(&ns.name)).await?;

    let sa = wait_for_identity_sa(&h, &ns.name).await?;

    let labels = sa.metadata.labels.as_ref().expect("identity SA labels");
    assert_eq!(
        labels.get("team").map(String::as_str),
        Some("platform"),
        "infrastructure.labels.team must propagate onto the identity SA"
    );
    assert_eq!(
        labels
            .get("app.kubernetes.io/component")
            .map(String::as_str),
        Some("shared-gateway-sa"),
        "identity SA carries the shared-gateway-sa component"
    );
    assert_eq!(
        labels
            .get("app.kubernetes.io/managed-by")
            .map(String::as_str),
        Some("coxswain")
    );
    let anno = sa
        .metadata
        .annotations
        .as_ref()
        .expect("identity SA annotations");
    assert_eq!(
        anno.get("coxswain.example/owner").map(String::as_str),
        Some("tenant-team"),
        "infrastructure.annotations must propagate onto the identity SA"
    );
    let owners = sa.metadata.owner_references.as_ref().expect("owner refs");
    assert_eq!(owners.len(), 1, "exactly one owner ref");
    assert_eq!(owners[0].name, SHARED_INFRA_GATEWAY);
    assert_eq!(owners[0].kind, "Gateway");
    assert_eq!(owners[0].controller, Some(true));
    assert_eq!(owners[0].block_owner_deletion, Some(true));

    Ok(())
}

/// 482b (sad) — A user `infrastructure.labels` override on a reserved key is
/// dropped: the live identity SA keeps the controller's value, while a benign
/// non-reserved label is propagated.
#[tokio::test]
async fn shared_gateway_drops_reserved_label_override_keeping_controller_value()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-shared-infra-reserved").await?;
    fixtures::apply_fixture(dedicated::SHARED_GATEWAY_INFRA, FixtureVars::new(&ns.name)).await?;

    let sa = wait_for_identity_sa(&h, &ns.name).await?;
    let labels = sa.metadata.labels.as_ref().expect("identity SA labels");

    assert_eq!(
        labels.get("app.kubernetes.io/name").map(String::as_str),
        Some("coxswain"),
        "reserved key app.kubernetes.io/name=evil override must be dropped"
    );
    assert_eq!(
        labels.get(GATEWAY_NAME_LABEL).map(String::as_str),
        Some(SHARED_INFRA_GATEWAY),
        "reserved gateway-name label must hold the real Gateway name"
    );
    assert_eq!(
        labels.get("kept").map(String::as_str),
        Some("yes"),
        "benign non-reserved label still propagates"
    );

    Ok(())
}

/// 482c (remove) — Removing an infra label from the Gateway spec prunes it from
/// the live identity SA: SSA force-apply re-asserts the full label set, so a
/// dropped key disappears (the add/update/remove acceptance criterion).
#[tokio::test]
async fn shared_gateway_removes_infra_label_from_service_account_on_spec_edit() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-shared-infra-remove").await?;
    fixtures::apply_fixture(dedicated::SHARED_GATEWAY_INFRA, FixtureVars::new(&ns.name)).await?;

    // Baseline: the identity SA carries the `team` label.
    let sa = wait_for_identity_sa(&h, &ns.name).await?;
    assert_eq!(
        sa.metadata
            .labels
            .as_ref()
            .and_then(|l| l.get("team"))
            .map(String::as_str),
        Some("platform"),
        "precondition: team label present before removal"
    );

    // Remove `team` from infrastructure.labels via a JSON merge patch (null deletes).
    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let patch = serde_json::json!({
        "spec": { "infrastructure": { "labels": { "team": serde_json::Value::Null } } }
    });
    gateways
        .patch(
            SHARED_INFRA_GATEWAY,
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await?;

    // The next reconcile re-applies the SA without `team`; force-apply prunes it.
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            format!(
                "identity SA in {} to drop the removed 'team' label",
                ns.name
            )
        },
        || async {
            let sa = list_identity_sas(&h, &ns.name)
                .await
                .ok()?
                .into_iter()
                .next()?;
            let has_team = sa
                .metadata
                .labels
                .as_ref()
                .is_some_and(|l| l.contains_key("team"));
            (!has_team).then_some(())
        },
    )
    .await?;

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
    // relinquish is faithfully observed as the host leaving the controller's
    // per-proxy routes view (#537) — the same intent the shared pool was pushed.
    let routes_url = h.shared_proxy_routes_url().await?;
    let client = reqwest::Client::new();
    let still_serving = |json: &serde_json::Value, host: &str| -> bool {
        json["routes"]["gateway"]["hosts"]
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

/// 12b — Scope isolation (#426): two cut-over dedicated Gateways A and B exist
/// concurrently. A's dedicated proxy must serve only A's host and return `404`
/// for B's host — proving the discovery server filters each subscriber's
/// snapshot to its own Gateway's routing world via the dedicated registry, and
/// never leaks another scope's routes. This is the direct regression guard for
/// the per-proxy scope-filtering behaviour; the other dedicated tests assert it
/// only indirectly via the shared-pool relinquish.
#[tokio::test]
async fn dedicated_proxy_does_not_serve_foreign_gateway_routes() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns_a = NamespaceGuard::create(&h.client, "prov-ded-scope-a").await?;
    let ns_b = NamespaceGuard::create(&h.client, "prov-ded-scope-b").await?;

    // Provision two independent cut-over dedicated Gateways, one per namespace.
    for ns in [&ns_a, &ns_b] {
        fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
        wait::wait_for_backends(&ns.name).await?;
        fixtures::apply_fixture(dedicated::TRAFFIC, FixtureVars::new(&ns.name)).await?;
        let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
        wait_for_cut_over(&gateways, GATEWAY_NAME, Duration::from_secs(60)).await?;
    }

    let host_a = format!("dedicated.{}.local", ns_a.name);
    let host_b = format!("dedicated.{}.local", ns_b.name);

    let addr_a =
        wait::wait_for_dedicated_proxy_endpoint(&ns_a.name, GATEWAY_NAME, Duration::from_secs(60))
            .await?;
    let http_a = HttpClient::new(addr_a)?;

    // Positive: A serves its own Gateway's route — proves A's subscription
    // (Scope::Gateway{ns_a}) received its own slice from the dedicated registry.
    let resp = wait::wait_for_route(&http_a, &host_a, "/", Duration::from_secs(60)).await?;
    resp.assert_backend("echo-a");

    // Negative: A must NOT serve B's host. B is a *real* cut-over Gateway whose
    // routes exist in the dedicated registry under B's own key, so this 404
    // proves scope filtering — A never receives B's routes, not merely that the
    // host is unknown cluster-wide.
    wait::wait_for_route_status(&http_a, &host_b, "/", 404, Duration::from_secs(30)).await?;

    Ok(())
}

/// 13 — An HTTPRoute with a backend Service in a different namespace resolves
/// via `ReferenceGrant`, and traffic flows through the dedicated subprocess.
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
/// from the dedicated proxy's routing table (requests 500).
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

    use gateway_api_types::apis::standard::referencegrants::ReferenceGrant;
    let grants: Api<ReferenceGrant> = Api::namespaced(h.client.clone(), &tenant.name);
    let grant_name = format!("allow-httproute-from-{}", ns.name);
    grants.delete(&grant_name, &DeleteParams::default()).await?;

    // Cross-namespace backend dropped from the routing table → reflector
    // installs an "error route" returning 500 ("No ready endpoints for rule —
    // installing error route (500)"; see `coxswain_reflector::gateway_api::reconcile`).
    wait::wait_for_route_status(&http, &host, "/", 500, Duration::from_secs(30)).await?;

    Ok(())
}

/// 16 — Gateway deletion cascades to Deployment/Service/ServiceAccount via
/// owner-ref GC, and the Gateway itself is removed after the dedicated-cleanup
/// finalizer runs. (Sibling of test 2 which asserts the same against
/// `DEDICATED_GATEWAY`; this variant exercises the same path with the
/// lifecycle-suite fixture for consistency with the rest of the suite.)
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

// ── API-surface flag-gating (#492) ───────────────────────────────────────────
//
// Serial tests: both reconfigure the shared Helm release and must restore the
// default config before returning. The nextest `serial` group in
// `.config/nextest.toml` ensures these do not overlap other global-config tests.
//
// Pattern: apply a positive-control resource (from the STILL-ENABLED surface) +
// the resource under test (from the DISABLED surface). Wait for the positive
// control to confirm the controller ran. Then assert the disabled-surface
// resource was left untouched.

/// Make a raw HTTP GET to the proxy and return the status code only.
///
/// Does not attempt JSON body parsing — safe to call with go-httpbin backends
/// whose `/status/:code` endpoints return plain-text or empty bodies. Mirrors
/// `traffic_policy.rs`'s helper of the same shape (kept local per-file since
/// each `tests/*.rs` file compiles as its own binary).
async fn raw_status(proxy_addr: SocketAddr, host: &str, path: &str) -> u16 {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let c = CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|e| panic!("build reqwest client: {e}"))
    });
    let url = format!("http://{proxy_addr}{path}");
    c.get(&url)
        .header("Host", host)
        .send()
        .await
        .map(|r| r.status().as_u16())
        .unwrap_or(0)
}

/// Sum `coxswain_proxy_upstream_retries_total` series for `condition` whose labels
/// mention `ns_marker` (the test namespace). Mirrors `traffic_policy.rs`'s helper.
async fn retry_count(h: &Harness, ns_marker: &str, condition: &str) -> u64 {
    let Ok(resp) = reqwest::get(h.admin_url("/metrics")).await else {
        return 0;
    };
    let Ok(body) = resp.text().await else {
        return 0;
    };
    body.lines()
        .filter(|l| l.starts_with("coxswain_proxy_upstream_retries_total{"))
        .filter(|l| l.contains(&format!("condition=\"{condition}\"")))
        .filter(|l| l.contains(ns_marker))
        .filter_map(|l| l.rsplit(' ').next().and_then(|v| v.parse::<f64>().ok()))
        .map(|v| v as u64)
        .sum()
}

/// (#492 sad) Gateway API disabled: a Gateway applied while the surface is off
/// receives no status conditions, proving coxswain does not reconcile Gateway
/// API resources when `--disable-gateway-api` is set.
///
/// Positive control: an Ingress from the still-enabled surface gets its
/// `loadBalancer` IP, confirming the controller processed the namespace and had
/// every opportunity to (wrongly) reconcile the Gateway.
///
/// At the end the chart default (`controller.gatewayApi.enabled=true`) is
/// restored so later serial tests run with stock config.
#[tokio::test]
async fn gateway_api_disabled_skips_gateway_reconcile() -> anyhow::Result<()> {
    const STATUS_IP: &str = "203.0.113.81";
    let h = Harness::start_with_options(ControllerOptions {
        gateway_api_enabled: Some(false),
        status_address: Some(STATUS_IP.to_string()),
        ..Default::default()
    })
    .await?;

    // Assert the health endpoint reports the surface as disabled.
    let health: serde_json::Value = reqwest::get(h.controller_admin_url("/api/v1/health"))
        .await?
        .json()
        .await?;
    assert_eq!(
        health["api_surfaces"]["gateway_api"].as_bool(),
        Some(false),
        "api_surfaces.gateway_api must be false when --disable-gateway-api is set; got: {health}"
    );
    assert_eq!(
        health["api_surfaces"]["ingress"].as_bool(),
        Some(true),
        "api_surfaces.ingress must remain true; got: {health}"
    );

    let ns = NamespaceGuard::create(&h.client, "prov-gw-disabled").await?;

    // Apply an Ingress (positive control: proves the controller processed the ns).
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ing::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    // Apply a Gateway that would normally be reconciled.
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    // Wait for the Ingress to get an LB IP — proves the controller ran and had
    // time to reconcile the Gateway if it were going to.
    wait::wait_for_ingress_lb_ip(
        &h.client,
        "echo-ingress",
        &ns.name,
        STATUS_IP,
        Duration::from_secs(60),
    )
    .await?;

    // Regression guard for #550 (and the identical prior fixes for `auth-jwt`/
    // `ext-auth`): the `Compression` CR reflector must be spawned always-on,
    // not only inside the gateway-api-gated reflector set — otherwise the
    // Ingress `compression` annotation is permanently unresolvable on an
    // Ingress-only install. Apply a `compression`-referencing Ingress here,
    // under `--disable-gateway-api`, and prove it still resolves and compresses.
    //
    // The route can become routable (via the Ingress reflector) slightly
    // before the just-restarted controller's Compression reflector finishes
    // its initial sync, so poll for the compressed response rather than
    // asserting on the first request after `wait_for_route`.
    fixtures::apply_fixture(ing::ANNOTATION_COMPRESSION_GZIP, FixtureVars::new(&ns.name)).await?;
    let compression_host = format!("compression-gzip.{}.local", ns.name);
    wait::wait_for_route(&h.http, &compression_host, "/", Duration::from_secs(60)).await?;
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            format!(
                "compression annotation to resolve and apply at {compression_host} \
                 even with gateway-api disabled (Compression CR store must be \
                 spawned always-on, not gateway-api-gated)"
            )
        },
        || async {
            let (_, resp_headers, _) = h
                .http
                .get_full_raw(&compression_host, "/", &[("Accept-Encoding", "gzip")])
                .await
                .ok()?;
            (resp_headers
                .get("content-encoding")
                .and_then(|v| v.to_str().ok())
                == Some("gzip"))
            .then_some(())
        },
    )
    .await?;

    // Regression guard for #551 (identical fix, same rationale, for `RetryPolicy`):
    // the CR reflector must be spawned always-on, not only inside the
    // gateway-api-gated reflector set — otherwise the Ingress `retry` annotation
    // is permanently unresolvable (and its health check permanently unregistered,
    // crash-looping the controller) on an Ingress-only install. Apply a
    // `retry`-referencing Ingress over go-httpbin here, under
    // `--disable-gateway-api`, and prove the retry loop actually fires.
    fixtures::apply_fixture(backends::GO_HTTPBIN, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["go-httpbin"]).await?;
    fixtures::apply_fixture(ing::ANNOTATION_RETRY_CODES, FixtureVars::new(&ns.name)).await?;
    let retry_host = format!("ingretry.{}.local", ns.name);
    let proxy = h.http.proxy_addr;
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async { format!("{retry_host} route live (go-httpbin 200)") },
        || async { (raw_status(proxy, &retry_host, "/status/200").await == 200).then_some(()) },
    )
    .await?;
    let before = retry_count(&h, &ns.name, "http-code").await;
    // The route can become routable (via the Ingress reflector) slightly before
    // the just-restarted controller's RetryPolicy reflector finishes its initial
    // sync, so re-drive the always-503 request inside the poll rather than
    // asserting on a single attempt right after the route goes live.
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            format!(
                "retry annotation to resolve and retry at {retry_host} even with \
                 gateway-api disabled (RetryPolicy CR store must be spawned \
                 always-on, not gateway-api-gated)"
            )
        },
        || async {
            let _ = raw_status(proxy, &retry_host, "/status/503").await;
            (retry_count(&h, &ns.name, "http-code").await > before).then_some(())
        },
    )
    .await?;

    // Negative assertion: the Gateway must NOT be reconciled by coxswain.
    // The Gateway API admission webhook injects Accepted=Unknown / Programmed=Unknown
    // conditions with observedGeneration=None at object creation time ("Waiting for
    // controller"). Coxswain always sets observedGeneration when it writes conditions,
    // so the absence of any condition with observedGeneration.is_some() proves it
    // never touched the Gateway.
    let gateways_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let gw = gateways_api.get("coxswain-test").await?;
    let conditions = gw
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_deref())
        .unwrap_or(&[]);
    let coxswain_reconciled = conditions.iter().any(|c| c.observed_generation.is_some());
    assert!(
        !coxswain_reconciled,
        "Gateway must not be reconciled by coxswain when gateway-api surface is disabled; \
         initial 'Unknown' conditions from the Gateway API admission webhook are expected, \
         but none with observedGeneration set should appear. Got: {conditions:?}"
    );

    // Restore the chart-default so later serial tests run with stock config.
    Harness::start_with_options(ControllerOptions {
        gateway_api_enabled: Some(true),
        ..Default::default()
    })
    .await?;

    Ok(())
}

/// (#492 sad) Ingress disabled: an Ingress applied while the surface is off
/// receives no `loadBalancer` status, proving coxswain does not reconcile
/// Ingress resources when `--disable-ingress` is set.
///
/// Positive control: a Gateway from the still-enabled surface reaches
/// `Accepted=True`, confirming the controller processed the namespace.
///
/// At the end the chart default (`controller.ingress.enabled=true`) is
/// restored so later serial tests run with stock config.
#[tokio::test]
async fn ingress_disabled_skips_ingress_reconcile() -> anyhow::Result<()> {
    let h = Harness::start_with_options(ControllerOptions {
        ingress_enabled: Some(false),
        ..Default::default()
    })
    .await?;

    // Assert the health endpoint reports the surface as disabled.
    let health: serde_json::Value = reqwest::get(h.controller_admin_url("/api/v1/health"))
        .await?
        .json()
        .await?;
    assert_eq!(
        health["api_surfaces"]["ingress"].as_bool(),
        Some(false),
        "api_surfaces.ingress must be false when --disable-ingress is set; got: {health}"
    );
    assert_eq!(
        health["api_surfaces"]["gateway_api"].as_bool(),
        Some(true),
        "api_surfaces.gateway_api must remain true; got: {health}"
    );

    let ns = NamespaceGuard::create(&h.client, "prov-ing-disabled").await?;

    // Apply a Gateway (positive control: proves the controller processed the ns).
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    // Apply an Ingress that would normally be reconciled.
    fixtures::apply_fixture(ing::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    // Wait for the Gateway to reach Accepted=True — proves the controller ran.
    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-test",
        &ns.name,
        "Accepted",
        "True",
        Duration::from_secs(60),
    )
    .await?;

    // Negative assertion: the Ingress must carry no loadBalancer status.
    let ingresses: Api<Ingress> = Api::namespaced(h.client.clone(), &ns.name);
    let ingress = ingresses.get("echo-ingress").await?;
    let lb_entries = ingress
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_deref())
        .unwrap_or(&[]);
    assert!(
        lb_entries.is_empty(),
        "Ingress must have no loadBalancer status when ingress surface is disabled, got: {lb_entries:?}"
    );

    // Restore the chart-default so later serial tests run with stock config.
    Harness::start_with_options(ControllerOptions {
        ingress_enabled: Some(true),
        ..Default::default()
    })
    .await?;

    Ok(())
}

// ── #497 — Dedicated-proxy autoscaling (HPA + PDB) ───────────────────────────

/// #497 — `autoscaling.enabled: true` provisions an HPA + PDB alongside the
/// dedicated-proxy Deployment.
///
/// Asserts: HPA exists with the correct scaleTargetRef, minReplicas,
/// maxReplicas, and CPU target; PDB exists (minReplicas=2 satisfies floor≥2);
/// Deployment has `spec.replicas` unset (HPA is the sole replica authority).
/// All three carry the GEP-1762 name and the `coxswain-controller` field manager.
#[tokio::test]
async fn params_autoscaling_provisions_hpa_and_pdb() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-dedgw-hpa").await?;

    fixtures::apply_fixture(
        dedicated::DEDICATED_GATEWAY_AUTOSCALING,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let hpas: Api<HorizontalPodAutoscaler> = Api::namespaced(h.client.clone(), &ns.name);
    let pdbs: Api<PodDisruptionBudget> = Api::namespaced(h.client.clone(), &ns.name);

    let deploy =
        wait::wait_for_resource(&deployments, RESOURCE_NAME, Duration::from_secs(30)).await?;
    let hpa = wait::wait_for_resource(&hpas, RESOURCE_NAME, Duration::from_secs(30)).await?;
    let pdb = wait::wait_for_resource(&pdbs, RESOURCE_NAME, Duration::from_secs(30)).await?;

    // The HPA — not the controller — owns the replica count. The operator omits
    // `spec.replicas` from its server-side-apply, but the apiserver defaults the
    // field to 1 on read, so it is always present; the real invariant is that the
    // `coxswain-controller` field manager does NOT manage `spec.replicas` (which
    // would make Helm/SSA fight the HPA). Assert via managedFields.
    let controller_owns_replicas = deploy
        .metadata
        .managed_fields
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|f| f.manager.as_deref() == Some("coxswain-controller"))
        .any(|f| {
            serde_json::to_string(f)
                .map(|s| s.contains("f:replicas"))
                .unwrap_or(false)
        });
    assert!(
        !controller_owns_replicas,
        "coxswain-controller must NOT manage spec.replicas when autoscaling is enabled (HPA owns the count)"
    );

    // HPA scaleTargetRef must point at the dedicated Deployment by GEP-1762 name.
    let spec = &hpa.spec;
    assert_eq!(
        spec.scale_target_ref.api_version.as_deref(),
        Some("apps/v1"),
        "HPA scaleTargetRef.apiVersion"
    );
    assert_eq!(
        spec.scale_target_ref.kind, "Deployment",
        "HPA scaleTargetRef.kind"
    );
    assert_eq!(
        spec.scale_target_ref.name, RESOURCE_NAME,
        "HPA scaleTargetRef.name must be the GEP-1762 resource name"
    );
    assert_eq!(
        spec.min_replicas,
        Some(2),
        "HPA minReplicas from autoscaling.minReplicas"
    );
    assert_eq!(
        spec.max_replicas, 5,
        "HPA maxReplicas from autoscaling.maxReplicas"
    );
    let cpu_target = spec
        .metrics
        .as_deref()
        .and_then(|m| m.first())
        .and_then(|m| m.resource.as_ref())
        .map(|r| r.target.average_utilization);
    assert_eq!(
        cpu_target,
        Some(Some(70)),
        "HPA CPU averageUtilization from autoscaling.targetCPUUtilizationPercentage"
    );

    // HPA must carry the GEP-1762 name and coxswain-controller field manager.
    let managers = hpa
        .metadata
        .managed_fields
        .as_ref()
        .expect("HPA managedFields present");
    assert!(
        managers
            .iter()
            .any(|f| f.manager.as_deref() == Some("coxswain-controller")),
        "HPA must have a managedFields entry with manager = 'coxswain-controller'"
    );

    // PDB must exist and be configured for maxUnavailable: 1.
    let pdb_spec = pdb.spec.as_ref().expect("PDB spec present");
    assert_eq!(
        pdb_spec.max_unavailable,
        Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(1)),
        "PDB maxUnavailable must be 1"
    );

    Ok(())
}

/// #497 (negative) — `autoscaling` absent provisions no HPA and no PDB when
/// the static replica count is 1 (the default).
///
/// Asserts: after the Deployment is up, neither an HPA nor a PDB exists at the
/// GEP-1762 name; Deployment has `spec.replicas: Some(1)`.
#[tokio::test]
async fn params_autoscaling_disabled_provisions_no_hpa() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "prov-dedgw-nohpa").await?;

    // A single-replica, no-autoscaling fixture (`replicas: 1`, no `autoscaling`
    // block) → neither HPA nor PDB should be provisioned (floor < 2). The
    // ClusterIP fixture fits exactly; the test only inspects the rendered
    // Deployment, not Pod readiness.
    fixtures::apply_fixture(
        dedicated::DEDICATED_GATEWAY_CLUSTERIP,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let deployments: Api<Deployment> = Api::namespaced(h.client.clone(), &ns.name);
    let hpas: Api<HorizontalPodAutoscaler> = Api::namespaced(h.client.clone(), &ns.name);
    let pdbs: Api<PodDisruptionBudget> = Api::namespaced(h.client.clone(), &ns.name);

    // Wait for the Deployment (positive control: controller processed this Gateway).
    let deploy =
        wait::wait_for_resource(&deployments, RESOURCE_NAME, Duration::from_secs(30)).await?;

    // Static replicas should be present (not None) because no HPA manages it.
    assert_eq!(
        deploy.spec.as_ref().and_then(|s| s.replicas),
        Some(1),
        "Deployment.spec.replicas must be Some(1) when autoscaling is disabled"
    );

    // HPA and PDB must NOT exist — the controller must not have provisioned them.
    let hpa_result = hpas.get(RESOURCE_NAME).await;
    assert!(
        hpa_result.is_err(),
        "HPA must not exist when autoscaling is disabled; got: {hpa_result:?}"
    );

    let pdb_result = pdbs.get(RESOURCE_NAME).await;
    assert!(
        pdb_result.is_err(),
        "PDB must not exist when replica floor < 2; got: {pdb_result:?}"
    );

    Ok(())
}
