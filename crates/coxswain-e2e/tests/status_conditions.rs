#![allow(missing_docs)]
//! Status & conditions control-plane: what the controller writes back.
//!
//! Plane: **control-plane**. Execution: **mostly parallel** — each test owns its
//! own Gateway/Ingress and reads only that object's status.
//!
//! Classification rule: a test belongs to the plane of its *primary assertion
//! target*. "The controller writes condition/address X" is control-plane even if
//! it sends a probe. Covers Ingress `loadBalancer` status, Gateway
//! `Accepted`/`Programmed`, `observedGeneration` tracking (GEP-1364),
//! `GatewayClass.status.supportedFeatures`, the dedicated-mode status writer
//! (#211): ClusterIP/LoadBalancer address derivation and `InvalidParameters`,
//! the per-parent `HTTPRoute` `ResolvedRefs`/`Programmed` conditions, the
//! ownership negative (an unowned IngressClass is never patched), and the
//! status-writer idempotency invariant — no-op reconciles must not re-stamp
//! `lastTransitionTime` or bump `observedGeneration` (#347).

use coxswain_e2e::{
    ControllerOptions, FixtureVars, Harness, NamespaceGuard,
    fixtures::{self, backends, dedicated_proxy as dedicated, gateway_api as gwa, ingress},
    harness::wait,
};
use gateway_api::apis::standard::gateways::Gateway;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Service, ServiceAccount};
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::Api;
use kube::api::{Patch, PatchParams};
use std::time::Duration;

mod common;
use common::dedicated::{GATEWAY_NAME, RESOURCE_NAME, gateway_addresses, gateway_condition};

#[tokio::test]
async fn status_reports_load_balancer_ip() -> anyhow::Result<()> {
    let h = Harness::start_with_options(ControllerOptions {
        status_address: Some("203.0.113.1".to_string()),
        ..Default::default()
    })
    .await?;
    let ns = NamespaceGuard::create(&h.client, "ing-lb-status").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    wait::wait_for_ingress_lb_ip(
        &h.client,
        "echo-ingress",
        &ns.name,
        "203.0.113.1",
        Duration::from_secs(30),
    )
    .await?;

    Ok(())
}

/// A valid Gateway with an attached HTTPRoute reaches both `Accepted=True` and
/// `Programmed=True`: the controller admits the Gateway, then programs the data
/// plane for it.
#[tokio::test]
async fn gateway_becomes_accepted_and_programmed() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-status").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    wait::wait_for_gateway_programmed(
        &h.client,
        "coxswain-test",
        &ns.name,
        Duration::from_secs(30),
    )
    .await?;

    // Programmed implies the controller first Accepted the Gateway; assert it
    // explicitly so the test name's "accepted_and" half is enforced.
    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let gw = gw_api.get("coxswain-test").await?;
    let (accepted, _) = gateway_condition(&gw, "Accepted")
        .unwrap_or_else(|| panic!("Gateway missing Accepted condition"));
    assert_eq!(
        accepted, "True",
        "Gateway should be Accepted=True once Programmed"
    );

    Ok(())
}

/// Verifies that `gateway_needs_status_patch` detects a stale `observedGeneration`
/// after a spec-only change and re-patches all conditions to the new generation.
/// Exercises the GEP-1364 requirement that `observedGeneration` tracks
/// `metadata.generation` even when the programmed-ness of the Gateway is unchanged.
#[tokio::test]
async fn gateway_status_tracks_generation_bumps() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-gen-tracking").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    wait::wait_for_gateway_programmed(
        &h.client,
        "coxswain-test",
        &ns.name,
        Duration::from_secs(30),
    )
    .await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let gw = gw_api.get("coxswain-test").await?;
    let gen_before = gw.metadata.generation.unwrap_or(0);

    // Sanity: initial conditions should already be at gen_before.
    let top_conds = gw
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_deref())
        .unwrap_or(&[]);
    for c in top_conds {
        assert_eq!(
            c.observed_generation.unwrap_or(0),
            gen_before,
            "condition {} not at initial generation",
            c.type_
        );
    }

    // Bump .metadata.generation with a harmless spec change (allowedRoutes.namespaces.from
    // changes from Same to All — the HTTPRoute is in the same namespace so it still attaches).
    let http_port = h.controller.gateway_http_addr.port();
    let bump_patch = serde_json::json!({
        "spec": {
            "listeners": [{"name": "http", "port": http_port, "protocol": "HTTP",
                           "allowedRoutes": {"namespaces": {"from": "All"}}}]
        }
    });
    gw_api
        .patch(
            "coxswain-test",
            &PatchParams::default(),
            &Patch::Merge(&bump_patch),
        )
        .await?;

    // Wait for the controller to detect the stale observedGeneration and re-patch
    // every condition (top-level + per-listener) up to the new generation.
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            let observed = gw_api.get("coxswain-test").await.ok().map_or_else(
                || "<could not fetch Gateway>".to_string(),
                |gw| {
                    let current_gen = gw.metadata.generation.unwrap_or(0);
                    let top: Vec<i64> = gw
                        .status
                        .as_ref()
                        .and_then(|s| s.conditions.as_deref())
                        .unwrap_or(&[])
                        .iter()
                        .map(|c| c.observed_generation.unwrap_or(0))
                        .collect();
                    format!("generation={current_gen}, top observedGenerations={top:?}")
                },
            );
            format!(
                "Gateway coxswain-test conditions to advance observedGeneration past {gen_before} \
                 after a spec bump; {observed}"
            )
        },
        || async {
            let gw = gw_api.get("coxswain-test").await.ok()?;
            let new_gen = gw.metadata.generation.unwrap_or(0);
            if new_gen <= gen_before {
                return None;
            }
            let top = gw
                .status
                .as_ref()
                .and_then(|s| s.conditions.as_deref())
                .unwrap_or(&[]);
            let listeners = gw
                .status
                .as_ref()
                .and_then(|s| s.listeners.as_deref())
                .unwrap_or(&[]);
            let top_fresh = top
                .iter()
                .all(|c| c.observed_generation.unwrap_or(0) >= new_gen);
            let listeners_fresh = listeners.iter().all(|sl| {
                sl.conditions
                    .iter()
                    .all(|c| c.observed_generation.unwrap_or(0) >= new_gen)
            });
            (top_fresh && listeners_fresh).then_some(())
        },
    )
    .await
}

#[tokio::test]
async fn gatewayclass_supported_features() -> anyhow::Result<()> {
    let h = Harness::start().await?;

    let feats = wait::wait_for_gatewayclass_supported_features(
        &h.client,
        "coxswain",
        Duration::from_secs(30),
    )
    .await?;

    assert!(
        !feats.is_empty(),
        "GatewayClass coxswain must have non-empty status.supportedFeatures"
    );
    assert!(
        feats.contains(&"Gateway".to_string()),
        "must advertise core Gateway feature; got: {feats:?}"
    );
    assert!(
        feats.contains(&"HTTPRoute".to_string()),
        "must advertise core HTTPRoute feature; got: {feats:?}"
    );

    Ok(())
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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "dedgw-status-clusterip").await?;

    fixtures::apply_fixture(
        dedicated::DEDICATED_GATEWAY_CLUSTERIP,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    let svc = wait::wait_for_resource(&services, RESOURCE_NAME, Duration::from_secs(15)).await?;
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
    // the operator's reconcile to propagate. 120s window accommodates image
    // pull and pod startup on a cold local cluster.
    let gw = wait::poll_until(
        Duration::from_secs(120),
        wait::POLL,
        || async {
            let observed = gateways.get(GATEWAY_NAME).await.ok().map_or_else(
                || "<could not fetch Gateway>".to_string(),
                |gw| {
                    format!(
                        "Accepted={:?}, Programmed={:?}, DedicatedProxyReady={:?}, addresses={:?}",
                        gateway_condition(&gw, "Accepted"),
                        gateway_condition(&gw, "Programmed"),
                        gateway_condition(&gw, "gateway.coxswain-labs.dev/DedicatedProxyReady"),
                        gateway_addresses(&gw),
                    )
                },
            );
            format!(
                "Gateway {GATEWAY_NAME} to be Accepted+Programmed+DedicatedProxyReady with an address; observed {observed}"
            )
        },
        || async {
            let gw = gateways.get(GATEWAY_NAME).await.ok()?;
            let accepted = gateway_condition(&gw, "Accepted")?;
            let programmed = gateway_condition(&gw, "Programmed")?;
            let cut_over = gateway_condition(&gw, "gateway.coxswain-labs.dev/DedicatedProxyReady")?;
            let addresses = gateway_addresses(&gw);
            (accepted == ("True".to_string(), "Accepted".to_string())
                && programmed == ("True".to_string(), "Programmed".to_string())
                && cut_over == ("True".to_string(), "Ready".to_string())
                && !addresses.is_empty())
            .then_some(gw)
        },
    )
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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "dedgw-status-lb").await?;

    fixtures::apply_fixture(
        dedicated::DEDICATED_GATEWAY_LOADBALANCER,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let services: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    wait::wait_for_resource(&services, RESOURCE_NAME, Duration::from_secs(15)).await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);

    // Before any LB ingress is assigned the operator must surface
    // Programmed=False with one of two reasons:
    //   * Pending — pod not yet Ready (precedence: pod-ready > address)
    //   * AddressNotAssigned — pod is Ready but no LB IP yet
    wait::poll_until(
        Duration::from_secs(45),
        wait::POLL,
        || async {
            let observed = gateways.get(GATEWAY_NAME).await.ok().map_or_else(
                || "<could not fetch Gateway>".to_string(),
                |gw| format!("Programmed={:?}", gateway_condition(&gw, "Programmed")),
            );
            format!(
                "Gateway {GATEWAY_NAME} to surface Programmed=False (AddressNotAssigned|Pending); observed {observed}"
            )
        },
        || async {
            let gw = gateways.get(GATEWAY_NAME).await.ok()?;
            let programmed = gateway_condition(&gw, "Programmed")?;
            (programmed.0 == "False"
                && (programmed.1 == "AddressNotAssigned" || programmed.1 == "Pending"))
            .then_some(())
        },
    )
    .await?;

    // Give an in-cluster LB controller a short window to assign an IP. If
    // nothing shows up in 10 s we synthetically patch the status subresource
    // so the test still exercises address propagation on bare clusters.
    // Plain `.patch()` would target the spec subresource — `/status` writes
    // MUST go through `.patch_status()`.
    let in_cluster_assigned = wait::poll_until(
        Duration::from_secs(10),
        wait::POLL,
        || async { format!("Service {RESOURCE_NAME} to receive an in-cluster LB ingress IP") },
        || async {
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
        },
    )
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
    let gw = wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            let observed = gateways.get(GATEWAY_NAME).await.ok().map_or_else(
                || "<could not fetch Gateway>".to_string(),
                |gw| {
                    format!(
                        "Programmed={:?}, addresses={:?}",
                        gateway_condition(&gw, "Programmed"),
                        gateway_addresses(&gw),
                    )
                },
            );
            format!(
                "Gateway {GATEWAY_NAME} to be Programmed=True with address {expected_ip}; observed {observed}"
            )
        },
        || async {
            let gw = gateways.get(GATEWAY_NAME).await.ok()?;
            let programmed = gateway_condition(&gw, "Programmed")?;
            let addresses = gateway_addresses(&gw);
            (programmed == ("True".to_string(), "Programmed".to_string())
                && addresses
                    .iter()
                    .any(|(t, v)| t == "IPAddress" && v == &expected_ip))
            .then_some(gw)
        },
    )
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
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "dedgw-status-invalid").await?;

    fixtures::apply_fixture(
        dedicated::DEDICATED_GATEWAY_INVALID_PARAMS,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            let observed = gateways.get(GATEWAY_NAME).await.ok().map_or_else(
                || "<could not fetch Gateway>".to_string(),
                |gw| {
                    format!(
                        "Accepted={:?}, Programmed={:?}",
                        gateway_condition(&gw, "Accepted"),
                        gateway_condition(&gw, "Programmed"),
                    )
                },
            );
            format!(
                "Gateway {GATEWAY_NAME} to be Accepted=False(InvalidParameters)+Programmed=False(Invalid); observed {observed}"
            )
        },
        || async {
            let gw = gateways.get(GATEWAY_NAME).await.ok()?;
            let accepted = gateway_condition(&gw, "Accepted")?;
            let programmed = gateway_condition(&gw, "Programmed")?;
            (accepted == ("False".to_string(), "InvalidParameters".to_string())
                && programmed == ("False".to_string(), "Invalid".to_string()))
            .then_some(())
        },
    )
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

/// 15 — `Programmed=True` plus `status.addresses` populated for a ClusterIP
/// dedicated-mode Gateway. (Sibling of test 8 which also pins ClusterIP, but
/// gates only on conditions/addresses without the cutover-and-traffic plumbing.)
#[tokio::test]
async fn lifecycle_gateway_status_conditions_and_addresses() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "ded-life-status").await?;

    fixtures::apply_fixture(dedicated::PROVISIONING, FixtureVars::new(&ns.name)).await?;

    wait::wait_for_gateway_programmed(&h.client, GATEWAY_NAME, &ns.name, Duration::from_secs(120))
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
    let addresses = gateway_addresses(&gw);
    assert!(
        addresses
            .iter()
            .any(|(t, v)| t == "IPAddress" && v == &cluster_ip),
        "Gateway.status.addresses should include ({cluster_ip}); got {addresses:?}"
    );

    Ok(())
}

/// The status writer writes per-parent `HTTPRoute` conditions that reflect
/// backend resolution: a route whose backend Service exists resolves
/// (`ResolvedRefs=True`), while a sibling route attached to the same Gateway but
/// pointing at a missing Service stays `Accepted=True` yet flips
/// `ResolvedRefs=False/BackendNotFound`. Closes the route-status happy+sad gap
/// the #347 work-queue migration relies on `mark_http_route_programmed` to cover.
#[tokio::test]
async fn route_status_reports_resolved_refs_per_backend() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "route-status-refs").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::ROUTE_STATUS_BACKENDS, FixtureVars::new(&ns.name)).await?;

    // The resolvable route programming proves the writer is live for this ns —
    // so the ghost route below has had equal opportunity to be evaluated.
    wait::wait_for_httproute_programmed(&h.client, "good-route", &ns.name, Duration::from_secs(30))
        .await?;

    let routes: Api<HTTPRoute> = Api::namespaced(h.client.clone(), &ns.name);

    // Happy: good-route attaches and resolves.
    let good = routes.get("good-route").await?;
    assert_eq!(
        route_parent_condition(&good, "Accepted").map(|(s, _)| s),
        Some("True".to_string()),
        "good-route must be Accepted=True"
    );
    assert_eq!(
        route_parent_condition(&good, "Programmed").map(|(s, _)| s),
        Some("True".to_string()),
        "good-route must be Programmed=True"
    );
    assert_eq!(
        route_parent_condition(&good, "ResolvedRefs"),
        Some(("True".to_string(), "ResolvedRefs".to_string())),
        "good-route's existing backend must yield ResolvedRefs=True"
    );

    // Sad: ghost-route attaches (Accepted=True) but its backend Service is
    // missing — ResolvedRefs must be False/BackendNotFound. Poll: the ghost
    // route may settle a beat after the good one.
    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            let observed = routes.get("ghost-route").await.ok().map_or_else(
                || "<could not fetch ghost-route>".to_string(),
                |r| {
                    format!(
                        "Accepted={:?}, ResolvedRefs={:?}",
                        route_parent_condition(&r, "Accepted"),
                        route_parent_condition(&r, "ResolvedRefs"),
                    )
                },
            );
            format!(
                "ghost-route to be Accepted=True + ResolvedRefs=False(BackendNotFound); observed {observed}"
            )
        },
        || async {
            let r = routes.get("ghost-route").await.ok()?;
            (route_parent_condition(&r, "Accepted").map(|(s, _)| s) == Some("True".to_string())
                && route_parent_condition(&r, "ResolvedRefs")
                    == Some(("False".to_string(), "BackendNotFound".to_string())))
            .then_some(())
        },
    )
    .await
}

/// Ownership negative: the status writer patches `loadBalancer` status only onto
/// Ingresses whose class we own. An Ingress claiming a foreign IngressClass must
/// be left untouched, even while an owned sibling in the same namespace is
/// patched. Guards the `reconcile_ingress` ownership branch (#347).
#[tokio::test]
async fn ingress_status_skips_unowned_ingress_class() -> anyhow::Result<()> {
    let status_ip = "203.0.113.9";
    let h = Harness::start_with_options(ControllerOptions {
        status_address: Some(status_ip.to_string()),
        ..Default::default()
    })
    .await?;
    let ns = NamespaceGuard::create(&h.client, "ing-foreign-class").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(ingress::FOREIGN_CLASS, FixtureVars::new(&ns.name)).await?;

    // Positive control: the owned Ingress receives the configured status IP.
    // Reaching this proves the writer processed this namespace's Ingresses, so
    // the foreign one below had equal opportunity to (wrongly) be patched.
    wait::wait_for_ingress_lb_ip(
        &h.client,
        "owned-ingress",
        &ns.name,
        status_ip,
        Duration::from_secs(30),
    )
    .await?;

    // Negative: the foreign-class Ingress must carry no loadBalancer ingress.
    let ingresses: Api<Ingress> = Api::namespaced(h.client.clone(), &ns.name);
    let foreign = ingresses.get("foreign-ingress").await?;
    let lb_ingress = foreign
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_deref())
        .unwrap_or(&[]);
    assert!(
        lb_ingress.is_empty(),
        "foreign-class Ingress must not receive a loadBalancer status patch, got {lb_ingress:?}"
    );

    Ok(())
}

/// Idempotency invariant (#347): once a Gateway and HTTPRoute are programmed,
/// reconciles that change no spec must not re-stamp `lastTransitionTime` or bump
/// `observedGeneration`. The work-queue migration deleted the `STATUS_RESYNC_INTERVAL`
/// backstop and now funnels resync + health + spec events through one reconcile,
/// so this churn-free property — unit-tested via `route_status_unchanged` /
/// `gateway_needs_status_patch` — needs a live guard too. We force reconciles
/// with metadata-only annotation pokes (which bump `resourceVersion` and fire a
/// watch event, but not `metadata.generation`) and assert the condition stamps
/// never move.
#[tokio::test]
async fn status_writes_are_idempotent_no_condition_churn() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "status-idempotent").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    wait::wait_for_gateway_programmed(
        &h.client,
        "coxswain-test",
        &ns.name,
        Duration::from_secs(30),
    )
    .await?;
    wait::wait_for_httproute_programmed(&h.client, "echo-route", &ns.name, Duration::from_secs(30))
        .await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let routes: Api<HTTPRoute> = Api::namespaced(h.client.clone(), &ns.name);

    // Snapshot the (type → lastTransitionTime, observedGeneration) fingerprint of
    // every condition the writer owns. A churning writer re-stamps
    // lastTransitionTime on each no-op reconcile; an idempotent one leaves it.
    let gw_before = gateway_condition_stamps(&gateways.get("coxswain-test").await?);
    let route_before = route_condition_stamps(&routes.get("echo-route").await?);
    assert!(
        !gw_before.is_empty(),
        "expected Gateway conditions to be present before poking"
    );
    assert!(
        !route_before.is_empty(),
        "expected HTTPRoute conditions to be present before poking"
    );

    const POKE_ANNOTATION: &str = "e2e.coxswain-labs.dev/poke";
    for round in 0..3 {
        let want = round.to_string();
        let poke = serde_json::json!({ "metadata": { "annotations": { POKE_ANNOTATION: want } } });
        gateways
            .patch(
                "coxswain-test",
                &PatchParams::default(),
                &Patch::Merge(&poke),
            )
            .await?;
        routes
            .patch("echo-route", &PatchParams::default(), &Patch::Merge(&poke))
            .await?;

        // Wait until both pokes are observable again through the API — informers
        // have therefore delivered them and the work-queues have processed the
        // update (a real post-condition, not a blind sleep). This is the window
        // in which a broken idempotency gate would re-patch status.
        wait::poll_until(
            Duration::from_secs(15),
            wait::POLL,
            || async { format!("poke round {round} to land on both Gateway and HTTPRoute") },
            || async {
                let gw_ann = gateways
                    .get("coxswain-test")
                    .await
                    .ok()
                    .and_then(|g| g.metadata.annotations?.get(POKE_ANNOTATION).cloned());
                let rt_ann = routes
                    .get("echo-route")
                    .await
                    .ok()
                    .and_then(|r| r.metadata.annotations?.get(POKE_ANNOTATION).cloned());
                (gw_ann.as_deref() == Some(want.as_str())
                    && rt_ann.as_deref() == Some(want.as_str()))
                .then_some(())
            },
        )
        .await?;

        let gw_after = gateway_condition_stamps(&gateways.get("coxswain-test").await?);
        let route_after = route_condition_stamps(&routes.get("echo-route").await?);
        assert_eq!(
            gw_after, gw_before,
            "Gateway condition stamps churned on round {round} — the status writer re-patched on a no-op reconcile"
        );
        assert_eq!(
            route_after, route_before,
            "HTTPRoute condition stamps churned on round {round} — the status writer re-patched on a no-op reconcile"
        );
    }

    Ok(())
}

/// `(type, lastTransitionTime, observedGeneration)` for every top-level Gateway
/// condition, sorted by type — a stable fingerprint of what the writer stamped.
fn gateway_condition_stamps(gw: &Gateway) -> Vec<(String, Time, Option<i64>)> {
    let mut out: Vec<(String, Time, Option<i64>)> = gw
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .map(|cs| {
            cs.iter()
                .map(|c| {
                    (
                        c.type_.clone(),
                        c.last_transition_time.clone(),
                        c.observed_generation,
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Same fingerprint across every parent's conditions of an HTTPRoute.
fn route_condition_stamps(route: &HTTPRoute) -> Vec<(String, Time, Option<i64>)> {
    let mut out: Vec<(String, Time, Option<i64>)> = route
        .status
        .as_ref()
        .map(|s| {
            s.parents
                .iter()
                .flat_map(|p| {
                    p.conditions.iter().map(|c| {
                        (
                            c.type_.clone(),
                            c.last_transition_time.clone(),
                            c.observed_generation,
                        )
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// `(status, reason)` of the first parent condition of `type_`, or `None`.
fn route_parent_condition(route: &HTTPRoute, type_: &str) -> Option<(String, String)> {
    route.status.as_ref()?.parents.iter().find_map(|p| {
        p.conditions
            .iter()
            .find(|c| c.type_ == type_)
            .map(|c| (c.status.clone(), c.reason.clone()))
    })
}

/// Verifies that a Gateway with no `addresses` field provided is still correctly processed
/// and its status correctly reflects whatever IP is allocated by the Service.
#[tokio::test]
async fn gateway_address_empty_allocates_dynamically() -> anyhow::Result<()> {
    // Start controller with a specific status address representing the LB IP
    let h = Harness::start_with_options(ControllerOptions {
        status_address: Some("203.0.113.8".to_string()),
        ..Default::default()
    })
    .await?;
    let ns = NamespaceGuard::create(&h.client, "gw-empty-addr").await?;

    fixtures::apply_fixture(gwa::EMPTY_ADDRESS, FixtureVars::new(&ns.name)).await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);

    // Wait for the gateway to become Accepted=True and get its addresses populated
    let (addresses, _) = wait::poll_until(
        Duration::from_secs(30),
        Duration::from_secs(1),
        || async {
            let gw = gw_api.get("coxswain-test").await.unwrap();
            let cond = gateway_condition(&gw, "Accepted");
            let addrs = gateway_addresses(&gw);
            format!("Accepted: {cond:?}, addresses: {addrs:?}")
        },
        || async {
            let gw = gw_api.get("coxswain-test").await.ok()?;
            let is_accepted = gateway_condition(&gw, "Accepted").is_some_and(|(s, _)| s == "True");
            let addrs = gateway_addresses(&gw);
            if is_accepted && !addrs.is_empty() {
                Some((addrs, gw))
            } else {
                None
            }
        },
    )
    .await?;

    assert_eq!(addresses.len(), 1, "expected exactly one address");
    assert_eq!(addresses[0].0, "IPAddress");
    assert_eq!(addresses[0].1, "203.0.113.8");

    Ok(())
}
