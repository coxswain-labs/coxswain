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
//! `GatewayClass.status.supportedFeatures`, and the dedicated-mode status writer
//! (#211): ClusterIP/LoadBalancer address derivation and `InvalidParameters`.

use coxswain_e2e::{
    ControllerOptions, FixtureVars, Harness, NamespaceGuard,
    fixtures::{self, backends, dedicated_proxy as dedicated, gateway_api as gwa, ingress},
    harness::wait,
};
use gateway_api::apis::standard::gateways::Gateway;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Service, ServiceAccount};
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
    // the operator's reconcile to propagate. 60s window accommodates image
    // pull and pod startup on a cold local cluster.
    let gw = wait::poll_until(
        Duration::from_secs(60),
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
    let addresses = gateway_addresses(&gw);
    assert!(
        addresses
            .iter()
            .any(|(t, v)| t == "IPAddress" && v == &cluster_ip),
        "Gateway.status.addresses should include ({cluster_ip}); got {addresses:?}"
    );

    Ok(())
}
