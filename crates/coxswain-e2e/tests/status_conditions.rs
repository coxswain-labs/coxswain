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
    ControllerOptions, FixtureVars, GeneratedCert, Harness, MtlsCerts, NamespaceGuard,
    fixtures::{self, backends, dedicated_proxy as dedicated, gateway_api as gwa, ingress},
    harness::{GATEWAY_TLS_PASSTHROUGH_PORT, wait},
};
use gateway_api_types::apis::standard::gateways::Gateway;
use gateway_api_types::apis::standard::grpcroutes::GrpcRoute;
use gateway_api_types::apis::standard::httproutes::HttpRoute;
use gateway_api_types::apis::standard::listenersets::ListenerSet;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Service, ServiceAccount, ServicePort, ServiceSpec};
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
    let ns = NamespaceGuard::create(&h.client, "sc-ing-lb-status").await?;

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
    let ns = NamespaceGuard::create(&h.client, "sc-gw-status").await?;

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
    let ns = NamespaceGuard::create(&h.client, "sc-gw-gen-tracking").await?;

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
    let gw_http = h.gateway_http_addr(&ns.name).await?;
    let http_port = gw_http.port();
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
/// `serviceType: ClusterIP`, wait for the provisioned proxy to come up and
/// report its listener ports bound (#531), then assert the operator
/// writes `Accepted=True`, `Programmed=True`,
/// `gateway.coxswain-labs.dev/DedicatedProxyReady=True/Ready`, and
/// `status.addresses[0]` matching the provisioned Service's `spec.clusterIP`.
///
/// Uses [`dedicated::DEDICATED_GATEWAY_CLUSTERIP`], which runs the real
/// coxswain image: since #531 `Programmed=True` additionally requires the
/// dedicated proxy to connect to discovery and report the Gateway's
/// listener ports bound, which no stub container can do.
#[tokio::test]
async fn writes_clusterip_address_and_programmed_true_when_proxy_binds() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-dedgw-status-clusterip").await?;

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
    // Programmed=True takes a moment: the provisioned proxy must start,
    // bootstrap its SVID over discovery, receive its first snapshot, bind the
    // listener, and report the bound port back before the operator's status
    // write converges. 90s accommodates all of that on a cold cluster,
    // matching the sibling dedicated tests on the same convergence path.
    let gw = wait::poll_until(
        Duration::from_secs(90),
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
    let ns = NamespaceGuard::create(&h.client, "sc-dedgw-status-lb").await?;

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
    //   * Pending — pod not yet Ready, or the proxy has not yet reported the
    //     Gateway's listener ports bound (#531)
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
    let ns = NamespaceGuard::create(&h.client, "sc-dedgw-status-invalid").await?;

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

/// Gateway API `GatewayInvalidParametersRef` (#517), shared-pool path: a Gateway
/// whose `spec.infrastructure.parametersRef` targets a kind coxswain does not
/// recognize gets `Accepted=False, reason=InvalidParameters`. (The dedicated-mode
/// counterpart — a missing `CoxswainGatewayParameters` — is covered above.)
///   - happy: a Gateway with no `parametersRef` is `Accepted=True/Accepted`;
///   - sad: a Gateway with a foreign `parametersRef` kind is
///     `Accepted=False/InvalidParameters`.
#[tokio::test]
async fn gateway_rejected_when_parameters_ref_unsupported() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-bad-params").await?;

    fixtures::apply_fixture(gwa::GATEWAY_INVALID_PARAMS_REF, FixtureVars::new(&ns.name)).await?;
    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);

    // Sad: the foreign-parametersRef Gateway is rejected.
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            let observed = gateways.get("coxswain-bad-params").await.ok().map_or_else(
                || "<none>".to_string(),
                |gw| format!("{:?}", gateway_condition(&gw, "Accepted")),
            );
            format!(
                "coxswain-bad-params to be Accepted=False(InvalidParameters); observed {observed}"
            )
        },
        || async {
            let gw = gateways.get("coxswain-bad-params").await.ok()?;
            (gateway_condition(&gw, "Accepted")?
                == ("False".to_string(), "InvalidParameters".to_string()))
                .then_some(())
        },
    )
    .await?;

    // Happy: the clean Gateway (no parametersRef) is accepted.
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async { "coxswain-clean to be Accepted=True(Accepted)".to_string() },
        || async {
            let gw = gateways.get("coxswain-clean").await.ok()?;
            (gateway_condition(&gw, "Accepted")? == ("True".to_string(), "Accepted".to_string()))
                .then_some(())
        },
    )
    .await?;

    Ok(())
}

/// Gateway API `GatewayListenerUnsupportedProtocol` (#517): a listener whose
/// protocol coxswain does not route gets `Accepted=False, reason=UnsupportedProtocol`
/// with empty `supportedKinds`, and the Gateway rolls up to `ListenersNotValid`.
///   - all-unsupported: Gateway `Accepted=False/ListenersNotValid`, the listener
///     `Accepted=False/UnsupportedProtocol` with `supportedKinds: []`;
///   - mixed: Gateway `Accepted=True/ListenersNotValid` (one listener still valid),
///     the HTTP listener `Accepted=True`, the bad listener `Accepted=False/UnsupportedProtocol`.
#[tokio::test]
async fn gateway_listener_protocol_validation() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-bad-proto").await?;

    fixtures::apply_fixture(
        gwa::GATEWAY_UNSUPPORTED_PROTOCOL,
        FixtureVars::new(&ns.name),
    )
    .await?;
    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);

    // ── all-unsupported: Gateway not accepted, listener UnsupportedProtocol ──
    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-all-bad",
        &ns.name,
        "Accepted",
        "False",
        Duration::from_secs(60),
    )
    .await?;
    wait::wait_for_gateway_listener_condition(
        &h.client,
        "coxswain-all-bad",
        &ns.name,
        "invalid",
        "Accepted",
        "False",
        Duration::from_secs(30),
    )
    .await?;
    let gw = gateways.get("coxswain-all-bad").await?;
    assert_eq!(
        gateway_condition(&gw, "Accepted"),
        Some(("False".to_string(), "ListenersNotValid".to_string())),
        "all-unsupported Gateway must be Accepted=False/ListenersNotValid"
    );
    let inv = gw
        .status
        .as_ref()
        .and_then(|s| s.listeners.as_ref())
        .and_then(|ls| ls.iter().find(|l| l.name == "invalid"))
        .expect("invalid listener status");
    let inv_acc = inv
        .conditions
        .iter()
        .find(|c| c.type_ == "Accepted")
        .expect("invalid listener Accepted condition");
    assert_eq!(
        (inv_acc.status.as_str(), inv_acc.reason.as_str()),
        ("False", "UnsupportedProtocol"),
        "unsupported-protocol listener must be Accepted=False/UnsupportedProtocol"
    );
    assert!(
        inv.supported_kinds.as_ref().is_none_or(|k| k.is_empty()),
        "unsupported-protocol listener must advertise empty supportedKinds, got {:?}",
        inv.supported_kinds
    );

    // ── mixed: Gateway accepted (True) but reason ListenersNotValid ──
    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-mixed",
        &ns.name,
        "Accepted",
        "True",
        Duration::from_secs(60),
    )
    .await?;
    let gw = gateways.get("coxswain-mixed").await?;
    assert_eq!(
        gateway_condition(&gw, "Accepted"),
        Some(("True".to_string(), "ListenersNotValid".to_string())),
        "mixed Gateway must be Accepted=True/ListenersNotValid (one listener still valid)"
    );
    let listeners = gw
        .status
        .as_ref()
        .and_then(|s| s.listeners.as_ref())
        .expect("mixed listener statuses");
    let http_acc = listeners
        .iter()
        .find(|l| l.name == "http")
        .and_then(|l| l.conditions.iter().find(|c| c.type_ == "Accepted"))
        .expect("http listener Accepted condition");
    assert_eq!(
        http_acc.status, "True",
        "valid HTTP listener must be Accepted=True"
    );
    let bad_acc = listeners
        .iter()
        .find(|l| l.name == "invalid")
        .and_then(|l| l.conditions.iter().find(|c| c.type_ == "Accepted"))
        .expect("invalid listener Accepted condition");
    assert_eq!(
        (bad_acc.status.as_str(), bad_acc.reason.as_str()),
        ("False", "UnsupportedProtocol"),
        "unsupported listener on the mixed Gateway must be Accepted=False/UnsupportedProtocol"
    );

    Ok(())
}

/// 15 — `Programmed=True` plus `status.addresses` populated for a ClusterIP
/// dedicated-mode Gateway. (Sibling of test 8 which also pins ClusterIP, but
/// gates only on conditions/addresses without the cutover-and-traffic plumbing.)
#[tokio::test]
async fn lifecycle_gateway_status_conditions_and_addresses() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-ded-life-status").await?;

    fixtures::apply_fixture(dedicated::PROVISIONING, FixtureVars::new(&ns.name)).await?;

    // 90s: real-proxy convergence (schedule → SVID bootstrap → snapshot →
    // bind → bound-port report), matching the sibling dedicated tests.
    wait::wait_for_gateway_programmed(&h.client, GATEWAY_NAME, &ns.name, Duration::from_secs(90))
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

    let routes: Api<HttpRoute> = Api::namespaced(h.client.clone(), &ns.name);

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
    let ns = NamespaceGuard::create(&h.client, "sc-ing-foreign-class").await?;

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
    let routes: Api<HttpRoute> = Api::namespaced(h.client.clone(), &ns.name);

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
fn route_condition_stamps(route: &HttpRoute) -> Vec<(String, Time, Option<i64>)> {
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
fn route_parent_condition(route: &HttpRoute, type_: &str) -> Option<(String, String)> {
    route.status.as_ref()?.parents.iter().find_map(|p| {
        p.conditions
            .iter()
            .find(|c| c.type_ == type_)
            .map(|c| (c.status.clone(), c.reason.clone()))
    })
}

/// Verifies that a Gateway with no `addresses` field is still correctly
/// processed and its status reflects the IP dynamically allocated for it.
///
/// With per-Gateway addressing (#472) that IP is the Gateway's OWN VIP Service
/// address, allocated by the cluster's LB controller — and it overrides the
/// global `--status-address`: a shared Gateway never advertises the global
/// address (whose fixed 80/443 serve Ingress only). So the controller is given
/// a global address here precisely to prove the VIP wins over it.
#[tokio::test]
async fn gateway_address_empty_allocates_dynamically() -> anyhow::Result<()> {
    // A global --status-address the Gateway must NOT end up advertising: its own
    // per-Gateway VIP takes precedence (#472).
    let h = Harness::start_with_options(ControllerOptions {
        status_address: Some("203.0.113.8".to_string()),
        ..Default::default()
    })
    .await?;
    let ns = NamespaceGuard::create(&h.client, "sc-gw-empty-addr").await?;

    fixtures::apply_fixture(gwa::EMPTY_ADDRESS, FixtureVars::new(&ns.name)).await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);

    // Wait for the gateway to become Accepted=True and get its addresses
    // populated. The window matches the harness VIP wait: provisioning the VIP
    // Service and resolving its LB IP is a multi-step async chain.
    let (addresses, _) = wait::poll_until(
        Duration::from_secs(120),
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
    // The Gateway advertises its OWN dynamically-allocated VIP (#472), a real
    // cluster IP — never the global --status-address fallback.
    let addr = &addresses[0].1;
    assert!(
        addr.parse::<std::net::Ipv4Addr>().is_ok(),
        "expected a dynamically-allocated IPv4 VIP, got {addr:?}"
    );
    assert_ne!(
        addr, "203.0.113.8",
        "shared Gateway must advertise its own VIP, not the global --status-address"
    );

    Ok(())
}

// ── GatewayStaticAddresses (#260) ────────────────────────────────────────────

/// Probe `n` known-free in-CIDR clusterIPs: the apiserver assigns one to each
/// throwaway ClusterIP Service; deleting them frees those exact IPs for coxswain
/// to re-request. clusterIPs are cluster-global, so a test-namespace probe
/// yields service-CIDR addresses. All probes are created before any is deleted,
/// so the returned IPs are guaranteed pairwise distinct — deleting between
/// probes would let the allocator hand the same IP out twice.
async fn probe_free_cluster_ips(
    svc_api: &Api<Service>,
    prefix: &str,
    n: usize,
) -> anyhow::Result<Vec<String>> {
    let mut ips = Vec::with_capacity(n);
    for i in 0..n {
        let probe = Service {
            metadata: kube::api::ObjectMeta {
                name: Some(format!("{prefix}-{i}")),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some("ClusterIP".to_string()),
                ports: Some(vec![ServicePort {
                    port: 80,
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let created = svc_api.create(&Default::default(), &probe).await?;
        let ip = created
            .spec
            .and_then(|s| s.cluster_ip)
            .filter(|ip| !ip.is_empty() && ip != "None")
            .ok_or_else(|| anyhow::anyhow!("probe Service {prefix}-{i} got no clusterIP"))?;
        ips.push(ip);
    }
    for i in 0..n {
        svc_api
            .delete(&format!("{prefix}-{i}"), &Default::default())
            .await?;
    }
    Ok(ips)
}

/// Sad path: a Gateway requesting an address of an unsupported `type`
/// (`test/fake-invalid-type`) is rejected with
/// `Accepted=False/UnsupportedAddress`. VIP-type-agnostic.
#[tokio::test]
async fn accepted_false_unsupported_address_when_invalid_type() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-static-unsupported").await?;
    fixtures::apply_fixture(
        gwa::STATIC_ADDRESS,
        FixtureVars::new(&ns.name)
            .with("ADDR_TYPE", "test/fake-invalid-type")
            .with("ADDR_VALUE", "fake address teehee"),
    )
    .await?;
    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait::poll_until(
        Duration::from_secs(30),
        Duration::from_secs(1),
        || async {
            let c = gw_api
                .get("coxswain-test")
                .await
                .ok()
                .and_then(|gw| gateway_condition(&gw, "Accepted"));
            format!("Accepted to be False/UnsupportedAddress; observed {c:?}")
        },
        || async {
            let gw = gw_api.get("coxswain-test").await.ok()?;
            (gateway_condition(&gw, "Accepted")
                == Some(("False".to_string(), "UnsupportedAddress".to_string())))
            .then_some(())
        },
    )
    .await?;
    Ok(())
}

/// Sad path: a Gateway requesting a supported-type IP that coxswain cannot bind
/// (TEST-NET-1 `192.0.2.1`, outside any Service CIDR — the apiserver rejects it
/// as a clusterIP under either VIP Service type) stays `Accepted=True` but goes
/// `Programmed=False/AddressNotUsable`. VIP-type-agnostic.
#[tokio::test]
async fn programmed_false_address_not_usable_when_out_of_cidr_ip() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-static-unusable").await?;
    fixtures::apply_fixture(
        gwa::STATIC_ADDRESS,
        FixtureVars::new(&ns.name)
            .with("ADDR_TYPE", "IPAddress")
            .with("ADDR_VALUE", "192.0.2.1"),
    )
    .await?;
    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait::poll_until(
        Duration::from_secs(60),
        Duration::from_secs(1),
        || async {
            let gw = gw_api.get("coxswain-test").await.ok();
            let acc = gw.as_ref().and_then(|g| gateway_condition(g, "Accepted"));
            let prog = gw.as_ref().and_then(|g| gateway_condition(g, "Programmed"));
            format!("Accepted=True + Programmed=False/AddressNotUsable; observed Accepted={acc:?} Programmed={prog:?}")
        },
        || async {
            let gw = gw_api.get("coxswain-test").await.ok()?;
            let accepted = gateway_condition(&gw, "Accepted")?;
            let programmed = gateway_condition(&gw, "Programmed")?;
            (accepted == ("True".to_string(), "Accepted".to_string())
                && programmed == ("False".to_string(), "AddressNotUsable".to_string()))
            .then_some(())
        },
    )
    .await?;
    // The rejected address must NOT leak into status.addresses.
    let gw = gw_api.get("coxswain-test").await?;
    assert!(
        !gateway_addresses(&gw).iter().any(|(_, v)| v == "192.0.2.1"),
        "unusable requested address must not appear in status.addresses"
    );
    Ok(())
}

/// Sad path: requesting two distinct static IPs is inherently unusable — a single
/// backing Service binds at most one clusterIP, so the second can never be
/// satisfied → `Programmed=False/AddressNotUsable`. VIP-type-agnostic.
#[tokio::test]
async fn programmed_false_address_not_usable_when_two_ips_requested() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-static-two-ips").await?;
    fixtures::apply_fixture(
        gwa::STATIC_ADDRESSES_PAIR,
        FixtureVars::new(&ns.name)
            .with("ADDR_ONE", "192.0.2.1")
            .with("ADDR_TWO", "192.0.2.2"),
    )
    .await?;
    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait::poll_until(
        Duration::from_secs(60),
        Duration::from_secs(1),
        || async {
            let prog = gw_api
                .get("coxswain-test")
                .await
                .ok()
                .and_then(|g| gateway_condition(&g, "Programmed"));
            format!("Programmed to be False/AddressNotUsable; observed {prog:?}")
        },
        || async {
            let gw = gw_api.get("coxswain-test").await.ok()?;
            let accepted = gateway_condition(&gw, "Accepted")?;
            let programmed = gateway_condition(&gw, "Programmed")?;
            (accepted.0 == "True"
                && programmed == ("False".to_string(), "AddressNotUsable".to_string()))
                .then_some(())
        },
    )
    .await?;
    Ok(())
}

/// Happy path: a Gateway requesting a known-free in-CIDR IP has it honored —
/// coxswain provisions that Gateway's VIP as a ClusterIP pinned to the requested
/// IP (apiserver-assigned, deterministic on every cluster), so it surfaces as the
/// resolved address → `Programmed=True` with the requested IP in
/// `status.addresses`. Cluster-type-agnostic: the static-IP Gateway is forced to
/// ClusterIP regardless of the global VIP type.
#[tokio::test]
async fn programmed_true_and_address_written_when_usable_clusterip_requested() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-static-usable").await?;

    let svc_api: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    let usable_ip = probe_free_cluster_ips(&svc_api, "static-addr-probe", 1)
        .await?
        .remove(0);

    fixtures::apply_fixture(
        gwa::STATIC_ADDRESS,
        FixtureVars::new(&ns.name)
            .with("ADDR_TYPE", "IPAddress")
            .with("ADDR_VALUE", &usable_ip),
    )
    .await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let usable_for_assert = usable_ip.clone();
    wait::poll_until(
        Duration::from_secs(120),
        Duration::from_secs(1),
        || async {
            let gw = gw_api.get("coxswain-test").await.ok();
            let prog = gw.as_ref().and_then(|g| gateway_condition(g, "Programmed"));
            let addrs = gw.as_ref().map(gateway_addresses).unwrap_or_default();
            format!("Programmed=True with requested IP {usable_ip} in addresses; observed Programmed={prog:?} addresses={addrs:?}")
        },
        || async {
            let gw = gw_api.get("coxswain-test").await.ok()?;
            let accepted = gateway_condition(&gw, "Accepted")?;
            let programmed = gateway_condition(&gw, "Programmed")?;
            let has_addr = gateway_addresses(&gw)
                .iter()
                .any(|(t, v)| t == "IPAddress" && v == &usable_for_assert);
            (accepted == ("True".to_string(), "Accepted".to_string())
                && programmed == ("True".to_string(), "Programmed".to_string())
                && has_addr)
                .then_some(())
        },
    )
    .await?;
    Ok(())
}

/// #558 regression: repinning a static address (patching `spec.addresses` from
/// one free clusterIP to another) must converge to `Programmed=True` carrying
/// the NEW address at the new generation. The repin forces the operator to
/// delete + recreate the VIP Service (`spec.clusterIP` is immutable), a window
/// where the shared status writer can observe a resolved-but-stale address with
/// zero requested matches; before #558 that settled `AddressNotUsable` and went
/// quiet (`await_change`) — no Gateway event ever healed it, the
/// `GatewayStaticAddresses` conformance flake.
#[tokio::test]
async fn programmed_recovers_with_new_address_after_static_address_repin() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-static-repin").await?;

    let svc_api: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    let mut probed = probe_free_cluster_ips(&svc_api, "repin-probe", 2).await?;
    let second_ip = probed.remove(1);
    let first_ip = probed.remove(0);

    fixtures::apply_fixture(
        gwa::STATIC_ADDRESS,
        FixtureVars::new(&ns.name)
            .with("ADDR_TYPE", "IPAddress")
            .with("ADDR_VALUE", &first_ip),
    )
    .await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let first_for_assert = first_ip.clone();
    wait::poll_until(
        Duration::from_secs(120),
        Duration::from_secs(1),
        || async {
            let gw = gw_api.get("coxswain-test").await.ok();
            let prog = gw.as_ref().and_then(|g| gateway_condition(g, "Programmed"));
            let addrs = gw.as_ref().map(gateway_addresses).unwrap_or_default();
            format!(
                "Programmed=True with first IP {first_ip} in addresses; \
                 observed Programmed={prog:?} addresses={addrs:?}"
            )
        },
        || async {
            let gw = gw_api.get("coxswain-test").await.ok()?;
            let programmed = gateway_condition(&gw, "Programmed")?;
            let has_addr = gateway_addresses(&gw)
                .iter()
                .any(|(t, v)| t == "IPAddress" && v == &first_for_assert);
            (programmed == ("True".to_string(), "Programmed".to_string()) && has_addr).then_some(())
        },
    )
    .await?;

    // Repin: same fixture, new address → generation bump + immutable-clusterIP
    // Service delete/recreate on the operator side.
    fixtures::apply_fixture(
        gwa::STATIC_ADDRESS,
        FixtureVars::new(&ns.name)
            .with("ADDR_TYPE", "IPAddress")
            .with("ADDR_VALUE", &second_ip),
    )
    .await?;

    let second_for_assert = second_ip.clone();
    let first_for_negative = first_ip.clone();
    wait::poll_until(
        Duration::from_secs(120),
        Duration::from_secs(1),
        || async {
            let gw = gw_api.get("coxswain-test").await.ok();
            let addrs = gw.as_ref().map(gateway_addresses).unwrap_or_default();
            format!(
                "Programmed=True at the new generation carrying only {second_ip}; \
                 observed Programmed={:?} addresses={addrs:?}",
                gw.as_ref().and_then(programmed_full)
            )
        },
        || async {
            let gw = gw_api.get("coxswain-test").await.ok()?;
            let generation = gw.metadata.generation.unwrap_or(0);
            let (status, _reason, observed) = programmed_full(&gw)?;
            let addrs = gateway_addresses(&gw);
            let has_new = addrs
                .iter()
                .any(|(t, v)| t == "IPAddress" && v == &second_for_assert);
            let has_old = addrs.iter().any(|(_, v)| v == &first_for_negative);
            (status == "True" && observed == generation && has_new && !has_old).then_some(())
        },
    )
    .await?;
    Ok(())
}

// ── observedGeneration-vs-address convergence (#533) ─────────────────────────

/// The `(status, reason, observedGeneration)` of a Gateway's top-level
/// `Programmed` condition — `observedGeneration` is not exposed by the shared
/// `gateway_condition` helper but is the crux of the #533 coherence invariant.
fn programmed_full(gw: &Gateway) -> Option<(String, String, i64)> {
    gw.status
        .as_ref()?
        .conditions
        .as_ref()?
        .iter()
        .find(|c| c.type_ == "Programmed")
        .map(|c| {
            (
                c.status.clone(),
                c.reason.clone(),
                c.observed_generation.unwrap_or(0),
            )
        })
}

/// #533 happy path + coherence invariant (shared): the `Programmed` condition's
/// `observedGeneration` must never reach `metadata.generation` while the
/// requested static address is still missing from `status.addresses`. Sample
/// rapidly through the convergence window and fail the instant that coherence
/// breaks; converge on `Programmed=True` carrying the requested IP.
#[tokio::test]
async fn shared_gateway_generation_trails_address_until_resolved() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-gw-gen-trails-addr").await?;

    let svc_api: Api<Service> = Api::namespaced(h.client.clone(), &ns.name);
    let usable_ip = probe_free_cluster_ips(&svc_api, "gen-trails-probe", 1)
        .await?
        .remove(0);

    fixtures::apply_fixture(
        gwa::STATIC_ADDRESS,
        FixtureVars::new(&ns.name)
            .with("ADDR_TYPE", "IPAddress")
            .with("ADDR_VALUE", &usable_ip),
    )
    .await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let usable_for_assert = usable_ip.clone();
    wait::poll_until(
        Duration::from_secs(120),
        wait::POLL,
        || async {
            let gw = gw_api.get("coxswain-test").await.ok();
            format!(
                "Programmed=True carrying {usable_ip}; observed Programmed={:?} addresses={:?}",
                gw.as_ref().and_then(programmed_full),
                gw.as_ref().map(gateway_addresses).unwrap_or_default()
            )
        },
        || async {
            let gw = gw_api.get("coxswain-test").await.ok()?;
            let generation = gw.metadata.generation.unwrap_or(0);
            let (status, _reason, observed) = programmed_full(&gw)?;
            let has_ip = gateway_addresses(&gw)
                .iter()
                .any(|(t, v)| t == "IPAddress" && v == &usable_for_assert);
            // #533 invariant: Programmed cannot claim generation N is fully
            // processed while the requested address is unresolved.
            assert!(
                !(observed >= generation && !has_ip),
                "#533 violated: Programmed observedGeneration {observed} >= generation {generation} \
                 while status.addresses is missing {usable_for_assert}"
            );
            (status == "True" && has_ip).then_some(())
        },
    )
    .await?;
    Ok(())
}

/// #533 sad companion (shared): a *settled negative* — a requested static IP
/// outside the service CIDR that can never be assigned — must stamp its
/// `Programmed=False/AddressNotUsable` at the current generation, NOT be held
/// below it. The convergence hold applies only to states still racing to
/// converge, never to a real, final negative outcome.
#[tokio::test]
async fn shared_gateway_settled_address_not_usable_stamps_current_generation() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-gw-settled-negative-gen").await?;

    fixtures::apply_fixture(
        gwa::STATIC_ADDRESS,
        FixtureVars::new(&ns.name)
            .with("ADDR_TYPE", "IPAddress")
            .with("ADDR_VALUE", "192.0.2.1"), // TEST-NET-1: never in the service CIDR
    )
    .await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            let gw = gw_api.get("coxswain-test").await.ok();
            format!(
                "Programmed=False/AddressNotUsable at current generation; observed {:?}",
                gw.as_ref().and_then(programmed_full)
            )
        },
        || async {
            let gw = gw_api.get("coxswain-test").await.ok()?;
            let generation = gw.metadata.generation.unwrap_or(0);
            let (status, reason, observed) = programmed_full(&gw)?;
            (status == "False" && reason == "AddressNotUsable" && observed == generation)
                .then_some(())
        },
    )
    .await?;
    Ok(())
}

/// #533 happy path + coherence invariant (dedicated): the dedicated-proxy
/// Service address resolves through the watch-lagged services store, so the
/// operator's `Programmed` writer must never report `AddressNotAssigned` at the
/// current generation — that transient is held one generation below until the
/// address lands. Sample through convergence and converge on `Programmed=True`
/// carrying the Service's clusterIP.
#[tokio::test]
async fn dedicated_gateway_generation_trails_address_until_resolved() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-dedgw-gen-trails-addr").await?;

    fixtures::apply_fixture(
        dedicated::DEDICATED_GATEWAY_CLUSTERIP,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait::poll_until(
        Duration::from_secs(90),
        wait::POLL,
        || async {
            let gw = gateways.get(GATEWAY_NAME).await.ok();
            format!(
                "dedicated Programmed=True with an address; observed Programmed={:?} addresses={:?}",
                gw.as_ref().and_then(programmed_full),
                gw.as_ref().map(gateway_addresses).unwrap_or_default()
            )
        },
        || async {
            let gw = gateways.get(GATEWAY_NAME).await.ok()?;
            let generation = gw.metadata.generation.unwrap_or(0);
            let (status, reason, observed) = programmed_full(&gw)?;
            // #533 invariant: `AddressNotAssigned` (address genuinely unresolved)
            // must never be stamped at the current generation.
            assert!(
                !(reason == "AddressNotAssigned" && observed >= generation),
                "#533 violated (dedicated): AddressNotAssigned stamped at generation {generation} \
                 (observedGeneration {observed}) while the Service address is unresolved"
            );
            (status == "True" && !gateway_addresses(&gw).is_empty()).then_some(())
        },
    )
    .await?;
    Ok(())
}

// ── ValidatingAdmissionPolicy (#29) ──────────────────────────────────────────

/// VAP positive path: a well-formed Ingress with valid coxswain annotations
/// (one per validated format category) must be accepted unchanged (#29).
#[tokio::test]
async fn vap_accepts_well_formed_annotations() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "vap-valid").await?;
    fixtures::apply_fixture(ingress::VAP_VALID_ANNOTATIONS, FixtureVars::new(&ns.name)).await?;
    Ok(())
}

/// VAP rejects a boolean annotation with an invalid value (`use-regex: "yep"`) (#29).
#[tokio::test]
async fn vap_rejects_invalid_boolean_annotation() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "vap-bool").await?;
    let msg = fixtures::apply_fixture_expect_rejected(
        ingress::VAP_REJECT_BOOLEAN,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("use-regex"),
        "VAP rejection message must name the offending annotation, got: {msg}"
    );
    Ok(())
}

/// VAP rejects an enum annotation with an invalid value (`path-normalize: "invalid"`) (#29).
/// Retargeted from `session-affinity` after #554 converged it to
/// `CoxswainBackendPolicy`, which is not VAP-validated by design.
#[tokio::test]
async fn vap_rejects_invalid_enum_annotation() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "vap-enum").await?;
    let msg = fixtures::apply_fixture_expect_rejected(
        ingress::VAP_REJECT_ENUM,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("path-normalize"),
        "VAP rejection message must name the offending annotation, got: {msg}"
    );
    Ok(())
}

/// VAP rejects a CIDR-list annotation with an invalid token
/// (`forwarded-for-trusted-cidrs: "not-a-cidr"`) (#29). Retargeted from
/// `allow-source-range` after #553 converged `ip-access-control` to a CR
/// reference with no VAP rule.
#[tokio::test]
async fn vap_rejects_invalid_cidr_annotation() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "vap-cidr").await?;
    let msg = fixtures::apply_fixture_expect_rejected(
        ingress::VAP_REJECT_CIDR,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("forwarded-for-trusted-cidrs"),
        "VAP rejection message must name the offending annotation, got: {msg}"
    );
    Ok(())
}

/// VAP rejects a URL annotation with an invalid scheme (`auth-url: "ftp://..."`) (#29).
#[tokio::test]
async fn vap_rejects_invalid_url_annotation() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "vap-url").await?;
    let msg = fixtures::apply_fixture_expect_rejected(
        ingress::VAP_REJECT_URL,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("auth-url"),
        "VAP rejection message must name the offending annotation, got: {msg}"
    );
    Ok(())
}

/// VAP rejects a port annotation out of range (`redirect-port: "99999"`) (#29).
#[tokio::test]
async fn vap_rejects_out_of_range_port_annotation() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "vap-port").await?;
    let msg = fixtures::apply_fixture_expect_rejected(
        ingress::VAP_REJECT_PORT,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("redirect-port"),
        "VAP rejection message must name the offending annotation, got: {msg}"
    );
    Ok(())
}

/// VAP rejects a duration annotation with an invalid value (`read-timeout: "notaduration"`) (#29).
/// Retargeted from `upstream-keepalive-timeout` after #554 converged it to
/// `CoxswainBackendPolicy`, which is not VAP-validated by design.
#[tokio::test]
async fn vap_rejects_invalid_duration_annotation() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "vap-dur").await?;
    let msg = fixtures::apply_fixture_expect_rejected(
        ingress::VAP_REJECT_DURATION,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("read-timeout"),
        "VAP rejection message must name the offending annotation, got: {msg}"
    );
    Ok(())
}

/// VAP rejects a size-string annotation with an invalid value (`max-body-size: "garbage"`) (#29).
#[tokio::test]
async fn vap_rejects_invalid_size_string_annotation() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "vap-size").await?;
    let msg = fixtures::apply_fixture_expect_rejected(
        ingress::ANNOTATION_MAX_BODY_SIZE_INVALID,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("max-body-size"),
        "VAP rejection message must name the offending annotation, got: {msg}"
    );
    Ok(())
}

/// VAP rejects a positive-integer annotation with an invalid value
/// (`auth-tls-verify-depth: "notanumber"`) (#29). Retargeted from
/// `circuit-breaker-threshold` after #554 converged it to
/// `CoxswainBackendPolicy`, which is not VAP-validated by design — this test
/// exercises the general ">= 1 positive integer" VAP rule shape, not
/// `circuit-breaker-threshold` specifically (itself previously retargeted
/// from `rate-limit-rps` after #552).
#[tokio::test]
async fn vap_rejects_invalid_positive_integer_annotation() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "vap-int").await?;
    let msg = fixtures::apply_fixture_expect_rejected(
        ingress::VAP_REJECT_POSITIVE_INTEGER,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("auth-tls-verify-depth"),
        "VAP rejection message must name the offending annotation, got: {msg}"
    );
    Ok(())
}

/// Ingress with no coxswain annotations must not be touched by the VAP (#29).
#[tokio::test]
async fn vap_ignores_ingress_without_coxswain_annotations() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "vap-noanno").await?;
    // DEFAULT_BACKEND carries no coxswain annotations — must apply cleanly.
    fixtures::apply_fixture(ingress::DEFAULT_BACKEND, FixtureVars::new(&ns.name)).await?;
    Ok(())
}

// ── CRD openAPIV3Schema validation (#335) ────────────────────────────────────

/// Gateway with `port: 99999` is rejected by the gateway-api CRD structural
/// schema (`port` has `maximum: 65535`) — before the controller sees it (#335).
#[tokio::test]
async fn gateway_with_out_of_range_port_rejected() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "crd-gw-port").await?;
    let msg = fixtures::apply_fixture_expect_rejected(
        gwa::REJECT_GATEWAY_OUT_OF_RANGE_PORT,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("65535"),
        "CRD rejection message must mention the maximum port, got: {msg}"
    );
    Ok(())
}

/// HTTPRoute with an invalid path-match `type` value is rejected by the
/// gateway-api CRD structural schema — before the controller sees it (#335).
#[tokio::test]
async fn httproute_with_invalid_path_match_type_rejected() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "crd-ht-path").await?;
    let msg = fixtures::apply_fixture_expect_rejected(
        gwa::REJECT_HTTPROUTE_INVALID_PATH_TYPE,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("Glob"),
        "CRD rejection message must name the invalid value, got: {msg}"
    );
    Ok(())
}

/// `RateLimit` CR with the required `requestsPerSecond` field omitted is
/// rejected by the coxswain-owned CRD structural schema (#335).
#[tokio::test]
async fn ratelimit_missing_required_field_rejected() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "crd-rl-req").await?;
    let msg = fixtures::apply_fixture_expect_rejected(
        gwa::REJECT_RATELIMIT_MISSING_RPS,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("requestsPerSecond"),
        "CRD rejection message must name the missing required field, got: {msg}"
    );
    Ok(())
}

/// `CoxswainGatewayParameters` with an invalid `serviceType` value is rejected
/// by the coxswain-owned CRD structural schema (#335).
#[tokio::test]
async fn coxswain_gateway_parameters_invalid_service_type_rejected() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "crd-cgp-svc").await?;
    let msg = fixtures::apply_fixture_expect_rejected(
        dedicated::REJECT_GATEWAY_PARAMS_INVALID_SERVICE_TYPE,
        FixtureVars::new(&ns.name),
    )
    .await?;
    anyhow::ensure!(
        msg.contains("serviceType"),
        "CRD rejection message must name the offending field, got: {msg}"
    );
    Ok(())
}

/// A valid GRPCRoute with a resolvable backend reaches `Accepted=True`,
/// `Programmed=True`, and `ResolvedRefs=True`.
///
/// Closes the GRPCRoute status writer happy path: the controller must populate
/// all three conditions on a well-formed route, mirroring the HTTPRoute path.
#[tokio::test]
async fn grpc_route_accepted_and_programmed_when_valid() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-grpc-good").await?;

    fixtures::apply_fixture(backends::GRPC_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["grpc-echo"]).await?;
    fixtures::apply_fixture(gwa::GRPC_ROUTE_STATUS, FixtureVars::new(&ns.name)).await?;

    wait::wait_for_grpcroute_programmed(
        &h.client,
        "good-grpc-route",
        &ns.name,
        Duration::from_secs(30),
    )
    .await?;

    let routes: kube::Api<GrpcRoute> = kube::Api::namespaced(h.client.clone(), &ns.name);
    let good = routes.get("good-grpc-route").await?;

    assert_eq!(
        grpcroute_parent_condition(&good, "Accepted").map(|(s, _)| s),
        Some("True".to_string()),
        "good-grpc-route must be Accepted=True"
    );
    assert_eq!(
        grpcroute_parent_condition(&good, "Programmed").map(|(s, _)| s),
        Some("True".to_string()),
        "good-grpc-route must be Programmed=True"
    );
    assert_eq!(
        grpcroute_parent_condition(&good, "ResolvedRefs"),
        Some(("True".to_string(), "ResolvedRefs".to_string())),
        "good-grpc-route backend must resolve to ResolvedRefs=True"
    );

    Ok(())
}

/// A GRPCRoute whose backendRef points at a missing Service gets
/// `Accepted=True` but `ResolvedRefs=False(BackendNotFound)`.
///
/// Mirrors the HTTPRoute `ghost-route` sad path: the route is structurally
/// valid (Accepted) but the controller cannot resolve the backend reference.
#[tokio::test]
async fn grpc_route_resolvedrefs_false_when_backend_missing() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-grpc-ghost").await?;

    fixtures::apply_fixture(backends::GRPC_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["grpc-echo"]).await?;
    fixtures::apply_fixture(gwa::GRPC_ROUTE_STATUS, FixtureVars::new(&ns.name)).await?;

    // Wait for good-grpc-route to be Programmed — proves the writer is live in
    // this namespace, so ghost-grpc-route has had equal opportunity.
    wait::wait_for_grpcroute_programmed(
        &h.client,
        "good-grpc-route",
        &ns.name,
        Duration::from_secs(30),
    )
    .await?;

    let routes: kube::Api<GrpcRoute> = kube::Api::namespaced(h.client.clone(), &ns.name);

    wait::poll_until(
        Duration::from_secs(30),
        wait::POLL,
        || async {
            let observed = routes.get("ghost-grpc-route").await.ok().map_or_else(
                || "<could not fetch ghost-grpc-route>".to_string(),
                |r| {
                    format!(
                        "Accepted={:?}, ResolvedRefs={:?}",
                        grpcroute_parent_condition(&r, "Accepted"),
                        grpcroute_parent_condition(&r, "ResolvedRefs"),
                    )
                },
            );
            format!(
                "ghost-grpc-route to be Accepted=True + ResolvedRefs=False(BackendNotFound); observed {observed}"
            )
        },
        || async {
            let r = routes.get("ghost-grpc-route").await.ok()?;
            (grpcroute_parent_condition(&r, "Accepted").map(|(s, _)| s)
                == Some("True".to_string())
                && grpcroute_parent_condition(&r, "ResolvedRefs")
                    == Some(("False".to_string(), "BackendNotFound".to_string())))
            .then_some(())
        },
    )
    .await
}

/// `(status, reason)` of the first parent condition of `type_` on a GRPCRoute, or `None`.
fn grpcroute_parent_condition(route: &GrpcRoute, type_: &str) -> Option<(String, String)> {
    route.status.as_ref()?.parents.iter().find_map(|p| {
        p.conditions
            .iter()
            .find(|c| c.type_ == type_)
            .map(|c| (c.status.clone(), c.reason.clone()))
    })
}

// ── listener attachedRoutes across route kinds (#470) ─────────────────────────

/// `status.listeners[name].attachedRoutes` for the named listener, or `None` if
/// the Gateway has no status yet or no listener by that name.
fn listener_attached_routes(gw: &Gateway, listener: &str) -> Option<i32> {
    gw.status
        .as_ref()?
        .listeners
        .as_deref()?
        .iter()
        .find(|l| l.name == listener)
        .map(|l| l.attached_routes)
}

/// `status.listeners[name].supportedKinds[*].kind` for the named listener.
fn listener_supported_kinds(gw: &Gateway, listener: &str) -> Option<Vec<String>> {
    gw.status
        .as_ref()?
        .listeners
        .as_deref()?
        .iter()
        .find(|l| l.name == listener)
        .and_then(|l| l.supported_kinds.as_deref())
        .map(|kinds| kinds.iter().map(|k| k.kind.clone()).collect())
}

/// Both GRPCRoutes in the fixture attach to the Gateway's HTTP listener, so its
/// `attachedRoutes` reaches 2. Guards the GRPCRoute arm of [#470]: before the
/// fix the counter only walked HTTPRoutes, so GRPC-only listeners reported 0.
#[tokio::test]
async fn grpc_routes_counted_in_listener_attached_routes() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-grpc-attached").await?;

    fixtures::apply_fixture(backends::GRPC_ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_deployments(&ns.name, &["grpc-echo"]).await?;
    fixtures::apply_fixture(gwa::GRPC_ROUTE_STATUS, FixtureVars::new(&ns.name)).await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            let observed = gw_api
                .get("coxswain-grpc-status-gw")
                .await
                .ok()
                .map_or_else(
                    || "<could not fetch Gateway>".to_string(),
                    |gw| format!("attachedRoutes={:?}", listener_attached_routes(&gw, "http")),
                );
            format!(
                "Gateway coxswain-grpc-status-gw listener 'http' to report attachedRoutes=2 \
                 (both GRPCRoutes attach); observed {observed}"
            )
        },
        || async {
            let gw = gw_api.get("coxswain-grpc-status-gw").await.ok()?;
            (listener_attached_routes(&gw, "http") == Some(2)).then_some(())
        },
    )
    .await
}

/// A TLSRoute on a `TLS/Passthrough` listener bumps that listener's
/// `attachedRoutes` to 1. Before [#470] passthrough listeners were never
/// counted (the HTTPRoute-only counter skipped passthrough listeners), so this
/// always read 0.
#[tokio::test]
async fn tls_passthrough_route_counted_in_listener_attached_routes() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-tls-attached").await?;
    let hostname = format!("passthrough.{}.local", ns.name);

    fixtures::apply_fixture(
        gwa::TLS_PASSTHROUGH,
        FixtureVars::new(&ns.name)
            .with(
                "GATEWAY_TLS_PASSTHROUGH_PORT",
                &GATEWAY_TLS_PASSTHROUGH_PORT.to_string(),
            )
            .with("PASSTHROUGH_HOSTNAME", &hostname),
    )
    .await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            let observed = gw_api
                .get("coxswain-passthrough-gw")
                .await
                .ok()
                .map_or_else(
                    || "<could not fetch Gateway>".to_string(),
                    |gw| {
                        format!(
                            "attachedRoutes={:?}",
                            listener_attached_routes(&gw, "tls-passthrough")
                        )
                    },
                );
            format!(
                "Gateway coxswain-passthrough-gw listener 'tls-passthrough' to report \
                 attachedRoutes=1; observed {observed}"
            )
        },
        || async {
            let gw = gw_api.get("coxswain-passthrough-gw").await.ok()?;
            (listener_attached_routes(&gw, "tls-passthrough") == Some(1)).then_some(())
        },
    )
    .await
}

/// Sad path: a `TLS/Passthrough` listener with no TLSRoute reports
/// `attachedRoutes=0` — the counter must not over-count, and a passthrough
/// listener still gets a status entry once the Gateway is Programmed.
#[tokio::test]
async fn tls_passthrough_listener_without_route_reports_zero_attached_routes() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-tls-noroute-attached").await?;
    let hostname = format!("passthrough.{}.local", ns.name);

    fixtures::apply_fixture(
        gwa::TLS_PASSTHROUGH_GW_ONLY,
        FixtureVars::new(&ns.name)
            .with(
                "GATEWAY_TLS_PASSTHROUGH_PORT",
                &GATEWAY_TLS_PASSTHROUGH_PORT.to_string(),
            )
            .with("PASSTHROUGH_HOSTNAME", &hostname),
    )
    .await?;

    // Programmed=True proves the controller reconciled and wrote listener status.
    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-passthrough-gw-only",
        &ns.name,
        "Programmed",
        "True",
        Duration::from_secs(60),
    )
    .await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let gw = gw_api.get("coxswain-passthrough-gw-only").await?;
    assert_eq!(
        listener_attached_routes(&gw, "tls-passthrough"),
        Some(0),
        "passthrough listener with no TLSRoute must report attachedRoutes=0"
    );

    Ok(())
}

/// A TLSRoute attached to a `TLS/Terminate` listener increments that listener's
/// `attachedRoutes`. Guards the bug where `count_attached_routes` only counted
/// TLSRoutes on `TlsPassthrough` listeners, leaving Terminate listeners at 0.
#[tokio::test]
async fn tls_terminate_route_counted_in_listener_attached_routes() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-tls-term-attached").await?;
    let hostname = format!("terminate.{}.local", ns.name);
    let gw_cert = GeneratedCert::for_host(&hostname);

    fixtures::apply_fixture(
        gwa::TLS_TERMINATE,
        FixtureVars::new(&ns.name)
            .with(
                "GATEWAY_TLS_PASSTHROUGH_PORT",
                &GATEWAY_TLS_PASSTHROUGH_PORT.to_string(),
            )
            .with("TERMINATE_HOSTNAME", &hostname)
            .with("GW_TLS_CRT_B64", &gw_cert.cert_b64())
            .with("GW_TLS_KEY_B64", &gw_cert.key_b64()),
    )
    .await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            let observed = gw_api.get("coxswain-terminate-gw").await.ok().map_or_else(
                || "<could not fetch Gateway>".to_string(),
                |gw| {
                    format!(
                        "attachedRoutes={:?}",
                        listener_attached_routes(&gw, "tls-terminate")
                    )
                },
            );
            format!(
                "Gateway coxswain-terminate-gw listener 'tls-terminate' to report \
                 attachedRoutes=1; observed {observed}"
            )
        },
        || async {
            let gw = gw_api.get("coxswain-terminate-gw").await.ok()?;
            (listener_attached_routes(&gw, "tls-terminate") == Some(1)).then_some(())
        },
    )
    .await
}

/// A `TLS/Terminate` listener reports `TLSRoute` in its `supportedKinds` —
/// not `HTTPRoute`. Guards the bug where `listener_route_kind_info` only
/// recognised Passthrough listeners as TLS-kind listeners, defaulting Terminate
/// to HTTPRoute and rejecting explicit `allowedRoutes.kinds: [TLSRoute]`.
#[tokio::test]
async fn tls_terminate_listener_reports_tls_route_in_supported_kinds() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-tls-term-kinds").await?;
    let hostname = format!("terminate.{}.local", ns.name);
    let gw_cert = GeneratedCert::for_host(&hostname);

    fixtures::apply_fixture(
        gwa::TLS_TERMINATE,
        FixtureVars::new(&ns.name)
            .with(
                "GATEWAY_TLS_PASSTHROUGH_PORT",
                &GATEWAY_TLS_PASSTHROUGH_PORT.to_string(),
            )
            .with("TERMINATE_HOSTNAME", &hostname)
            .with("GW_TLS_CRT_B64", &gw_cert.cert_b64())
            .with("GW_TLS_KEY_B64", &gw_cert.key_b64()),
    )
    .await?;

    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-terminate-gw",
        &ns.name,
        "Programmed",
        "True",
        Duration::from_secs(60),
    )
    .await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let gw = gw_api.get("coxswain-terminate-gw").await?;
    assert_eq!(
        listener_supported_kinds(&gw, "tls-terminate"),
        Some(vec!["TLSRoute".to_string()]),
        "TLS/Terminate listener must report supportedKinds=[TLSRoute], not HTTPRoute"
    );

    Ok(())
}

// ── GEP-91 InsecureFrontendValidationMode condition (#86) ─────────────────────

/// Gateway `spec.tls.frontend.default.validation.mode: AllowInsecureFallback`
/// must produce a top-level Gateway condition
/// `InsecureFrontendValidationMode=True/ConfigurationChanged` (GEP-91 mandate).
/// Reverting to `AllowValidOnly` must remove that condition.
#[tokio::test]
async fn gateway_signals_insecure_frontend_validation_mode_condition() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "gw-insecure-cond").await?;

    let mtls = MtlsCerts::generate();
    let server_cert = GeneratedCert::for_host(&format!("gw-insecure.{}.local", ns.name));
    let host = format!("gw-insecure.{}.local", ns.name);

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;

    // Apply with AllowInsecureFallback; the gateway emits the GEP-91 warning condition.
    fixtures::apply_fixture(
        gwa::FRONTEND_MTLS_INSECURE_FALLBACK,
        FixtureVars::new(&ns.name)
            .with("HOSTNAME", &host)
            .with("SECRET_NAME", "gw-insecure-cert")
            .with("TLS_CRT_B64", server_cert.cert_b64())
            .with("TLS_KEY_B64", server_cert.key_b64())
            .with("CA_CRT_PEM", &mtls.ca_cert_pem),
    )
    .await?;

    // Gateway must gain InsecureFrontendValidationMode=True (GEP-91 mandate).
    wait::wait_for_gateway_condition(
        &h.client,
        "coxswain-frontend-fallback",
        &ns.name,
        "InsecureFrontendValidationMode",
        "True",
        Duration::from_secs(60),
    )
    .await?;

    // Flip the gateway-level frontend validation mode back to AllowValidOnly.
    // GEP-91 places frontend validation at spec.tls.frontend (gateway-wide), a
    // sibling of spec.listeners — not under a listener's tls block. A JSON merge
    // patch on just the mode field leaves caCertificateRefs intact.
    let gateways: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    let revert_to_valid_only = serde_json::json!({
        "spec": {
            "tls": {
                "frontend": {
                    "default": {
                        "validation": {
                            "mode": "AllowValidOnly"
                        }
                    }
                }
            }
        }
    });
    gateways
        .patch(
            "coxswain-frontend-fallback",
            &PatchParams::apply("coxswain-e2e"),
            &Patch::Merge(&revert_to_valid_only),
        )
        .await?;

    // InsecureFrontendValidationMode must be removed (absence = AllowValidOnly).
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            "Gateway coxswain-frontend-fallback to drop InsecureFrontendValidationMode condition \
             after reverting to AllowValidOnly"
                .to_string()
        },
        || async {
            gateways
                .get("coxswain-frontend-fallback")
                .await
                .ok()
                .filter(|gw| {
                    gw.status
                        .as_ref()
                        .and_then(|s| s.conditions.as_deref())
                        .is_some_and(|conds| {
                            !conds
                                .iter()
                                .any(|c| c.type_ == "InsecureFrontendValidationMode")
                        })
                })
                .map(|_| ())
        },
    )
    .await
}

// ── GEP-3155: Gateway backend client-cert status conditions ───────────────────

/// GEP-3155 sad path: Gateway `spec.tls.backend.clientCertificateRef` points to
/// a Secret that does not exist.
///
/// Expected: gateway-level `ResolvedRefs=False/InvalidClientCertificateRef`.
/// `Accepted=True` must remain (invalid ref ≠ invalid config, per GEP-3155).
#[tokio::test]
async fn gateway_resolvedrefs_false_when_backend_client_cert_secret_missing() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-gw-backend-cc-missing").await?;

    fixtures::apply_fixture(
        gwa::BACKEND_CLIENT_CERT_MISSING_SECRET,
        FixtureVars::new(&ns.name),
    )
    .await?;

    // ResolvedRefs must go False because the referenced Secret does not exist.
    wait::wait_for_gateway_condition(
        &h.client,
        "backend-cc-missing-gw",
        &ns.name,
        "ResolvedRefs",
        "False",
        Duration::from_secs(60),
    )
    .await?;

    // Accepted must stay True — the ref failure only affects ResolvedRefs, not Accepted.
    wait::wait_for_gateway_condition(
        &h.client,
        "backend-cc-missing-gw",
        &ns.name,
        "Accepted",
        "True",
        Duration::from_secs(10),
    )
    .await?;

    Ok(())
}

// ── GEP-1713: ListenerSet status ─────────────────────────────────────────────

/// Top-level `(status, reason)` for a ListenerSet condition type, or `None`.
fn ls_condition(ls: &ListenerSet, type_: &str) -> Option<(String, String)> {
    ls.status
        .as_ref()?
        .conditions
        .as_ref()?
        .iter()
        .find(|c| c.type_ == type_)
        .map(|c| (c.status.clone(), c.reason.clone()))
}

/// `(status, reason)` for a per-listener condition on a ListenerSet, or `None`.
fn ls_listener_condition(
    ls: &ListenerSet,
    listener: &str,
    type_: &str,
) -> Option<(String, String)> {
    ls.status
        .as_ref()?
        .listeners
        .as_ref()?
        .iter()
        .find(|l| l.name == listener)?
        .conditions
        .iter()
        .find(|c| c.type_ == type_)
        .map(|c| (c.status.clone(), c.reason.clone()))
}

/// Sad path: a Gateway that sets no `allowedListeners` defaults to `from: None`
/// and rejects every ListenerSet — the ListenerSet must be `Accepted=False` with
/// reason `NotAllowed` and its listener never programmed.
#[tokio::test]
async fn gateway_listenerset_rejected_when_parent_opts_out() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-ls-optout").await?;

    fixtures::apply_fixture(gwa::LISTENERSET_OPT_OUT, FixtureVars::new(&ns.name)).await?;

    let api: Api<ListenerSet> = Api::namespaced(h.client.clone(), &ns.name);
    let ls = wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            let observed = api.get("team-ls").await.ok().map_or_else(
                || "<no ListenerSet>".to_string(),
                |ls| format!("Accepted={:?}", ls_condition(&ls, "Accepted")),
            );
            format!("ListenerSet team-ls to be Accepted=False/NotAllowed; observed {observed}")
        },
        || async {
            let ls = api.get("team-ls").await.ok()?;
            (ls_condition(&ls, "Accepted")? == ("False".to_string(), "NotAllowed".to_string()))
                .then_some(ls)
        },
    )
    .await?;

    // The rejected listener must not be Programmed.
    if let Some((status, _)) = ls_listener_condition(&ls, "ls-http", "Programmed") {
        assert_ne!(
            status, "True",
            "a ListenerSet rejected by allowedListeners must not program its listener"
        );
    }

    Ok(())
}

/// Provenance: a Gateway listener and a ListenerSet listener share the name "web"
/// on different ports. Duplicate names are legal; both must program, each under
/// its own resource — a name-keyed health model would collide. The ListenerSet's
/// own `web` listener is `Programmed=True` and the ListenerSet `Accepted=True`.
#[tokio::test]
async fn gateway_listenerset_duplicate_listener_name_both_program() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-ls-dup").await?;

    fixtures::apply_fixture(gwa::LISTENERSET_DUPLICATE_NAME, FixtureVars::new(&ns.name)).await?;

    // The parent Gateway's own "web" listener programs.
    wait::wait_for_gateway_programmed(
        &h.client,
        "coxswain-test",
        &ns.name,
        Duration::from_secs(60),
    )
    .await?;

    // The ListenerSet's same-named "web" listener also programs, attributed to
    // the ListenerSet — proving provenance-keyed listener health.
    let api: Api<ListenerSet> = Api::namespaced(h.client.clone(), &ns.name);
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            let observed = api.get("team-ls").await.ok().map_or_else(
                || "<no ListenerSet>".to_string(),
                |ls| {
                    format!(
                        "Accepted={:?}, listener[web].Programmed={:?}",
                        ls_condition(&ls, "Accepted"),
                        ls_listener_condition(&ls, "web", "Programmed"),
                    )
                },
            );
            format!("ListenerSet team-ls Accepted=True and its web listener Programmed=True; observed {observed}")
        },
        || async {
            let ls = api.get("team-ls").await.ok()?;
            let accepted = ls_condition(&ls, "Accepted")?;
            let programmed = ls_listener_condition(&ls, "web", "Programmed")?;
            (accepted.0 == "True" && programmed.0 == "True").then_some(())
        },
    )
    .await?;

    Ok(())
}

/// `(status, reason)` of a route's parent-status condition `type_` for the parent
/// whose `parentRef.kind` is `ListenerSet` and name is `ls_name`, or `None`. The
/// kind match is the point: a ListenerSet parentRef must surface its OWN status
/// entry (not be folded into / mislabelled as a Gateway parent).
fn route_listenerset_parent_condition(
    route: &HttpRoute,
    ls_name: &str,
    type_: &str,
) -> Option<(String, String)> {
    route.status.as_ref()?.parents.iter().find_map(|p| {
        (p.parent_ref.kind.as_deref() == Some("ListenerSet") && p.parent_ref.name == ls_name)
            .then(|| {
                p.conditions
                    .iter()
                    .find(|c| c.type_ == type_)
                    .map(|c| (c.status.clone(), c.reason.clone()))
            })
            .flatten()
    })
}

/// GEP-1713 conflict-with-survivor: a ListenerSet with one listener that loses a
/// hostname conflict to the parent Gateway and one that programs cleanly must
/// still report top-level `Accepted=True`/`Programmed=True`. The losing listener
/// is individually `Programmed=False/HostnameConflict`; the survivor is
/// `Programmed=True`. Guards the per-listener-vs-aggregate split: a single losing
/// listener must NOT drag the whole ListenerSet to `Programmed=False`.
#[tokio::test]
async fn gateway_listenerset_one_conflicted_listener_keeps_set_programmed() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-ls-conflict").await?;

    fixtures::apply_fixture(gwa::LISTENERSET_CONFLICT, FixtureVars::new(&ns.name)).await?;

    let api: Api<ListenerSet> = Api::namespaced(h.client.clone(), &ns.name);
    let ls = wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            let observed = api.get("team-ls").await.ok().map_or_else(
                || "<no ListenerSet>".to_string(),
                |ls| {
                    format!(
                        "top Programmed={:?}, ls-conflict.Programmed={:?}, ls-ok.Programmed={:?}",
                        ls_condition(&ls, "Programmed"),
                        ls_listener_condition(&ls, "ls-conflict", "Programmed"),
                        ls_listener_condition(&ls, "ls-ok", "Programmed"),
                    )
                },
            );
            format!(
                "ListenerSet team-ls top Programmed=True with one conflicted + one programmed \
                 listener; observed {observed}"
            )
        },
        || async {
            let ls = api.get("team-ls").await.ok()?;
            // Top-level Programmed=True despite one losing listener.
            let top = ls_condition(&ls, "Programmed")?;
            // The survivor programs; the conflict-loser does not.
            let ok = ls_listener_condition(&ls, "ls-ok", "Programmed")?;
            let lost = ls_listener_condition(&ls, "ls-conflict", "Programmed")?;
            (top == ("True".to_string(), "Programmed".to_string())
                && ok.0 == "True"
                && lost.0 == "False")
                .then_some(ls)
        },
    )
    .await?;

    // The whole set is Accepted (not all listeners invalid), and the loser is
    // marked Conflicted=True so operators can see WHY it did not program.
    assert_eq!(
        ls_condition(&ls, "Accepted"),
        Some(("True".to_string(), "Accepted".to_string())),
        "a ListenerSet with at least one valid listener must be Accepted=True"
    );
    assert_eq!(
        ls_listener_condition(&ls, "ls-conflict", "Conflicted").map(|c| c.0),
        Some("True".to_string()),
        "the losing listener must report Conflicted=True"
    );

    Ok(())
}

/// GEP-1713: an HTTPRoute attached via `parentRef.kind: ListenerSet` must get its
/// OWN parent-status entry, keyed by `kind: ListenerSet`, reporting `Accepted` and
/// `ResolvedRefs`. Without it the route silently lacks status on the ListenerSet
/// parent (the data plane routes, but the route object never reflects acceptance).
#[tokio::test]
async fn httproute_on_listenerset_reports_listenerset_parent_accepted() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-ls-routestatus").await?;

    // ECHO backend so the route's backendRef resolves (ResolvedRefs=True).
    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::LISTENERSET_BASIC, FixtureVars::new(&ns.name)).await?;

    let api: Api<HttpRoute> = Api::namespaced(h.client.clone(), &ns.name);
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            let observed = api.get("ls-route").await.ok().map_or_else(
                || "<no HTTPRoute>".to_string(),
                |r| {
                    format!(
                        "ListenerSet-parent Accepted={:?}, ResolvedRefs={:?}",
                        route_listenerset_parent_condition(&r, "team-ls", "Accepted"),
                        route_listenerset_parent_condition(&r, "team-ls", "ResolvedRefs"),
                    )
                },
            );
            format!(
                "HTTPRoute ls-route to carry a kind=ListenerSet parent (team-ls) with \
                 Accepted=True/ResolvedRefs=True; observed {observed}"
            )
        },
        || async {
            let r = api.get("ls-route").await.ok()?;
            let accepted = route_listenerset_parent_condition(&r, "team-ls", "Accepted")?;
            let resolved = route_listenerset_parent_condition(&r, "team-ls", "ResolvedRefs")?;
            (accepted.0 == "True" && resolved.0 == "True").then_some(())
        },
    )
    .await?;

    Ok(())
}

/// GEP-1713 `ListenerSetAllowedRoutesCrossNamespace` (#515): a ListenerSet
/// listener's `allowedRoutes.namespaces` default (`Same`) scopes to the
/// ListenerSet's OWN namespace, not the parent Gateway's —
/// `listener_merge.rs::ls_route_namespaces` resolves it via the ListenerSet's
/// `metadata.namespace`. A route in a different (tenant) namespace targeting
/// that listener is rejected (`Accepted=False/NotAllowedByListeners`); the same
/// tenant route targeting a sibling listener widened to `All` is accepted.
#[tokio::test]
async fn gateway_listenerset_cross_namespace_route_scoped_to_own_namespace_by_default()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-ls-xns-primary").await?;
    let tenant = NamespaceGuard::create(&h.client, "sc-ls-xns-tenant").await?;

    fixtures::apply_fixture(gwa::LISTENERSET_XNS_ROUTE, FixtureVars::new(&ns.name)).await?;
    fixtures::apply_fixture(
        gwa::LISTENERSET_XNS_TENANT,
        FixtureVars::new(&tenant.name).with("TESTNS", &ns.name),
    )
    .await?;
    wait::wait_for_deployments(&tenant.name, &["echo-xns"]).await?;

    let api: Api<HttpRoute> = Api::namespaced(h.client.clone(), &tenant.name);
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            let same = api
                .get("xns-route-same")
                .await
                .ok()
                .and_then(|r| route_listenerset_parent_condition(&r, "team-ls", "Accepted"));
            let all = api
                .get("xns-route-all")
                .await
                .ok()
                .and_then(|r| route_listenerset_parent_condition(&r, "team-ls", "Accepted"));
            format!(
                "xns-route-same (targets ls-same, namespaces=Same) to be \
                 Accepted=False/NotAllowedByListeners and xns-route-all (targets \
                 ls-all, namespaces=All) to be Accepted=True; observed same={same:?}, all={all:?}"
            )
        },
        || async {
            let same_route = api.get("xns-route-same").await.ok()?;
            let all_route = api.get("xns-route-all").await.ok()?;
            let same = route_listenerset_parent_condition(&same_route, "team-ls", "Accepted")?;
            let all = route_listenerset_parent_condition(&all_route, "team-ls", "Accepted")?;
            (same == ("False".to_string(), "NotAllowedByListeners".to_string()) && all.0 == "True")
                .then_some(())
        },
    )
    .await?;

    Ok(())
}

/// GEP-1713 `ListenerSetAllowedRoutesSupportedKinds` (#515): a ListenerSet
/// TLS-passthrough listener whose `allowedRoutes.kinds` is restricted to a kind
/// incompatible with its protocol (`HTTPRoute` on `TLS`, which only ever carries
/// `TLSRoute`) reports `ResolvedRefs=False/InvalidRouteKinds` on its OWN listener
/// status — no route needs to attach for this to trigger. A sibling listener
/// restricted to the matching `TLSRoute` kind reports `ResolvedRefs=True`.
#[tokio::test]
async fn gateway_listenerset_kind_restriction_matches_protocol() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-ls-kinds").await?;

    fixtures::apply_fixture(
        gwa::LISTENERSET_KIND_RESTRICTION,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let api: Api<ListenerSet> = Api::namespaced(h.client.clone(), &ns.name);
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            let observed = api.get("team-ls").await.ok().map_or_else(
                || "<no ListenerSet>".to_string(),
                |ls| {
                    format!(
                        "ls-bad-kind.ResolvedRefs={:?}, ls-good-kind.ResolvedRefs={:?}",
                        ls_listener_condition(&ls, "ls-bad-kind", "ResolvedRefs"),
                        ls_listener_condition(&ls, "ls-good-kind", "ResolvedRefs"),
                    )
                },
            );
            format!(
                "ListenerSet team-ls listener ls-bad-kind to be \
                 ResolvedRefs=False/InvalidRouteKinds and ls-good-kind to be \
                 ResolvedRefs=True; observed {observed}"
            )
        },
        || async {
            let ls = api.get("team-ls").await.ok()?;
            let bad = ls_listener_condition(&ls, "ls-bad-kind", "ResolvedRefs")?;
            let good = ls_listener_condition(&ls, "ls-good-kind", "ResolvedRefs")?;
            (bad == ("False".to_string(), "InvalidRouteKinds".to_string()) && good.0 == "True")
                .then_some(())
        },
    )
    .await?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// #531 — shared-mode `Programmed=True` gated on proxy listener-bind readiness
// ─────────────────────────────────────────────────────────────────────────────

/// The `message` of a Gateway's top-level `Programmed` condition.
fn programmed_message(gw: &Gateway) -> Option<String> {
    gw.status
        .as_ref()?
        .conditions
        .as_ref()?
        .iter()
        .find(|c| c.type_ == "Programmed")
        .map(|c| c.message.clone())
}

/// The `lastTransitionTime` of the `Programmed` condition — bumped only on a
/// status change, so equality across a churn window proves zero flaps even
/// between poll ticks.
fn programmed_transition_time(gw: &Gateway) -> Option<Time> {
    gw.status
        .as_ref()?
        .conditions
        .as_ref()?
        .iter()
        .find(|c| c.type_ == "Programmed")
        .map(|c| c.last_transition_time.clone())
}

/// #531 happy path + coherence invariant (shared): `Programmed` must never be
/// stamped at the current generation while not `True` (the pre-bind hold
/// trails at `generation - 1`), and the moment it flips `True` the Gateway's
/// VIP must already serve traffic — `Programmed=True` is a data-plane
/// guarantee, not a status-only signal. This is the assertion that fails on
/// the old status-ahead-of-dataplane race (the conformance
/// `GatewayFrontendClientCertificateValidation` flake).
#[tokio::test]
async fn shared_gateway_generation_trails_programmed_until_pool_binds() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-gw-pool-bind-gate").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait::poll_until(
        Duration::from_secs(120),
        wait::POLL,
        || async {
            format!(
                "Programmed=True at the current generation; observed {:?}",
                gw_api
                    .get("coxswain-test")
                    .await
                    .ok()
                    .as_ref()
                    .and_then(programmed_full)
            )
        },
        || async {
            let gw = gw_api.get("coxswain-test").await.ok()?;
            let generation = gw.metadata.generation.unwrap_or(0);
            let (status, _reason, observed) = programmed_full(&gw)?;
            // #531 invariant: a not-yet-bound Gateway must trail at gen-1 —
            // Programmed may never claim generation N while not True.
            assert!(
                !(observed >= generation && status != "True"),
                "#531 violated: Programmed observedGeneration {observed} >= generation \
                 {generation} while status is {status:?} (pre-bind hold must trail)"
            );
            (status == "True" && observed >= generation).then_some(())
        },
    )
    .await?;

    // Programmed=True now implies every connected pool member bound the VIP's
    // internal ports — the VIP must serve immediately. The short bound absorbs
    // host-side LB/conntrack propagation only; the race detector is the
    // per-tick invariant above.
    let host = format!("echo.{}.local", ns.name);
    let gw_http = h.gateway_http(&ns.name).await?;
    wait::wait_for_backend(&gw_http, &host, "/a", "echo-a", Duration::from_secs(10)).await?;
    Ok(())
}

/// #531 sad path (shared): with ZERO connected shared-pool proxies the gate
/// fails closed — the Gateway holds `Programmed=False/Pending` below its
/// generation and must never claim readiness for a VIP nothing serves. When
/// the pool returns, the readiness report re-drives the reconcile and the
/// Gateway converges to `True` with the VIP actually serving (the recovery is
/// part of the assertion, so a broken restore fails loudly here).
#[tokio::test]
async fn shared_gateway_with_no_connected_proxies_holds_programmed_pending_until_pool_returns()
-> anyhow::Result<()> {
    use common::shared_proxy::{SharedProxyScaleGuard, scale_shared_proxy};

    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-gw-pool-empty-holds").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;

    // Panic-safe restore; the explicit scale-up below is the real assertion.
    let _restore = SharedProxyScaleGuard;
    scale_shared_proxy(0).await?;

    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    // Phase 1: the hold is observable *steadily* — scale-to-zero freezes the
    // usually-subsecond pre-bind window open.
    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait::poll_until(
        Duration::from_secs(60),
        wait::POLL,
        || async {
            format!(
                "Programmed held at False/Pending below generation with the pool at 0; \
                 observed {:?} message {:?}",
                gw_api
                    .get("coxswain-test")
                    .await
                    .ok()
                    .as_ref()
                    .and_then(programmed_full),
                gw_api
                    .get("coxswain-test")
                    .await
                    .ok()
                    .as_ref()
                    .and_then(programmed_message),
            )
        },
        || async {
            let gw = gw_api.get("coxswain-test").await.ok()?;
            let generation = gw.metadata.generation.unwrap_or(0);
            let (status, reason, observed) = programmed_full(&gw)?;
            assert!(
                status != "True",
                "must never report Programmed=True with zero connected shared proxies"
            );
            (status == "False" && reason == "Pending" && observed < generation).then_some(())
        },
    )
    .await?;

    // Phase 2: pool returns → NodeStatus re-populates the registry → the
    // re-drive flips Programmed without waiting for an unrelated event.
    scale_shared_proxy(1).await?;
    wait::poll_until(
        Duration::from_secs(120),
        wait::POLL,
        || async {
            format!(
                "Programmed=True after the pool returned; observed {:?}",
                gw_api
                    .get("coxswain-test")
                    .await
                    .ok()
                    .as_ref()
                    .and_then(programmed_full)
            )
        },
        || async {
            let gw = gw_api.get("coxswain-test").await.ok()?;
            let generation = gw.metadata.generation.unwrap_or(0);
            let (status, _reason, observed) = programmed_full(&gw)?;
            (status == "True" && observed >= generation).then_some(())
        },
    )
    .await?;

    let host = format!("echo.{}.local", ns.name);
    let gw_http = h.gateway_http(&ns.name).await?;
    wait::wait_for_backend(&gw_http, &host, "/a", "echo-a", Duration::from_secs(30)).await?;
    Ok(())
}

/// #531 anti-flap: an established `Programmed=True` generation must survive a
/// shared-proxy rollout untouched — the replacement pod connects with an empty
/// bound set and the draining pod disconnects, but pool churn never re-arms
/// the gate for an already-programmed generation. Terminal condition is a real
/// event (rollout settled + VIP serving again); every tick asserts the
/// condition unchanged, and the final `lastTransitionTime` equality catches
/// even a sub-tick flap (Kubernetes bumps it on any status change).
#[tokio::test]
async fn programmed_gateway_stays_true_through_shared_proxy_rollout() -> anyhow::Result<()> {
    use common::shared_proxy::{rollout_restart_shared_proxy, shared_proxy_settled};

    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-gw-antiflap-rollout").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(gwa::PATH_MATCHING, FixtureVars::new(&ns.name)).await?;

    let host = format!("echo.{}.local", ns.name);
    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait::wait_for_gateway_programmed(
        &h.client,
        "coxswain-test",
        &ns.name,
        Duration::from_secs(120),
    )
    .await?;
    let gw_http = h.gateway_http(&ns.name).await?;
    wait::wait_for_backend(&gw_http, &host, "/a", "echo-a", Duration::from_secs(60)).await?;

    let baseline_gw = gw_api.get("coxswain-test").await?;
    let baseline = programmed_full(&baseline_gw)
        .ok_or_else(|| anyhow::anyhow!("no Programmed condition on the baseline Gateway"))?;
    let baseline_ltt = programmed_transition_time(&baseline_gw)
        .ok_or_else(|| anyhow::anyhow!("no lastTransitionTime on the baseline Programmed"))?;

    rollout_restart_shared_proxy().await?;

    wait::poll_until(
        Duration::from_secs(120),
        wait::POLL,
        || async {
            "shared-proxy rollout settled and the VIP serving again, with Programmed \
             unchanged at every tick"
                .to_string()
        },
        || async {
            let gw = gw_api.get("coxswain-test").await.ok()?;
            let now = programmed_full(&gw)?;
            assert_eq!(
                now, baseline,
                "#531 anti-flap violated: Programmed changed during shared-proxy rollout"
            );
            if !shared_proxy_settled(1).await.unwrap_or(false) {
                return None;
            }
            // Rollout settled — terminal once the VIP serves from the new pod.
            let resp = gw_http.get(&host, "/a").await.ok()?;
            resp.pod
                .as_deref()
                .is_some_and(|pod| pod.starts_with("echo-a-"))
                .then_some(())
        },
    )
    .await?;

    // Catch sub-tick flaps: any True→Pending→True bounce bumps the timestamp.
    let final_gw = gw_api.get("coxswain-test").await?;
    let final_ltt = programmed_transition_time(&final_gw)
        .ok_or_else(|| anyhow::anyhow!("no lastTransitionTime after the rollout"))?;
    anyhow::ensure!(
        final_ltt == baseline_ltt,
        "#531 anti-flap violated between poll ticks: Programmed lastTransitionTime moved \
         {baseline_ltt:?} -> {final_ltt:?} across the shared-proxy rollout"
    );
    Ok(())
}

/// #531 dedicated-mode coherence: adding a listener to an already-Programmed
/// dedicated Gateway (generation bump) must hold `Programmed` below the new
/// generation until the dedicated proxy actually re-binds — pod readiness
/// alone is stale here (the pod was Ready long before the new port). Converges
/// at `True@gen2` only once the proxy's bound-port report covers the new
/// listener.
#[tokio::test]
async fn dedicated_gateway_listener_addition_trails_programmed_until_rebound() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    let ns = NamespaceGuard::create(&h.client, "sc-ded-listener-add-gate").await?;

    fixtures::apply_fixture(backends::ECHO, FixtureVars::new(&ns.name)).await?;
    wait::wait_for_backends(&ns.name).await?;
    fixtures::apply_fixture(
        dedicated::DEDICATED_GATEWAY_CLUSTERIP,
        FixtureVars::new(&ns.name),
    )
    .await?;

    let gw_api: Api<Gateway> = Api::namespaced(h.client.clone(), &ns.name);
    wait::wait_for_gateway_programmed(&h.client, GATEWAY_NAME, &ns.name, Duration::from_secs(180))
        .await?;

    // Generation bump: add a second HTTP listener on a fresh port.
    // Merge-patch replaces the whole listeners list: keep the fixture's
    // existing http/8100 listener and add a second one on a fresh port.
    let patch = serde_json::json!({
        "spec": { "listeners": [
            {
                "name": "http",
                "port": 8100,
                "protocol": "HTTP",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            },
            {
                "name": "http-extra",
                "port": 8190,
                "protocol": "HTTP",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            },
        ]}
    });
    gw_api
        .patch(
            GATEWAY_NAME,
            &PatchParams::apply("e2e-listener-add"),
            &Patch::Merge(&patch),
        )
        .await?;

    wait::poll_until(
        Duration::from_secs(120),
        wait::POLL,
        || async {
            format!(
                "Programmed=True at the bumped generation; observed {:?} generation {:?}",
                gw_api
                    .get(GATEWAY_NAME)
                    .await
                    .ok()
                    .as_ref()
                    .and_then(programmed_full),
                gw_api
                    .get(GATEWAY_NAME)
                    .await
                    .ok()
                    .and_then(|g| g.metadata.generation)
            )
        },
        || async {
            let gw = gw_api.get(GATEWAY_NAME).await.ok()?;
            let generation = gw.metadata.generation.unwrap_or(0);
            // The listener add landed: generation must be past the initial 1.
            if generation < 2 {
                return None;
            }
            let (status, _reason, observed) = programmed_full(&gw)?;
            assert!(
                !(observed >= generation && status != "True"),
                "#531 (dedicated) violated: Programmed claims generation {generation} \
                 while {status:?} — the rebind hold must trail"
            );
            (status == "True" && observed >= generation).then_some(())
        },
    )
    .await?;
    Ok(())
}
