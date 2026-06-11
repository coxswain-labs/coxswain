//! Unit tests for the dedicated-mode `Gateway.status` writer.
//!
//! Cover the three `ServiceType` address branches, the Programmed
//! precedence ladder, the `dedicated_gateway_needs_status_patch` idempotence
//! check, the unified-patch shape (Accepted/Programmed/DedicatedProxyReady
//! all carried in one JSON merge patch), and the foreign-condition
//! preservation contract.

use crate::operator::status::{
    AcceptedOutcome, DEDICATED_PROXY_READY_CONDITION_TYPE, DedicatedGatewayStatusInputs,
    build_dedicated_gateway_status_patch, dedicated_gateway_needs_status_patch,
};
use coxswain_reflector::gw_types::v::gateways::{
    Gateway, GatewayListeners, GatewaySpec, GatewayStatus, GatewayStatusAddresses,
    GatewayStatusListeners,
};
use coxswain_reflector::ingress::IngressPorts;
use coxswain_reflector::tls::GatewayListenerHealth;
use k8s_openapi::api::core::v1::{
    LoadBalancerIngress, LoadBalancerStatus, Node, NodeAddress, NodeStatus, Service, ServiceSpec,
    ServiceStatus,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::ObjectMeta;
use std::sync::Arc;

fn epoch() -> Time {
    Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH)
}

fn gateway(generation: i64, listeners: Vec<(&str, i32)>, status: Option<GatewayStatus>) -> Gateway {
    Gateway {
        metadata: ObjectMeta {
            name: Some("my-gw".to_string()),
            namespace: Some("default".to_string()),
            generation: Some(generation),
            ..Default::default()
        },
        spec: GatewaySpec {
            gateway_class_name: "coxswain".to_string(),
            listeners: listeners
                .into_iter()
                .map(|(name, port)| GatewayListeners {
                    name: name.to_string(),
                    port,
                    protocol: "HTTP".to_string(),
                    hostname: None,
                    tls: None,
                    allowed_routes: None,
                })
                .collect(),
            ..Default::default()
        },
        status,
    }
}

fn service_loadbalancer(ingress: Vec<LoadBalancerIngress>) -> Service {
    Service {
        metadata: ObjectMeta::default(),
        spec: Some(ServiceSpec {
            type_: Some("LoadBalancer".to_string()),
            ..Default::default()
        }),
        status: Some(ServiceStatus {
            load_balancer: Some(LoadBalancerStatus {
                ingress: Some(ingress),
            }),
            ..Default::default()
        }),
    }
}

fn service_clusterip(cluster_ip: &str) -> Service {
    Service {
        metadata: ObjectMeta::default(),
        spec: Some(ServiceSpec {
            type_: Some("ClusterIP".to_string()),
            cluster_ip: Some(cluster_ip.to_string()),
            ..Default::default()
        }),
        status: None,
    }
}

fn service_nodeport() -> Service {
    Service {
        metadata: ObjectMeta::default(),
        spec: Some(ServiceSpec {
            type_: Some("NodePort".to_string()),
            ..Default::default()
        }),
        status: None,
    }
}

fn node(addresses: Vec<(&str, &str)>) -> Arc<Node> {
    Arc::new(Node {
        metadata: ObjectMeta::default(),
        spec: None,
        status: Some(NodeStatus {
            addresses: Some(
                addresses
                    .into_iter()
                    .map(|(type_, addr)| NodeAddress {
                        type_: type_.to_string(),
                        address: addr.to_string(),
                    })
                    .collect(),
            ),
            ..Default::default()
        }),
    })
}

fn empty_health() -> &'static GatewayListenerHealth {
    use std::sync::OnceLock;
    static H: OnceLock<GatewayListenerHealth> = OnceLock::new();
    H.get_or_init(GatewayListenerHealth::default)
}

fn inputs<'a>(
    gw: &'a Gateway,
    service: Option<&'a Service>,
    nodes: &'a [Arc<Node>],
    health: &'a GatewayListenerHealth,
    accepted: AcceptedOutcome,
    ready_pods: usize,
) -> DedicatedGatewayStatusInputs<'a> {
    DedicatedGatewayStatusInputs {
        gw,
        service,
        nodes,
        tls_health: health,
        ingress_ports: IngressPorts::new(None, None),
        accepted,
        ready_pod_count: ready_pods,
    }
}

/// Extract a `(status, reason)` pair from the produced patch's
/// `status.conditions[type=...]` entry.
fn condition_of(patch: &serde_json::Value, type_: &str) -> Option<(String, String)> {
    patch["status"]["conditions"]
        .as_array()?
        .iter()
        .find(|c| c["type"].as_str() == Some(type_))
        .map(|c| {
            (
                c["status"].as_str().unwrap_or("").to_string(),
                c["reason"].as_str().unwrap_or("").to_string(),
            )
        })
}

fn addresses_of(patch: &serde_json::Value) -> Vec<(String, String)> {
    patch["status"]["addresses"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|a| {
                    (
                        a["type"].as_str().unwrap_or("").to_string(),
                        a["value"].as_str().unwrap_or("").to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

// ============================================================================
// compute_addresses — three ServiceType branches
// ============================================================================

#[test]
fn loadbalancer_ingress_ip_becomes_ip_address() {
    let gw = gateway(1, vec![("http", 80)], None);
    let svc = service_loadbalancer(vec![LoadBalancerIngress {
        ip: Some("203.0.113.1".to_string()),
        hostname: None,
        ..Default::default()
    }]);
    let inputs = inputs(
        &gw,
        Some(&svc),
        &[],
        empty_health(),
        AcceptedOutcome::Accepted,
        1,
    );
    let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
    assert_eq!(
        addresses_of(&patch),
        vec![("IPAddress".to_string(), "203.0.113.1".to_string())]
    );
}

#[test]
fn loadbalancer_ingress_hostname_becomes_hostname() {
    let gw = gateway(1, vec![("http", 80)], None);
    let svc = service_loadbalancer(vec![LoadBalancerIngress {
        ip: None,
        hostname: Some("gw.example.com".to_string()),
        ..Default::default()
    }]);
    let inputs = inputs(
        &gw,
        Some(&svc),
        &[],
        empty_health(),
        AcceptedOutcome::Accepted,
        1,
    );
    let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
    assert_eq!(
        addresses_of(&patch),
        vec![("Hostname".to_string(), "gw.example.com".to_string())]
    );
}

#[test]
fn clusterip_yields_ip_address() {
    let gw = gateway(1, vec![("http", 80)], None);
    let svc = service_clusterip("10.96.7.42");
    let inputs = inputs(
        &gw,
        Some(&svc),
        &[],
        empty_health(),
        AcceptedOutcome::Accepted,
        1,
    );
    let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
    assert_eq!(
        addresses_of(&patch),
        vec![("IPAddress".to_string(), "10.96.7.42".to_string())]
    );
}

#[test]
fn clusterip_none_drops_to_empty() {
    let gw = gateway(1, vec![("http", 80)], None);
    let svc = service_clusterip("None");
    let inputs = inputs(
        &gw,
        Some(&svc),
        &[],
        empty_health(),
        AcceptedOutcome::Accepted,
        1,
    );
    let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
    assert!(addresses_of(&patch).is_empty());
}

#[test]
fn nodeport_prefers_external_ip() {
    let gw = gateway(1, vec![("http", 80)], None);
    let svc = service_nodeport();
    let nodes = vec![
        node(vec![
            ("ExternalIP", "198.51.100.1"),
            ("InternalIP", "10.0.0.1"),
        ]),
        node(vec![
            ("ExternalIP", "198.51.100.2"),
            ("InternalIP", "10.0.0.2"),
        ]),
    ];
    let inputs = inputs(
        &gw,
        Some(&svc),
        &nodes,
        empty_health(),
        AcceptedOutcome::Accepted,
        1,
    );
    let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
    let addrs = addresses_of(&patch);
    assert_eq!(addrs.len(), 2, "addresses: {addrs:?}");
    assert!(addrs.contains(&("IPAddress".to_string(), "198.51.100.1".to_string())));
    assert!(addrs.contains(&("IPAddress".to_string(), "198.51.100.2".to_string())));
    assert!(!addrs.iter().any(|(_, v)| v.starts_with("10.0.0."))); // No InternalIP fallback.
}

#[test]
fn nodeport_falls_back_to_internal_ip() {
    let gw = gateway(1, vec![("http", 80)], None);
    let svc = service_nodeport();
    // No ExternalIP on any Node — fallback should kick in.
    let nodes = vec![node(vec![("InternalIP", "10.0.0.1")])];
    let inputs = inputs(
        &gw,
        Some(&svc),
        &nodes,
        empty_health(),
        AcceptedOutcome::Accepted,
        1,
    );
    let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
    assert_eq!(
        addresses_of(&patch),
        vec![("IPAddress".to_string(), "10.0.0.1".to_string())]
    );
}

#[test]
fn nodeport_dedupes_repeated_addresses() {
    let gw = gateway(1, vec![("http", 80)], None);
    let svc = service_nodeport();
    let nodes = vec![
        node(vec![("ExternalIP", "198.51.100.1")]),
        node(vec![("ExternalIP", "198.51.100.1")]), // Duplicate.
    ];
    let inputs = inputs(
        &gw,
        Some(&svc),
        &nodes,
        empty_health(),
        AcceptedOutcome::Accepted,
        1,
    );
    let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
    assert_eq!(addresses_of(&patch).len(), 1);
}

// ============================================================================
// Programmed precedence ladder
// ============================================================================

#[test]
fn programmed_invalid_when_accepted_false() {
    let gw = gateway(1, vec![("http", 80)], None);
    let inputs = inputs(
        &gw,
        None,
        &[],
        empty_health(),
        AcceptedOutcome::InvalidParameters,
        0,
    );
    let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
    assert_eq!(
        condition_of(&patch, "Accepted"),
        Some(("False".to_string(), "InvalidParameters".to_string()))
    );
    assert_eq!(
        condition_of(&patch, "Programmed"),
        Some(("False".to_string(), "Invalid".to_string())),
        "InvalidParameters dominates Pending and AddressNotAssigned"
    );
}

#[test]
fn programmed_pending_when_no_ready_pod() {
    let gw = gateway(1, vec![("http", 80)], None);
    let svc = service_clusterip("10.96.7.42");
    let inputs = inputs(
        &gw,
        Some(&svc),
        &[],
        empty_health(),
        AcceptedOutcome::Accepted,
        0,
    );
    let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
    assert_eq!(
        condition_of(&patch, "Programmed"),
        Some(("False".to_string(), "Pending".to_string()))
    );
}

#[test]
fn programmed_address_not_assigned_when_no_addresses() {
    let gw = gateway(1, vec![("http", 80)], None);
    // LoadBalancer Service with empty ingress — Pod ready but no address yet.
    let svc = service_loadbalancer(vec![]);
    let inputs = inputs(
        &gw,
        Some(&svc),
        &[],
        empty_health(),
        AcceptedOutcome::Accepted,
        1,
    );
    let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
    assert_eq!(
        condition_of(&patch, "Programmed"),
        Some(("False".to_string(), "AddressNotAssigned".to_string()))
    );
}

#[test]
fn programmed_true_when_pod_ready_and_address_assigned() {
    let gw = gateway(1, vec![("http", 80)], None);
    let svc = service_clusterip("10.96.7.42");
    let inputs = inputs(
        &gw,
        Some(&svc),
        &[],
        empty_health(),
        AcceptedOutcome::Accepted,
        1,
    );
    let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
    assert_eq!(
        condition_of(&patch, "Accepted"),
        Some(("True".to_string(), "Accepted".to_string()))
    );
    assert_eq!(
        condition_of(&patch, "Programmed"),
        Some(("True".to_string(), "Programmed".to_string()))
    );
}

// ============================================================================
// DedicatedProxyReady cut-over signal — emitted in the same patch
// ============================================================================

#[test]
fn dedicated_proxy_ready_in_same_patch_when_pod_ready() {
    let gw = gateway(1, vec![("http", 80)], None);
    let svc = service_clusterip("10.96.7.42");
    let inputs = inputs(
        &gw,
        Some(&svc),
        &[],
        empty_health(),
        AcceptedOutcome::Accepted,
        2,
    );
    let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
    assert_eq!(
        condition_of(&patch, DEDICATED_PROXY_READY_CONDITION_TYPE),
        Some(("True".to_string(), "Ready".to_string())),
        "cut-over condition rides the same patch (not a separate write)"
    );
}

#[test]
fn dedicated_proxy_ready_false_when_no_ready_pod() {
    let gw = gateway(1, vec![("http", 80)], None);
    let inputs = inputs(&gw, None, &[], empty_health(), AcceptedOutcome::Accepted, 0);
    let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
    assert_eq!(
        condition_of(&patch, DEDICATED_PROXY_READY_CONDITION_TYPE),
        Some(("False".to_string(), "Provisioning".to_string()))
    );
}

#[test]
fn dedicated_proxy_ready_false_when_invalid_parameters() {
    let gw = gateway(1, vec![("http", 80)], None);
    // Even with a ready pod, InvalidParameters means the cut-over signal
    // must stay False — the dedicated pool isn't authoritative.
    let inputs = inputs(
        &gw,
        None,
        &[],
        empty_health(),
        AcceptedOutcome::InvalidParameters,
        1,
    );
    let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
    assert_eq!(
        condition_of(&patch, DEDICATED_PROXY_READY_CONDITION_TYPE),
        Some(("False".to_string(), "Provisioning".to_string()))
    );
}

// ============================================================================
// Foreign-condition preservation
// ============================================================================

#[test]
fn foreign_conditions_preserved_across_patch() {
    let foreign = Condition {
        type_: "external-policy.example.com/Audit".to_string(),
        status: "True".to_string(),
        reason: "Compliant".to_string(),
        message: String::new(),
        observed_generation: Some(1),
        last_transition_time: epoch(),
    };
    let gw = gateway(
        1,
        vec![("http", 80)],
        Some(GatewayStatus {
            conditions: Some(vec![foreign.clone()]),
            ..Default::default()
        }),
    );
    let svc = service_clusterip("10.96.7.42");
    let inputs = inputs(
        &gw,
        Some(&svc),
        &[],
        empty_health(),
        AcceptedOutcome::Accepted,
        1,
    );
    let patch = build_dedicated_gateway_status_patch(&inputs, 1, &epoch());
    let types: Vec<String> = patch["status"]["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["type"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(
        types.contains(&"external-policy.example.com/Audit".to_string()),
        "foreign condition must survive a patch: got {types:?}"
    );
    assert!(types.contains(&"Accepted".to_string()));
    assert!(types.contains(&"Programmed".to_string()));
    assert!(types.contains(&DEDICATED_PROXY_READY_CONDITION_TYPE.to_string()));
}

// ============================================================================
// dedicated_gateway_needs_status_patch — idempotence
// ============================================================================

fn cond(type_: &str, status: &str, reason: &str, observed_gen: i64) -> Condition {
    Condition {
        type_: type_.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message: String::new(),
        observed_generation: Some(observed_gen),
        last_transition_time: epoch(),
    }
}

fn listener_status(
    name: &str,
    observed_gen: i64,
    resolved_refs: bool,
    attached: i32,
) -> GatewayStatusListeners {
    GatewayStatusListeners {
        name: name.to_string(),
        attached_routes: attached,
        supported_kinds: None,
        conditions: vec![
            cond("Accepted", "True", "Accepted", observed_gen),
            cond(
                "ResolvedRefs",
                if resolved_refs { "True" } else { "False" },
                "ResolvedRefs",
                observed_gen,
            ),
            cond("Programmed", "True", "Programmed", observed_gen),
        ],
    }
}

#[test]
fn needs_patch_true_when_no_status() {
    let gw = gateway(1, vec![("http", 80)], None);
    let svc = service_clusterip("10.96.7.42");
    let inputs = inputs(
        &gw,
        Some(&svc),
        &[],
        empty_health(),
        AcceptedOutcome::Accepted,
        1,
    );
    assert!(dedicated_gateway_needs_status_patch(&inputs));
}

#[test]
fn needs_patch_false_when_fully_in_sync() {
    // Gateway already carries the exact set of conditions + listener +
    // addresses the writer would emit.
    let gw = gateway(
        1,
        vec![("http", 80)],
        Some(GatewayStatus {
            conditions: Some(vec![
                cond("Accepted", "True", "Accepted", 1),
                cond("Programmed", "True", "Programmed", 1),
                cond(DEDICATED_PROXY_READY_CONDITION_TYPE, "True", "Ready", 1),
            ]),
            listeners: Some(vec![listener_status("http", 1, true, 0)]),
            addresses: Some(vec![GatewayStatusAddresses {
                r#type: Some("IPAddress".to_string()),
                value: "10.96.7.42".to_string(),
            }]),
            ..Default::default()
        }),
    );
    let svc = service_clusterip("10.96.7.42");
    let inputs = inputs(
        &gw,
        Some(&svc),
        &[],
        empty_health(),
        AcceptedOutcome::Accepted,
        1,
    );
    assert!(
        !dedicated_gateway_needs_status_patch(&inputs),
        "idempotence: fully-converged Gateway must not repatch"
    );
}

#[test]
fn needs_patch_true_when_status_reason_flips_without_generation_bump() {
    // Critical: pod-readiness transitions don't bump metadata.generation,
    // so an observed-generation-only check would miss this.
    let gw = gateway(
        1,
        vec![("http", 80)],
        Some(GatewayStatus {
            conditions: Some(vec![
                cond("Accepted", "True", "Accepted", 1),
                // Old reason was Pending; the new reconcile has a ready pod.
                cond("Programmed", "False", "Pending", 1),
                cond(
                    DEDICATED_PROXY_READY_CONDITION_TYPE,
                    "False",
                    "Provisioning",
                    1,
                ),
            ]),
            listeners: Some(vec![listener_status("http", 1, true, 0)]),
            addresses: Some(vec![GatewayStatusAddresses {
                r#type: Some("IPAddress".to_string()),
                value: "10.96.7.42".to_string(),
            }]),
            ..Default::default()
        }),
    );
    let svc = service_clusterip("10.96.7.42");
    let inputs = inputs(
        &gw,
        Some(&svc),
        &[],
        empty_health(),
        AcceptedOutcome::Accepted,
        1,
    );
    assert!(
        dedicated_gateway_needs_status_patch(&inputs),
        "(status, reason) flip must trigger a repatch even when generation is unchanged"
    );
}

#[test]
fn needs_patch_true_when_addresses_drift() {
    let gw = gateway(
        1,
        vec![("http", 80)],
        Some(GatewayStatus {
            conditions: Some(vec![
                cond("Accepted", "True", "Accepted", 1),
                cond("Programmed", "True", "Programmed", 1),
                cond(DEDICATED_PROXY_READY_CONDITION_TYPE, "True", "Ready", 1),
            ]),
            listeners: Some(vec![listener_status("http", 1, true, 0)]),
            // Stale: a different IP from the current Service spec.
            addresses: Some(vec![GatewayStatusAddresses {
                r#type: Some("IPAddress".to_string()),
                value: "10.96.7.99".to_string(),
            }]),
            ..Default::default()
        }),
    );
    let svc = service_clusterip("10.96.7.42");
    let inputs = inputs(
        &gw,
        Some(&svc),
        &[],
        empty_health(),
        AcceptedOutcome::Accepted,
        1,
    );
    assert!(dedicated_gateway_needs_status_patch(&inputs));
}

#[test]
fn needs_patch_true_when_generation_stale() {
    // GEP-1364: an observed_generation lagging metadata.generation means
    // the spec has moved on — repatch even if (status, reason) match.
    let gw = gateway(
        3, // bumped from 1
        vec![("http", 80)],
        Some(GatewayStatus {
            conditions: Some(vec![
                cond("Accepted", "True", "Accepted", 1),
                cond("Programmed", "True", "Programmed", 1),
                cond(DEDICATED_PROXY_READY_CONDITION_TYPE, "True", "Ready", 1),
            ]),
            listeners: Some(vec![listener_status("http", 1, true, 0)]),
            addresses: Some(vec![GatewayStatusAddresses {
                r#type: Some("IPAddress".to_string()),
                value: "10.96.7.42".to_string(),
            }]),
            ..Default::default()
        }),
    );
    let svc = service_clusterip("10.96.7.42");
    let inputs = inputs(
        &gw,
        Some(&svc),
        &[],
        empty_health(),
        AcceptedOutcome::Accepted,
        1,
    );
    assert!(dedicated_gateway_needs_status_patch(&inputs));
}
