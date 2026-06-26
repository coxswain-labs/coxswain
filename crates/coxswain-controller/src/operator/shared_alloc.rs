//! Shared-mode internal-port allocation glue (#472).
//!
//! Bridges the Kubernetes object world (owned shared-mode Gateways + the VIP
//! Services the operator provisions) to the pure
//! [`coxswain_reflector::port_alloc::allocate_internal_ports`] allocator:
//!
//! - [`desired_listener_keys`] enumerates every `(Gateway, listenerPort)` pair
//!   that needs an internal port, from all owned shared Gateways.
//! - [`existing_internal_ports`] reconstructs the assignments already persisted
//!   in the provisioned Services — the durable source of truth that keeps
//!   allocations stable across reconciles and controller restarts.
//!
//! The single serialized `run_vip_reconciler` task (NOT the concurrent
//! per-Gateway work-queue) runs the allocator over these two inputs in one
//! consistent pass, so the global map is computed and applied atomically — no
//! two reconciles can diverge and double-book a port.

use std::collections::HashMap;
use std::sync::Arc;

use coxswain_core::ownership::ObjectKey;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use coxswain_reflector::port_alloc::{ListenerKey, read_vip_internal_ports};
use k8s_openapi::api::core::v1::Service;

/// Enumerate the `(Gateway, listenerPort)` pairs needing an internal port across
/// every owned shared-mode Gateway. `is_owned_shared` filters to Gateways this
/// controller owns that are NOT in dedicated mode.
pub(super) fn desired_listener_keys(
    gateways: &[Arc<Gateway>],
    is_owned_shared: impl Fn(&Gateway) -> bool,
) -> Vec<ListenerKey> {
    let mut out = Vec::new();
    for gw in gateways {
        if !is_owned_shared(gw) {
            continue;
        }
        let (Some(ns), Some(name)) = (
            gw.metadata.namespace.as_deref(),
            gw.metadata.name.as_deref(),
        ) else {
            continue;
        };
        let key = ObjectKey::new(ns, name);
        for listener in &gw.spec.listeners {
            if let Ok(port) = u16::try_from(listener.port) {
                out.push((key.clone(), port));
            }
        }
    }
    out
}

/// The `(Gateway, listenerPort) → internalPort` assignments already persisted in
/// the provisioned VIP Services — the allocator's `existing` (reuse) input.
///
/// Delegates to the canonical [`read_vip_internal_ports`] so the operator
/// (allocation) and the reflector (route/TLS keying) read the Service
/// source-of-truth through exactly one code path.
pub(super) fn existing_internal_ports(services: &[Arc<Service>]) -> HashMap<ListenerKey, u16> {
    read_vip_internal_ports(services)
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_reflector::gw_types::v::gateways::{GatewayListeners, GatewaySpec};
    use coxswain_reflector::port_alloc::{
        DEFAULT_INTERNAL_PORT_RANGE, SHARED_GATEWAY_VIP_COMPONENT, VIP_GATEWAY_NAME_LABEL,
        VIP_GATEWAY_NAMESPACE_LABEL, allocate_internal_ports,
    };
    use k8s_openapi::api::core::v1::{ServicePort, ServiceSpec};
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    use kube::api::ObjectMeta;
    use std::collections::BTreeMap;

    fn gw(ns: &str, name: &str, ports: &[i32]) -> Arc<Gateway> {
        Arc::new(Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "coxswain".to_string(),
                listeners: ports
                    .iter()
                    .map(|p| GatewayListeners {
                        name: format!("l{p}"),
                        port: *p,
                        protocol: "HTTPS".to_string(),
                        hostname: None,
                        tls: None,
                        allowed_routes: None,
                    })
                    .collect(),
                ..Default::default()
            },
            status: None,
        })
    }

    fn vip_service(ns: &str, gw_name: &str, mappings: &[(i32, i32)]) -> Arc<Service> {
        let mut labels = BTreeMap::new();
        labels.insert(
            "app.kubernetes.io/component".to_string(),
            SHARED_GATEWAY_VIP_COMPONENT.to_string(),
        );
        labels.insert(VIP_GATEWAY_NAME_LABEL.to_string(), gw_name.to_string());
        labels.insert(VIP_GATEWAY_NAMESPACE_LABEL.to_string(), ns.to_string());
        Arc::new(Service {
            metadata: ObjectMeta {
                // The VIP Service lives in the controller namespace in production;
                // its own namespace is irrelevant — the mapping is via labels.
                name: Some(format!("{gw_name}-shared-gw")),
                namespace: Some("coxswain-system".to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                ports: Some(
                    mappings
                        .iter()
                        .map(|(port, tp)| ServicePort {
                            port: *port,
                            target_port: Some(IntOrString::Int(*tp)),
                            ..Default::default()
                        })
                        .collect(),
                ),
                ..Default::default()
            }),
            status: None,
        })
    }

    #[test]
    fn desired_keys_cover_only_owned_shared_gateways() {
        let gateways = vec![gw("default", "a", &[80, 443]), gw("default", "b", &[443])];
        let desired = desired_listener_keys(&gateways, |g| g.metadata.name.as_deref() == Some("a"));
        assert_eq!(desired.len(), 2, "only gateway a's two listeners");
        assert!(desired.contains(&(ObjectKey::new("default", "a"), 80)));
        assert!(desired.contains(&(ObjectKey::new("default", "a"), 443)));
    }

    #[test]
    fn existing_ports_parse_from_vip_services() {
        let services = vec![vip_service("default", "a", &[(443, 30001), (80, 30000)])];
        let existing = existing_internal_ports(&services);
        assert_eq!(
            existing.get(&(ObjectKey::new("default", "a"), 443)),
            Some(&30001)
        );
        assert_eq!(
            existing.get(&(ObjectKey::new("default", "a"), 80)),
            Some(&30000)
        );
    }

    #[test]
    fn non_vip_services_are_ignored() {
        let mut svc = (*vip_service("default", "a", &[(443, 30001)])).clone();
        // Strip the VIP component label → not ours.
        svc.metadata
            .labels
            .as_mut()
            .unwrap()
            .remove("app.kubernetes.io/component");
        let existing = existing_internal_ports(&[Arc::new(svc)]);
        assert!(
            existing.is_empty(),
            "service without VIP component label is ignored"
        );
    }

    #[test]
    fn round_trip_existing_keeps_allocation_stable() {
        // Provision → read back the Service ports → re-allocate → identical map.
        let gateways = vec![gw("default", "a", &[80, 443])];
        let desired = desired_listener_keys(&gateways, |_| true);
        let first = allocate_internal_ports(&desired, &HashMap::new(), DEFAULT_INTERNAL_PORT_RANGE);
        let a = ObjectKey::new("default", "a");
        let mappings: Vec<(i32, i32)> = first
            .for_gateway(&a)
            .into_iter()
            .map(|(lp, ip)| (i32::from(lp), i32::from(ip)))
            .collect();
        let services = vec![vip_service("default", "a", &mappings)];
        let existing = existing_internal_ports(&services);
        let second = allocate_internal_ports(&desired, &existing, DEFAULT_INTERNAL_PORT_RANGE);
        assert_eq!(
            first, second,
            "allocation stable through Service round-trip"
        );
    }
}
