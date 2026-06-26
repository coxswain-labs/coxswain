//! Endpoint resolution: maps `EndpointSlice` ready addresses into `BackendGroup`s.

use coxswain_core::routing::{BackendProtocol, parse_app_protocol};
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::runtime::reflector;
use std::net::{IpAddr, SocketAddr};

/// Resolved addresses and protocol metadata for a single backend service port.
pub(crate) struct ResolvedEndpoints {
    pub addrs: Vec<SocketAddr>,
    /// Backend wire protocol, parsed from `Service.spec.ports[].appProtocol`.
    pub app_protocol: BackendProtocol,
    /// Whether the referenced Service exists in the cluster (present in the
    /// Service store). Lets callers separate "valid Service, zero ready
    /// endpoints" (Gateway API: SHOULD 503) from "no such Service" (MUST 500).
    pub service_exists: bool,
}

struct ServicePortInfo {
    target_port: Option<i32>,
    app_protocol: Option<String>,
}

/// Looks up `svc` in the Service store and returns the pod-facing target port
/// (and `appProtocol`) for the given service port number. Returns `None` if the
/// Service is not in the store or the port is not found.
fn lookup_service_port(
    ns: &str,
    svc: &str,
    service_port: i32,
    services: &reflector::Store<Service>,
) -> Option<ServicePortInfo> {
    let key = reflector::ObjectRef::<Service>::new(svc).within(ns);
    let service = services.get(&key)?;
    let ports = service.spec.as_ref()?.ports.as_deref()?;
    for sp in ports {
        if sp.port == service_port {
            let target_port = match sp.target_port.as_ref()? {
                IntOrString::Int(tp) => Some(*tp),
                IntOrString::String(_) => None, // named port, fall back to caller
            };
            return Some(ServicePortInfo {
                target_port,
                app_protocol: sp.app_protocol.clone(),
            });
        }
    }
    None
}

/// Looks up `svc` in the Service store and returns the numeric service port
/// whose `name` field matches `port_name`. Returns `None` if the Service is
/// not in the store or no port has the given name.
pub(crate) fn port_for_name(
    ns: &str,
    svc: &str,
    port_name: &str,
    services: &reflector::Store<Service>,
) -> Option<i32> {
    let key = reflector::ObjectRef::<Service>::new(svc).within(ns);
    let service = services.get(&key)?;
    let ports = service.spec.as_ref()?.ports.as_deref()?;
    ports
        .iter()
        .find(|sp| sp.name.as_deref() == Some(port_name))
        .map(|sp| sp.port)
}

/// Scans the local `EndpointSlice` store for ready pod addresses backing
/// `svc` in `ns` on `port`. When the Service is in the store and its port
/// has a numeric `targetPort`, the pod port is resolved correctly even when
/// it differs from the service port. Also returns the `appProtocol` of the
/// matched Service port (if any) for backend protocol selection. Never
/// queries the API server.
pub(crate) fn resolve(
    ns: &str,
    svc: &str,
    port: i32,
    slices: &reflector::Store<EndpointSlice>,
    services: &reflector::Store<Service>,
) -> ResolvedEndpoints {
    let port_info = lookup_service_port(ns, svc, port, services);
    let pod_port = port_info
        .as_ref()
        .and_then(|i| i.target_port)
        .unwrap_or(port);
    let app_protocol = parse_app_protocol(
        port_info
            .and_then(|i| i.app_protocol)
            .as_deref()
            .unwrap_or(""),
    );

    let mut addrs = Vec::new();
    for slice in slices.state() {
        if slice.metadata.namespace.as_deref() != Some(ns) {
            continue;
        }
        let slice_svc = slice
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get("kubernetes.io/service-name").map(String::as_str));
        if slice_svc != Some(svc) {
            continue;
        }
        for ep in slice.endpoints.iter().flatten() {
            let cond = ep.conditions.as_ref();

            // Exclude terminating endpoints unconditionally — they must not
            // receive new requests regardless of the `drain-timeout` annotation
            // value. This matches the K8s EndpointSlice spec: `terminating=true`
            // means the pod's deletion has been acknowledged; the preStop hook may
            // still be running, but routing new traffic to it races the shutdown.
            if cond.is_some_and(|c| c.terminating == Some(true)) {
                tracing::debug!(
                    ns,
                    svc,
                    addrs = ?ep.addresses,
                    "Skipping terminating endpoint"
                );
                continue;
            }

            // `serving` is authoritative when set (K8s 1.22+); fall back to `ready`
            // for older clusters. Skip only when the effective signal is explicitly
            // false; treat unknown (None) as eligible.
            let eligible = cond.and_then(|c| c.serving.or(c.ready));
            if eligible == Some(false) {
                continue;
            }
            for addr in &ep.addresses {
                if let Ok(ip) = addr.parse::<IpAddr>() {
                    addrs.push(SocketAddr::new(ip, pod_port as u16));
                }
            }
        }
    }
    tracing::debug!(
        ns,
        svc,
        service_port = port,
        pod_port,
        count = addrs.len(),
        "Resolved endpoints"
    );
    let service_exists = {
        let key = reflector::ObjectRef::<Service>::new(svc).within(ns);
        services.get(&key).is_some()
    };
    ResolvedEndpoints {
        addrs,
        app_protocol,
        service_exists,
    }
}

#[cfg(test)]
mod tests {
    use crate::endpoints::resolve;
    use crate::tests::fixtures::{
        empty_svc_store, make_slice_with_all_conditions, make_slice_with_conditions,
        make_svc_store, slice_store,
    };
    use coxswain_core::routing::BackendProtocol;
    use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    use kube::api::ObjectMeta;
    use std::net::SocketAddr;

    fn make_service(ns: &str, name: &str, service_port: i32, target_port: i32) -> Service {
        Service {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                ports: Some(vec![ServicePort {
                    port: service_port,
                    target_port: Some(IntOrString::Int(target_port)),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn resolve_returns_ready_endpoints() {
        let store = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            None,
            Some(true),
        )]);
        let r = resolve("ns", "svc", 8080, &store, &empty_svc_store());
        assert_eq!(
            r.addrs,
            vec!["10.0.0.1:8080".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn resolve_skips_not_ready_endpoints() {
        let store = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            None,
            Some(false),
        )]);
        assert!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .is_empty()
        );
    }

    #[test]
    fn resolve_includes_unknown_ready_endpoints() {
        let store = slice_store(vec![make_slice_with_conditions(
            "ns", "svc", "10.0.0.1", None, None,
        )]);
        assert_eq!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .len(),
            1
        );
    }

    #[test]
    fn resolve_ignores_wrong_namespace() {
        let store = slice_store(vec![make_slice_with_conditions(
            "other-ns",
            "svc",
            "10.0.0.1",
            None,
            Some(true),
        )]);
        assert!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .is_empty()
        );
    }

    #[test]
    fn resolve_ignores_wrong_service() {
        let store = slice_store(vec![make_slice_with_conditions(
            "ns",
            "other-svc",
            "10.0.0.1",
            None,
            Some(true),
        )]);
        assert!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .is_empty()
        );
    }

    #[test]
    fn resolve_empty_store() {
        assert!(
            resolve("ns", "svc", 8080, &slice_store(vec![]), &empty_svc_store())
                .addrs
                .is_empty()
        );
    }

    #[test]
    fn resolve_uses_target_port_when_service_port_differs() {
        let slices = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            None,
            Some(true),
        )]);
        let svcs = make_svc_store(vec![make_service("ns", "svc", 8082, 3000)]);
        let r = resolve("ns", "svc", 8082, &slices, &svcs);
        assert_eq!(
            r.addrs,
            vec!["10.0.0.1:3000".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn resolve_falls_back_to_service_port_when_service_missing() {
        let slices = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            None,
            Some(true),
        )]);
        let r = resolve("ns", "svc", 8082, &slices, &empty_svc_store());
        assert_eq!(
            r.addrs,
            vec!["10.0.0.1:8082".parse::<SocketAddr>().unwrap()]
        );
    }

    // --- serving condition tests ---

    #[test]
    fn resolve_skips_not_serving_endpoints_even_when_ready_true() {
        // Regression: serving:false must exclude the endpoint even if ready:true
        // (the race window during rolling deploys where ready lags behind serving).
        let store = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            Some(false),
            Some(true),
        )]);
        assert!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .is_empty()
        );
    }

    #[test]
    fn resolve_includes_serving_endpoints_with_unknown_ready() {
        let store = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            Some(true),
            None,
        )]);
        assert_eq!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .len(),
            1
        );
    }

    #[test]
    fn resolve_falls_back_to_ready_when_serving_unset_and_ready_true() {
        let store = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            None,
            Some(true),
        )]);
        assert_eq!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .len(),
            1
        );
    }

    #[test]
    fn resolve_falls_back_to_ready_when_serving_unset_and_ready_false() {
        let store = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            None,
            Some(false),
        )]);
        assert!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .is_empty()
        );
    }

    #[test]
    fn resolve_serving_true_overrides_ready_false() {
        // serving wins when both are set; serving:true/ready:false means the
        // endpoint is in the process of becoming ready but can serve traffic.
        let store = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            Some(true),
            Some(false),
        )]);
        assert_eq!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .len(),
            1
        );
    }

    // --- terminating condition tests (#281) ---

    #[test]
    fn resolve_excludes_terminating_endpoints_regardless_of_serving() {
        // terminating=true + serving=true: endpoint is shutting down — must be excluded
        // so new requests do not race the pod's preStop hook.
        let store = slice_store(vec![make_slice_with_all_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            Some(true),
            Some(true),
            Some(true),
        )]);
        assert!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .is_empty(),
            "terminating=true must exclude even when serving=true"
        );
    }

    #[test]
    fn resolve_excludes_terminating_endpoints_with_unknown_serving() {
        // terminating=true + serving=None: older cluster; still must exclude.
        let store = slice_store(vec![make_slice_with_all_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            None,
            Some(true),
            Some(true),
        )]);
        assert!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .is_empty(),
            "terminating=true must exclude even when serving is unset"
        );
    }

    #[test]
    fn resolve_includes_non_terminating_endpoints_normally() {
        // terminating=false: endpoint is live — must be included as normal.
        let store = slice_store(vec![make_slice_with_all_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            Some(true),
            Some(true),
            Some(false),
        )]);
        assert_eq!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .len(),
            1,
            "terminating=false must not exclude the endpoint"
        );
    }

    #[test]
    fn resolve_includes_endpoint_when_terminating_unset() {
        // terminating=None: condition absent (pre-1.22 or not yet set) — keep existing
        // serving/ready gate behaviour with no additional exclusion.
        let store = slice_store(vec![make_slice_with_all_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            Some(true),
            Some(true),
            None,
        )]);
        assert_eq!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .len(),
            1,
            "terminating=None must not exclude the endpoint"
        );
    }

    fn make_service_with_app_protocol(
        ns: &str,
        name: &str,
        service_port: i32,
        target_port: i32,
        app_protocol: &str,
    ) -> Service {
        Service {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                ports: Some(vec![ServicePort {
                    port: service_port,
                    target_port: Some(IntOrString::Int(target_port)),
                    app_protocol: Some(app_protocol.to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn resolve_propagates_app_protocol_from_service_port() {
        let slices = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            None,
            Some(true),
        )]);
        let svcs = make_svc_store(vec![make_service_with_app_protocol(
            "ns",
            "svc",
            8080,
            8080,
            "kubernetes.io/h2c",
        )]);
        let r = resolve("ns", "svc", 8080, &slices, &svcs);
        assert_eq!(r.app_protocol, BackendProtocol::H2c);
    }

    #[test]
    fn resolve_app_protocol_absent_when_service_missing() {
        let slices = slice_store(vec![make_slice_with_conditions(
            "ns",
            "svc",
            "10.0.0.1",
            None,
            Some(true),
        )]);
        let r = resolve("ns", "svc", 8080, &slices, &empty_svc_store());
        assert_eq!(r.app_protocol, BackendProtocol::Http1);
    }
}
