use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::runtime::reflector;
use std::net::{IpAddr, SocketAddr};

/// Resolved addresses and protocol metadata for a single backend service port.
pub(crate) struct ResolvedEndpoints {
    pub addrs: Vec<SocketAddr>,
    /// Raw `appProtocol` string from the matched `ServicePort`, if present.
    pub app_protocol: Option<String>,
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

/// Looks up `svc` in the Service store and returns the `name` field of the
/// `ServicePort` whose `port` number matches `service_port`. Returns `None`
/// if the Service is absent or the port has no name.
///
/// Used by BackendTLSPolicy look-up to map a numeric `backendRef.port` to
/// the `sectionName` in the policy's `targetRefs`.
pub(crate) fn port_name_for(
    ns: &str,
    svc: &str,
    service_port: i32,
    services: &reflector::Store<Service>,
) -> Option<String> {
    let key = reflector::ObjectRef::<Service>::new(svc).within(ns);
    let service = services.get(&key)?;
    let ports = service.spec.as_ref()?.ports.as_deref()?;
    ports
        .iter()
        .find(|sp| sp.port == service_port)
        .and_then(|sp| sp.name.clone())
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
    let app_protocol = port_info.and_then(|i| i.app_protocol);

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
        for ep in &slice.endpoints {
            // `serving` is authoritative when set (K8s 1.22+); fall back to `ready`
            // for older clusters. Skip only when the effective signal is explicitly
            // false; treat unknown (None) as eligible.
            let cond = ep.conditions.as_ref();
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
    ResolvedEndpoints {
        addrs,
        app_protocol,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointSlice};
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    use kube::api::ObjectMeta;
    use kube::runtime::watcher;
    use std::collections::BTreeMap;

    fn make_slice(
        ns: &str,
        svc: &str,
        ip: &str,
        serving: Option<bool>,
        ready: Option<bool>,
    ) -> EndpointSlice {
        let mut labels = BTreeMap::new();
        labels.insert("kubernetes.io/service-name".to_string(), svc.to_string());
        EndpointSlice {
            metadata: ObjectMeta {
                name: Some(format!("{svc}-slice")),
                namespace: Some(ns.to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            address_type: "IPv4".to_string(),
            endpoints: vec![Endpoint {
                addresses: vec![ip.to_string()],
                conditions: Some(EndpointConditions {
                    serving,
                    ready,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ports: None,
        }
    }

    fn make_store(slices: Vec<EndpointSlice>) -> reflector::Store<EndpointSlice> {
        let mut writer = reflector::store::Writer::<EndpointSlice>::default();
        for slice in slices {
            writer.apply_watcher_event(&watcher::Event::Apply(slice));
        }
        writer.as_reader()
    }

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

    fn make_svc_store(services: Vec<Service>) -> reflector::Store<Service> {
        let mut writer = reflector::store::Writer::<Service>::default();
        for svc in services {
            writer.apply_watcher_event(&watcher::Event::Apply(svc));
        }
        writer.as_reader()
    }

    fn empty_svc_store() -> reflector::Store<Service> {
        make_svc_store(vec![])
    }

    #[test]
    fn resolve_returns_ready_endpoints() {
        let store = make_store(vec![make_slice("ns", "svc", "10.0.0.1", None, Some(true))]);
        let r = resolve("ns", "svc", 8080, &store, &empty_svc_store());
        assert_eq!(
            r.addrs,
            vec!["10.0.0.1:8080".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn resolve_skips_not_ready_endpoints() {
        let store = make_store(vec![make_slice("ns", "svc", "10.0.0.1", None, Some(false))]);
        assert!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .is_empty()
        );
    }

    #[test]
    fn resolve_includes_unknown_ready_endpoints() {
        let store = make_store(vec![make_slice("ns", "svc", "10.0.0.1", None, None)]);
        assert_eq!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .len(),
            1
        );
    }

    #[test]
    fn resolve_ignores_wrong_namespace() {
        let store = make_store(vec![make_slice(
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
        let store = make_store(vec![make_slice(
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
            resolve("ns", "svc", 8080, &make_store(vec![]), &empty_svc_store())
                .addrs
                .is_empty()
        );
    }

    #[test]
    fn resolve_uses_target_port_when_service_port_differs() {
        let slices = make_store(vec![make_slice("ns", "svc", "10.0.0.1", None, Some(true))]);
        let svcs = make_svc_store(vec![make_service("ns", "svc", 8082, 3000)]);
        let r = resolve("ns", "svc", 8082, &slices, &svcs);
        assert_eq!(
            r.addrs,
            vec!["10.0.0.1:3000".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn resolve_falls_back_to_service_port_when_service_missing() {
        let slices = make_store(vec![make_slice("ns", "svc", "10.0.0.1", None, Some(true))]);
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
        let store = make_store(vec![make_slice(
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
        let store = make_store(vec![make_slice("ns", "svc", "10.0.0.1", Some(true), None)]);
        assert_eq!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .len(),
            1
        );
    }

    #[test]
    fn resolve_falls_back_to_ready_when_serving_unset_and_ready_true() {
        let store = make_store(vec![make_slice("ns", "svc", "10.0.0.1", None, Some(true))]);
        assert_eq!(
            resolve("ns", "svc", 8080, &store, &empty_svc_store())
                .addrs
                .len(),
            1
        );
    }

    #[test]
    fn resolve_falls_back_to_ready_when_serving_unset_and_ready_false() {
        let store = make_store(vec![make_slice("ns", "svc", "10.0.0.1", None, Some(false))]);
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
        let store = make_store(vec![make_slice(
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
        let slices = make_store(vec![make_slice("ns", "svc", "10.0.0.1", None, Some(true))]);
        let svcs = make_svc_store(vec![make_service_with_app_protocol(
            "ns",
            "svc",
            8080,
            8080,
            "kubernetes.io/h2c",
        )]);
        let r = resolve("ns", "svc", 8080, &slices, &svcs);
        assert_eq!(r.app_protocol.as_deref(), Some("kubernetes.io/h2c"));
    }

    #[test]
    fn resolve_app_protocol_absent_when_service_missing() {
        let slices = make_store(vec![make_slice("ns", "svc", "10.0.0.1", None, Some(true))]);
        let r = resolve("ns", "svc", 8080, &slices, &empty_svc_store());
        assert!(r.app_protocol.is_none());
    }
}
