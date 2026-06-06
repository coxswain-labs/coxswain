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
