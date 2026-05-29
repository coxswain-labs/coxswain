use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector;
use std::net::{IpAddr, SocketAddr};

/// Scans the local `EndpointSlice` store for ready pod addresses backing
/// `svc` in `ns` on `port`. Never queries the API server.
pub(crate) fn resolve(
    ns: &str,
    svc: &str,
    port: i32,
    slices: &reflector::Store<EndpointSlice>,
) -> Vec<SocketAddr> {
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
            // Skip endpoints explicitly marked not-ready; treat unknown (None) as ready.
            if ep.conditions.as_ref().and_then(|c| c.ready) == Some(false) {
                continue;
            }
            for addr in &ep.addresses {
                if let Ok(ip) = addr.parse::<IpAddr>() {
                    addrs.push(SocketAddr::new(ip, port as u16));
                }
            }
        }
    }
    addrs
}
