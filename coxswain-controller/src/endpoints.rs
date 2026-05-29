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

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointSlice};
    use kube::api::ObjectMeta;
    use kube::runtime::watcher;
    use std::collections::BTreeMap;

    fn make_slice(ns: &str, svc: &str, ip: &str, ready: Option<bool>) -> EndpointSlice {
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

    #[test]
    fn resolve_returns_ready_endpoints() {
        let store = make_store(vec![make_slice("ns", "svc", "10.0.0.1", Some(true))]);
        let addrs = resolve("ns", "svc", 8080, &store);
        assert_eq!(addrs, vec!["10.0.0.1:8080".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn resolve_skips_not_ready_endpoints() {
        let store = make_store(vec![make_slice("ns", "svc", "10.0.0.1", Some(false))]);
        assert!(resolve("ns", "svc", 8080, &store).is_empty());
    }

    #[test]
    fn resolve_includes_unknown_ready_endpoints() {
        let store = make_store(vec![make_slice("ns", "svc", "10.0.0.1", None)]);
        assert_eq!(resolve("ns", "svc", 8080, &store).len(), 1);
    }

    #[test]
    fn resolve_ignores_wrong_namespace() {
        let store = make_store(vec![make_slice("other-ns", "svc", "10.0.0.1", Some(true))]);
        assert!(resolve("ns", "svc", 8080, &store).is_empty());
    }

    #[test]
    fn resolve_ignores_wrong_service() {
        let store = make_store(vec![make_slice("ns", "other-svc", "10.0.0.1", Some(true))]);
        assert!(resolve("ns", "svc", 8080, &store).is_empty());
    }

    #[test]
    fn resolve_empty_store() {
        assert!(resolve("ns", "svc", 8080, &make_store(vec![])).is_empty());
    }
}
