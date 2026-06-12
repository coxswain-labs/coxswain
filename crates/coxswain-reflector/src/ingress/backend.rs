//! Resolves Ingress backend service port numbers from `Service.spec.ports`.

use crate::endpoints;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::networking::v1::IngressServiceBackend;
use kube::runtime::reflector;

/// Resolves a backend port to its numeric value.
///
/// Tries `port.number` first; when absent, looks up `port.name` in the
/// Service store. Emits a warning and returns `None` when the name is set
/// but the Service is missing or has no matching port.
pub(super) fn resolve_backend_port(
    ns: &str,
    svc: &IngressServiceBackend,
    services: &reflector::Store<Service>,
) -> Option<i32> {
    let port = svc.port.as_ref()?;
    if let Some(n) = port.number {
        return Some(n);
    }
    let name = port.name.as_deref()?;
    let resolved = endpoints::port_for_name(ns, &svc.name, name, services);
    if resolved.is_none() {
        tracing::warn!(
            namespace = %ns,
            service = %svc.name,
            port_name = %name,
            "Ingress backend references unknown named port on Service — skipping"
        );
    }
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::tests::*;
    use k8s_openapi::api::core::v1::{ServicePort, ServiceSpec};
    use k8s_openapi::api::networking::v1::{IngressServiceBackend, ServiceBackendPort};

    fn svc_backend(
        name: &str,
        port_number: Option<i32>,
        port_name: Option<&str>,
    ) -> IngressServiceBackend {
        IngressServiceBackend {
            name: name.to_string(),
            port: Some(ServiceBackendPort {
                number: port_number,
                name: port_name.map(str::to_string),
            }),
        }
    }

    fn svc_with_named_port(ns: &str, name: &str, port_name: &str, port_number: i32) -> Service {
        Service {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                ports: Some(vec![ServicePort {
                    name: Some(port_name.to_string()),
                    port: port_number,
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    // ── resolve_backend_port ──────────────────────────────────────────────────────

    #[test]
    fn numeric_port_resolves_directly() {
        let svc = svc_backend("my-svc", Some(8080), None);
        let store = empty_svc_store();
        assert_eq!(
            super::super::backend::resolve_backend_port("default", &svc, &store),
            Some(8080)
        );
    }

    #[test]
    fn named_port_resolves_via_service_store() {
        let svc = svc_backend("my-svc", None, Some("http"));
        let store = make_svc_store(vec![svc_with_named_port("default", "my-svc", "http", 8080)]);
        assert_eq!(
            super::super::backend::resolve_backend_port("default", &svc, &store),
            Some(8080)
        );
    }

    #[test]
    fn named_port_returns_none_when_service_missing() {
        let svc = svc_backend("missing-svc", None, Some("http"));
        let store = empty_svc_store();
        assert_eq!(
            super::super::backend::resolve_backend_port("default", &svc, &store),
            None
        );
    }

    #[test]
    fn named_port_returns_none_when_port_name_not_on_service() {
        let svc = svc_backend("my-svc", None, Some("http"));
        // Service has port "grpc", not "http"
        let store = make_svc_store(vec![svc_with_named_port("default", "my-svc", "grpc", 9000)]);
        assert_eq!(
            super::super::backend::resolve_backend_port("default", &svc, &store),
            None
        );
    }

    #[test]
    fn no_port_spec_returns_none() {
        let svc = IngressServiceBackend {
            name: "my-svc".to_string(),
            port: None,
        };
        assert_eq!(
            super::super::backend::resolve_backend_port("default", &svc, &empty_svc_store()),
            None
        );
    }

    #[test]
    fn numeric_port_takes_precedence_over_name() {
        // Both number and name set — number wins (checked first)
        let svc = svc_backend("my-svc", Some(8080), Some("http"));
        let store = make_svc_store(vec![svc_with_named_port("default", "my-svc", "http", 9090)]);
        assert_eq!(
            super::super::backend::resolve_backend_port("default", &svc, &store),
            Some(8080)
        );
    }
}
