use super::*;
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
