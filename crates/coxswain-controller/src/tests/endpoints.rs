use crate::endpoints::resolve;
use crate::tests::fixtures::{
    empty_svc_store, make_slice_with_conditions, make_svc_store, slice_store,
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
