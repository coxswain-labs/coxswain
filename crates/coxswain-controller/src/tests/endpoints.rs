use crate::endpoints::resolve;
use coxswain_core::routing::BackendProtocol;
use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointSlice};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;
use kube::runtime::{reflector, watcher};
use std::collections::BTreeMap;
use std::net::SocketAddr;

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
    assert_eq!(r.app_protocol, BackendProtocol::H2c);
}

#[test]
fn resolve_app_protocol_absent_when_service_missing() {
    let slices = make_store(vec![make_slice("ns", "svc", "10.0.0.1", None, Some(true))]);
    let r = resolve("ns", "svc", 8080, &slices, &empty_svc_store());
    assert_eq!(r.app_protocol, BackendProtocol::Http1);
}
