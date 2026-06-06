use super::*;
use crate::gw_types::v::gateways::{Gateway, GatewayListeners, GatewaySpec};
use crate::gw_types::v::httproutes::{
    HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs, HttpRouteSpec,
};
use crate::keys::RouteParentKey;
use crate::tls::HttpRouteHealthMap;
use coxswain_core::reference_grants::ReferenceGrantKey;
use kube::api::ObjectMeta;
use kube::runtime::{reflector, watcher};
use std::sync::Arc;

fn make_gateway(ns: &str, name: &str, listener_hostname: &str, port: u16) -> Arc<Gateway> {
    Arc::new(Gateway {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(ns.to_string()),
            ..Default::default()
        },
        spec: GatewaySpec {
            gateway_class_name: "coxswain".to_string(),
            listeners: vec![GatewayListeners {
                name: "http".to_string(),
                protocol: "HTTP".to_string(),
                port: port as i32,
                hostname: if listener_hostname.is_empty() {
                    None
                } else {
                    Some(listener_hostname.to_string())
                },
                ..Default::default()
            }],
            ..Default::default()
        },
        status: None,
    })
}

fn make_route(
    route_ns: &str,
    route_name: &str,
    hostnames: &[&str],
    gw_ns: &str,
    gw_name: &str,
) -> Arc<HttpRoute> {
    Arc::new(HttpRoute {
        metadata: ObjectMeta {
            name: Some(route_name.to_string()),
            namespace: Some(route_ns.to_string()),
            ..Default::default()
        },
        spec: HttpRouteSpec {
            parent_refs: Some(vec![HttpRouteParentRefs {
                name: gw_name.to_string(),
                namespace: Some(gw_ns.to_string()),
                ..Default::default()
            }]),
            hostnames: if hostnames.is_empty() {
                None
            } else {
                Some(hostnames.iter().map(|s| s.to_string()).collect())
            },
            rules: Some(vec![HttpRouteRules {
                backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                    name: "svc".to_string(),
                    port: Some(80),
                    ..Default::default()
                }]),
                ..Default::default()
            }]),
        },
        ..Default::default()
    })
}

fn service_store_with(ns: &str, name: &str) -> reflector::Store<Service> {
    let mut w = reflector::store::Writer::<Service>::default();
    w.apply_watcher_event(&watcher::Event::Apply(Service {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(ns.to_string()),
            ..Default::default()
        },
        ..Default::default()
    }));
    w.as_reader()
}

fn run(
    routes: &[Arc<HttpRoute>],
    gateways: &[Arc<Gateway>],
    owned: &[(&str, &str)],
    grants: &HashSet<ReferenceGrantKey>,
    services: &reflector::Store<Service>,
) -> HttpRouteHealthMap {
    let owned_set: HashSet<ObjectKey> = owned
        .iter()
        .map(|(ns, name)| ObjectKey::new(*ns, *name))
        .collect();
    super::super::status::compute_route_health(routes, gateways, &owned_set, grants, services)
}

fn key(route_ns: &str, route_name: &str, gw_ns: &str, gw_name: &str) -> RouteParentKey {
    RouteParentKey::new(route_ns, route_name, gw_ns, gw_name, String::new())
}

// ── compute_route_health ──────────────────────────────────────────────────────

#[test]
fn route_with_owned_gateway_is_accepted() {
    let gw = make_gateway("default", "gw", "", 80);
    let route = make_route("default", "route", &["example.com"], "default", "gw");
    let services = service_store_with("default", "svc");

    let map = run(
        &[route],
        &[gw],
        &[("default", "gw")],
        &HashSet::new(),
        &services,
    );

    let h = map.get(&key("default", "route", "default", "gw")).unwrap();
    assert!(h.accepted, "expected Accepted=true");
    assert_eq!(h.accepted_reason, "Accepted");
    assert!(h.resolved_refs);
    assert_eq!(h.resolved_refs_reason, "ResolvedRefs");
}

#[test]
fn route_with_unowned_gateway_produces_no_entry() {
    let gw = make_gateway("default", "gw", "", 80);
    let route = make_route("default", "route", &[], "default", "gw");

    // owned set is empty — gw is not owned
    let map = run(&[route], &[gw], &[], &HashSet::new(), &empty_svc_store());

    assert!(!map.contains_key(&key("default", "route", "default", "gw")));
}

#[test]
fn route_hostname_not_intersecting_listener_is_rejected() {
    let gw = make_gateway("default", "gw", "other.com", 80);
    let route = make_route("default", "route", &["example.com"], "default", "gw");
    let services = service_store_with("default", "svc");

    let map = run(
        &[route],
        &[gw],
        &[("default", "gw")],
        &HashSet::new(),
        &services,
    );

    let h = map.get(&key("default", "route", "default", "gw")).unwrap();
    assert!(!h.accepted);
    assert_eq!(h.accepted_reason, "NoMatchingListenerHostname");
}

#[test]
fn route_hostname_matching_listener_wildcard_is_accepted() {
    let gw = make_gateway("default", "gw", "*.example.com", 80);
    let route = make_route("default", "route", &["api.example.com"], "default", "gw");
    let services = service_store_with("default", "svc");

    let map = run(
        &[route],
        &[gw],
        &[("default", "gw")],
        &HashSet::new(),
        &services,
    );

    let h = map.get(&key("default", "route", "default", "gw")).unwrap();
    assert!(h.accepted);
}

#[test]
fn backend_service_not_found_sets_resolved_refs_false() {
    let gw = make_gateway("default", "gw", "", 80);
    let route = make_route("default", "route", &[], "default", "gw");

    // "svc" not present in the store
    let map = run(
        &[route],
        &[gw],
        &[("default", "gw")],
        &HashSet::new(),
        &empty_svc_store(),
    );

    let h = map.get(&key("default", "route", "default", "gw")).unwrap();
    assert!(h.accepted);
    assert!(!h.resolved_refs);
    assert_eq!(h.resolved_refs_reason, "BackendNotFound");
}

#[test]
fn cross_namespace_route_blocked_when_listener_allows_same_only() {
    // Gateway in "gw-ns", route in "app-ns".
    // Listener has no AllowedRoutes override → defaults to Same namespace only.
    let gw = make_gateway("gw-ns", "gw", "", 80);
    let route = make_route("app-ns", "route", &[], "gw-ns", "gw");

    let map = run(
        &[route],
        &[gw],
        &[("gw-ns", "gw")],
        &HashSet::new(),
        &empty_svc_store(),
    );

    let k = RouteParentKey::new("app-ns", "route", "gw-ns", "gw", String::new());
    let h = map.get(&k).unwrap();
    assert!(!h.accepted);
    assert_eq!(h.accepted_reason, "NotAllowedByListeners");
}
