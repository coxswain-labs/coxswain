use super::*;
use coxswain_core::routing::{RequestContext, RoutingTableBuilder};
use k8s_openapi::api::networking::v1::{
    HTTPIngressPath, HTTPIngressRuleValue, IngressBackend, IngressRule, IngressServiceBackend,
    IngressSpec, ServiceBackendPort,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::api::ObjectMeta;

fn make_ingress_with_timestamp(
    ns: &str,
    host: Option<&str>,
    path: &str,
    path_type: &str,
    svc: &str,
    created_at_ms: i64,
) -> Ingress {
    Ingress {
        metadata: ObjectMeta {
            name: Some(format!("{svc}-ingress")),
            namespace: Some(ns.to_string()),
            creation_timestamp: Some(Time(
                k8s_openapi::jiff::Timestamp::from_millisecond(created_at_ms).unwrap(),
            )),
            ..Default::default()
        },
        spec: Some(IngressSpec {
            ingress_class_name: Some("coxswain".to_string()),
            rules: Some(vec![IngressRule {
                host: host.map(str::to_string),
                http: Some(HTTPIngressRuleValue {
                    paths: vec![HTTPIngressPath {
                        path: Some(path.to_string()),
                        path_type: path_type.to_string(),
                        backend: IngressBackend {
                            service: Some(IngressServiceBackend {
                                name: svc.to_string(),
                                port: Some(ServiceBackendPort {
                                    number: Some(80),
                                    ..Default::default()
                                }),
                            }),
                            ..Default::default()
                        },
                    }],
                }),
            }]),
            ..Default::default()
        }),
        status: None,
    }
}

#[test]
fn reconcile_default_backend_catches_path_miss() {
    let store = slice_store(vec![
        make_slice("default", "rule-svc", "10.0.0.1"),
        make_slice("default", "default-svc", "10.0.0.2"),
    ]);
    let ingress = make_ingress_with_default(
        "default",
        Some("example.com"),
        "/api",
        "rule-svc",
        Some("default-svc"),
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert_eq!(
        table
            .route(80, "example.com", "/api/v1", &ctx)
            .unwrap()
            .name(),
        "default/rule-svc"
    );
    assert_eq!(
        table
            .route(80, "example.com", "/other", &ctx)
            .unwrap()
            .name(),
        "default/default-svc"
    );
}

#[test]
fn reconcile_default_backend_only_routes_all_traffic() {
    let store = slice_store(vec![make_slice("default", "default-svc", "10.0.0.1")]);
    let ingress = make_default_only_ingress("default", "default-svc");
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert_eq!(
        table.route(80, "any.host.com", "/", &ctx).unwrap().name(),
        "default/default-svc"
    );
    assert_eq!(
        table.route(80, "other.io", "/api/v1", &ctx).unwrap().name(),
        "default/default-svc"
    );
}

#[test]
fn reconcile_default_backend_catches_unmatched_host() {
    let store = slice_store(vec![
        make_slice("default", "rule-svc", "10.0.0.1"),
        make_slice("default", "default-svc", "10.0.0.2"),
    ]);
    let ingress = make_ingress_with_default(
        "default",
        Some("a.com"),
        "/api",
        "rule-svc",
        Some("default-svc"),
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert_eq!(
        table.route(80, "a.com", "/api", &ctx).unwrap().name(),
        "default/rule-svc"
    );
    assert_eq!(
        table.route(80, "a.com", "/other", &ctx).unwrap().name(),
        "default/default-svc"
    );
    assert_eq!(
        table.route(80, "b.com", "/", &ctx).unwrap().name(),
        "default/default-svc"
    );
}

#[test]
fn reconcile_older_ingress_wins_same_prefix_path() {
    let store = slice_store(vec![
        make_slice("default", "old-svc", "10.0.0.1"),
        make_slice("default", "new-svc", "10.0.0.2"),
    ]);
    let old_ingress = make_ingress_with_timestamp(
        "default",
        Some("example.com"),
        "/foo",
        "Prefix",
        "old-svc",
        1000,
    );
    let new_ingress = make_ingress_with_timestamp(
        "default",
        Some("example.com"),
        "/foo",
        "Prefix",
        "new-svc",
        2000,
    );

    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &old_ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    reconcile_no_default(
        &new_ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert_eq!(
        table.route(80, "example.com", "/foo", &ctx).unwrap().name(),
        "default/old-svc",
        "older Ingress should win on conflicting Prefix /foo"
    );
}

#[test]
fn reconcile_exact_beats_prefix_same_path() {
    let store = slice_store(vec![
        make_slice("default", "exact-svc", "10.0.0.1"),
        make_slice("default", "prefix-svc", "10.0.0.2"),
    ]);
    let ingress = Ingress {
        metadata: ObjectMeta {
            name: Some("test-ingress".to_string()),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        spec: Some(IngressSpec {
            ingress_class_name: Some("coxswain".to_string()),
            rules: Some(vec![IngressRule {
                host: Some("example.com".to_string()),
                http: Some(HTTPIngressRuleValue {
                    paths: vec![
                        HTTPIngressPath {
                            path: Some("/foo".to_string()),
                            path_type: "Exact".to_string(),
                            backend: IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: "exact-svc".to_string(),
                                    port: Some(ServiceBackendPort {
                                        number: Some(80),
                                        ..Default::default()
                                    }),
                                }),
                                ..Default::default()
                            },
                        },
                        HTTPIngressPath {
                            path: Some("/foo".to_string()),
                            path_type: "Prefix".to_string(),
                            backend: IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: "prefix-svc".to_string(),
                                    port: Some(ServiceBackendPort {
                                        number: Some(80),
                                        ..Default::default()
                                    }),
                                }),
                                ..Default::default()
                            },
                        },
                    ],
                }),
            }]),
            ..Default::default()
        }),
        status: None,
    };
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert_eq!(
        table.route(80, "example.com", "/foo", &ctx).unwrap().name(),
        "default/exact-svc",
        "Exact /foo should win over Prefix /foo"
    );
    assert_eq!(
        table
            .route(80, "example.com", "/foo/sub", &ctx)
            .unwrap()
            .name(),
        "default/prefix-svc",
        "Prefix /foo should still match /foo/sub"
    );
}

#[test]
fn reconcile_default_backend_skipped_when_no_endpoints() {
    let store = slice_store(vec![
        make_slice("default", "rule-svc", "10.0.0.1"),
        // no slice for default-svc → no endpoints
    ]);
    let ingress = make_ingress_with_default(
        "default",
        Some("example.com"),
        "/api",
        "rule-svc",
        Some("default-svc"),
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert!(table.route(80, "example.com", "/api", &ctx).is_some());
    assert!(table.route(80, "example.com", "/other", &ctx).is_none());
}

#[test]
fn reconcile_default_backend_on_wildcard_host() {
    let store = slice_store(vec![
        make_slice("default", "rule-svc", "10.0.0.1"),
        make_slice("default", "default-svc", "10.0.0.2"),
    ]);
    let ingress = make_ingress_with_default(
        "default",
        Some("*.example.com"),
        "/api",
        "rule-svc",
        Some("default-svc"),
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert_eq!(
        table
            .route(80, "api.example.com", "/api", &ctx)
            .unwrap()
            .name(),
        "default/rule-svc"
    );
    assert_eq!(
        table
            .route(80, "api.example.com", "/other", &ctx)
            .unwrap()
            .name(),
        "default/default-svc"
    );
}

#[test]
fn reconcile_rule_root_path_wins_over_default_backend() {
    let store = slice_store(vec![
        make_slice("default", "rule-svc", "10.0.0.1"),
        make_slice("default", "default-svc", "10.0.0.2"),
    ]);
    // Rule already claims "/"; defaultBackend should not override it.
    let ingress = make_ingress_with_default(
        "default",
        Some("example.com"),
        "/",
        "rule-svc",
        Some("default-svc"),
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert_eq!(
        table
            .route(80, "example.com", "/anything", &ctx)
            .unwrap()
            .name(),
        "default/rule-svc"
    );
}

#[test]
fn reconcile_exact_path_type() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let ingress = make_ingress(
        "default",
        Some("example.com"),
        "/api",
        "Exact",
        "svc",
        Some("coxswain"),
        None,
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert!(table.route(80, "example.com", "/api", &ctx).is_some());
    assert!(table.route(80, "example.com", "/api/users", &ctx).is_none());
}

#[test]
fn reconcile_named_port_resolves_to_route() {
    let slices = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let svcs = make_svc_store(vec![make_service_with_named_port(
        "default", "svc", "http", 80,
    )]);
    let ingress = make_ingress_named_port("default", Some("example.com"), "svc", "http");
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &slices,
        &svcs,
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    let route = table.route(80, "example.com", "/named", &ctx);
    assert!(
        route.is_some(),
        "named port backend should resolve to a route"
    );
    assert_eq!(route.unwrap().name(), "default/svc");
}

#[test]
fn reconcile_named_port_skips_when_service_missing() {
    let slices = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    // No Service in the store → port_for_name returns None → path skipped
    let ingress = make_ingress_named_port("default", Some("example.com"), "svc", "http");
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &slices,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    assert!(
        table
            .route(80, "example.com", "/named", &RequestContext::default())
            .is_none()
    );
}

#[test]
fn reconcile_named_port_skips_when_port_name_not_found() {
    let slices = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    // Service exists but has port name "grpc", not "http"
    let svcs = make_svc_store(vec![make_service_with_named_port(
        "default", "svc", "grpc", 9000,
    )]);
    let ingress = make_ingress_named_port("default", Some("example.com"), "svc", "http");
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &slices,
        &svcs,
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    assert!(
        table
            .route(80, "example.com", "/named", &RequestContext::default())
            .is_none()
    );
}

#[test]
fn reconcile_named_port_default_backend_resolves() {
    let slices = slice_store(vec![
        make_slice("default", "rule-svc", "10.0.0.1"),
        make_slice("default", "default-svc", "10.0.0.2"),
    ]);
    let svcs = make_svc_store(vec![make_service_with_named_port(
        "default",
        "default-svc",
        "http",
        80,
    )]);
    let ingress = Ingress {
        metadata: ObjectMeta {
            name: Some("test-ingress".to_string()),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        spec: Some(IngressSpec {
            ingress_class_name: Some("coxswain".to_string()),
            rules: Some(vec![IngressRule {
                host: Some("example.com".to_string()),
                http: Some(HTTPIngressRuleValue {
                    paths: vec![HTTPIngressPath {
                        path: Some("/api".to_string()),
                        path_type: "Prefix".to_string(),
                        backend: IngressBackend {
                            service: Some(IngressServiceBackend {
                                name: "rule-svc".to_string(),
                                port: Some(ServiceBackendPort {
                                    number: Some(80),
                                    ..Default::default()
                                }),
                            }),
                            ..Default::default()
                        },
                    }],
                }),
            }]),
            default_backend: Some(IngressBackend {
                service: Some(IngressServiceBackend {
                    name: "default-svc".to_string(),
                    port: Some(ServiceBackendPort {
                        name: Some("http".to_string()),
                        number: None,
                    }),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        status: None,
    };
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &slices,
        &svcs,
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert_eq!(
        table
            .route(80, "example.com", "/api/v1", &ctx)
            .unwrap()
            .name(),
        "default/rule-svc"
    );
    assert_eq!(
        table
            .route(80, "example.com", "/other", &ctx)
            .unwrap()
            .name(),
        "default/default-svc"
    );
}

#[test]
fn reconcile_prefix_path_type() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let ingress = make_ingress(
        "default",
        Some("example.com"),
        "/api",
        "Prefix",
        "svc",
        Some("coxswain"),
        None,
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert!(table.route(80, "example.com", "/api", &ctx).is_some());
    assert!(table.route(80, "example.com", "/api/users", &ctx).is_some());
    assert!(table.route(80, "example.com", "/other", &ctx).is_none());
}

#[test]
fn reconcile_implementation_specific_maps_to_prefix() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let ingress = make_ingress(
        "default",
        Some("example.com"),
        "/api",
        "ImplementationSpecific",
        "svc",
        Some("coxswain"),
        None,
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert!(table.route(80, "example.com", "/api", &ctx).is_some());
    assert!(table.route(80, "example.com", "/api/v2", &ctx).is_some());
}

#[test]
fn reconcile_exact_hostname() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let ingress = make_ingress(
        "default",
        Some("example.com"),
        "/",
        "Prefix",
        "svc",
        Some("coxswain"),
        None,
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert!(table.route(80, "example.com", "/", &ctx).is_some());
    assert!(table.route(80, "other.com", "/", &ctx).is_none());
}

#[test]
fn reconcile_wildcard_hostname() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let ingress = make_ingress(
        "default",
        Some("*.example.com"),
        "/",
        "Prefix",
        "svc",
        Some("coxswain"),
        None,
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert!(table.route(80, "api.example.com", "/", &ctx).is_some());
    assert!(table.route(80, "example.com", "/", &ctx).is_none());
}

#[test]
fn reconcile_no_host_goes_to_catchall() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let ingress = make_ingress(
        "default",
        None,
        "/",
        "Prefix",
        "svc",
        Some("coxswain"),
        None,
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert!(table.route(80, "any-host.example.com", "/", &ctx).is_some());
    assert!(table.route(80, "other.io", "/", &ctx).is_some());
}

#[test]
fn reconcile_skips_rule_with_no_endpoints() {
    let store = slice_store(vec![]); // no slices → no endpoints
    let ingress = make_ingress(
        "default",
        Some("example.com"),
        "/",
        "Prefix",
        "svc",
        Some("coxswain"),
        None,
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert!(table.route(80, "example.com", "/", &ctx).is_none());
}

#[test]
fn reconcile_matches_owned_class_name() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let ingress = make_ingress(
        "default",
        Some("example.com"),
        "/",
        "Prefix",
        "svc",
        Some("coxswain"),
        None,
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    assert!(
        builder
            .build()
            .unwrap()
            .route(80, "example.com", "/", &RequestContext::default())
            .is_some()
    );
}

#[test]
fn reconcile_skips_unowned_class_name() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let ingress = make_ingress(
        "default",
        Some("example.com"),
        "/",
        "Prefix",
        "svc",
        Some("nginx"),
        None,
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    assert!(
        builder
            .build()
            .unwrap()
            .route(80, "example.com", "/", &RequestContext::default())
            .is_none()
    );
}

#[test]
fn reconcile_matches_via_legacy_annotation() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let ingress = make_ingress(
        "default",
        Some("example.com"),
        "/",
        "Prefix",
        "svc",
        None,
        Some("coxswain"),
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    assert!(
        builder
            .build()
            .unwrap()
            .route(80, "example.com", "/", &RequestContext::default())
            .is_some()
    );
}

#[test]
fn reconcile_skips_unowned_legacy_annotation() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let ingress = make_ingress(
        "default",
        Some("example.com"),
        "/",
        "Prefix",
        "svc",
        None,
        Some("nginx"),
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    assert!(
        builder
            .build()
            .unwrap()
            .route(80, "example.com", "/", &RequestContext::default())
            .is_none()
    );
}

#[test]
fn reconcile_skips_when_both_unset() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let ingress = make_ingress(
        "default",
        Some("example.com"),
        "/",
        "Prefix",
        "svc",
        None,
        None,
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    assert!(
        builder
            .build()
            .unwrap()
            .route(80, "example.com", "/", &RequestContext::default())
            .is_none()
    );
}

#[test]
fn reconcile_claims_unclassified_when_owned_default_exists() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let ingress = make_ingress(
        "default",
        Some("example.com"),
        "/",
        "Prefix",
        "svc",
        None,
        None,
    );
    let mut builder = RoutingTableBuilder::new();
    IngressReconciler::reconcile(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        Some("coxswain"),
        IngressPorts::new(Some(80), None),
        &mut builder,
    );
    assert!(
        builder
            .build()
            .unwrap()
            .route(80, "example.com", "/", &RequestContext::default())
            .is_some()
    );
}

#[test]
fn reconcile_skips_unclassified_when_no_owned_default() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let ingress = make_ingress(
        "default",
        Some("example.com"),
        "/",
        "Prefix",
        "svc",
        None,
        None,
    );
    let mut builder = RoutingTableBuilder::new();
    IngressReconciler::reconcile(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        None,
        IngressPorts::new(Some(80), None),
        &mut builder,
    );
    assert!(
        builder
            .build()
            .unwrap()
            .route(80, "example.com", "/", &RequestContext::default())
            .is_none()
    );
}

#[test]
fn reconcile_skips_when_owned_set_empty() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let ingress = make_ingress(
        "default",
        Some("example.com"),
        "/",
        "Prefix",
        "svc",
        Some("coxswain"),
        None,
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&[]),
        &mut builder,
    );
    assert!(
        builder
            .build()
            .unwrap()
            .route(80, "example.com", "/", &RequestContext::default())
            .is_none()
    );
}

#[test]
fn reconcile_path_resource_backend_skipped() {
    use k8s_openapi::api::core::v1::TypedLocalObjectReference;

    let store = slice_store(vec![]);
    let ingress = Ingress {
        metadata: ObjectMeta {
            name: Some("test-ingress".to_string()),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        spec: Some(IngressSpec {
            ingress_class_name: Some("coxswain".to_string()),
            rules: Some(vec![IngressRule {
                host: Some("example.com".to_string()),
                http: Some(HTTPIngressRuleValue {
                    paths: vec![HTTPIngressPath {
                        path: Some("/api".to_string()),
                        path_type: "Prefix".to_string(),
                        backend: IngressBackend {
                            service: None,
                            resource: Some(TypedLocalObjectReference {
                                api_group: Some("example.com".to_string()),
                                kind: "StorageBucket".to_string(),
                                name: "my-bucket".to_string(),
                            }),
                        },
                    }],
                }),
            }]),
            ..Default::default()
        }),
        status: None,
    };
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    assert!(
        table
            .route(80, "example.com", "/api", &RequestContext::default())
            .is_none(),
        "Resource backend path rule should not install a route"
    );
}

#[test]
fn reconcile_default_backend_resource_skipped() {
    use k8s_openapi::api::core::v1::TypedLocalObjectReference;

    let store = slice_store(vec![]);
    let ingress = Ingress {
        metadata: ObjectMeta {
            name: Some("test-ingress".to_string()),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        spec: Some(IngressSpec {
            ingress_class_name: Some("coxswain".to_string()),
            rules: None,
            default_backend: Some(IngressBackend {
                service: None,
                resource: Some(TypedLocalObjectReference {
                    api_group: Some("example.com".to_string()),
                    kind: "StorageBucket".to_string(),
                    name: "my-bucket".to_string(),
                }),
            }),
            ..Default::default()
        }),
        status: None,
    };
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    assert!(
        table
            .route(80, "any.host.com", "/", &RequestContext::default())
            .is_none(),
        "Resource defaultBackend should not install a catchall route"
    );
}

#[test]
fn reconcile_field_takes_precedence_over_annotation() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    // field = "coxswain" (owned), annotation = "nginx" (not owned) → should reconcile
    let ingress = make_ingress(
        "default",
        Some("example.com"),
        "/",
        "Prefix",
        "svc",
        Some("coxswain"),
        Some("nginx"),
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    assert!(
        builder
            .build()
            .unwrap()
            .route(80, "example.com", "/", &RequestContext::default())
            .is_some()
    );
}

#[tracing_test::traced_test]
#[test]
fn reconcile_skips_path_without_leading_slash() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let ingress = make_ingress(
        "default",
        Some("example.com"),
        "api/v1",
        "Prefix",
        "svc",
        Some("coxswain"),
        None,
    );
    let mut builder = RoutingTableBuilder::new();
    reconcile_no_default(
        &ingress,
        &store,
        &empty_svc_store(),
        &owned(&["coxswain"]),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let ctx = RequestContext::default();

    assert!(
        table.route(80, "example.com", "/api/v1", &ctx).is_none(),
        "malformed path without leading slash should not install a route"
    );
    assert!(
        logs_contain("does not start with '/'"),
        "expected warning about missing leading slash"
    );
    assert!(
        logs_contain("api/v1"),
        "warning should include the malformed path"
    );
}
