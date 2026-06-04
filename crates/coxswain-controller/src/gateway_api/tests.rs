use super::*;
use coxswain_core::ownership::ObjectKey;
use coxswain_core::routing::RoutingTableBuilder;
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs,
    HttpRouteRulesMatches, HttpRouteRulesMatchesHeaders, HttpRouteRulesMatchesHeadersType,
    HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesPath, HttpRouteRulesMatchesPathType,
    HttpRouteRulesMatchesQueryParams, HttpRouteRulesMatchesQueryParamsType, HttpRouteSpec,
};
use http::{HeaderMap, HeaderName, Method};
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointSlice};
use kube::api::ObjectMeta;
use kube::runtime::watcher;
use std::collections::BTreeMap;

fn make_slice(ns: &str, svc: &str, ip: &str) -> EndpointSlice {
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
                ready: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }],
        ports: None,
    }
}

fn slice_store(slices: Vec<EndpointSlice>) -> reflector::Store<EndpointSlice> {
    let mut writer = reflector::store::Writer::<EndpointSlice>::default();
    for slice in slices {
        writer.apply_watcher_event(&watcher::Event::Apply(slice));
    }
    writer.as_reader()
}

fn empty_svc_store() -> reflector::Store<Service> {
    reflector::store::Writer::<Service>::default().as_reader()
}

fn owned(pairs: &[(&str, &str)]) -> HashSet<ObjectKey> {
    pairs
        .iter()
        .map(|(ns, name)| ObjectKey::new(*ns, *name))
        .collect()
}

/// Default owned set used by tests that exercise routing logic (not filtering).
fn default_owned() -> HashSet<ObjectKey> {
    owned(&[("default", "gw")])
}

/// Empty listener-hostname map for tests that don't exercise hostname scoping.
fn no_listeners() -> HashMap<ListenerKey, String> {
    HashMap::new()
}

/// Default parent refs pointing to the Gateway in `default_owned`.
fn default_parents() -> Option<Vec<HttpRouteParentRefs>> {
    Some(vec![HttpRouteParentRefs {
        name: "gw".to_string(),
        namespace: Some("default".to_string()),
        ..Default::default()
    }])
}

fn make_route(
    ns: &str,
    hostnames: &[&str],
    matches: Option<Vec<HttpRouteRulesMatches>>,
    svc: &str,
) -> HTTPRoute {
    HTTPRoute {
        metadata: ObjectMeta {
            name: Some("route".to_string()),
            namespace: Some(ns.to_string()),
            ..Default::default()
        },
        spec: HttpRouteSpec {
            parent_refs: default_parents(),
            hostnames: if hostnames.is_empty() {
                None
            } else {
                Some(hostnames.iter().map(|h| h.to_string()).collect())
            },
            rules: Some(vec![HttpRouteRules {
                backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                    name: svc.to_string(),
                    port: Some(80),
                    ..Default::default()
                }]),
                matches,
                ..Default::default()
            }]),
        },
        ..Default::default()
    }
}

fn path_match(path: &str, kind: HttpRouteRulesMatchesPathType) -> HttpRouteRulesMatches {
    HttpRouteRulesMatches {
        path: Some(HttpRouteRulesMatchesPath {
            r#type: Some(kind),
            value: Some(path.to_string()),
        }),
        ..Default::default()
    }
}

fn header_exact_match(path: &str, header_name: &str, header_value: &str) -> HttpRouteRulesMatches {
    HttpRouteRulesMatches {
        path: Some(HttpRouteRulesMatchesPath {
            r#type: Some(HttpRouteRulesMatchesPathType::PathPrefix),
            value: Some(path.to_string()),
        }),
        headers: Some(vec![HttpRouteRulesMatchesHeaders {
            name: header_name.to_string(),
            value: header_value.to_string(),
            r#type: Some(HttpRouteRulesMatchesHeadersType::Exact),
        }]),
        ..Default::default()
    }
}

fn header_regex_match(path: &str, header_name: &str, pattern: &str) -> HttpRouteRulesMatches {
    HttpRouteRulesMatches {
        path: Some(HttpRouteRulesMatchesPath {
            r#type: Some(HttpRouteRulesMatchesPathType::PathPrefix),
            value: Some(path.to_string()),
        }),
        headers: Some(vec![HttpRouteRulesMatchesHeaders {
            name: header_name.to_string(),
            value: pattern.to_string(),
            r#type: Some(HttpRouteRulesMatchesHeadersType::RegularExpression),
        }]),
        ..Default::default()
    }
}

fn method_match(path: &str, method: HttpRouteRulesMatchesMethod) -> HttpRouteRulesMatches {
    HttpRouteRulesMatches {
        path: Some(HttpRouteRulesMatchesPath {
            r#type: Some(HttpRouteRulesMatchesPathType::PathPrefix),
            value: Some(path.to_string()),
        }),
        method: Some(method),
        ..Default::default()
    }
}

fn query_exact_match(path: &str, param: &str, value: &str) -> HttpRouteRulesMatches {
    HttpRouteRulesMatches {
        path: Some(HttpRouteRulesMatchesPath {
            r#type: Some(HttpRouteRulesMatchesPathType::PathPrefix),
            value: Some(path.to_string()),
        }),
        query_params: Some(vec![HttpRouteRulesMatchesQueryParams {
            name: param.to_string(),
            value: value.to_string(),
            r#type: Some(HttpRouteRulesMatchesQueryParamsType::Exact),
        }]),
        ..Default::default()
    }
}

fn ctx_with<'a>(
    method: &'a Method,
    headers: &'a HeaderMap,
    query: Option<&'a str>,
) -> coxswain_core::routing::RequestContext<'a> {
    coxswain_core::routing::RequestContext {
        method,
        headers,
        query,
    }
}

fn headers_from(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut m = HeaderMap::new();
    for (k, v) in pairs {
        m.insert(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    m
}

// ── Original path-matching tests (unchanged behaviour) ────────────────────

#[test]
fn reconcile_exact_path() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route(
        "default",
        &["example.com"],
        Some(vec![path_match(
            "/api",
            HttpRouteRulesMatchesPathType::Exact,
        )]),
        "svc",
    );
    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let empty_hdrs = HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

    assert!(table.route("example.com", "/api", &ctx).is_some());
    assert!(table.route("example.com", "/api/users", &ctx).is_none());
}

#[test]
fn reconcile_prefix_path() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route(
        "default",
        &["example.com"],
        Some(vec![path_match(
            "/api",
            HttpRouteRulesMatchesPathType::PathPrefix,
        )]),
        "svc",
    );
    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let empty_hdrs = HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

    assert!(table.route("example.com", "/api", &ctx).is_some());
    assert!(table.route("example.com", "/api/users", &ctx).is_some());
}

#[test]
fn reconcile_regex_path() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route(
        "default",
        &["example.com"],
        Some(vec![path_match(
            r"/item/\d+",
            HttpRouteRulesMatchesPathType::RegularExpression,
        )]),
        "svc",
    );
    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let empty_hdrs = HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

    assert!(table.route("example.com", "/item/42", &ctx).is_some());
    assert!(table.route("example.com", "/item/abc", &ctx).is_none());
}

#[test]
fn reconcile_no_matches_defaults_to_root_prefix() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route("default", &["example.com"], None, "svc");
    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let empty_hdrs = HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

    assert!(table.route("example.com", "/anything", &ctx).is_some());
}

#[test]
fn reconcile_skips_route_without_owned_parent() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route("default", &["example.com"], None, "svc");
    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &owned(&[("other", "gw")]),
        &grants,
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let empty_hdrs = HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

    assert!(table.route("example.com", "/", &ctx).is_none());
}

// ── New predicate tests ────────────────────────────────────────────────────

#[test]
fn reconcile_header_exact_routes_to_correct_backend() {
    let store = slice_store(vec![
        make_slice("default", "svc-a", "10.0.0.1"),
        make_slice("default", "svc-b", "10.0.0.2"),
    ]);

    // Two rules: same path, different header → different backends.
    let route = HTTPRoute {
        metadata: ObjectMeta {
            name: Some("route".to_string()),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        spec: HttpRouteSpec {
            parent_refs: default_parents(),
            hostnames: Some(vec!["example.com".to_string()]),
            rules: Some(vec![
                HttpRouteRules {
                    matches: Some(vec![header_exact_match("/", "x-tenant", "a")]),
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc-a".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
                HttpRouteRules {
                    matches: Some(vec![header_exact_match("/", "x-tenant", "b")]),
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc-b".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
            ]),
        },
        ..Default::default()
    };

    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();

    let hdrs_a = headers_from(&[("x-tenant", "a")]);
    let hdrs_b = headers_from(&[("x-tenant", "b")]);
    let ctx_a = ctx_with(&Method::GET, &hdrs_a, None);
    let ctx_b = ctx_with(&Method::GET, &hdrs_b, None);

    assert_eq!(
        table.route("example.com", "/", &ctx_a).unwrap().name,
        "default/svc-a"
    );
    assert_eq!(
        table.route("example.com", "/", &ctx_b).unwrap().name,
        "default/svc-b"
    );
}

#[test]
fn reconcile_header_regex_routes_to_correct_backend() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route(
        "default",
        &["example.com"],
        Some(vec![header_regex_match("/", "x-version", r"^v\d+$")]),
        "svc",
    );
    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();

    let hdrs_ok = headers_from(&[("x-version", "v42")]);
    let hdrs_bad = headers_from(&[("x-version", "beta")]);
    let ctx_ok = ctx_with(&Method::GET, &hdrs_ok, None);
    let ctx_bad = ctx_with(&Method::GET, &hdrs_bad, None);

    assert!(table.route("example.com", "/", &ctx_ok).is_some());
    assert!(table.route("example.com", "/", &ctx_bad).is_none());
}

#[test]
fn reconcile_method_routes_to_correct_backend() {
    let store = slice_store(vec![
        make_slice("default", "svc-get", "10.0.0.1"),
        make_slice("default", "svc-post", "10.0.0.2"),
    ]);

    let route = HTTPRoute {
        metadata: ObjectMeta {
            name: Some("route".to_string()),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        spec: HttpRouteSpec {
            parent_refs: default_parents(),
            hostnames: Some(vec!["example.com".to_string()]),
            rules: Some(vec![
                HttpRouteRules {
                    matches: Some(vec![method_match("/", HttpRouteRulesMatchesMethod::Get)]),
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc-get".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
                HttpRouteRules {
                    matches: Some(vec![method_match("/", HttpRouteRulesMatchesMethod::Post)]),
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc-post".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
            ]),
        },
        ..Default::default()
    };

    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();

    let h = HeaderMap::new();
    let ctx_get = ctx_with(&Method::GET, &h, None);
    let ctx_post = ctx_with(&Method::POST, &h, None);

    assert_eq!(
        table.route("example.com", "/", &ctx_get).unwrap().name,
        "default/svc-get"
    );
    assert_eq!(
        table.route("example.com", "/", &ctx_post).unwrap().name,
        "default/svc-post"
    );
}

#[test]
fn reconcile_query_param_routes_to_correct_backend() {
    let store = slice_store(vec![
        make_slice("default", "svc-v1", "10.0.0.1"),
        make_slice("default", "svc-v2", "10.0.0.2"),
    ]);

    let route = HTTPRoute {
        metadata: ObjectMeta {
            name: Some("route".to_string()),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        spec: HttpRouteSpec {
            parent_refs: default_parents(),
            hostnames: Some(vec!["example.com".to_string()]),
            rules: Some(vec![
                HttpRouteRules {
                    matches: Some(vec![query_exact_match("/", "version", "v1")]),
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc-v1".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
                HttpRouteRules {
                    matches: Some(vec![query_exact_match("/", "version", "v2")]),
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc-v2".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
            ]),
        },
        ..Default::default()
    };

    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();

    let h = HeaderMap::new();
    let ctx_v1 = ctx_with(&Method::GET, &h, Some("version=v1"));
    let ctx_v2 = ctx_with(&Method::GET, &h, Some("version=v2"));

    assert_eq!(
        table.route("example.com", "/", &ctx_v1).unwrap().name,
        "default/svc-v1"
    );
    assert_eq!(
        table.route("example.com", "/", &ctx_v2).unwrap().name,
        "default/svc-v2"
    );
}

#[test]
fn reconcile_invalid_regex_skips_match_entry() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route(
        "default",
        &["example.com"],
        Some(vec![
            // invalid regex
            HttpRouteRulesMatches {
                headers: Some(vec![HttpRouteRulesMatchesHeaders {
                    name: "x-bad".to_string(),
                    value: "[invalid".to_string(),
                    r#type: Some(HttpRouteRulesMatchesHeadersType::RegularExpression),
                }]),
                ..Default::default()
            },
            // valid path-only fallback
            path_match("/", HttpRouteRulesMatchesPathType::PathPrefix),
        ]),
        "svc",
    );
    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();

    let empty_hdrs = HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);
    assert!(table.route("example.com", "/", &ctx).is_some());
}

#[test]
fn reconcile_header_name_dedup_keeps_first() {
    let m = HttpRouteRulesMatches {
        headers: Some(vec![
            HttpRouteRulesMatchesHeaders {
                name: "X-Tenant".to_string(),
                value: "first".to_string(),
                r#type: Some(HttpRouteRulesMatchesHeadersType::Exact),
            },
            HttpRouteRulesMatchesHeaders {
                name: "x-tenant".to_string(), // same header, different case
                value: "second".to_string(),
                r#type: Some(HttpRouteRulesMatchesHeadersType::Exact),
            },
        ]),
        ..Default::default()
    };
    let predicates = super::filters::build_predicates(&m).unwrap();
    assert_eq!(predicates.headers.len(), 1);
    match &predicates.headers[0].matcher {
        coxswain_core::routing::ValueMatch::Exact(v) => assert_eq!(v, "first"),
        _ => panic!("expected exact matcher"),
    }
}

// ── Filter tests ────────────────────────────────────────────────────────────

use coxswain_core::routing::{FilterAction, PathModifier, RouteOutcome};
use gateway_api::apis::standard::httproutes::{
    HttpRouteRulesFilters, HttpRouteRulesFiltersRequestHeaderModifier,
    HttpRouteRulesFiltersRequestHeaderModifierSet, HttpRouteRulesFiltersRequestRedirect,
    HttpRouteRulesFiltersResponseHeaderModifier, HttpRouteRulesFiltersResponseHeaderModifierAdd,
    HttpRouteRulesFiltersType, HttpRouteRulesFiltersUrlRewrite,
    HttpRouteRulesFiltersUrlRewritePath, HttpRouteRulesFiltersUrlRewritePathType,
};

fn make_route_with_filters(
    ns: &str,
    hostname: &str,
    path: &str,
    path_type: HttpRouteRulesMatchesPathType,
    svc: &str,
    filters: Vec<HttpRouteRulesFilters>,
) -> HTTPRoute {
    HTTPRoute {
        metadata: ObjectMeta {
            name: Some("route".to_string()),
            namespace: Some(ns.to_string()),
            ..Default::default()
        },
        spec: HttpRouteSpec {
            parent_refs: default_parents(),
            hostnames: Some(vec![hostname.to_string()]),
            rules: Some(vec![HttpRouteRules {
                backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                    name: svc.to_string(),
                    port: Some(80),
                    ..Default::default()
                }]),
                matches: Some(vec![path_match(path, path_type)]),
                filters: Some(filters),
                ..Default::default()
            }]),
        },
        ..Default::default()
    }
}

fn find_filters(
    table: &coxswain_core::routing::RoutingTable,
    host: &str,
    path: &str,
) -> std::sync::Arc<[FilterAction]> {
    let empty_hdrs = http::HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);
    match table.find(host, path, &ctx) {
        RouteOutcome::Found(_, f, _) => f,
        _ => panic!("expected Found"),
    }
}

#[test]
fn reconcile_request_header_modifier_stored() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route_with_filters(
        "default",
        "example.com",
        "/",
        HttpRouteRulesMatchesPathType::PathPrefix,
        "svc",
        vec![HttpRouteRulesFilters {
            r#type: HttpRouteRulesFiltersType::RequestHeaderModifier,
            request_header_modifier: Some(HttpRouteRulesFiltersRequestHeaderModifier {
                set: Some(vec![HttpRouteRulesFiltersRequestHeaderModifierSet {
                    name: "X-Env".to_string(),
                    value: "prod".to_string(),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }],
    );
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &HashSet::new(),
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let filter_list = find_filters(&table, "example.com", "/");
    assert_eq!(filter_list.len(), 1);
    match &filter_list[0] {
        FilterAction::RequestHeaderModifier(m) => {
            assert_eq!(m.set, vec![("X-Env".to_string(), "prod".to_string())]);
        }
        _ => panic!("expected RequestHeaderModifier"),
    }
}

#[test]
fn reconcile_response_header_modifier_stored() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route_with_filters(
        "default",
        "example.com",
        "/",
        HttpRouteRulesMatchesPathType::PathPrefix,
        "svc",
        vec![HttpRouteRulesFilters {
            r#type: HttpRouteRulesFiltersType::ResponseHeaderModifier,
            response_header_modifier: Some(HttpRouteRulesFiltersResponseHeaderModifier {
                add: Some(vec![HttpRouteRulesFiltersResponseHeaderModifierAdd {
                    name: "X-Served-By".to_string(),
                    value: "coxswain".to_string(),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }],
    );
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &HashSet::new(),
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let filter_list = find_filters(&table, "example.com", "/");
    assert_eq!(filter_list.len(), 1);
    match &filter_list[0] {
        FilterAction::ResponseHeaderModifier(m) => {
            assert_eq!(
                m.add,
                vec![("X-Served-By".to_string(), "coxswain".to_string())]
            );
        }
        _ => panic!("expected ResponseHeaderModifier"),
    }
}

#[test]
fn reconcile_request_redirect_stored() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route_with_filters(
        "default",
        "example.com",
        "/old",
        HttpRouteRulesMatchesPathType::PathPrefix,
        "svc",
        vec![HttpRouteRulesFilters {
            r#type: HttpRouteRulesFiltersType::RequestRedirect,
            request_redirect: Some(HttpRouteRulesFiltersRequestRedirect {
                hostname: Some("new.example.com".to_string()),
                status_code: Some(301),
                ..Default::default()
            }),
            ..Default::default()
        }],
    );
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &HashSet::new(),
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let filter_list = find_filters(&table, "example.com", "/old");
    assert_eq!(filter_list.len(), 1);
    match &filter_list[0] {
        FilterAction::RequestRedirect {
            hostname,
            status_code,
            ..
        } => {
            assert_eq!(hostname.as_deref(), Some("new.example.com"));
            assert_eq!(*status_code, 301);
        }
        _ => panic!("expected RequestRedirect"),
    }
}

#[test]
fn reconcile_url_rewrite_replace_prefix_stored() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route_with_filters(
        "default",
        "example.com",
        "/api",
        HttpRouteRulesMatchesPathType::PathPrefix,
        "svc",
        vec![HttpRouteRulesFilters {
            r#type: HttpRouteRulesFiltersType::UrlRewrite,
            url_rewrite: Some(HttpRouteRulesFiltersUrlRewrite {
                path: Some(HttpRouteRulesFiltersUrlRewritePath {
                    r#type: HttpRouteRulesFiltersUrlRewritePathType::ReplacePrefixMatch,
                    replace_prefix_match: Some("/v3".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }],
    );
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &HashSet::new(),
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let filter_list = find_filters(&table, "example.com", "/api/users");
    assert_eq!(filter_list.len(), 1);
    match &filter_list[0] {
        FilterAction::UrlRewrite {
            hostname,
            path:
                Some(PathModifier::ReplacePrefixMatch {
                    prefix,
                    replacement,
                }),
        } => {
            assert!(hostname.is_none());
            assert_eq!(prefix, "/api");
            assert_eq!(replacement, "/v3");
        }
        _ => panic!("expected UrlRewrite with ReplacePrefixMatch"),
    }
}

// ── Timeout tests ────────────────────────────────────────────────────────────

use gateway_api::apis::standard::httproutes::HttpRouteRulesTimeouts;
use std::time::Duration;

fn find_timeouts(
    table: &coxswain_core::routing::RoutingTable,
    host: &str,
    path: &str,
) -> coxswain_core::routing::RouteTimeouts {
    let empty_hdrs = http::HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);
    match table.find(host, path, &ctx) {
        RouteOutcome::Found(_, _, t) => t,
        _ => panic!("expected Found"),
    }
}

#[test]
fn parse_gateway_duration_parses_common_values() {
    assert_eq!(
        super::timeouts::parse_gateway_duration("10s"),
        Some(Duration::from_secs(10))
    );
    assert_eq!(
        super::timeouts::parse_gateway_duration("500ms"),
        Some(Duration::from_millis(500))
    );
    assert_eq!(
        super::timeouts::parse_gateway_duration("1m"),
        Some(Duration::from_secs(60))
    );
    assert_eq!(
        super::timeouts::parse_gateway_duration("2h45m"),
        Some(Duration::from_secs(2 * 3600 + 45 * 60))
    );
}

#[test]
fn parse_gateway_duration_zero_returns_none() {
    assert_eq!(super::timeouts::parse_gateway_duration("0s"), None);
    assert_eq!(super::timeouts::parse_gateway_duration("0"), None);
    assert_eq!(super::timeouts::parse_gateway_duration(""), None);
}

#[test]
fn parse_gateway_duration_invalid_returns_none() {
    assert_eq!(super::timeouts::parse_gateway_duration("10x"), None);
    assert_eq!(super::timeouts::parse_gateway_duration("abc"), None);
}

#[test]
fn reconcile_timeouts_stored_and_round_trip() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);

    let route = HTTPRoute {
        metadata: ObjectMeta {
            name: Some("route".to_string()),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        spec: gateway_api::apis::standard::httproutes::HttpRouteSpec {
            parent_refs: default_parents(),
            hostnames: Some(vec!["example.com".to_string()]),
            rules: Some(vec![
                gateway_api::apis::standard::httproutes::HttpRouteRules {
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    timeouts: Some(HttpRouteRulesTimeouts {
                        request: Some("10s".to_string()),
                        backend_request: Some("2s".to_string()),
                    }),
                    ..Default::default()
                },
            ]),
        },
        ..Default::default()
    };

    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let t = find_timeouts(&table, "example.com", "/");
    assert_eq!(t.request, Some(Duration::from_secs(10)));
    assert_eq!(t.backend_request, Some(Duration::from_secs(2)));
}

// ── Listener isolation tests ──────────────────────────────────────────────────

fn make_listener_hostnames(
    gw_ns: &str,
    gw_name: &str,
    listeners: &[(&str, &str)],
) -> HashMap<ListenerKey, String> {
    listeners
        .iter()
        .map(|(ln, h)| (ListenerKey::new(gw_ns, gw_name, *ln), h.to_string()))
        .collect()
}

#[test]
fn listener_isolation_empty_listener_route_not_accessible_via_more_specific_listener() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route_with_hostnames_and_parent(
        "default",
        &["bar.com", "*.example.com"],
        "gw",
        Some("empty-listener"),
    );
    let listeners = make_listener_hostnames(
        "default",
        "gw",
        &[
            ("empty-listener", ""),
            ("specific-listener", "*.example.com"),
        ],
    );
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &HashSet::new(),
        &listeners,
        &mut builder,
    );
    let table = builder.build().unwrap();
    assert!(
        table.route("bar.com", "/", &ctx_get()).is_some(),
        "bar.com should be routable"
    );
    assert!(
        table.route("bar.example.com", "/", &ctx_get()).is_none(),
        "bar.example.com should not leak from the empty-hostname listener"
    );
}

fn make_route_with_hostnames_and_parent(
    ns: &str,
    hostnames: &[&str],
    gw_name: &str,
    section_name: Option<&str>,
) -> HTTPRoute {
    use gateway_api::apis::standard::httproutes::HttpRouteSpec;
    HTTPRoute {
        metadata: kube::api::ObjectMeta {
            name: Some("test-route".to_string()),
            namespace: Some(ns.to_string()),
            ..Default::default()
        },
        spec: HttpRouteSpec {
            parent_refs: Some(vec![HttpRouteParentRefs {
                name: gw_name.to_string(),
                namespace: Some(ns.to_string()),
                section_name: section_name.map(str::to_string),
                ..Default::default()
            }]),
            hostnames: Some(hostnames.iter().map(|h| h.to_string()).collect()),
            rules: Some(vec![make_simple_rule("svc")]),
        },
        status: None,
    }
}

fn make_simple_rule(svc: &str) -> gateway_api::apis::standard::httproutes::HttpRouteRules {
    use gateway_api::apis::standard::httproutes::{HttpRouteRules, HttpRouteRulesBackendRefs};
    HttpRouteRules {
        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
            name: svc.to_string(),
            port: Some(8080),
            ..Default::default()
        }]),
        ..Default::default()
    }
}

fn ctx_get() -> coxswain_core::routing::RequestContext<'static> {
    static METHOD: std::sync::LazyLock<Method> = std::sync::LazyLock::new(|| Method::GET);
    static HDRS: std::sync::LazyLock<http::HeaderMap> =
        std::sync::LazyLock::new(http::HeaderMap::new);
    coxswain_core::routing::RequestContext {
        method: &METHOD,
        headers: &HDRS,
        query: None,
    }
}

#[test]
fn reconcile_timeouts_missing_field_falls_back_to_none() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route("default", &["example.com"], None, "svc");
    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let t = find_timeouts(&table, "example.com", "/");
    assert!(t.request.is_none());
    assert!(t.backend_request.is_none());
}

// ── Weighted backendRefs (issue #17) ─────────────────────────────────────────

fn weighted_route(ns: &str, refs: &[(&str, Option<i32>)]) -> HTTPRoute {
    HTTPRoute {
        metadata: ObjectMeta {
            name: Some("route".to_string()),
            namespace: Some(ns.to_string()),
            ..Default::default()
        },
        spec: HttpRouteSpec {
            parent_refs: default_parents(),
            hostnames: Some(vec!["example.com".to_string()]),
            rules: Some(vec![HttpRouteRules {
                backend_refs: Some(
                    refs.iter()
                        .map(|(svc, w)| HttpRouteRulesBackendRefs {
                            name: svc.to_string(),
                            port: Some(80),
                            weight: *w,
                            ..Default::default()
                        })
                        .collect(),
                ),
                ..Default::default()
            }]),
        },
        ..Default::default()
    }
}

#[test]
fn weighted_backends_80_20_split() {
    let a_ip = "10.0.0.1";
    let b_ip = "10.0.1.1";
    let store = slice_store(vec![
        make_slice("default", "svc-a", a_ip),
        make_slice("default", "svc-b", b_ip),
    ]);
    let route = weighted_route("default", &[("svc-a", Some(4)), ("svc-b", Some(1))]);
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &HashSet::new(),
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let upstream = table.route("example.com", "/", &ctx_get()).unwrap();

    let a: std::net::SocketAddr = format!("{a_ip}:80").parse().unwrap();
    let n = 1000usize;
    let mut a_count = 0usize;
    for _ in 0..n {
        let addr = upstream.next_endpoint().unwrap();
        if addr == a {
            a_count += 1;
        }
    }
    let ratio = a_count as f64 / n as f64;
    assert!(
        (0.75..=0.85).contains(&ratio),
        "backend-A ratio {ratio:.3} expected 0.75–0.85"
    );
}

#[test]
fn zero_weight_backend_gets_no_traffic() {
    let a_ip = "10.0.0.1";
    let b_ip = "10.0.1.1";
    let store = slice_store(vec![
        make_slice("default", "svc-a", a_ip),
        make_slice("default", "svc-b", b_ip),
    ]);
    let route = weighted_route("default", &[("svc-a", Some(0)), ("svc-b", Some(1))]);
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &HashSet::new(),
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let upstream = table.route("example.com", "/", &ctx_get()).unwrap();

    let b: std::net::SocketAddr = format!("{b_ip}:80").parse().unwrap();
    for _ in 0..100 {
        assert_eq!(
            upstream.next_endpoint().unwrap(),
            b,
            "weight-0 backend should receive no traffic"
        );
    }
}

#[test]
fn all_zero_weights_installs_error_route() {
    let store = slice_store(vec![
        make_slice("default", "svc-a", "10.0.0.1"),
        make_slice("default", "svc-b", "10.0.1.1"),
    ]);
    let route = weighted_route("default", &[("svc-a", Some(0)), ("svc-b", Some(0))]);
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &HashSet::new(),
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    // All weights zero → empty upstream → error_status = Some(500) → RouteOutcome::Error
    let outcome = table.find("example.com", "/", &ctx_get());
    assert!(
        matches!(outcome, coxswain_core::routing::RouteOutcome::Error(500)),
        "all-zero-weight rule must resolve to Error(500)"
    );
}

#[test]
fn absent_weight_defaults_to_1() {
    let a_ip = "10.0.0.1";
    let b_ip = "10.0.1.1";
    let store = slice_store(vec![
        make_slice("default", "svc-a", a_ip),
        make_slice("default", "svc-b", b_ip),
    ]);
    // weight field is None — should default to 1 each → roughly equal split
    let route = weighted_route("default", &[("svc-a", None), ("svc-b", None)]);
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &HashSet::new(),
        &no_listeners(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let upstream = table.route("example.com", "/", &ctx_get()).unwrap();

    let a: std::net::SocketAddr = format!("{a_ip}:80").parse().unwrap();
    let b: std::net::SocketAddr = format!("{b_ip}:80").parse().unwrap();
    let results: Vec<_> = (0..4).map(|_| upstream.next_endpoint().unwrap()).collect();
    // With equal weights, slots = [0, 1]; cycling: a, b, a, b
    assert_eq!(results, [a, b, a, b]);
}
