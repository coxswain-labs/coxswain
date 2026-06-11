use super::*;

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
) -> HttpRoute {
    HttpRoute {
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
    table: &coxswain_core::routing::GatewayRoutingTable,
    host: &str,
    path: &str,
) -> std::sync::Arc<[FilterAction]> {
    let empty_hdrs = http::HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);
    match table.find(80, host, path, &ctx) {
        RouteOutcome::Found(_, f, _, _) => f,
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
        crate::gateway_api::RouteResolution {
            listener_info: &no_listener_info(),
            policy_index: &HashMap::new(),
        },
        &mut builder,
    );
    let table = builder.build().unwrap();
    let filter_list = find_filters(&table, "example.com", "/");
    assert_eq!(filter_list.len(), 1);
    match &filter_list[0] {
        FilterAction::RequestHeaderModifier(m) => {
            assert_eq!(m.set.len(), 1);
            assert_eq!(m.set[0].0.as_str(), "x-env");
            assert_eq!(m.set[0].1, "prod");
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
        crate::gateway_api::RouteResolution {
            listener_info: &no_listener_info(),
            policy_index: &HashMap::new(),
        },
        &mut builder,
    );
    let table = builder.build().unwrap();
    let filter_list = find_filters(&table, "example.com", "/");
    assert_eq!(filter_list.len(), 1);
    match &filter_list[0] {
        FilterAction::ResponseHeaderModifier(m) => {
            assert_eq!(m.add.len(), 1);
            assert_eq!(m.add[0].0.as_str(), "x-served-by");
            assert_eq!(m.add[0].1, "coxswain");
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
        crate::gateway_api::RouteResolution {
            listener_info: &no_listener_info(),
            policy_index: &HashMap::new(),
        },
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
        crate::gateway_api::RouteResolution {
            listener_info: &no_listener_info(),
            policy_index: &HashMap::new(),
        },
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
