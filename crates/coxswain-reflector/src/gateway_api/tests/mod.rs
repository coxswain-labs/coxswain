use super::*;
pub(super) use crate::gateway_api::GatewayApiReconciler;
pub(super) use crate::gw_types::HttpRoute;
pub(super) use crate::gw_types::v::httproutes::{
    HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs, HttpRouteRulesMatches,
    HttpRouteRulesMatchesHeaders, HttpRouteRulesMatchesHeadersType, HttpRouteRulesMatchesMethod,
    HttpRouteRulesMatchesPath, HttpRouteRulesMatchesPathType, HttpRouteRulesMatchesQueryParams,
    HttpRouteRulesMatchesQueryParamsType, HttpRouteSpec,
};
pub(super) use crate::keys::ListenerKey;
pub(super) use coxswain_core::ownership::ObjectKey;
pub(super) use coxswain_core::routing::RoutingTableBuilder;
pub(super) use http::{HeaderMap, HeaderName, Method};
pub(super) use kube::api::ObjectMeta;
pub(super) use std::collections::{HashMap, HashSet};

pub(super) use crate::tests::fixtures::{
    empty_basic_auth_store, empty_compression_store, empty_external_auth_store,
    empty_ip_access_store, empty_jwks_cache, empty_jwt_auth_store, empty_path_rewrite_store,
    empty_rate_limit_store, empty_request_size_limit_store, empty_retry_policy_store,
    empty_secret_store, empty_svc_store, endpoint_cache, make_basic_auth_store,
    make_compression_store, make_ip_access_store, make_jwt_auth_store,
    make_request_size_limit_store, make_secret_store, make_slice,
};

pub(super) fn owned(pairs: &[(&str, &str)]) -> HashSet<ObjectKey> {
    pairs
        .iter()
        .map(|(ns, name)| ObjectKey::new(*ns, *name))
        .collect()
}

/// Default owned set used by tests that exercise routing logic (not filtering).
pub(super) fn default_owned() -> HashSet<ObjectKey> {
    owned(&[("default", "gw")])
}

/// Empty listener info map for tests that don't exercise hostname or port scoping.
pub(super) fn no_listener_info() -> HashMap<ListenerKey, ListenerBinding> {
    HashMap::new()
}

/// Build a listener info map from `(listener_name, hostname, port)` triples.
pub(super) fn make_listener_info(
    gw_ns: &str,
    gw_name: &str,
    listeners: &[(&str, &str, u16)],
) -> HashMap<ListenerKey, ListenerBinding> {
    listeners
        .iter()
        .map(|(ln, hostname, port)| {
            (
                ListenerKey::new(gw_ns, gw_name, *ln),
                ListenerBinding {
                    hostname: hostname.to_string(),
                    port: *port,
                    // Tests don't allocate internal ports; bind == spec.
                    bind_port: *port,
                    // Helper-built listeners admit any namespace; tests that exercise
                    // namespace scoping construct bindings explicitly.
                    route_namespaces: coxswain_core::listener_status::RouteNamespaceSet::All,
                },
            )
        })
        .collect()
}

/// Default parent refs pointing to the Gateway in `default_owned`.
pub(super) fn default_parents() -> Option<Vec<HttpRouteParentRefs>> {
    Some(vec![HttpRouteParentRefs {
        name: "gw".to_string(),
        namespace: Some("default".to_string()),
        ..Default::default()
    }])
}

pub(super) fn make_route(
    ns: &str,
    hostnames: &[&str],
    matches: Option<Vec<HttpRouteRulesMatches>>,
    svc: &str,
) -> HttpRoute {
    HttpRoute {
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

pub(super) fn path_match(path: &str, kind: HttpRouteRulesMatchesPathType) -> HttpRouteRulesMatches {
    HttpRouteRulesMatches {
        path: Some(HttpRouteRulesMatchesPath {
            r#type: Some(kind),
            value: Some(path.to_string()),
        }),
        ..Default::default()
    }
}

pub(super) fn header_exact_match(
    path: &str,
    header_name: &str,
    header_value: &str,
) -> HttpRouteRulesMatches {
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

pub(super) fn header_regex_match(
    path: &str,
    header_name: &str,
    pattern: &str,
) -> HttpRouteRulesMatches {
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

pub(super) fn method_match(
    path: &str,
    method: HttpRouteRulesMatchesMethod,
) -> HttpRouteRulesMatches {
    HttpRouteRulesMatches {
        path: Some(HttpRouteRulesMatchesPath {
            r#type: Some(HttpRouteRulesMatchesPathType::PathPrefix),
            value: Some(path.to_string()),
        }),
        method: Some(method),
        ..Default::default()
    }
}

pub(super) fn query_exact_match(path: &str, param: &str, value: &str) -> HttpRouteRulesMatches {
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

pub(super) fn ctx_with<'a>(
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

pub(super) fn headers_from(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut m = HeaderMap::new();
    for (k, v) in pairs {
        m.insert(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    m
}

pub(super) fn make_route_with_hostnames_and_parent(
    ns: &str,
    hostnames: &[&str],
    gw_name: &str,
    section_name: Option<&str>,
) -> HttpRoute {
    pub(super) use crate::gw_types::v::httproutes::HttpRouteSpec;
    HttpRoute {
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

pub(super) fn make_route_with_parent_port(
    ns: &str,
    hostnames: &[&str],
    gw_name: &str,
    port: Option<i32>,
) -> HttpRoute {
    pub(super) use crate::gw_types::v::httproutes::HttpRouteSpec;
    HttpRoute {
        metadata: kube::api::ObjectMeta {
            name: Some("test-route".to_string()),
            namespace: Some(ns.to_string()),
            ..Default::default()
        },
        spec: HttpRouteSpec {
            parent_refs: Some(vec![HttpRouteParentRefs {
                name: gw_name.to_string(),
                namespace: Some(ns.to_string()),
                port,
                ..Default::default()
            }]),
            hostnames: Some(hostnames.iter().map(|h| h.to_string()).collect()),
            rules: Some(vec![make_simple_rule("svc")]),
        },
        status: None,
    }
}

pub(super) fn make_simple_rule(svc: &str) -> crate::gw_types::v::httproutes::HttpRouteRules {
    pub(super) use crate::gw_types::v::httproutes::{HttpRouteRules, HttpRouteRulesBackendRefs};
    HttpRouteRules {
        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
            name: svc.to_string(),
            port: Some(8080),
            ..Default::default()
        }]),
        ..Default::default()
    }
}

pub(super) fn ctx_get() -> coxswain_core::routing::RequestContext<'static> {
    static METHOD: std::sync::LazyLock<Method> = std::sync::LazyLock::new(|| Method::GET);
    static HDRS: std::sync::LazyLock<http::HeaderMap> =
        std::sync::LazyLock::new(http::HeaderMap::new);
    coxswain_core::routing::RequestContext {
        method: &METHOD,
        headers: &HDRS,
        query: None,
    }
}
