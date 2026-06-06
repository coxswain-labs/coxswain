mod bindings;
mod filters;
mod hostnames;
mod reconcile;
mod status;
mod timeouts;

use super::*;
use crate::gw_types::HttpRoute;
use crate::gw_types::v::httproutes::{
    HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs, HttpRouteRulesMatches,
    HttpRouteRulesMatchesHeaders, HttpRouteRulesMatchesHeadersType, HttpRouteRulesMatchesMethod,
    HttpRouteRulesMatchesPath, HttpRouteRulesMatchesPathType, HttpRouteRulesMatchesQueryParams,
    HttpRouteRulesMatchesQueryParamsType, HttpRouteSpec,
};
use crate::keys::ListenerKey;
use coxswain_core::ownership::ObjectKey;
use coxswain_core::routing::RoutingTableBuilder;
use http::{HeaderMap, HeaderName, Method};
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointSlice};
use kube::api::ObjectMeta;
use kube::runtime::watcher;
use std::collections::{BTreeMap, HashMap, HashSet};

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

/// Empty listener info map for tests that don't exercise hostname or port scoping.
fn no_listener_info() -> HashMap<ListenerKey, ListenerBinding> {
    HashMap::new()
}

/// Build a listener info map from `(listener_name, hostname, port)` triples.
fn make_listener_info(
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
                },
            )
        })
        .collect()
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

fn make_route_with_hostnames_and_parent(
    ns: &str,
    hostnames: &[&str],
    gw_name: &str,
    section_name: Option<&str>,
) -> HttpRoute {
    use gateway_api::apis::standard::httproutes::HttpRouteSpec;
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

fn make_route_with_parent_port(
    ns: &str,
    hostnames: &[&str],
    gw_name: &str,
    port: Option<i32>,
) -> HttpRoute {
    use gateway_api::apis::standard::httproutes::HttpRouteSpec;
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
