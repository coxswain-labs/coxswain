//! Computes the `ResolvedRefs` and `Accepted` health for each (HTTPRoute, parent) pair.

use crate::gateway_api::hostnames::hostnames_intersect;
use crate::gw_types::v::gateways::{Gateway, GatewayListenersAllowedRoutesNamespacesFrom};
use crate::gw_types::v::httproutes::{HTTPRoute, HttpRouteRulesFiltersType};
use crate::keys::RouteParentKey;
use crate::tls::{HttpRouteHealthMap, RouteParentHealth};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::reference_grants::{self, ReferenceGrantKey};
use k8s_openapi::api::core::v1::Service;
use kube::runtime::reflector;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

struct ListenerEntry {
    name: String,
    hostname: String,
    allows_all: bool,
    port: u16,
}

/// `(listener_name, hostname, port)` — used by `compute_accepted` once cross-namespace
/// checks are already resolved.
struct ListenerHnEntry {
    name: String,
    hostname: String,
    port: u16,
}

type ListenerHnMap = HashMap<ObjectKey, Vec<ListenerHnEntry>>;

/// Computes `Accepted` and `ResolvedRefs` health for every (route, parent) pair
/// that references an owned gateway. Called during the reconciler's rebuild so the
/// controller can write accurate HTTPRoute status conditions.
pub(super) fn compute_route_health(
    routes: &[Arc<HTTPRoute>],
    gateways: &[Arc<Gateway>],
    owned_gateways: &HashSet<ObjectKey>,
    backend_grants: &HashSet<ReferenceGrantKey>,
    service_store: &reflector::Store<Service>,
) -> HttpRouteHealthMap {
    // Build listener info map: ObjectKey(gw_ns, gw_name) → Vec<ListenerEntry>
    let gw_listeners: HashMap<ObjectKey, Vec<ListenerEntry>> = gateways
        .iter()
        .filter_map(|gw| {
            let ns = gw.metadata.namespace.as_deref()?.to_string();
            let name = gw.metadata.name.as_deref()?.to_string();
            let key = ObjectKey::new(&ns, &name);
            if !owned_gateways.contains(&key) {
                return None;
            }
            let listeners = gw
                .spec
                .listeners
                .iter()
                .map(|l| {
                    let allows_all = l
                        .allowed_routes
                        .as_ref()
                        .and_then(|ar| ar.namespaces.as_ref())
                        .and_then(|ns| ns.from.as_ref())
                        .map(|f| !matches!(f, GatewayListenersAllowedRoutesNamespacesFrom::Same))
                        .unwrap_or(false);
                    ListenerEntry {
                        name: l.name.clone(),
                        hostname: l.hostname.as_deref().unwrap_or("").to_string(),
                        allows_all,
                        port: l.port as u16,
                    }
                })
                .collect();
            Some((key, listeners))
        })
        .collect();

    let mut map = HttpRouteHealthMap::new();

    for route in routes {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let route_name = route.metadata.name.as_deref().unwrap_or("unknown");
        let route_hostnames: Vec<&str> = route
            .spec
            .hostnames
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(String::as_str)
            .collect();

        for pr in route.spec.parent_refs.as_deref().unwrap_or(&[]) {
            let gw_ns = pr.namespace.as_deref().unwrap_or(route_ns);
            let gw_name = pr.name.as_str();
            let gw_key = ObjectKey::new(gw_ns, gw_name);

            if !owned_gateways.contains(&gw_key) {
                continue;
            }

            let section = pr.section_name.as_deref().unwrap_or("").to_string();
            let health_key =
                RouteParentKey::new(route_ns, route_name, gw_ns, gw_name, section.clone());

            // Cross-namespace check: reject routes whose namespace is not allowed by the
            // listener. Default per spec is Same (only same namespace); must be All or
            // Selector to permit cross-namespace parentRefs.
            if gw_ns != route_ns {
                let blocked = gw_listeners.get(&gw_key).is_some_and(|ls| {
                    let relevant: Vec<_> = if section.is_empty() {
                        ls.iter().collect()
                    } else {
                        ls.iter().filter(|l| l.name.as_str() == section).collect()
                    };
                    !relevant.is_empty() && relevant.iter().all(|l| !l.allows_all)
                });
                if blocked {
                    map.insert(
                        health_key,
                        RouteParentHealth {
                            accepted: false,
                            accepted_reason: "NotAllowedByListeners",
                            resolved_refs: true,
                            resolved_refs_reason: "ResolvedRefs",
                        },
                    );
                    continue;
                }
            }

            // Strip allows_all, keep name/hostname/port for compute_accepted.
            let listeners_hn: ListenerHnMap = std::iter::once((
                gw_key.clone(),
                gw_listeners
                    .get(&gw_key)
                    .map(|ls| {
                        ls.iter()
                            .map(|l| ListenerHnEntry {
                                name: l.name.clone(),
                                hostname: l.hostname.clone(),
                                port: l.port,
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            ))
            .collect();

            let (mut accepted, mut accepted_reason) = compute_accepted(
                &route_hostnames,
                &section,
                pr.port.map(|p| p as u16),
                &gw_key,
                &listeners_hn,
            );

            if accepted {
                let has_unsupported = route.spec.rules.as_deref().unwrap_or(&[]).iter().any(|r| {
                    r.filters.as_deref().unwrap_or(&[]).iter().any(|f| {
                        if matches!(f.r#type, HttpRouteRulesFiltersType::ExtensionRef) {
                            if let Some(ext) = &f.extension_ref {
                                return ext.group != "coxswain-labs.dev"
                                    || (ext.kind != "RateLimit" && ext.kind != "PathRewriteRegex");
                            }
                        }
                        false
                    })
                });
                if has_unsupported {
                    accepted = false;
                    accepted_reason = "UnsupportedValue";
                }
            }

            let (resolved_refs, resolved_refs_reason) = if accepted {
                check_backend_refs(route, route_ns, backend_grants, service_store)
            } else {
                (true, "ResolvedRefs")
            };

            map.insert(
                health_key,
                RouteParentHealth {
                    resolved_refs,
                    resolved_refs_reason,
                    accepted,
                    accepted_reason,
                },
            );
        }
    }

    map
}

/// Returns `(accepted, reason)` for one (route, parent) pair based on listener hostname and port
/// matching.
fn compute_accepted(
    route_hostnames: &[&str],
    section_name: &str,
    port: Option<u16>,
    gw_key: &ObjectKey,
    gw_listeners: &ListenerHnMap,
) -> (bool, &'static str) {
    let Some(listeners) = gw_listeners.get(gw_key) else {
        return (true, "Accepted");
    };

    if !section_name.is_empty() {
        let matching: Vec<&ListenerHnEntry> = listeners
            .iter()
            .filter(|l| l.name == section_name)
            .collect();
        if matching.is_empty() {
            return (false, "NoMatchingParent");
        }
        if let Some(p) = port
            && !matching.iter().any(|l| l.port == p)
        {
            return (false, "NoMatchingParent");
        }
        let intersects = matching
            .iter()
            .any(|l| hostnames_intersect(route_hostnames, &l.hostname));
        return if intersects {
            (true, "Accepted")
        } else {
            (false, "NoMatchingListenerHostname")
        };
    }

    let port_filtered: Vec<&ListenerHnEntry> = if let Some(p) = port {
        listeners.iter().filter(|l| l.port == p).collect()
    } else {
        listeners.iter().collect()
    };

    if port.is_some() && port_filtered.is_empty() {
        return (false, "NoMatchingParent");
    }

    let intersects = port_filtered
        .iter()
        .any(|l| hostnames_intersect(route_hostnames, &l.hostname));
    if intersects {
        (true, "Accepted")
    } else {
        (false, "NoMatchingListenerHostname")
    }
}

/// Checks all backend refs in a route for validity.
/// Returns `(resolved_refs, reason)` — `resolved_refs=true` means all backends valid.
pub(super) fn check_backend_refs(
    route: &HTTPRoute,
    route_ns: &str,
    backend_grants: &HashSet<ReferenceGrantKey>,
    service_store: &reflector::Store<Service>,
) -> (bool, &'static str) {
    for rule in route.spec.rules.as_deref().unwrap_or(&[]) {
        let has_redirect = rule
            .filters
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .any(|f| matches!(f.r#type, HttpRouteRulesFiltersType::RequestRedirect));
        if has_redirect {
            continue;
        }

        for b in rule.backend_refs.as_deref().unwrap_or(&[]) {
            let b_kind = b.kind.as_deref().unwrap_or("Service");
            let b_group = b.group.as_deref().unwrap_or("");

            if b_kind != "Service" || (!b_group.is_empty() && b_group != "core") {
                return (false, "InvalidKind");
            }

            let b_ns = b.namespace.as_deref().unwrap_or(route_ns);

            if b_ns != route_ns
                && !reference_grants::backend_ref_allowed(route_ns, b_ns, &b.name, backend_grants)
            {
                return (false, "RefNotPermitted");
            }

            if b.port.is_some() {
                let svc_key = reflector::ObjectRef::<Service>::new(&b.name).within(b_ns);
                if service_store.get(&svc_key).is_none() {
                    return (false, "BackendNotFound");
                }
            }
        }
    }
    (true, "ResolvedRefs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_api::tests::*;
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
                use_default_gateways: None,
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
}
