use crate::gateway_api::hostnames::hostnames_intersect;
use crate::tls::{HttpRouteHealthMap, RouteParentHealth};
use coxswain_core::reference_grants;
use gateway_api::apis::standard::gateways::{Gateway, GatewayListenersAllowedRoutesNamespacesFrom};
use gateway_api::apis::standard::httproutes::{HTTPRoute, HttpRouteRulesFiltersType};
use k8s_openapi::api::core::v1::Service;
use kube::runtime::reflector;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// `(listener_name, hostname, port)` stripped of the `allows_all` flag; passed to
/// `compute_accepted` where cross-namespace checks are already done.
type ListenerHnEntry = (String, String, u16);
type ListenerHnMap = HashMap<(String, String), Vec<ListenerHnEntry>>;

/// Computes `Accepted` and `ResolvedRefs` health for every (route, parent) pair
/// that references an owned gateway. Called during the reconciler's rebuild so the
/// controller can write accurate HTTPRoute status conditions.
pub(super) fn compute_route_health(
    routes: &[Arc<HTTPRoute>],
    gateways: &[Arc<Gateway>],
    owned_gateways: &HashSet<(String, String)>,
    backend_grants: &HashSet<(String, String, Option<String>)>,
    service_store: &reflector::Store<Service>,
) -> HttpRouteHealthMap {
    // (listener_name, hostname, allows_all_ns, port)
    type ListenerInfo = Vec<(String, String, bool, u16)>;
    // Build listener info map: (gw_ns, gw_name) → ListenerInfo
    // allows_all_ns = true when allowedRoutes.namespaces.from is All or Selector (not Same).
    let gw_listeners: HashMap<(String, String), ListenerInfo> = gateways
        .iter()
        .filter_map(|gw| {
            let ns = gw.metadata.namespace.as_deref()?.to_string();
            let name = gw.metadata.name.as_deref()?.to_string();
            if !owned_gateways.contains(&(ns.clone(), name.clone())) {
                return None;
            }
            let listeners: Vec<(String, String, bool, u16)> = gw
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
                    (
                        l.name.clone(),
                        l.hostname.as_deref().unwrap_or("").to_string(),
                        allows_all,
                        l.port as u16,
                    )
                })
                .collect();
            Some(((ns, name), listeners))
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
            let gw_key = (gw_ns.to_string(), gw_name.to_string());

            if !owned_gateways.contains(&gw_key) {
                continue;
            }

            let section = pr.section_name.as_deref().unwrap_or("").to_string();
            let health_key = (
                route_ns.to_string(),
                route_name.to_string(),
                gw_ns.to_string(),
                gw_name.to_string(),
                section.clone(),
            );

            // Cross-namespace check: reject routes whose namespace is not allowed by the
            // listener. Default per spec is Same (only same namespace); must be All or
            // Selector to permit cross-namespace parentRefs.
            if gw_ns != route_ns {
                let blocked = gw_listeners.get(&gw_key).is_some_and(|ls| {
                    let relevant: Vec<_> = if section.is_empty() {
                        ls.iter().collect()
                    } else {
                        ls.iter()
                            .filter(|(n, _, _, _)| n.as_str() == section)
                            .collect()
                    };
                    !relevant.is_empty() && relevant.iter().all(|(_, _, allows, _)| !allows)
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

            // Strip allows_all bool, keep port for port-matching check.
            let listeners_hn: ListenerHnMap = std::iter::once((
                gw_key.clone(),
                gw_listeners
                    .get(&gw_key)
                    .map(|ls| {
                        ls.iter()
                            .map(|(n, h, _, p)| (n.clone(), h.clone(), *p))
                            .collect()
                    })
                    .unwrap_or_default(),
            ))
            .collect();

            let (accepted, accepted_reason) = compute_accepted(
                &route_hostnames,
                &section,
                pr.port.map(|p| p as u16),
                &gw_key,
                &listeners_hn,
            );

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
    gw_key: &(String, String),
    gw_listeners: &ListenerHnMap,
) -> (bool, &'static str) {
    let Some(listeners) = gw_listeners.get(gw_key) else {
        return (true, "Accepted");
    };

    if !section_name.is_empty() {
        let matching: Vec<&(String, String, u16)> = listeners
            .iter()
            .filter(|(n, _, _)| n == section_name)
            .collect();
        if matching.is_empty() {
            return (false, "NoMatchingParent");
        }
        // parentRef.port must match the named listener's port when specified.
        if let Some(p) = port
            && !matching.iter().any(|(_, _, lp)| *lp == p)
        {
            return (false, "NoMatchingParent");
        }
        let intersects = matching
            .iter()
            .any(|(_, hn, _)| hostnames_intersect(route_hostnames, hn));
        return if intersects {
            (true, "Accepted")
        } else {
            (false, "NoMatchingListenerHostname")
        };
    }

    // No sectionName: filter candidate listeners by port first (if specified).
    let port_filtered: Vec<&(String, String, u16)> = if let Some(p) = port {
        listeners.iter().filter(|(_, _, lp)| *lp == p).collect()
    } else {
        listeners.iter().collect()
    };

    if port.is_some() && port_filtered.is_empty() {
        return (false, "NoMatchingParent");
    }

    let intersects = port_filtered
        .iter()
        .any(|(_, hn, _)| hostnames_intersect(route_hostnames, hn));
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
    backend_grants: &HashSet<(String, String, Option<String>)>,
    service_store: &reflector::Store<Service>,
) -> (bool, &'static str) {
    for rule in route.spec.rules.as_deref().unwrap_or(&[]) {
        // Rules with RequestRedirect don't need backends
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

            // Unsupported kind/group
            if b_kind != "Service" || (!b_group.is_empty() && b_group != "core") {
                return (false, "InvalidKind");
            }

            let b_ns = b.namespace.as_deref().unwrap_or(route_ns);

            // Cross-namespace ref requires a ReferenceGrant
            if b_ns != route_ns
                && !reference_grants::backend_ref_allowed(route_ns, b_ns, &b.name, backend_grants)
            {
                return (false, "RefNotPermitted");
            }

            // Service must exist in the store
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
