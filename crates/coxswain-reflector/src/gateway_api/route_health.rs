//! Kind-generic `Accepted` / `ResolvedRefs` health computation for Gateway-API
//! routes, shared by the HTTPRoute and GRPCRoute status modules.
//!
//! Issue #33 deliberately kept the GRPCRoute status path a copy-paste sibling of
//! the HTTPRoute one, deferring any shared abstraction until "the second concrete
//! reconciler exists and the actual repetition is visible" — to avoid fitting a
//! trait against a single implementation. That condition is now met: GRPCRoute
//! exists and a body-diff showed the two paths were ~95% identical. This module
//! realizes that deferred abstraction via the small [`RouteLike`] trait — the
//! per-kind divergence (route type, the unsupported-filter predicate, and the
//! HTTP-only redirect-skip) is pushed behind trait methods; everything else (the
//! listener-binding setup, parent-ref loop, `compute_accepted`, cross-namespace
//! gate, and backend-ref validation) runs once here.

use crate::gateway_api::hostnames::hostnames_intersect;
use crate::gw_types::v::gateways::{Gateway, GatewayListenersAllowedRoutesNamespacesFrom};
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

struct ListenerHnEntry {
    name: String,
    hostname: String,
    port: u16,
}

type ListenerHnMap = HashMap<ObjectKey, Vec<ListenerHnEntry>>;

/// Normalized view of one of a route's `parentRefs`, projected by the per-kind
/// [`RouteLike`] impl so the shared algorithm need not know the concrete type.
pub(super) struct ParentRefView<'a> {
    pub namespace: Option<&'a str>,
    pub name: &'a str,
    pub section_name: Option<&'a str>,
    pub port: Option<u16>,
}

/// Normalized view of one backend ref to validate for `ResolvedRefs`, with the
/// per-kind rule-skipping (HTTP drops `RequestRedirect` rules) already applied by
/// [`RouteLike::health_backend_refs`].
pub(super) struct BackendRefView<'a> {
    pub kind: &'a str,
    pub group: &'a str,
    pub namespace: Option<&'a str>,
    pub name: &'a str,
    pub has_port: bool,
}

/// The per-kind surface the generic health computation needs from a route.
///
/// Only the genuinely kind-specific bits are methods: the metadata/hostname/
/// parent-ref projections (trivial field access over the codegen structs), the
/// `has_unsupported_filter` predicate (which `FilterAction`s force
/// `Accepted=UnsupportedValue`), and `health_backend_refs` (the backend refs to
/// validate, after applying any kind-specific rule skip).
pub(super) trait RouteLike {
    fn route_namespace(&self) -> Option<&str>;
    fn route_name(&self) -> Option<&str>;
    fn route_hostnames(&self) -> Vec<&str>;
    fn route_parent_refs(&self) -> Vec<ParentRefView<'_>>;
    /// `true` when any rule carries a filter this route kind doesn't support
    /// (→ `Accepted=UnsupportedValue`).
    fn has_unsupported_filter(&self) -> bool;
    /// Backend refs to validate for `ResolvedRefs`, with kind-specific rule
    /// skipping (e.g. HTTPRoute skips `RequestRedirect` rules) already applied.
    fn health_backend_refs(&self) -> Vec<BackendRefView<'_>>;
}

/// Computes `Accepted` and `ResolvedRefs` health for every (route, parent) pair
/// that references an owned gateway.
pub(super) fn compute_route_health<R: RouteLike>(
    routes: &[Arc<R>],
    gateways: &[Arc<Gateway>],
    owned_gateways: &HashSet<ObjectKey>,
    backend_grants: &HashSet<ReferenceGrantKey>,
    service_store: &reflector::Store<Service>,
) -> HttpRouteHealthMap {
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
        let route: &R = route.as_ref();
        let route_ns = route.route_namespace().unwrap_or("default");
        let route_name = route.route_name().unwrap_or("unknown");
        let route_hostnames = route.route_hostnames();

        for pr in route.route_parent_refs() {
            let gw_ns = pr.namespace.unwrap_or(route_ns);
            let gw_name = pr.name;
            let gw_key = ObjectKey::new(gw_ns, gw_name);

            if !owned_gateways.contains(&gw_key) {
                continue;
            }

            let section = pr.section_name.unwrap_or("").to_string();
            let health_key =
                RouteParentKey::new(route_ns, route_name, gw_ns, gw_name, section.clone());

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

            let (mut accepted, mut accepted_reason) =
                compute_accepted(&route_hostnames, &section, pr.port, &gw_key, &listeners_hn);

            if accepted && route.has_unsupported_filter() {
                accepted = false;
                accepted_reason = "UnsupportedValue";
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

/// Validates every backend ref the route exposes for health (post rule-skip).
///
/// Returns `(resolved_refs, reason)` — `resolved_refs=true` means all backends valid.
fn check_backend_refs<R: RouteLike>(
    route: &R,
    route_ns: &str,
    backend_grants: &HashSet<ReferenceGrantKey>,
    service_store: &reflector::Store<Service>,
) -> (bool, &'static str) {
    for b in route.health_backend_refs() {
        if b.kind != "Service" || (!b.group.is_empty() && b.group != "core") {
            return (false, "InvalidKind");
        }

        let b_ns = b.namespace.unwrap_or(route_ns);

        if b_ns != route_ns
            && !reference_grants::backend_ref_allowed(route_ns, b_ns, b.name, backend_grants)
        {
            return (false, "RefNotPermitted");
        }

        if b.has_port {
            let svc_key = reflector::ObjectRef::<Service>::new(b.name).within(b_ns);
            if service_store.get(&svc_key).is_none() {
                return (false, "BackendNotFound");
            }
        }
    }
    (true, "ResolvedRefs")
}
