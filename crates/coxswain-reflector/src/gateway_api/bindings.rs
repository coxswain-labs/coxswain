//! Listener binding: matches route `parentRefs` to Gateway listeners.

use super::hostnames;
use crate::gw_types::v::grpcroutes::GrpcRouteParentRefs;
use crate::gw_types::v::httproutes::HttpRouteParentRefs;
use crate::keys::ListenerKey;
use crate::tls::ListenerSource;
use coxswain_core::ownership::ObjectKey;
use std::collections::{HashMap, HashSet};

/// Resolve a route `parentRef`'s `(group, kind)` to the listener source it targets
/// (GEP-1713). `kind: ListenerSet` in the Gateway API group targets that
/// ListenerSet's listeners; anything else (`Gateway`, or unspecified) targets the
/// Gateway. `(ref_ns, ref_name)` identify the referenced resource.
pub(crate) fn parent_listener_source(
    group: Option<&str>,
    kind: Option<&str>,
    ref_ns: &str,
    ref_name: &str,
) -> ListenerSource {
    let gw_api_group = group.is_none_or(|g| g.is_empty() || g == "gateway.networking.k8s.io");
    if gw_api_group && kind == Some("ListenerSet") {
        ListenerSource::ListenerSet(ObjectKey::new(ref_ns, ref_name))
    } else {
        ListenerSource::Gateway
    }
}

/// Build the [`ListenerKey`] for a `(source, ref_ns, ref_name, listener)` tuple.
/// For a ListenerSet source the `(ns, name)` slots come from the source's key.
fn listener_key(
    source: &ListenerSource,
    ref_ns: &str,
    ref_name: &str,
    listener: &str,
) -> ListenerKey {
    match source {
        ListenerSource::Gateway => ListenerKey::new(ref_ns, ref_name, listener),
        ListenerSource::ListenerSet(k) => ListenerKey::for_listener_set(k, listener),
    }
}

/// Resolved hostname and port for a single Gateway listener, indexed by [`ListenerKey`].
///
/// Used to scope `HTTPRoute` entries to the correct per-port routing table slot and to
/// apply listener hostname filtering when the route has no `spec.hostnames` of its own.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct ListenerBinding {
    /// Listener `hostname` (empty string = match all).
    pub hostname: String,
    /// Listener **spec** port — the advertised port a route's `parentRef.port`
    /// is matched against.
    pub port: u16,
    /// Listener **bind** port — the local port the proxy accepts on and keys its
    /// routing table by (#472). Equals the allocated internal port for shared-mode
    /// Gateways, else the spec port. Routes are inserted under this port.
    pub bind_port: u16,
}

/// Returns one entry per (listener hostname, listener port) binding derived from the
/// route's `parentRefs`. `None` hostname means insert under the port's catchall.
/// When no listener info is available (tests/misconfigured), port 80 is used as a fallback.
pub(super) fn compute_listener_bindings(
    route_hostnames: &[&str],
    parent_refs: &[HttpRouteParentRefs],
    route_ns: &str,
    listener_info: &HashMap<ListenerKey, ListenerBinding>,
) -> Vec<(Option<String>, u16)> {
    // Maps hostname_opt → set of ports.  None key = catchall.
    let mut bindings: HashMap<Option<String>, HashSet<u16>> = HashMap::new();

    macro_rules! add {
        ($hostname:expr, $port:expr) => {
            bindings.entry($hostname).or_default().insert($port);
        };
    }

    if listener_info.is_empty() {
        // No listener info: tests or misconfigured — use port 80 as fallback.
        if route_hostnames.is_empty() {
            add!(None, 80u16);
        } else {
            for h in route_hostnames {
                add!(Some(h.to_string()), 80u16);
            }
        }
    } else {
        for pr in parent_refs {
            let gw_ns = pr.namespace.as_deref().unwrap_or(route_ns);
            let gw_name = pr.name.as_str();
            let pr_port_filter = pr.port.map(|p| p as u16);
            // GEP-1713: the parentRef may target a Gateway or a ListenerSet.
            let source =
                parent_listener_source(pr.group.as_deref(), pr.kind.as_deref(), gw_ns, gw_name);

            // Collect (port, listener_hostname) pairs for this parentRef.
            let l_bindings: Vec<(u16, &str)> = if let Some(sn) = pr.section_name.as_deref() {
                let key = listener_key(&source, gw_ns, gw_name, sn);
                match listener_info.get(&key) {
                    Some(info) if pr_port_filter.is_none_or(|pp| pp == info.port) => {
                        vec![(info.bind_port, info.hostname.as_str())]
                    }
                    _ => vec![],
                }
            } else {
                listener_info
                    .iter()
                    .filter_map(|(k, info)| {
                        if k.source != source || k.gw_ns != gw_ns || k.gw_name != gw_name {
                            return None;
                        }
                        if pr_port_filter.is_none_or(|pp| pp == info.port) {
                            Some((info.bind_port, info.hostname.as_str()))
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            for (port, lh) in l_bindings {
                if lh.is_empty() {
                    if route_hostnames.is_empty() {
                        add!(None, port);
                    } else {
                        for h in route_hostnames {
                            add!(Some(h.to_string()), port);
                        }
                    }
                } else if route_hostnames.is_empty() {
                    add!(Some(lh.to_string()), port);
                } else {
                    // Intersection: the effective hostname is the more specific of the two.
                    for rh in route_hostnames {
                        if hostnames::hostname_matches(rh, lh) {
                            let effective = if rh.starts_with("*.") && !lh.starts_with("*.") {
                                lh.to_string()
                            } else if rh.starts_with("*.")
                                && lh.starts_with("*.")
                                && lh.len() > rh.len()
                            {
                                // Both wildcards: the listener is more specific
                                // (longer suffix) → use the listener hostname.
                                lh.to_string()
                            } else {
                                rh.to_string()
                            };
                            add!(Some(effective), port);
                        }
                    }
                }
            }
        }
    }

    // Listener isolation: drop any hostname that a more-specific listener in the same
    // gateway would claim exclusively. Catchall bindings (None) are never dominated.
    if !listener_info.is_empty() {
        bindings.retain(|hostname_opt, _| {
            let e = match hostname_opt {
                Some(h) => h.as_str(),
                None => return true,
            };
            // Isolation only applies when the parentRef names a specific listener.
            !parent_refs.iter().any(|pr| {
                let our_sn = match pr.section_name.as_deref() {
                    Some(sn) if !sn.is_empty() => sn,
                    _ => return false,
                };
                let gw_ns = pr.namespace.as_deref().unwrap_or(route_ns);
                let gw_name = pr.name.as_str();
                // Isolation is scoped to listeners declared by the SAME resource
                // (the parentRef's Gateway or ListenerSet), GEP-1713.
                let source =
                    parent_listener_source(pr.group.as_deref(), pr.kind.as_deref(), gw_ns, gw_name);
                let our_spec = listener_info
                    .get(&listener_key(&source, gw_ns, gw_name, our_sn))
                    .map(|info| hostnames::listener_specificity(&info.hostname))
                    .unwrap_or(0);
                let e_is_wildcard = e.starts_with("*.");
                listener_info.iter().any(|(k, info)| {
                    let h_other = &info.hostname;
                    k.source == source
                        && k.gw_ns == gw_ns
                        && k.gw_name == gw_name
                        && k.listener.as_str() != our_sn
                        && hostnames::listener_specificity(h_other) > our_spec
                        && if e_is_wildcard {
                            h_other == e
                        } else {
                            hostnames::hostname_matches(e, h_other)
                        }
                })
            })
        });
    }

    let mut result = Vec::new();
    for (hostname_opt, ports) in bindings {
        for port in ports {
            result.push((hostname_opt.clone(), port));
        }
    }
    result
}

/// Identical to [`compute_listener_bindings`] but accepts `GRPCRoute.parentRefs`.
///
/// The body is a sibling copy — `GrpcRouteParentRefs` has the same relevant fields
/// (`name`, `namespace`, `port`, `section_name`) as `HttpRouteParentRefs` but is a
/// distinct Rust type from the kopium codegen. Kept as a concrete copy per the
/// no-shared-abstraction constraint for this issue.
#[must_use = "compute_grpc_listener_bindings always returns a Vec"]
pub(super) fn compute_grpc_listener_bindings(
    route_hostnames: &[&str],
    parent_refs: &[GrpcRouteParentRefs],
    route_ns: &str,
    listener_info: &HashMap<ListenerKey, ListenerBinding>,
) -> Vec<(Option<String>, u16)> {
    let mut bindings: HashMap<Option<String>, HashSet<u16>> = HashMap::new();

    macro_rules! add {
        ($hostname:expr, $port:expr) => {
            bindings.entry($hostname).or_default().insert($port);
        };
    }

    if listener_info.is_empty() {
        if route_hostnames.is_empty() {
            add!(None, 80u16);
        } else {
            for h in route_hostnames {
                add!(Some(h.to_string()), 80u16);
            }
        }
    } else {
        for pr in parent_refs {
            let gw_ns = pr.namespace.as_deref().unwrap_or(route_ns);
            let gw_name = pr.name.as_str();
            let pr_port_filter = pr.port.map(|p| p as u16);
            // GEP-1713: the parentRef may target a Gateway or a ListenerSet.
            let source =
                parent_listener_source(pr.group.as_deref(), pr.kind.as_deref(), gw_ns, gw_name);

            let l_bindings: Vec<(u16, &str)> = if let Some(sn) = pr.section_name.as_deref() {
                let key = listener_key(&source, gw_ns, gw_name, sn);
                match listener_info.get(&key) {
                    Some(info) if pr_port_filter.is_none_or(|pp| pp == info.port) => {
                        vec![(info.bind_port, info.hostname.as_str())]
                    }
                    _ => vec![],
                }
            } else {
                listener_info
                    .iter()
                    .filter_map(|(k, info)| {
                        if k.source != source || k.gw_ns != gw_ns || k.gw_name != gw_name {
                            return None;
                        }
                        if pr_port_filter.is_none_or(|pp| pp == info.port) {
                            Some((info.bind_port, info.hostname.as_str()))
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            for (port, lh) in l_bindings {
                if lh.is_empty() {
                    if route_hostnames.is_empty() {
                        add!(None, port);
                    } else {
                        for h in route_hostnames {
                            add!(Some(h.to_string()), port);
                        }
                    }
                } else if route_hostnames.is_empty() {
                    add!(Some(lh.to_string()), port);
                } else {
                    for rh in route_hostnames {
                        if hostnames::hostname_matches(rh, lh) {
                            let effective = if rh.starts_with("*.") && !lh.starts_with("*.") {
                                lh.to_string()
                            } else if rh.starts_with("*.")
                                && lh.starts_with("*.")
                                && lh.len() > rh.len()
                            {
                                // Both wildcards: the listener is more specific
                                // (longer suffix) → use the listener hostname.
                                lh.to_string()
                            } else {
                                rh.to_string()
                            };
                            add!(Some(effective), port);
                        }
                    }
                }
            }
        }
    }

    if !listener_info.is_empty() {
        bindings.retain(|hostname_opt, _| {
            let e = match hostname_opt {
                Some(h) => h.as_str(),
                None => return true,
            };
            !parent_refs.iter().any(|pr| {
                let our_sn = match pr.section_name.as_deref() {
                    Some(sn) if !sn.is_empty() => sn,
                    _ => return false,
                };
                let gw_ns = pr.namespace.as_deref().unwrap_or(route_ns);
                let gw_name = pr.name.as_str();
                let source =
                    parent_listener_source(pr.group.as_deref(), pr.kind.as_deref(), gw_ns, gw_name);
                let our_spec = listener_info
                    .get(&listener_key(&source, gw_ns, gw_name, our_sn))
                    .map(|info| hostnames::listener_specificity(&info.hostname))
                    .unwrap_or(0);
                let e_is_wildcard = e.starts_with("*.");
                listener_info.iter().any(|(k, info)| {
                    let h_other = &info.hostname;
                    k.source == source
                        && k.gw_ns == gw_ns
                        && k.gw_name == gw_name
                        && k.listener.as_str() != our_sn
                        && hostnames::listener_specificity(h_other) > our_spec
                        && if e_is_wildcard {
                            h_other == e
                        } else {
                            hostnames::hostname_matches(e, h_other)
                        }
                })
            })
        });
    }

    let mut result = Vec::new();
    for (hostname_opt, ports) in bindings {
        for port in ports {
            result.push((hostname_opt.clone(), port));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_api::tests::*;

    // ── Listener isolation tests ──────────────────────────────────────────────────

    #[test]
    fn listener_isolation_empty_listener_route_not_accessible_via_more_specific_listener() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route_with_hostnames_and_parent(
            "default",
            &["bar.com", "*.example.com"],
            "gw",
            Some("empty-listener"),
        );
        let listener_info = make_listener_info(
            "default",
            "gw",
            &[
                ("empty-listener", "", 80),
                ("specific-listener", "*.example.com", 80),
            ],
        );
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &listener_info,
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            table.route(80, "bar.com", "/", &ctx_get()).is_some(),
            "bar.com should be routable"
        );
        assert!(
            table
                .route(80, "bar.example.com", "/", &ctx_get())
                .is_none(),
            "bar.example.com should not leak from the empty-hostname listener"
        );
    }

    // ── parentRef.port tests ──────────────────────────────────────────────────────

    #[test]
    fn parent_ref_port_filters_to_matching_listener() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route_with_parent_port("default", &["h.example.com"], "gw", Some(80));
        let listener_info = make_listener_info(
            "default",
            "gw",
            &[("a", "h.example.com", 80), ("b", "h.example.com", 8080)],
        );
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &owned(&[("default", "gw")]),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &listener_info,
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            table.route(80, "h.example.com", "/", &ctx_get()).is_some(),
            "route must be installed for port 80"
        );
        assert!(
            table
                .route(8080, "h.example.com", "/", &ctx_get())
                .is_none(),
            "route must not be installed for port 8080"
        );
    }

    #[test]
    fn parent_ref_port_unset_attaches_to_all_listeners() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route_with_parent_port("default", &["h.example.com"], "gw", None);
        let listener_info = make_listener_info(
            "default",
            "gw",
            &[("a", "h.example.com", 80), ("b", "h.example.com", 8080)],
        );
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &owned(&[("default", "gw")]),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &listener_info,
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            table.route(80, "h.example.com", "/", &ctx_get()).is_some(),
            "route must be installed for port 80"
        );
        assert!(
            table
                .route(8080, "h.example.com", "/", &ctx_get())
                .is_some(),
            "route must be installed for port 8080"
        );
    }

    #[test]
    fn parent_ref_port_no_match_drops_route() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route_with_parent_port("default", &["h.example.com"], "gw", Some(9999));
        let listener_info = make_listener_info(
            "default",
            "gw",
            &[("a", "h.example.com", 80), ("b", "h.example.com", 8080)],
        );
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &owned(&[("default", "gw")]),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &listener_info,
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            table.route(80, "h.example.com", "/", &ctx_get()).is_none(),
            "route must not be installed for port 80"
        );
        assert!(
            table
                .route(8080, "h.example.com", "/", &ctx_get())
                .is_none(),
            "route must not be installed for port 8080"
        );
        assert!(
            table
                .route(9999, "h.example.com", "/", &ctx_get())
                .is_none(),
            "route must not be installed for port 9999"
        );
    }

    #[test]
    fn parent_ref_port_with_section_name_combined() {
        // parentRef with both sectionName and port: only attaches when both match.
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let listener_info = make_listener_info(
            "default",
            "gw",
            &[("a", "h.example.com", 80), ("b", "h.example.com", 8080)],
        );
        let owned_gw = owned(&[("default", "gw")]);

        let make_route_sn_port = |section_name: Option<&str>, port: Option<i32>| {
            use crate::gw_types::v::httproutes::HttpRouteSpec;
            HttpRoute {
                metadata: kube::api::ObjectMeta {
                    name: Some("test-route".to_string()),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                },
                spec: HttpRouteSpec {
                    parent_refs: Some(vec![HttpRouteParentRefs {
                        name: "gw".to_string(),
                        namespace: Some("default".to_string()),
                        section_name: section_name.map(str::to_string),
                        port,
                        ..Default::default()
                    }]),
                    hostnames: Some(vec!["h.example.com".to_string()]),
                    rules: Some(vec![make_simple_rule("svc")]),
                    ..Default::default()
                },
                status: None,
            }
        };

        // sectionName="a" + port=80: listener "a" is on port 80 → should attach.
        let route_match = make_route_sn_port(Some("a"), Some(80));
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route_match,
            &store,
            &empty_svc_store(),
            &owned_gw,
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &listener_info,
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            table.route(80, "h.example.com", "/", &ctx_get()).is_some(),
            "sectionName=a + port=80 must attach"
        );

        // sectionName="a" + port=8080: listener "a" is on port 80, not 8080 → must not attach.
        let route_mismatch = make_route_sn_port(Some("a"), Some(8080));
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route_mismatch,
            &store,
            &empty_svc_store(),
            &owned_gw,
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &listener_info,
                policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                path_rewrites: &empty_path_rewrite_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            table.route(80, "h.example.com", "/", &ctx_get()).is_none(),
            "sectionName=a + port=8080 must not attach"
        );
        assert!(
            table
                .route(8080, "h.example.com", "/", &ctx_get())
                .is_none(),
            "sectionName=a + port=8080 must not appear under 8080 either"
        );
    }

    // ── GEP-1713: ListenerSet parentRef resolution ────────────────────────────────

    #[test]
    fn listener_set_parent_ref_resolves_to_its_own_listener_without_colliding() {
        // A Gateway listener "web":80 and a ListenerSet ("apps/team") listener "web"
        // :8080 share a name but live under distinct sources — they must NOT collide,
        // and each parentRef kind must resolve to its own listener's port.
        let ls_key = ObjectKey::new("apps", "team");
        let mut info: HashMap<ListenerKey, ListenerBinding> = HashMap::new();
        info.insert(
            ListenerKey::new("default", "gw", "web"),
            ListenerBinding {
                hostname: String::new(),
                port: 80,
                bind_port: 80,
            },
        );
        info.insert(
            ListenerKey::for_listener_set(&ls_key, "web"),
            ListenerBinding {
                hostname: String::new(),
                port: 8080,
                bind_port: 8080,
            },
        );

        let gw_pr = vec![HttpRouteParentRefs {
            name: "gw".to_string(),
            namespace: Some("default".to_string()),
            section_name: Some("web".to_string()),
            ..Default::default()
        }];
        assert_eq!(
            compute_listener_bindings(&[], &gw_pr, "default", &info),
            vec![(None, 80u16)],
            "Gateway parentRef binds the Gateway's own web:80, not the ListenerSet's"
        );

        let ls_pr = vec![HttpRouteParentRefs {
            kind: Some("ListenerSet".to_string()),
            name: "team".to_string(),
            namespace: Some("apps".to_string()),
            section_name: Some("web".to_string()),
            ..Default::default()
        }];
        assert_eq!(
            compute_listener_bindings(&[], &ls_pr, "default", &info),
            vec![(None, 8080u16)],
            "ListenerSet parentRef binds the ListenerSet's web:8080"
        );
    }
}
