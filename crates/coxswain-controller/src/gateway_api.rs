use crate::endpoints;
use coxswain_core::ownership::parent_ref_owned;
use coxswain_core::reference_grants;
use coxswain_core::routing::{HostRouterBuilder, RoutingTableBuilder, Upstream};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteRulesBackendRefs, HttpRouteRulesMatchesPathType,
};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct GatewayApiReconciler;

impl GatewayApiReconciler {
    /// Skips routes whose `spec.parentRefs` do not include at least one Gateway
    /// managed by this controller. Never queries the API server.
    pub fn reconcile(
        route: &HTTPRoute,
        slices: &reflector::Store<EndpointSlice>,
        owned_gateways: &HashSet<(String, String)>,
        grants: &HashSet<(String, String, Option<String>)>,
        builder: &mut RoutingTableBuilder,
    ) {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");

        // Only reconcile routes attached to at least one Gateway we manage.
        let has_owned_parent = route
            .spec
            .parent_refs
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .any(|p| {
                parent_ref_owned(
                    p.group.as_deref(),
                    p.kind.as_deref(),
                    p.namespace.as_deref(),
                    &p.name,
                    route_ns,
                    owned_gateways,
                )
            });

        if !has_owned_parent {
            tracing::debug!(
                name = ?route.metadata.name,
                ns = route_ns,
                "Skipping HTTPRoute — no parentRef to a Coxswain-managed Gateway"
            );
            return;
        }

        let rules = match route.spec.rules.as_deref() {
            Some(r) if !r.is_empty() => r,
            _ => return,
        };

        let hostnames: Vec<&str> = route
            .spec
            .hostnames
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(String::as_str)
            .collect();

        tracing::debug!(
            name = ?route.metadata.name,
            ns = route_ns,
            rules = rules.len(),
            hostnames = hostnames.len(),
            "Reconciling HTTPRoute"
        );

        for rule in rules {
            let backend_refs = match rule.backend_refs.as_deref() {
                Some(b) if !b.is_empty() => b,
                _ => continue,
            };

            let addrs = Self::resolve_upstream_addrs(backend_refs, route_ns, slices, grants);
            if addrs.is_empty() {
                tracing::warn!(
                    route = ?route.metadata.name,
                    "No ready endpoints for rule — skipping"
                );
                continue;
            }

            let upstream = Arc::new(Upstream::new(
                format!("{route_ns}/{}", backend_refs[0].name),
                addrs,
            ));

            // Default to PathPrefix "/" when no matches are specified (Gateway API §4.1).
            let apply = |pb: &mut HostRouterBuilder| match rule.matches.as_deref() {
                None | Some([]) => {
                    pb.add_prefix_route("/", Arc::clone(&upstream));
                }
                Some(ms) => {
                    for m in ms {
                        let val = m
                            .path
                            .as_ref()
                            .and_then(|p| p.value.as_deref())
                            .unwrap_or("/");
                        match m.path.as_ref().and_then(|p| p.r#type.as_ref()) {
                            Some(HttpRouteRulesMatchesPathType::Exact) => {
                                pb.add_exact_route(val, Arc::clone(&upstream));
                            }
                            Some(HttpRouteRulesMatchesPathType::RegularExpression) => {
                                pb.add_regex_route(val, Arc::clone(&upstream));
                            }
                            // PathPrefix is the default per spec
                            _ => {
                                pb.add_prefix_route(val, Arc::clone(&upstream));
                            }
                        }
                    }
                }
            };

            if hostnames.is_empty() {
                apply(builder.catchall());
            } else {
                for h in &hostnames {
                    if h.starts_with("*.") {
                        apply(builder.wildcard_host(h));
                    } else {
                        apply(builder.exact_host(h));
                    }
                }
            }
        }
    }

    fn resolve_upstream_addrs(
        backend_refs: &[HttpRouteRulesBackendRefs],
        route_ns: &str,
        slices: &reflector::Store<EndpointSlice>,
        grants: &HashSet<(String, String, Option<String>)>,
    ) -> Vec<SocketAddr> {
        backend_refs
            .iter()
            .filter_map(|b| b.port.map(|port| (b, port)))
            .flat_map(|(b, port)| {
                let ns = b.namespace.as_deref().unwrap_or(route_ns);
                if ns != route_ns
                    && !reference_grants::backend_ref_allowed(route_ns, ns, &b.name, grants)
                {
                    tracing::warn!(
                        route_ns,
                        backend_ns = ns,
                        backend_svc = %b.name,
                        "Cross-namespace backendRef denied — no matching ReferenceGrant"
                    );
                    return vec![];
                }
                endpoints::resolve(ns, &b.name, port, slices)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::routing::RoutingTableBuilder;
    use gateway_api::apis::standard::httproutes::{
        HTTPRoute, HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs,
        HttpRouteRulesMatches, HttpRouteRulesMatchesPath, HttpRouteRulesMatchesPathType,
        HttpRouteSpec,
    };
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

    fn owned(pairs: &[(&str, &str)]) -> HashSet<(String, String)> {
        pairs
            .iter()
            .map(|(ns, name)| (ns.to_string(), name.to_string()))
            .collect()
    }

    /// Default owned set used by tests that exercise routing logic (not filtering).
    fn default_owned() -> HashSet<(String, String)> {
        owned(&[("default", "gw")])
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
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn path_match(type_: HttpRouteRulesMatchesPathType, value: &str) -> Vec<HttpRouteRulesMatches> {
        vec![HttpRouteRulesMatches {
            path: Some(HttpRouteRulesMatchesPath {
                r#type: Some(type_),
                value: Some(value.to_string()),
            }),
            ..Default::default()
        }]
    }

    #[test]
    fn reconcile_exact_path() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route(
            "default",
            &["example.com"],
            Some(path_match(HttpRouteRulesMatchesPathType::Exact, "/api")),
            "svc",
        );
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &default_owned(),
            &HashSet::new(),
            &mut builder,
        );
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/api").is_some());
        assert!(table.route("example.com", "/api/users").is_none());
    }

    #[test]
    fn reconcile_prefix_path() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route(
            "default",
            &["example.com"],
            Some(path_match(
                HttpRouteRulesMatchesPathType::PathPrefix,
                "/api",
            )),
            "svc",
        );
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &default_owned(),
            &HashSet::new(),
            &mut builder,
        );
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/api").is_some());
        assert!(table.route("example.com", "/api/users").is_some());
        assert!(table.route("example.com", "/other").is_none());
    }

    #[test]
    fn reconcile_regex_path() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route(
            "default",
            &["example.com"],
            Some(path_match(
                HttpRouteRulesMatchesPathType::RegularExpression,
                "^/api/v[0-9]+/.*",
            )),
            "svc",
        );
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &default_owned(),
            &HashSet::new(),
            &mut builder,
        );
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/api/v1/users").is_some());
        assert!(table.route("example.com", "/api/vX/users").is_none());
    }

    #[test]
    fn reconcile_default_prefix_on_no_matches() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route("default", &["example.com"], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &default_owned(),
            &HashSet::new(),
            &mut builder,
        );
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_some());
        assert!(table.route("example.com", "/anything").is_some());
    }

    #[test]
    fn reconcile_exact_hostname() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route("default", &["example.com"], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &default_owned(),
            &HashSet::new(),
            &mut builder,
        );
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_some());
        assert!(table.route("other.com", "/").is_none());
    }

    #[test]
    fn reconcile_wildcard_hostname() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route("default", &["*.example.com"], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &default_owned(),
            &HashSet::new(),
            &mut builder,
        );
        let table = builder.build().unwrap();

        assert!(table.route("api.example.com", "/").is_some());
        assert!(table.route("example.com", "/").is_none());
    }

    #[test]
    fn reconcile_catchall_on_no_hostname() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route("default", &[], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &default_owned(),
            &HashSet::new(),
            &mut builder,
        );
        let table = builder.build().unwrap();

        assert!(table.route("any-host.example.com", "/").is_some());
        assert!(table.route("other.io", "/").is_some());
    }

    #[test]
    fn reconcile_skips_rule_with_no_endpoints() {
        let store = slice_store(vec![]); // no slices → no endpoints
        let route = make_route("default", &["example.com"], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &default_owned(),
            &HashSet::new(),
            &mut builder,
        );
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_none());
    }

    // --- parentRef filtering tests ---

    #[test]
    fn reconcile_skips_route_without_parent_refs() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let mut route = make_route("default", &["example.com"], None, "svc");
        route.spec.parent_refs = None;
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &default_owned(),
            &HashSet::new(),
            &mut builder,
        );
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_none());
    }

    #[test]
    fn reconcile_skips_route_with_empty_parent_refs() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let mut route = make_route("default", &["example.com"], None, "svc");
        route.spec.parent_refs = Some(vec![]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &default_owned(),
            &HashSet::new(),
            &mut builder,
        );
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_none());
    }

    #[test]
    fn reconcile_skips_route_for_non_owned_gateway() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let mut route = make_route("default", &["example.com"], None, "svc");
        route.spec.parent_refs = Some(vec![HttpRouteParentRefs {
            name: "envoy-gateway".to_string(),
            namespace: Some("default".to_string()),
            ..Default::default()
        }]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &default_owned(),
            &HashSet::new(),
            &mut builder,
        );
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_none());
    }

    #[test]
    fn reconcile_reconciles_route_with_at_least_one_owned_parent() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let mut route = make_route("default", &["example.com"], None, "svc");
        // Two parentRefs: one ours, one foreign.
        route.spec.parent_refs = Some(vec![
            HttpRouteParentRefs {
                name: "gw".to_string(),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            HttpRouteParentRefs {
                name: "envoy-gateway".to_string(),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
        ]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &default_owned(),
            &HashSet::new(),
            &mut builder,
        );
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_some());
    }

    #[test]
    fn reconcile_respects_explicit_parent_namespace() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let infra_owned = owned(&[("infra", "gw")]);
        // Route is in "default" namespace but parentRef points to "infra/gw".
        let mut route = make_route("default", &["example.com"], None, "svc");
        route.spec.parent_refs = Some(vec![HttpRouteParentRefs {
            name: "gw".to_string(),
            namespace: Some("infra".to_string()),
            ..Default::default()
        }]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &infra_owned,
            &HashSet::new(),
            &mut builder,
        );
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_some());
    }

    #[test]
    fn reconcile_uses_route_namespace_as_default_for_parent() {
        let store = slice_store(vec![make_slice("apps", "svc", "10.0.0.1")]);
        // Gateway lives in "apps", same namespace as the route. parentRef omits namespace.
        let apps_owned = owned(&[("apps", "gw")]);
        let route = HTTPRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("apps".to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: Some(vec![HttpRouteParentRefs {
                    name: "gw".to_string(),
                    namespace: None, // default → route namespace "apps"
                    ..Default::default()
                }]),
                hostnames: Some(vec!["example.com".to_string()]),
                rules: Some(vec![HttpRouteRules {
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(&route, &store, &apps_owned, &HashSet::new(), &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_some());
    }

    // --- ReferenceGrant tests ---

    fn grants(entries: &[(&str, &str, Option<&str>)]) -> HashSet<(String, String, Option<String>)> {
        entries
            .iter()
            .map(|(f, t, n)| (f.to_string(), t.to_string(), n.map(str::to_string)))
            .collect()
    }

    fn cross_ns_route(route_ns: &str, backend_ns: &str, svc: &str) -> HTTPRoute {
        HTTPRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some(route_ns.to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: default_parents(),
                hostnames: Some(vec!["example.com".to_string()]),
                rules: Some(vec![HttpRouteRules {
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: svc.to_string(),
                        port: Some(80),
                        namespace: Some(backend_ns.to_string()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn cross_ns_ref_denied_without_grant() {
        let store = slice_store(vec![make_slice("billing", "payments", "10.0.1.1")]);
        let route = cross_ns_route("apps", "billing", "payments");
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &default_owned(),
            &HashSet::new(),
            &mut builder,
        );
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_none());
    }

    #[test]
    fn cross_ns_ref_permitted_with_wildcard_grant() {
        let store = slice_store(vec![make_slice("billing", "payments", "10.0.1.1")]);
        let route = cross_ns_route("apps", "billing", "payments");
        let g = grants(&[("apps", "billing", None)]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(&route, &store, &default_owned(), &g, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_some());
    }

    #[test]
    fn cross_ns_ref_permitted_with_specific_grant() {
        let store = slice_store(vec![make_slice("billing", "payments", "10.0.1.1")]);
        let route = cross_ns_route("apps", "billing", "payments");
        let g = grants(&[("apps", "billing", Some("payments"))]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(&route, &store, &default_owned(), &g, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_some());
    }

    #[test]
    fn cross_ns_specific_grant_denies_different_svc() {
        let store = slice_store(vec![make_slice("billing", "other-svc", "10.0.1.2")]);
        let route = cross_ns_route("apps", "billing", "other-svc");
        let g = grants(&[("apps", "billing", Some("payments"))]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(&route, &store, &default_owned(), &g, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_none());
    }

    #[test]
    fn same_ns_ref_unaffected_by_empty_grants() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route("default", &["example.com"], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &default_owned(),
            &HashSet::new(),
            &mut builder,
        );
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_some());
    }
}
