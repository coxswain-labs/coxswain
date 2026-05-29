use crate::endpoints;
use coxswain_core::routing::{HostRouterBuilder, RoutingTableBuilder, Upstream};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteRulesBackendRefs, HttpRouteRulesMatchesPathType,
};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector;
use std::net::SocketAddr;
use std::sync::Arc;

/// Translates `HTTPRoute` resources into routing table entries.
pub struct GatewayApiReconciler;

impl GatewayApiReconciler {
    /// Translates one `HTTPRoute` into routing table entries, resolving pod
    /// addresses from the local `EndpointSlice` store. Never queries the API server.
    pub fn reconcile(
        route: &HTTPRoute,
        slices: &reflector::Store<EndpointSlice>,
        builder: &mut RoutingTableBuilder,
    ) {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
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

            let addrs = Self::resolve_upstream_addrs(backend_refs, route_ns, slices);
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
    ) -> Vec<SocketAddr> {
        backend_refs
            .iter()
            .filter_map(|b| b.port.map(|port| (b, port)))
            .flat_map(|(b, port)| {
                let ns = b.namespace.as_deref().unwrap_or(route_ns);
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
        HTTPRoute, HttpRouteRules, HttpRouteRulesBackendRefs, HttpRouteRulesMatches,
        HttpRouteRulesMatchesPath, HttpRouteRulesMatchesPathType, HttpRouteSpec,
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

    fn path_match(
        type_: HttpRouteRulesMatchesPathType,
        value: &str,
    ) -> Vec<HttpRouteRulesMatches> {
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
        GatewayApiReconciler::reconcile(&route, &store, &mut builder);
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
            Some(path_match(HttpRouteRulesMatchesPathType::PathPrefix, "/api")),
            "svc",
        );
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(&route, &store, &mut builder);
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
        GatewayApiReconciler::reconcile(&route, &store, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/api/v1/users").is_some());
        assert!(table.route("example.com", "/api/vX/users").is_none());
    }

    #[test]
    fn reconcile_default_prefix_on_no_matches() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route("default", &["example.com"], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(&route, &store, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_some());
        assert!(table.route("example.com", "/anything").is_some());
    }

    #[test]
    fn reconcile_exact_hostname() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route("default", &["example.com"], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(&route, &store, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_some());
        assert!(table.route("other.com", "/").is_none());
    }

    #[test]
    fn reconcile_wildcard_hostname() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route("default", &["*.example.com"], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(&route, &store, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("api.example.com", "/").is_some());
        assert!(table.route("example.com", "/").is_none());
    }

    #[test]
    fn reconcile_catchall_on_no_hostname() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route("default", &[], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(&route, &store, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("any-host.example.com", "/").is_some());
        assert!(table.route("other.io", "/").is_some());
    }

    #[test]
    fn reconcile_skips_rule_with_no_endpoints() {
        let store = slice_store(vec![]); // no slices → no endpoints
        let route = make_route("default", &["example.com"], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(&route, &store, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_none());
    }
}
