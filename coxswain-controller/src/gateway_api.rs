use crate::endpoints;
use coxswain_core::routing::{PathRouterBuilder, RoutingTableBuilder, Upstream};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteRulesBackendRefs, HttpRouteRulesMatchesPathType,
};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector;
use std::net::SocketAddr;
use std::sync::Arc;

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

        for rule in rules {
            let backend_refs = match rule.backend_refs.as_deref() {
                Some(b) if !b.is_empty() => b,
                _ => continue,
            };

            let addrs = Self::collect_addrs(backend_refs, route_ns, slices);
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
            let apply = |pb: &mut PathRouterBuilder| match rule.matches.as_deref() {
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

    fn collect_addrs(
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
