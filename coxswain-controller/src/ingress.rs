use crate::endpoints;
use coxswain_core::routing::{RoutingTableBuilder, Upstream};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::reflector;
use std::sync::Arc;

pub struct IngressReconciler;

impl IngressReconciler {
    /// Translates one `Ingress` into routing table entries, resolving pod
    /// addresses from the local `EndpointSlice` store. Never queries the API server.
    pub fn reconcile(
        ingress: &Ingress,
        slices: &reflector::Store<EndpointSlice>,
        builder: &mut RoutingTableBuilder,
    ) {
        let ns = ingress.metadata.namespace.as_deref().unwrap_or("default");
        let rules = match ingress.spec.as_ref().and_then(|s| s.rules.as_deref()) {
            Some(r) if !r.is_empty() => r,
            _ => return,
        };

        for rule in rules {
            let http = match rule.http.as_ref() {
                Some(h) => h,
                None => continue,
            };

            for path_rule in &http.paths {
                let svc = match path_rule.backend.service.as_ref() {
                    Some(s) => s,
                    None => continue,
                };
                let port = match svc.port.as_ref().and_then(|p| p.number) {
                    Some(p) => p,
                    None => continue,
                };

                let addrs = endpoints::resolve(ns, &svc.name, port, slices);
                if addrs.is_empty() {
                    tracing::warn!(
                        ingress = ?ingress.metadata.name,
                        svc = %svc.name,
                        "No ready endpoints — skipping path"
                    );
                    continue;
                }

                let upstream = Arc::new(Upstream::new(format!("{ns}/{}", svc.name), addrs));
                let path = path_rule.path.as_deref().unwrap_or("/");

                let host_builder = match rule.host.as_deref() {
                    None => builder.catchall(),
                    Some(h) if h.starts_with("*.") => builder.wildcard_host(h),
                    Some(h) => builder.exact_host(h),
                };

                // "Prefix" and "ImplementationSpecific" both map to prefix matching.
                match path_rule.path_type.as_str() {
                    "Exact" => {
                        host_builder.add_exact_route(path, upstream);
                    }
                    _ => {
                        host_builder.add_prefix_route(path, upstream);
                    }
                }
            }
        }
    }
}
