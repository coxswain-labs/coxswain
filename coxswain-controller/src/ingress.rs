use crate::endpoints;
use coxswain_core::routing::{RoutingTableBuilder, Upstream};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::reflector;
use std::sync::Arc;

/// Translates `Ingress` resources into routing table entries.
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

        tracing::debug!(name = ?ingress.metadata.name, ns, rules = rules.len(), "Reconciling Ingress");

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

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::routing::RoutingTableBuilder;
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointSlice};
    use k8s_openapi::api::networking::v1::{
        HTTPIngressPath, HTTPIngressRuleValue, IngressBackend, IngressRule, IngressServiceBackend,
        IngressSpec, ServiceBackendPort,
    };
    use kube::api::ObjectMeta;
    use kube::runtime::{reflector, watcher};
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

    fn make_ingress(ns: &str, host: Option<&str>, path: &str, path_type: &str, svc: &str) -> Ingress {
        Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                rules: Some(vec![IngressRule {
                    host: host.map(str::to_string),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![HTTPIngressPath {
                            path: Some(path.to_string()),
                            path_type: path_type.to_string(),
                            backend: IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: svc.to_string(),
                                    port: Some(ServiceBackendPort {
                                        number: Some(80),
                                        ..Default::default()
                                    }),
                                }),
                                ..Default::default()
                            },
                        }],
                    }),
                }]),
                ..Default::default()
            }),
            status: None,
        }
    }

    #[test]
    fn reconcile_exact_path_type() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress("default", Some("example.com"), "/api", "Exact", "svc");
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/api").is_some());
        assert!(table.route("example.com", "/api/users").is_none());
    }

    #[test]
    fn reconcile_prefix_path_type() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress("default", Some("example.com"), "/api", "Prefix", "svc");
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/api").is_some());
        assert!(table.route("example.com", "/api/users").is_some());
        assert!(table.route("example.com", "/other").is_none());
    }

    #[test]
    fn reconcile_implementation_specific_maps_to_prefix() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress =
            make_ingress("default", Some("example.com"), "/api", "ImplementationSpecific", "svc");
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/api").is_some());
        assert!(table.route("example.com", "/api/v2").is_some());
    }

    #[test]
    fn reconcile_exact_hostname() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress("default", Some("example.com"), "/", "Prefix", "svc");
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_some());
        assert!(table.route("other.com", "/").is_none());
    }

    #[test]
    fn reconcile_wildcard_hostname() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress("default", Some("*.example.com"), "/", "Prefix", "svc");
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("api.example.com", "/").is_some());
        assert!(table.route("example.com", "/").is_none());
    }

    #[test]
    fn reconcile_no_host_goes_to_catchall() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress("default", None, "/", "Prefix", "svc");
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("any-host.example.com", "/").is_some());
        assert!(table.route("other.io", "/").is_some());
    }

    #[test]
    fn reconcile_skips_rule_with_no_endpoints() {
        let store = slice_store(vec![]); // no slices → no endpoints
        let ingress = make_ingress("default", Some("example.com"), "/", "Prefix", "svc");
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_none());
    }
}
