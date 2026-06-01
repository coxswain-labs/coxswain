use crate::endpoints;
use coxswain_core::routing::{RoutingTableBuilder, Upstream};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::reflector;
use std::collections::HashSet;
use std::sync::Arc;

pub struct IngressReconciler;

/// Returns the IngressClass name claimed by `ingress`.
///
/// Checks `spec.ingressClassName` first; falls back to the legacy
/// `kubernetes.io/ingress.class` annotation. Returns `None` when neither
/// is set (opt-in semantics: unclassified Ingresses are ignored).
pub fn claimed_ingress_class(ingress: &Ingress) -> Option<&str> {
    ingress
        .spec
        .as_ref()
        .and_then(|s| s.ingress_class_name.as_deref())
        .or_else(|| {
            ingress
                .metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get("kubernetes.io/ingress.class").map(String::as_str))
        })
}

impl IngressReconciler {
    /// Skips the Ingress when it does not reference an owned IngressClass.
    /// Never queries the API server.
    pub fn reconcile(
        ingress: &Ingress,
        slices: &reflector::Store<EndpointSlice>,
        owned_classes: &HashSet<String>,
        builder: &mut RoutingTableBuilder,
    ) {
        let claimed_class = claimed_ingress_class(ingress);

        match claimed_class {
            None => {
                tracing::debug!(name = ?ingress.metadata.name, "Skipping Ingress — no ingressClassName or annotation");
                return;
            }
            Some(class) if !owned_classes.contains(class) => {
                tracing::debug!(name = ?ingress.metadata.name, %class, "Skipping Ingress — class not owned by this controller");
                return;
            }
            Some(_) => {}
        }

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

    fn owned(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

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

    fn make_ingress(
        ns: &str,
        host: Option<&str>,
        path: &str,
        path_type: &str,
        svc: &str,
        class_name: Option<&str>,
        annotation_class: Option<&str>,
    ) -> Ingress {
        let annotations = annotation_class.map(|c| {
            let mut m = BTreeMap::new();
            m.insert("kubernetes.io/ingress.class".to_string(), c.to_string());
            m
        });
        Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some(ns.to_string()),
                annotations,
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: class_name.map(str::to_string),
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
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/api",
            "Exact",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/api").is_some());
        assert!(table.route("example.com", "/api/users").is_none());
    }

    #[test]
    fn reconcile_prefix_path_type() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/api",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/api").is_some());
        assert!(table.route("example.com", "/api/users").is_some());
        assert!(table.route("example.com", "/other").is_none());
    }

    #[test]
    fn reconcile_implementation_specific_maps_to_prefix() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/api",
            "ImplementationSpecific",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/api").is_some());
        assert!(table.route("example.com", "/api/v2").is_some());
    }

    #[test]
    fn reconcile_exact_hostname() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_some());
        assert!(table.route("other.com", "/").is_none());
    }

    #[test]
    fn reconcile_wildcard_hostname() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("*.example.com"),
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("api.example.com", "/").is_some());
        assert!(table.route("example.com", "/").is_none());
    }

    #[test]
    fn reconcile_no_host_goes_to_catchall() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            None,
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("any-host.example.com", "/").is_some());
        assert!(table.route("other.io", "/").is_some());
    }

    #[test]
    fn reconcile_skips_rule_with_no_endpoints() {
        let store = slice_store(vec![]); // no slices → no endpoints
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();

        assert!(table.route("example.com", "/").is_none());
    }

    #[test]
    fn reconcile_matches_owned_class_name() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &owned(&["coxswain"]), &mut builder);
        assert!(builder.build().unwrap().route("example.com", "/").is_some());
    }

    #[test]
    fn reconcile_skips_unowned_class_name() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            Some("nginx"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &owned(&["coxswain"]), &mut builder);
        assert!(builder.build().unwrap().route("example.com", "/").is_none());
    }

    #[test]
    fn reconcile_matches_via_legacy_annotation() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            None,
            Some("coxswain"),
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &owned(&["coxswain"]), &mut builder);
        assert!(builder.build().unwrap().route("example.com", "/").is_some());
    }

    #[test]
    fn reconcile_skips_unowned_legacy_annotation() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            None,
            Some("nginx"),
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &owned(&["coxswain"]), &mut builder);
        assert!(builder.build().unwrap().route("example.com", "/").is_none());
    }

    #[test]
    fn reconcile_skips_when_both_unset() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            None,
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &owned(&["coxswain"]), &mut builder);
        assert!(builder.build().unwrap().route("example.com", "/").is_none());
    }

    #[test]
    fn reconcile_skips_when_owned_set_empty() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &owned(&[]), &mut builder);
        assert!(builder.build().unwrap().route("example.com", "/").is_none());
    }

    #[test]
    fn reconcile_field_takes_precedence_over_annotation() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        // field = "coxswain" (owned), annotation = "nginx" (not owned) → should reconcile
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            Some("nginx"),
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(&ingress, &store, &owned(&["coxswain"]), &mut builder);
        assert!(builder.build().unwrap().route("example.com", "/").is_some());
    }
}
