use crate::endpoints;
use crate::tls::load_tls_cert;
use coxswain_core::routing::{RouteEntry, RoutingTableBuilder, Upstream};
use coxswain_core::tls::TlsStoreBuilder;
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::reflector;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::SystemTime;

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
        services: &reflector::Store<Service>,
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
        let ingress_name = ingress.metadata.name.as_deref().unwrap_or("unknown");
        let route_id = format!("{ns}/{ingress_name}");
        let created_at: Option<SystemTime> = ingress
            .metadata
            .creation_timestamp
            .as_ref()
            .and_then(|t| t.0.as_millisecond().try_into().ok())
            .map(|ms: u64| SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(ms));
        let spec = ingress.spec.as_ref();
        let rules = spec.and_then(|s| s.rules.as_deref());

        if rules.is_none_or(|r| r.is_empty()) {
            if spec.and_then(|s| s.default_backend.as_ref()).is_some() {
                tracing::warn!(
                    name = ?ingress.metadata.name,
                    "spec.defaultBackend is set but spec.rules is empty — \
                     default backend is a no-op; use --ingress-default-backend \
                     for a controller-wide fallback"
                );
            }
            return;
        }
        let rules = rules.unwrap();

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

                let addrs = endpoints::resolve(ns, &svc.name, port, slices, services);
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

                let e = Arc::new(RouteEntry::path_only(
                    upstream,
                    route_id.clone(),
                    created_at,
                ));
                // "Prefix" and "ImplementationSpecific" both map to prefix matching.
                match path_rule.path_type.as_str() {
                    "Exact" => {
                        host_builder.add_exact_route(path, e);
                    }
                    _ => {
                        host_builder.add_prefix_route(path, e);
                    }
                }
            }
        }

        // Install spec.defaultBackend as prefix "/" on each rule host so path-misses
        // on those hosts fall to this backend. Per-rule routes win because they are
        // inserted above; first-writer-wins semantics mean "/" is only claimed here
        // if no rule already registered it.
        if let Some(default_svc) = spec
            .and_then(|s| s.default_backend.as_ref())
            .and_then(|b| b.service.as_ref())
            && let Some(port) = default_svc.port.as_ref().and_then(|p| p.number)
        {
            let addrs = endpoints::resolve(ns, &default_svc.name, port, slices, services);
            if addrs.is_empty() {
                tracing::warn!(
                    ingress = ?ingress.metadata.name,
                    svc = %default_svc.name,
                    "No ready endpoints for defaultBackend — skipping"
                );
            } else {
                let upstream = Arc::new(Upstream::new(format!("{ns}/{}", default_svc.name), addrs));
                for rule in rules {
                    let host_builder = match rule.host.as_deref() {
                        None => builder.catchall(),
                        Some(h) if h.starts_with("*.") => builder.wildcard_host(h),
                        Some(h) => builder.exact_host(h),
                    };
                    let e = Arc::new(RouteEntry::path_only(
                        Arc::clone(&upstream),
                        route_id.clone(),
                        created_at,
                    ));
                    host_builder.add_prefix_route("/", e);
                }
            }
        }
    }

    /// Reads `spec.tls` from `ingress` and registers certs in `builder`.
    ///
    /// Applies the same IngressClass filter as `reconcile()` — Ingresses not
    /// owned by this controller are silently skipped. Secrets that are missing,
    /// have the wrong type, or contain malformed PEM are warned-about and
    /// skipped; the Ingress's HTTP routes (installed by `reconcile()`) are
    /// unaffected.
    pub fn reconcile_tls(
        ingress: &Ingress,
        secrets: &reflector::Store<Secret>,
        owned_classes: &HashSet<String>,
        builder: &mut TlsStoreBuilder,
    ) {
        let claimed_class = claimed_ingress_class(ingress);
        match claimed_class {
            None => return,
            Some(class) if !owned_classes.contains(class) => return,
            Some(_) => {}
        }

        let ns = ingress.metadata.namespace.as_deref().unwrap_or("default");
        let spec = ingress.spec.as_ref();

        let tls_blocks = match spec.and_then(|s| s.tls.as_deref()) {
            Some(t) if !t.is_empty() => t,
            _ => return,
        };

        for tls in tls_blocks {
            let secret_name = match tls.secret_name.as_deref() {
                Some(n) => n,
                None => {
                    tracing::warn!(
                        ingress = ?ingress.metadata.name,
                        "spec.tls block has no secretName — skipping"
                    );
                    continue;
                }
            };

            let cert = match load_tls_cert(ns, secret_name, secrets) {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    tracing::warn!(
                        ingress = ?ingress.metadata.name,
                        secret = %format!("{ns}/{secret_name}"),
                        error = %e,
                        "TLS Secret unusable — skipping cert (HTTP routes unaffected)"
                    );
                    continue;
                }
            };

            for host in tls.hosts.as_deref().unwrap_or(&[]) {
                builder.add_cert(host, Arc::clone(&cert));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::routing::{RequestContext, RoutingTableBuilder};
    use coxswain_core::tls::TlsStoreBuilder;
    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::{Secret, Service};
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointSlice};
    use k8s_openapi::api::networking::v1::{
        HTTPIngressPath, HTTPIngressRuleValue, IngressBackend, IngressRule, IngressServiceBackend,
        IngressSpec, IngressTLS, ServiceBackendPort,
    };
    use kube::api::ObjectMeta;
    use kube::runtime::{reflector, watcher};
    use std::collections::BTreeMap;

    fn owned(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn empty_svc_store() -> reflector::Store<Service> {
        reflector::store::Writer::<Service>::default().as_reader()
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

    fn make_ingress_with_default(
        ns: &str,
        host: Option<&str>,
        rule_path: &str,
        rule_svc: &str,
        default_svc: Option<&str>,
    ) -> Ingress {
        Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some("coxswain".to_string()),
                rules: Some(vec![IngressRule {
                    host: host.map(str::to_string),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![HTTPIngressPath {
                            path: Some(rule_path.to_string()),
                            path_type: "Prefix".to_string(),
                            backend: IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: rule_svc.to_string(),
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
                default_backend: default_svc.map(|svc| IngressBackend {
                    service: Some(IngressServiceBackend {
                        name: svc.to_string(),
                        port: Some(ServiceBackendPort {
                            number: Some(80),
                            ..Default::default()
                        }),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            status: None,
        }
    }

    fn make_default_only_ingress(ns: &str, default_svc: &str) -> Ingress {
        Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some("coxswain".to_string()),
                rules: None,
                default_backend: Some(IngressBackend {
                    service: Some(IngressServiceBackend {
                        name: default_svc.to_string(),
                        port: Some(ServiceBackendPort {
                            number: Some(80),
                            ..Default::default()
                        }),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            status: None,
        }
    }

    #[test]
    fn reconcile_default_backend_catches_path_miss() {
        let store = slice_store(vec![
            make_slice("default", "rule-svc", "10.0.0.1"),
            make_slice("default", "default-svc", "10.0.0.2"),
        ]);
        let ingress = make_ingress_with_default(
            "default",
            Some("example.com"),
            "/api",
            "rule-svc",
            Some("default-svc"),
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert_eq!(
            table.route("example.com", "/api/v1", &ctx).unwrap().name,
            "default/rule-svc"
        );
        assert_eq!(
            table.route("example.com", "/other", &ctx).unwrap().name,
            "default/default-svc"
        );
    }

    #[test]
    fn reconcile_default_backend_skipped_when_no_rules() {
        let store = slice_store(vec![make_slice("default", "default-svc", "10.0.0.1")]);
        let ingress = make_default_only_ingress("default", "default-svc");
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route("any.host.com", "/", &ctx).is_none());
    }

    #[test]
    fn reconcile_default_backend_skipped_when_no_endpoints() {
        let store = slice_store(vec![
            make_slice("default", "rule-svc", "10.0.0.1"),
            // no slice for default-svc → no endpoints
        ]);
        let ingress = make_ingress_with_default(
            "default",
            Some("example.com"),
            "/api",
            "rule-svc",
            Some("default-svc"),
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route("example.com", "/api", &ctx).is_some());
        assert!(table.route("example.com", "/other", &ctx).is_none());
    }

    #[test]
    fn reconcile_default_backend_on_wildcard_host() {
        let store = slice_store(vec![
            make_slice("default", "rule-svc", "10.0.0.1"),
            make_slice("default", "default-svc", "10.0.0.2"),
        ]);
        let ingress = make_ingress_with_default(
            "default",
            Some("*.example.com"),
            "/api",
            "rule-svc",
            Some("default-svc"),
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert_eq!(
            table.route("api.example.com", "/api", &ctx).unwrap().name,
            "default/rule-svc"
        );
        assert_eq!(
            table.route("api.example.com", "/other", &ctx).unwrap().name,
            "default/default-svc"
        );
    }

    #[test]
    fn reconcile_rule_root_path_wins_over_default_backend() {
        let store = slice_store(vec![
            make_slice("default", "rule-svc", "10.0.0.1"),
            make_slice("default", "default-svc", "10.0.0.2"),
        ]);
        // Rule already claims "/"; defaultBackend should not override it.
        let ingress = make_ingress_with_default(
            "default",
            Some("example.com"),
            "/",
            "rule-svc",
            Some("default-svc"),
        );
        let mut builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert_eq!(
            table.route("example.com", "/anything", &ctx).unwrap().name,
            "default/rule-svc"
        );
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
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route("example.com", "/api", &ctx).is_some());
        assert!(table.route("example.com", "/api/users", &ctx).is_none());
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
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route("example.com", "/api", &ctx).is_some());
        assert!(table.route("example.com", "/api/users", &ctx).is_some());
        assert!(table.route("example.com", "/other", &ctx).is_none());
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
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route("example.com", "/api", &ctx).is_some());
        assert!(table.route("example.com", "/api/v2", &ctx).is_some());
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
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route("example.com", "/", &ctx).is_some());
        assert!(table.route("other.com", "/", &ctx).is_none());
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
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route("api.example.com", "/", &ctx).is_some());
        assert!(table.route("example.com", "/", &ctx).is_none());
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
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route("any-host.example.com", "/", &ctx).is_some());
        assert!(table.route("other.io", "/", &ctx).is_some());
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
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route("example.com", "/", &ctx).is_none());
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
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route("example.com", "/", &RequestContext::default())
                .is_some()
        );
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
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route("example.com", "/", &RequestContext::default())
                .is_none()
        );
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
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route("example.com", "/", &RequestContext::default())
                .is_some()
        );
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
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route("example.com", "/", &RequestContext::default())
                .is_none()
        );
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
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route("example.com", "/", &RequestContext::default())
                .is_none()
        );
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
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&[]),
            &mut builder,
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route("example.com", "/", &RequestContext::default())
                .is_none()
        );
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
        IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route("example.com", "/", &RequestContext::default())
                .is_some()
        );
    }

    // -------------------------------------------------------------------------
    // reconcile_tls tests
    // -------------------------------------------------------------------------

    fn secret_store(secrets: Vec<Secret>) -> reflector::Store<Secret> {
        let mut writer = reflector::store::Writer::<Secret>::default();
        for secret in secrets {
            writer.apply_watcher_event(&watcher::Event::Apply(secret));
        }
        writer.as_reader()
    }

    fn make_tls_secret(ns: &str, name: &str) -> Secret {
        let mut data = BTreeMap::new();
        data.insert(
            "tls.crt".to_string(),
            ByteString(
                b"-----BEGIN CERTIFICATE-----\nMIIBIjANBg==\n-----END CERTIFICATE-----\n".to_vec(),
            ),
        );
        data.insert(
            "tls.key".to_string(),
            ByteString(
                b"-----BEGIN PRIVATE KEY-----\nMIIBIjANBg==\n-----END PRIVATE KEY-----\n".to_vec(),
            ),
        );
        Secret {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            type_: Some("kubernetes.io/tls".to_string()),
            data: Some(data),
            ..Default::default()
        }
    }

    fn make_ingress_with_tls(ns: &str, class_name: &str, tls: Vec<IngressTLS>) -> Ingress {
        Ingress {
            metadata: ObjectMeta {
                name: Some("tls-ingress".to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some(class_name.to_string()),
                rules: Some(vec![IngressRule {
                    host: Some("example.com".to_string()),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![HTTPIngressPath {
                            path: Some("/".to_string()),
                            path_type: "Prefix".to_string(),
                            backend: IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: "svc".to_string(),
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
                tls: Some(tls),
                ..Default::default()
            }),
            status: None,
        }
    }

    #[test]
    fn reconcile_tls_loads_cert_for_owned_ingress() {
        let secrets = secret_store(vec![make_tls_secret("default", "my-cert")]);
        let ingress = make_ingress_with_tls(
            "default",
            "coxswain",
            vec![IngressTLS {
                hosts: Some(vec!["example.com".to_string()]),
                secret_name: Some("my-cert".to_string()),
            }],
        );
        let mut builder = TlsStoreBuilder::new();
        IngressReconciler::reconcile_tls(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        let store = builder.build();
        assert!(store.find_cert("example.com").is_some());
    }

    #[test]
    fn reconcile_tls_skips_missing_secret() {
        let secrets = secret_store(vec![]); // empty — no Secret in store
        let ingress = make_ingress_with_tls(
            "default",
            "coxswain",
            vec![IngressTLS {
                hosts: Some(vec!["example.com".to_string()]),
                secret_name: Some("my-cert".to_string()),
            }],
        );
        let mut builder = TlsStoreBuilder::new();
        IngressReconciler::reconcile_tls(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        assert!(builder.build().find_cert("example.com").is_none());
    }

    #[test]
    fn reconcile_tls_skips_wrong_type() {
        let mut secret = make_tls_secret("default", "my-cert");
        secret.type_ = Some("Opaque".to_string());
        let secrets = secret_store(vec![secret]);
        let ingress = make_ingress_with_tls(
            "default",
            "coxswain",
            vec![IngressTLS {
                hosts: Some(vec!["example.com".to_string()]),
                secret_name: Some("my-cert".to_string()),
            }],
        );
        let mut builder = TlsStoreBuilder::new();
        IngressReconciler::reconcile_tls(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        assert!(builder.build().find_cert("example.com").is_none());
    }

    #[test]
    fn reconcile_tls_skips_missing_tls_crt() {
        let mut secret = make_tls_secret("default", "my-cert");
        secret.data.as_mut().unwrap().remove("tls.crt");
        let secrets = secret_store(vec![secret]);
        let ingress = make_ingress_with_tls(
            "default",
            "coxswain",
            vec![IngressTLS {
                hosts: Some(vec!["example.com".to_string()]),
                secret_name: Some("my-cert".to_string()),
            }],
        );
        let mut builder = TlsStoreBuilder::new();
        IngressReconciler::reconcile_tls(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        assert!(builder.build().find_cert("example.com").is_none());
    }

    #[test]
    fn reconcile_tls_skips_missing_tls_key() {
        let mut secret = make_tls_secret("default", "my-cert");
        secret.data.as_mut().unwrap().remove("tls.key");
        let secrets = secret_store(vec![secret]);
        let ingress = make_ingress_with_tls(
            "default",
            "coxswain",
            vec![IngressTLS {
                hosts: Some(vec!["example.com".to_string()]),
                secret_name: Some("my-cert".to_string()),
            }],
        );
        let mut builder = TlsStoreBuilder::new();
        IngressReconciler::reconcile_tls(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        assert!(builder.build().find_cert("example.com").is_none());
    }

    #[test]
    fn reconcile_tls_skips_unowned_ingress() {
        let secrets = secret_store(vec![make_tls_secret("default", "my-cert")]);
        let ingress = make_ingress_with_tls(
            "default",
            "nginx", // not owned
            vec![IngressTLS {
                hosts: Some(vec!["example.com".to_string()]),
                secret_name: Some("my-cert".to_string()),
            }],
        );
        let mut builder = TlsStoreBuilder::new();
        IngressReconciler::reconcile_tls(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        assert!(builder.build().find_cert("example.com").is_none());
    }

    #[test]
    fn reconcile_tls_failure_does_not_affect_routes() {
        let slice_st = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let secrets = secret_store(vec![]); // missing secret
        let ingress = make_ingress_with_tls(
            "default",
            "coxswain",
            vec![IngressTLS {
                hosts: Some(vec!["example.com".to_string()]),
                secret_name: Some("my-cert".to_string()),
            }],
        );
        // Routes still reconcile even when TLS cert is missing
        let mut route_builder = RoutingTableBuilder::new();
        IngressReconciler::reconcile(
            &ingress,
            &slice_st,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut route_builder,
        );
        let table = route_builder.build().unwrap();
        assert!(
            table
                .route("example.com", "/", &RequestContext::default())
                .is_some()
        );

        // And TLS store ends up empty
        let mut tls_builder = TlsStoreBuilder::new();
        IngressReconciler::reconcile_tls(
            &ingress,
            &secrets,
            &owned(&["coxswain"]),
            &mut tls_builder,
        );
        assert!(tls_builder.build().find_cert("example.com").is_none());
    }

    #[test]
    fn reconcile_tls_registers_multiple_hosts_from_one_block() {
        let secrets = secret_store(vec![make_tls_secret("default", "wildcard-cert")]);
        let ingress = make_ingress_with_tls(
            "default",
            "coxswain",
            vec![IngressTLS {
                hosts: Some(vec![
                    "a.example.com".to_string(),
                    "b.example.com".to_string(),
                ]),
                secret_name: Some("wildcard-cert".to_string()),
            }],
        );
        let mut builder = TlsStoreBuilder::new();
        IngressReconciler::reconcile_tls(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        let store = builder.build();
        assert!(store.find_cert("a.example.com").is_some());
        assert!(store.find_cert("b.example.com").is_some());
    }
}
