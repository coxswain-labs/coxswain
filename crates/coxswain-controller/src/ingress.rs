use crate::endpoints;
use crate::tls::load_tls_cert;
use crate::translate::metadata_created_at;
use coxswain_core::routing::{RouteEntry, RoutingTableBuilder, Upstream};
use coxswain_core::tls::TlsStoreBuilder;
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::{Ingress, IngressClass, IngressServiceBackend};
use kube::runtime::reflector;
use std::collections::HashSet;
use std::sync::Arc;
pub const IS_DEFAULT_CLASS_ANNOTATION: &str = "ingressclass.kubernetes.io/is-default-class";

pub fn is_default_ingress_class(ic: &IngressClass) -> bool {
    ic.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(IS_DEFAULT_CLASS_ANNOTATION).map(String::as_str))
        == Some("true")
}

pub struct IngressReconciler;

/// Resolves a backend port to its numeric value.
///
/// Tries `port.number` first; when absent, looks up `port.name` in the
/// Service store. Emits a warning and returns `None` when the name is set
/// but the Service is missing or has no matching port.
fn resolve_backend_port(
    ns: &str,
    svc: &IngressServiceBackend,
    services: &reflector::Store<Service>,
) -> Option<i32> {
    let port = svc.port.as_ref()?;
    if let Some(n) = port.number {
        return Some(n);
    }
    let name = port.name.as_deref()?;
    let resolved = endpoints::port_for_name(ns, &svc.name, name, services);
    if resolved.is_none() {
        tracing::warn!(
            namespace = %ns,
            service = %svc.name,
            port_name = %name,
            "Ingress backend references unknown named port on Service — skipping"
        );
    }
    resolved
}

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
    /// When `owned_default_class` is `Some`, an Ingress with neither
    /// `spec.ingressClassName` nor the legacy annotation is also claimed.
    /// Never queries the API server.
    pub fn reconcile(
        ingress: &Ingress,
        slices: &reflector::Store<EndpointSlice>,
        services: &reflector::Store<Service>,
        owned_classes: &HashSet<String>,
        owned_default_class: Option<&str>,
        builder: &mut RoutingTableBuilder,
    ) {
        let claimed_class = claimed_ingress_class(ingress);

        match claimed_class {
            None => match owned_default_class {
                Some(_) => {}
                None => {
                    tracing::debug!(name = ?ingress.metadata.name, "Skipping Ingress — no ingressClassName or annotation");
                    return;
                }
            },
            Some(class) if !owned_classes.contains(class) => {
                tracing::debug!(name = ?ingress.metadata.name, %class, "Skipping Ingress — class not owned by this controller");
                return;
            }
            Some(_) => {}
        }

        let ns = ingress.metadata.namespace.as_deref().unwrap_or("default");
        let ingress_name = ingress.metadata.name.as_deref().unwrap_or("unknown");
        let route_id = format!("{ns}/{ingress_name}");
        let created_at = metadata_created_at(&ingress.metadata);
        let spec = ingress.spec.as_ref();
        let rules = spec.and_then(|s| s.rules.as_deref()).unwrap_or(&[]);

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
                let port = match resolve_backend_port(ns, svc, services) {
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

                let host_builder = builder.host_for(rule.host.as_deref());

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

        // Install spec.defaultBackend as prefix "/" on:
        //   - each rule host  → catches path-misses on hosts named in spec.rules
        //   - the catchall    → catches requests to hosts not named in any rule,
        //                       including rules-less Ingresses that claim all traffic
        //
        // Per-rule routes registered above are inserted as exact or as specific
        // prefix paths, so they outrank "/" via matchit's longest-match lookup.
        // The controller-wide --ingress-default-backend uses created_at = None
        // (sorts last), so this per-Ingress entry naturally wins on the catchall.
        if let Some(default_svc) = spec
            .and_then(|s| s.default_backend.as_ref())
            .and_then(|b| b.service.as_ref())
            && let Some(port) = resolve_backend_port(ns, default_svc, services)
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
                let make_entry = || {
                    Arc::new(RouteEntry::path_only(
                        Arc::clone(&upstream),
                        route_id.clone(),
                        created_at,
                    ))
                };
                for rule in rules {
                    builder
                        .host_for(rule.host.as_deref())
                        .add_prefix_route("/", make_entry());
                }
                builder.host_for(None).add_prefix_route("/", make_entry());
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
        owned_default_class: Option<&str>,
        builder: &mut TlsStoreBuilder,
    ) {
        let claimed_class = claimed_ingress_class(ingress);
        match claimed_class {
            None if owned_default_class.is_none() => return,
            None => {}
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
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use kube::api::ObjectMeta;
    use kube::runtime::{reflector, watcher};
    use std::collections::BTreeMap;

    fn owned(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn reconcile_no_default(
        ing: &Ingress,
        slices: &reflector::Store<EndpointSlice>,
        svcs: &reflector::Store<Service>,
        owned: &HashSet<String>,
        b: &mut RoutingTableBuilder,
    ) {
        IngressReconciler::reconcile(ing, slices, svcs, owned, None, b);
    }

    fn reconcile_tls_no_default(
        ing: &Ingress,
        secrets: &reflector::Store<Secret>,
        owned: &HashSet<String>,
        b: &mut TlsStoreBuilder,
    ) {
        IngressReconciler::reconcile_tls(ing, secrets, owned, None, b);
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

    fn make_svc_store(services: Vec<Service>) -> reflector::Store<Service> {
        let mut writer = reflector::store::Writer::<Service>::default();
        for svc in services {
            writer.apply_watcher_event(&watcher::Event::Apply(svc));
        }
        writer.as_reader()
    }

    fn make_service_with_named_port(
        ns: &str,
        name: &str,
        port_name: &str,
        port_number: i32,
    ) -> Service {
        use k8s_openapi::api::core::v1::{ServicePort, ServiceSpec};
        Service {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                ports: Some(vec![ServicePort {
                    name: Some(port_name.to_string()),
                    port: port_number,
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn make_ingress_named_port(
        ns: &str,
        host: Option<&str>,
        svc: &str,
        port_name: &str,
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
                            path: Some("/named".to_string()),
                            path_type: "Exact".to_string(),
                            backend: IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: svc.to_string(),
                                    port: Some(ServiceBackendPort {
                                        name: Some(port_name.to_string()),
                                        number: None,
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
        reconcile_no_default(
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
    fn reconcile_default_backend_only_routes_all_traffic() {
        let store = slice_store(vec![make_slice("default", "default-svc", "10.0.0.1")]);
        let ingress = make_default_only_ingress("default", "default-svc");
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert_eq!(
            table.route("any.host.com", "/", &ctx).unwrap().name,
            "default/default-svc"
        );
        assert_eq!(
            table.route("other.io", "/api/v1", &ctx).unwrap().name,
            "default/default-svc"
        );
    }

    #[test]
    fn reconcile_default_backend_catches_unmatched_host() {
        let store = slice_store(vec![
            make_slice("default", "rule-svc", "10.0.0.1"),
            make_slice("default", "default-svc", "10.0.0.2"),
        ]);
        let ingress = make_ingress_with_default(
            "default",
            Some("a.com"),
            "/api",
            "rule-svc",
            Some("default-svc"),
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert_eq!(
            table.route("a.com", "/api", &ctx).unwrap().name,
            "default/rule-svc"
        );
        assert_eq!(
            table.route("a.com", "/other", &ctx).unwrap().name,
            "default/default-svc"
        );
        assert_eq!(
            table.route("b.com", "/", &ctx).unwrap().name,
            "default/default-svc"
        );
    }

    fn make_ingress_with_timestamp(
        ns: &str,
        host: Option<&str>,
        path: &str,
        path_type: &str,
        svc: &str,
        created_at_ms: i64,
    ) -> Ingress {
        Ingress {
            metadata: ObjectMeta {
                name: Some(format!("{svc}-ingress")),
                namespace: Some(ns.to_string()),
                creation_timestamp: Some(Time(
                    k8s_openapi::jiff::Timestamp::from_millisecond(created_at_ms).unwrap(),
                )),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some("coxswain".to_string()),
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
    fn reconcile_older_ingress_wins_same_prefix_path() {
        let store = slice_store(vec![
            make_slice("default", "old-svc", "10.0.0.1"),
            make_slice("default", "new-svc", "10.0.0.2"),
        ]);
        let old_ingress = make_ingress_with_timestamp(
            "default",
            Some("example.com"),
            "/foo",
            "Prefix",
            "old-svc",
            1000,
        );
        let new_ingress = make_ingress_with_timestamp(
            "default",
            Some("example.com"),
            "/foo",
            "Prefix",
            "new-svc",
            2000,
        );

        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &old_ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        reconcile_no_default(
            &new_ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert_eq!(
            table.route("example.com", "/foo", &ctx).unwrap().name,
            "default/old-svc",
            "older Ingress should win on conflicting Prefix /foo"
        );
    }

    #[test]
    fn reconcile_exact_beats_prefix_same_path() {
        let store = slice_store(vec![
            make_slice("default", "exact-svc", "10.0.0.1"),
            make_slice("default", "prefix-svc", "10.0.0.2"),
        ]);
        let ingress = Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some("coxswain".to_string()),
                rules: Some(vec![IngressRule {
                    host: Some("example.com".to_string()),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![
                            HTTPIngressPath {
                                path: Some("/foo".to_string()),
                                path_type: "Exact".to_string(),
                                backend: IngressBackend {
                                    service: Some(IngressServiceBackend {
                                        name: "exact-svc".to_string(),
                                        port: Some(ServiceBackendPort {
                                            number: Some(80),
                                            ..Default::default()
                                        }),
                                    }),
                                    ..Default::default()
                                },
                            },
                            HTTPIngressPath {
                                path: Some("/foo".to_string()),
                                path_type: "Prefix".to_string(),
                                backend: IngressBackend {
                                    service: Some(IngressServiceBackend {
                                        name: "prefix-svc".to_string(),
                                        port: Some(ServiceBackendPort {
                                            number: Some(80),
                                            ..Default::default()
                                        }),
                                    }),
                                    ..Default::default()
                                },
                            },
                        ],
                    }),
                }]),
                ..Default::default()
            }),
            status: None,
        };
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert_eq!(
            table.route("example.com", "/foo", &ctx).unwrap().name,
            "default/exact-svc",
            "Exact /foo should win over Prefix /foo"
        );
        assert_eq!(
            table.route("example.com", "/foo/sub", &ctx).unwrap().name,
            "default/prefix-svc",
            "Prefix /foo should still match /foo/sub"
        );
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
        reconcile_no_default(
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
        reconcile_no_default(
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
        reconcile_no_default(
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
        reconcile_no_default(
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
    fn reconcile_named_port_resolves_to_route() {
        let slices = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let svcs = make_svc_store(vec![make_service_with_named_port(
            "default", "svc", "http", 80,
        )]);
        let ingress = make_ingress_named_port("default", Some("example.com"), "svc", "http");
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &slices,
            &svcs,
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        let route = table.route("example.com", "/named", &ctx);
        assert!(
            route.is_some(),
            "named port backend should resolve to a route"
        );
        assert_eq!(route.unwrap().name, "default/svc");
    }

    #[test]
    fn reconcile_named_port_skips_when_service_missing() {
        let slices = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        // No Service in the store → port_for_name returns None → path skipped
        let ingress = make_ingress_named_port("default", Some("example.com"), "svc", "http");
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &slices,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            table
                .route("example.com", "/named", &RequestContext::default())
                .is_none()
        );
    }

    #[test]
    fn reconcile_named_port_skips_when_port_name_not_found() {
        let slices = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        // Service exists but has port name "grpc", not "http"
        let svcs = make_svc_store(vec![make_service_with_named_port(
            "default", "svc", "grpc", 9000,
        )]);
        let ingress = make_ingress_named_port("default", Some("example.com"), "svc", "http");
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &slices,
            &svcs,
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            table
                .route("example.com", "/named", &RequestContext::default())
                .is_none()
        );
    }

    #[test]
    fn reconcile_named_port_default_backend_resolves() {
        let slices = slice_store(vec![
            make_slice("default", "rule-svc", "10.0.0.1"),
            make_slice("default", "default-svc", "10.0.0.2"),
        ]);
        let svcs = make_svc_store(vec![make_service_with_named_port(
            "default",
            "default-svc",
            "http",
            80,
        )]);
        let ingress = Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some("coxswain".to_string()),
                rules: Some(vec![IngressRule {
                    host: Some("example.com".to_string()),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![HTTPIngressPath {
                            path: Some("/api".to_string()),
                            path_type: "Prefix".to_string(),
                            backend: IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: "rule-svc".to_string(),
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
                default_backend: Some(IngressBackend {
                    service: Some(IngressServiceBackend {
                        name: "default-svc".to_string(),
                        port: Some(ServiceBackendPort {
                            name: Some("http".to_string()),
                            number: None,
                            ..Default::default()
                        }),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            status: None,
        };
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &slices,
            &svcs,
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
        reconcile_no_default(
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
        reconcile_no_default(
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
        reconcile_no_default(
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
        reconcile_no_default(
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
        reconcile_no_default(
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
        reconcile_no_default(
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
        reconcile_no_default(
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
        reconcile_no_default(
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
        reconcile_no_default(
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
        reconcile_no_default(
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
        reconcile_no_default(
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
    fn reconcile_claims_unclassified_when_owned_default_exists() {
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
            Some("coxswain"),
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
    fn reconcile_skips_unclassified_when_no_owned_default() {
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
            None,
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
        reconcile_no_default(
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
        reconcile_no_default(
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
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
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
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
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
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
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
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
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
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
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
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
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
        reconcile_no_default(
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
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut tls_builder);
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
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        let store = builder.build();
        assert!(store.find_cert("a.example.com").is_some());
        assert!(store.find_cert("b.example.com").is_some());
    }
}
