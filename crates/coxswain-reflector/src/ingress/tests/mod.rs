use super::*;
pub(super) use coxswain_core::routing::IngressRoutingTableBuilder;
pub(super) use coxswain_core::tls::{
    ClientCertStoreBuilder, PortTlsStore, PortTlsStoreBuilder, TlsCert,
};

/// Fixed Ingress HTTPS bind port used in tests (#472): all Ingress certs key
/// under it in the per-port store.
pub(super) const TEST_HTTPS_PORT: u16 = 443;

/// Look up a cert on the test HTTPS port of a per-port store.
pub(super) fn pcert(store: &PortTlsStore, host: &str) -> Option<std::sync::Arc<TlsCert>> {
    store.port(TEST_HTTPS_PORT).and_then(|s| s.find_cert(host))
}
pub(super) use k8s_openapi::api::core::v1::{Secret, Service};
pub(super) use k8s_openapi::api::discovery::v1::EndpointSlice;
pub(super) use k8s_openapi::api::networking::v1::{
    HTTPIngressPath, HTTPIngressRuleValue, Ingress, IngressBackend, IngressRule,
    IngressServiceBackend, IngressSpec, ServiceBackendPort,
};
pub(super) use kube::api::ObjectMeta;
pub(super) use kube::runtime::reflector;
pub(super) use std::collections::{BTreeMap, HashMap, HashSet};

pub(super) use crate::tests::fixtures::{
    empty_compression_store, empty_external_auth_store, empty_jwks_cache, empty_jwt_auth_store,
    empty_retry_policy_store, empty_secret_store, empty_svc_store, make_retry_policy_store,
    make_slice, make_svc_store, slice_store,
};

/// Empty `ReferenceGrant` set — every cross-namespace `CoxswainExternalAuth`
/// `backendRef` fails closed, matching production behaviour with no grants
/// applied.
pub(super) fn empty_backend_grants() -> crate::reference_grants::GrantSet {
    crate::reference_grants::GrantSet::default()
}

pub(super) fn owned(names: &[&str]) -> HashSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

pub(super) fn reconcile_no_default(
    ing: &Ingress,
    slices: &reflector::Store<EndpointSlice>,
    svcs: &reflector::Store<Service>,
    owned: &HashSet<String>,
    b: &mut IngressRoutingTableBuilder,
) {
    let no_class_defaults = HashMap::new();
    let _ = IngressReconciler::reconcile(
        ing,
        slices,
        svcs,
        &IngressClassContext::new(owned, None, &no_class_defaults),
        IngressPorts::new(Some(80), None),
        b,
        &crate::ingress::IngressExtensionStores::new(
            &empty_secret_store(),
            &empty_external_auth_store(),
            &empty_jwt_auth_store(),
            &empty_jwks_cache(),
            &empty_backend_grants(),
            &empty_compression_store(),
            &empty_retry_policy_store(),
        ),
    );
}

/// Like [`reconcile_no_default`] but with per-class params keyed by
/// IngressClass name — used to exercise the #190 class-defaults merge.
pub(super) fn reconcile_with_class_defaults(
    ing: &Ingress,
    slices: &reflector::Store<EndpointSlice>,
    svcs: &reflector::Store<Service>,
    owned: &HashSet<String>,
    defaults: &HashMap<String, crate::ingress::ResolvedClassParams>,
    b: &mut IngressRoutingTableBuilder,
) {
    let _ = IngressReconciler::reconcile(
        ing,
        slices,
        svcs,
        &IngressClassContext::new(owned, None, defaults),
        IngressPorts::new(Some(80), None),
        b,
        &crate::ingress::IngressExtensionStores::new(
            &empty_secret_store(),
            &empty_external_auth_store(),
            &empty_jwt_auth_store(),
            &empty_jwks_cache(),
            &empty_backend_grants(),
            &empty_compression_store(),
            &empty_retry_policy_store(),
        ),
    );
}

pub(super) fn reconcile_tls_no_default(
    ing: &Ingress,
    secrets: &reflector::Store<Secret>,
    owned: &HashSet<String>,
    b: &mut PortTlsStoreBuilder,
) {
    IngressReconciler::reconcile_tls(ing, secrets, owned, None, b, TEST_HTTPS_PORT);
}

pub(super) fn reconcile_client_certs_no_default(
    ing: &Ingress,
    auth_tls_secrets: &reflector::Store<Secret>,
    owned: &HashSet<String>,
    b: &mut ClientCertStoreBuilder,
) {
    IngressReconciler::reconcile_client_certs(ing, auth_tls_secrets, owned, None, b, 443);
}

pub(super) fn make_service_with_named_port(
    ns: &str,
    name: &str,
    port_name: &str,
    port_number: i32,
) -> Service {
    pub(super) use k8s_openapi::api::core::v1::{ServicePort, ServiceSpec};
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

pub(super) fn make_ingress_named_port(
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

pub(super) fn make_ingress(
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

pub(super) fn make_ingress_with_default(
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

/// Build an Ingress with arbitrary `ingress.coxswain-labs.dev/*` annotations.
///
/// `extra_annotations` supplements (or overrides) the `kubernetes.io/ingress.class`
/// annotation so tests can exercise the full annotation-parse → reconcile round-trip
/// without duplicating the boilerplate `make_ingress` setup.
pub(super) fn make_ingress_with_annotations(
    ns: &str,
    host: Option<&str>,
    path: &str,
    svc: &str,
    extra_annotations: &[(&str, &str)],
) -> Ingress {
    let mut annotations: BTreeMap<String, String> = extra_annotations
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    // Always claim the "coxswain" class so reconcile does not skip it.
    annotations
        .entry("kubernetes.io/ingress.class".to_string())
        .or_insert_with(|| "coxswain".to_string());
    Ingress {
        metadata: ObjectMeta {
            name: Some("test-ingress".to_string()),
            namespace: Some(ns.to_string()),
            annotations: Some(annotations),
            ..Default::default()
        },
        spec: Some(IngressSpec {
            ingress_class_name: Some("coxswain".to_string()),
            rules: Some(vec![IngressRule {
                host: host.map(str::to_string),
                http: Some(HTTPIngressRuleValue {
                    paths: vec![HTTPIngressPath {
                        path: Some(path.to_string()),
                        path_type: "Prefix".to_string(),
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

pub(super) fn make_default_only_ingress(ns: &str, default_svc: &str) -> Ingress {
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
