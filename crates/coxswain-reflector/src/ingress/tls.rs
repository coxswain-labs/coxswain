//! Ingress TLS reconciliation: maps `spec.tls[].secretName` entries into the TLS store.

use super::IngressReconciler;
use super::class::claimed_ingress_class;
use crate::tls::load_tls_cert;
use coxswain_core::tls::TlsStoreBuilder;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::reflector;
use std::collections::HashSet;
use std::sync::Arc;

impl IngressReconciler {
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

            let hosts = tls.hosts.as_deref().unwrap_or(&[]);
            if hosts.is_empty() {
                let fallback: Vec<&str> = spec
                    .and_then(|s| s.rules.as_deref())
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|r| r.host.as_deref())
                    .filter(|h| !h.is_empty())
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();
                tracing::warn!(
                    ingress = ?ingress.metadata.name,
                    secret = %format!("{ns}/{secret_name}"),
                    fallback_hosts = ?fallback,
                    "spec.tls[].hosts is empty or omitted — applying cert to rule hosts as fallback"
                );
                for host in &fallback {
                    builder.add_cert(host, Arc::clone(&cert));
                }
            } else {
                for host in hosts {
                    builder.add_cert(host, Arc::clone(&cert));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::tests::*;
    use coxswain_core::routing::{RequestContext, RoutingTableBuilder};
    use coxswain_core::tls::TlsStoreBuilder;
    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::api::networking::v1::{
        HTTPIngressPath, HTTPIngressRuleValue, IngressBackend, IngressRule, IngressServiceBackend,
        IngressSpec, IngressTLS, ServiceBackendPort,
    };
    use kube::api::ObjectMeta;
    use kube::runtime::{reflector, watcher};
    use std::collections::BTreeMap;

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
                .route(80, "example.com", "/", &RequestContext::default())
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

    // -------------------------------------------------------------------------
    // reconcile_tls: empty/omitted hosts fallback tests
    // -------------------------------------------------------------------------

    #[tracing_test::traced_test]
    #[test]
    fn reconcile_tls_falls_back_to_rule_hosts_when_hosts_omitted() {
        let secrets = secret_store(vec![make_tls_secret("default", "my-cert")]);
        let ingress = make_ingress_with_tls(
            "default",
            "coxswain",
            vec![IngressTLS {
                hosts: None,
                secret_name: Some("my-cert".to_string()),
            }],
        );
        let mut builder = TlsStoreBuilder::new();
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        let store = builder.build();
        // make_ingress_with_tls has spec.rules[0].host = "example.com"
        assert!(store.find_cert("example.com").is_some());
        assert!(logs_contain("my-cert"));
        assert!(logs_contain("hosts is empty or omitted"));
    }

    #[tracing_test::traced_test]
    #[test]
    fn reconcile_tls_falls_back_to_rule_hosts_when_hosts_empty() {
        let secrets = secret_store(vec![make_tls_secret("default", "my-cert")]);
        let ingress = make_ingress_with_tls(
            "default",
            "coxswain",
            vec![IngressTLS {
                hosts: Some(vec![]),
                secret_name: Some("my-cert".to_string()),
            }],
        );
        let mut builder = TlsStoreBuilder::new();
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        let store = builder.build();
        assert!(store.find_cert("example.com").is_some());
        assert!(logs_contain("my-cert"));
        assert!(logs_contain("hosts is empty or omitted"));
    }

    #[test]
    fn reconcile_tls_fallback_includes_wildcard_rule_host() {
        let secrets = secret_store(vec![make_tls_secret("default", "wildcard-cert")]);
        let ingress = make_ingress_with_tls(
            "default",
            "coxswain",
            vec![IngressTLS {
                hosts: None,
                secret_name: Some("wildcard-cert".to_string()),
            }],
        );
        // Reuse make_ingress_with_tls but override the rule host to a wildcard.
        let mut wildcard_ingress = ingress;
        wildcard_ingress
            .spec
            .as_mut()
            .unwrap()
            .rules
            .as_mut()
            .unwrap()[0]
            .host = Some("*.example.com".to_string());

        let mut builder = TlsStoreBuilder::new();
        reconcile_tls_no_default(
            &wildcard_ingress,
            &secrets,
            &owned(&["coxswain"]),
            &mut builder,
        );
        let store = builder.build();
        assert!(store.find_cert("api.example.com").is_some());
    }

    #[tracing_test::traced_test]
    #[test]
    fn reconcile_tls_fallback_no_rule_hosts_registers_nothing() {
        let secrets = secret_store(vec![make_tls_secret("default", "my-cert")]);
        // Ingress whose sole rule has no host (catchall) and tls.hosts is empty.
        let ingress = Ingress {
            metadata: ObjectMeta {
                name: Some("no-host-ingress".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some("coxswain".to_string()),
                rules: Some(vec![IngressRule {
                    host: None,
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
                tls: Some(vec![IngressTLS {
                    hosts: Some(vec![]),
                    secret_name: Some("my-cert".to_string()),
                }]),
                ..Default::default()
            }),
            status: None,
        };
        let mut builder = TlsStoreBuilder::new();
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        let store = builder.build();
        // No named rule hosts → no cert should be registered
        assert!(store.find_cert("any.host.com").is_none());
        assert!(logs_contain("hosts is empty or omitted"));
    }
}
