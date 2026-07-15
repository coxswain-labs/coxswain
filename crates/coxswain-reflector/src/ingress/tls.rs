//! Ingress TLS reconciliation: maps `spec.tls[].secretName` entries into the TLS store,
//! and `auth-tls-*` annotations into the client-cert mTLS store (#267).

use super::IngressReconciler;
use super::annotations::client_cert::{ClientCertAnnotation, parse_client_cert};
use super::class::claimed_ingress_class;
use crate::MergedStore;
use crate::tls::load_tls_cert;
use coxswain_core::tls::{
    ClientCertConfig, ClientCertConfigState, ClientCertStoreBuilder, PortTlsStoreBuilder,
};
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
    /// `https_port` is the fixed Ingress data-plane HTTPS bind port (#472): all
    /// Ingress TLS certs key under it in the per-port store, since Ingresses
    /// share the one fixed HTTPS listener (they merge by host, not per-Ingress
    /// addressing). The proxy's per-port `SniCertSelector` on that port finds them.
    pub fn reconcile_tls(
        ingress: &Ingress,
        secrets: &MergedStore<Secret>,
        owned_classes: &HashSet<String>,
        owned_default_class: Option<&str>,
        builder: &mut PortTlsStoreBuilder,
        https_port: u16,
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
                    builder.add_cert(https_port, host, Arc::clone(&cert));
                }
            } else {
                for host in hosts {
                    builder.add_cert(https_port, host, Arc::clone(&cert));
                }
            }
        }
    }

    /// Reads the `auth-tls-*` annotations from `ingress` and registers per-host
    /// client-cert mTLS configuration in `builder`.
    ///
    /// Applies the same IngressClass filter as `reconcile()`.  The CA Secret is
    /// looked up from the label-scoped `auth_tls_secrets` store and resolved to
    /// [`ClientCertConfigState::Config`]; any failure (missing Secret, wrong
    /// label, no `ca.crt` key, unparseable PEM) produces
    /// [`ClientCertConfigState::Unavailable`] so the proxy fails closed by
    /// aborting every TLS handshake to the affected host.
    ///
    /// Host set is derived from `spec.tls[].hosts` exactly as [`Self::reconcile_tls`]
    /// does (with the empty→rule-host fallback), guaranteeing that every mTLS host
    /// also has a server certificate registered.
    ///
    /// **v1 limitation:** `auth-tls-*` is read directly from
    /// `ingress.metadata.annotations` and does not inherit IngressClass-parameter
    /// annotation defaults.
    ///
    /// `https_port` is the fixed Ingress data-plane HTTPS bind port (#472):
    /// every mTLS config is keyed under it so the proxy's port-scoped lookup
    /// finds it, and so Ingress configs can never collide with Gateway
    /// listeners (which key their own internal ports).
    pub fn reconcile_client_certs(
        ingress: &Ingress,
        auth_tls_secrets: &MergedStore<Secret>,
        owned_classes: &HashSet<String>,
        owned_default_class: Option<&str>,
        builder: &mut ClientCertStoreBuilder,
        https_port: u16,
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

        // Parse the auth-tls annotation cluster.  None → mTLS not requested.
        let route_id = format!(
            "{}/{}",
            ns,
            ingress.metadata.name.as_deref().unwrap_or("<unknown>")
        );
        let raw_annotations = match ingress.metadata.annotations.as_ref() {
            Some(a) => a,
            None => return,
        };
        let Some(ann) = parse_client_cert(raw_annotations, &route_id) else {
            return;
        };

        // Resolve the CA Secret to a ClientCertConfigState.  Fail-closed.
        let config_state = Arc::new(resolve_client_cert_config(
            &ann,
            auth_tls_secrets,
            &route_id,
            ns,
        ));

        // Derive the host set from spec.tls[].hosts (same fallback as reconcile_tls).
        let tls_blocks = match spec.and_then(|s| s.tls.as_deref()) {
            Some(t) if !t.is_empty() => t,
            _ => {
                tracing::warn!(
                    ingress = %route_id,
                    "auth-tls-secret annotation present but spec.tls is empty \
                     — mTLS config has no hosts to register"
                );
                return;
            }
        };

        for tls in tls_blocks {
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
                for host in &fallback {
                    builder.add_client_cert(https_port, host, Arc::clone(&config_state));
                }
            } else {
                for host in hosts {
                    builder.add_client_cert(https_port, host, Arc::clone(&config_state));
                }
            }
        }
    }
}

/// Resolve the CA Secret referenced by `ann` into a [`ClientCertConfigState`].
///
/// # Errors (→ `Unavailable`)
///
/// - Secret not found in the reflector (not labeled / not cached).
/// - Belt-and-suspenders: label `ingress.coxswain-labs.dev/auth-tls=true` absent.
/// - `data["ca.crt"]` missing.
/// - PEM bytes not parseable as at least one X.509 certificate.
fn resolve_client_cert_config(
    ann: &ClientCertAnnotation,
    auth_tls_secrets: &MergedStore<Secret>,
    route_id: &str,
    ingress_ns: &str,
) -> ClientCertConfigState {
    let ns = if ann.secret.namespace.is_empty() {
        ingress_ns
    } else {
        &ann.secret.namespace
    };

    let key = reflector::ObjectRef::<Secret>::new(&ann.secret.name).within(ns);
    let Some(secret) = auth_tls_secrets.get(&key) else {
        tracing::warn!(
            ingress = %route_id,
            secret_ns = %ns,
            secret_name = %ann.secret.name,
            "auth-tls-secret not found in auth-tls reflector — \
             is the Secret labeled ingress.coxswain-labs.dev/auth-tls=true? \
             failing closed (TLS handshakes to this host will be aborted)"
        );
        return ClientCertConfigState::Unavailable;
    };

    // Belt-and-suspenders: guard against label removal during a reconcile race.
    let has_label = secret
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get("ingress.coxswain-labs.dev/auth-tls"))
        .is_some_and(|v| v == "true");
    if !has_label {
        tracing::warn!(
            ingress = %route_id,
            secret_ns = %ns,
            secret_name = %ann.secret.name,
            "Secret is missing label ingress.coxswain-labs.dev/auth-tls=true — \
             failing closed (TLS handshakes to this host will be aborted)"
        );
        return ClientCertConfigState::Unavailable;
    }

    let Some(ca_pem) = secret
        .data
        .as_ref()
        .and_then(|d| d.get("ca.crt"))
        .map(|b| b.0.clone())
    else {
        tracing::warn!(
            ingress = %route_id,
            secret_ns = %ns,
            secret_name = %ann.secret.name,
            "auth-tls-secret has no 'ca.crt' data key — \
             failing closed (TLS handshakes to this host will be aborted)"
        );
        return ClientCertConfigState::Unavailable;
    };

    // Validate the PEM parses as at least one X.509 cert at reconcile time so
    // a malformed CA is caught here (controller log) rather than silently at
    // every TLS handshake in the proxy.
    if let Err(e) = validate_ca_pem(&ca_pem) {
        tracing::warn!(
            ingress = %route_id,
            secret_ns = %ns,
            secret_name = %ann.secret.name,
            error = %e,
            "auth-tls-secret ca.crt PEM is unparseable — \
             failing closed (TLS handshakes to this host will be aborted)"
        );
        return ClientCertConfigState::Unavailable;
    }

    ClientCertConfigState::Config(ClientCertConfig::new(
        ca_pem,
        ann.verify_depth,
        ann.pass_to_upstream,
    ))
}

/// Validate that `pem` decodes as at least one PEM-encoded X.509 certificate.
///
/// Used at reconcile time to fail-close on a misconfigured CA before the proxy
/// attempts to use the bytes at handshake time.
fn validate_ca_pem(pem: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use x509_parser::pem::Pem;

    let mut reader = std::io::Cursor::new(pem);
    let mut cert_count = 0usize;
    loop {
        match Pem::read(&mut reader) {
            Ok((p, _)) if p.label == "CERTIFICATE" => cert_count += 1,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    if cert_count == 0 {
        return Err("no X.509 certificates found in ca.crt PEM".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::tests::*;
    use coxswain_core::routing::{RequestContext, RoutingTableBuilder};
    use coxswain_core::tls::ClientCertStoreBuilder;
    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::api::networking::v1::{
        HTTPIngressPath, HTTPIngressRuleValue, IngressBackend, IngressRule, IngressServiceBackend,
        IngressSpec, IngressTLS, ServiceBackendPort,
    };
    use kube::api::ObjectMeta;
    use kube::runtime::{reflector, watcher};
    use std::collections::BTreeMap;

    fn secret_store(secrets: Vec<Secret>) -> MergedStore<Secret> {
        let mut writer = reflector::store::Writer::<Secret>::default();
        for secret in secrets {
            writer.apply_watcher_event(&watcher::Event::Apply(secret));
        }
        MergedStore::single(writer.as_reader())
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
        let mut builder = PortTlsStoreBuilder::new();
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        let store = builder.build();
        assert!(pcert(&store, "example.com").is_some());
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
        let mut builder = PortTlsStoreBuilder::new();
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        assert!(pcert(&builder.build(), "example.com").is_none());
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
        let mut builder = PortTlsStoreBuilder::new();
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        assert!(pcert(&builder.build(), "example.com").is_none());
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
        let mut builder = PortTlsStoreBuilder::new();
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        assert!(pcert(&builder.build(), "example.com").is_none());
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
        let mut builder = PortTlsStoreBuilder::new();
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        assert!(pcert(&builder.build(), "example.com").is_none());
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
        let mut builder = PortTlsStoreBuilder::new();
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        assert!(pcert(&builder.build(), "example.com").is_none());
    }

    #[test]
    fn reconcile_tls_failure_does_not_affect_routes() {
        let slice_st = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
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
        let mut tls_builder = PortTlsStoreBuilder::new();
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut tls_builder);
        assert!(pcert(&tls_builder.build(), "example.com").is_none());
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
        let mut builder = PortTlsStoreBuilder::new();
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        let store = builder.build();
        assert!(pcert(&store, "a.example.com").is_some());
        assert!(pcert(&store, "b.example.com").is_some());
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
        let mut builder = PortTlsStoreBuilder::new();
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        let store = builder.build();
        // make_ingress_with_tls has spec.rules[0].host = "example.com"
        assert!(pcert(&store, "example.com").is_some());
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
        let mut builder = PortTlsStoreBuilder::new();
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        let store = builder.build();
        assert!(pcert(&store, "example.com").is_some());
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

        let mut builder = PortTlsStoreBuilder::new();
        reconcile_tls_no_default(
            &wildcard_ingress,
            &secrets,
            &owned(&["coxswain"]),
            &mut builder,
        );
        let store = builder.build();
        assert!(pcert(&store, "api.example.com").is_some());
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
        let mut builder = PortTlsStoreBuilder::new();
        reconcile_tls_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        let store = builder.build();
        // No named rule hosts → no cert should be registered
        assert!(pcert(&store, "any.host.com").is_none());
        assert!(logs_contain("hosts is empty or omitted"));
    }

    // -------------------------------------------------------------------------
    // reconcile_client_certs tests
    // -------------------------------------------------------------------------

    // Valid PEM for tests — properly formed but not a real cert (fake DER body).
    const FAKE_CA_PEM: &[u8] =
        b"-----BEGIN CERTIFICATE-----\nMIIBIjANBg==\n-----END CERTIFICATE-----\n";

    fn make_auth_tls_secret(ns: &str, name: &str, ca_pem: &[u8]) -> Secret {
        let mut data = BTreeMap::new();
        data.insert("ca.crt".to_string(), ByteString(ca_pem.to_vec()));
        let mut labels = BTreeMap::new();
        labels.insert(
            "ingress.coxswain-labs.dev/auth-tls".to_string(),
            "true".to_string(),
        );
        Secret {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        }
    }

    fn make_ingress_with_auth_tls(
        ns: &str,
        class_name: &str,
        secret_ref: &str,
        tls: Vec<IngressTLS>,
    ) -> Ingress {
        let mut annotations = BTreeMap::new();
        annotations.insert(
            "ingress.coxswain-labs.dev/auth-tls-secret".to_string(),
            secret_ref.to_string(),
        );
        Ingress {
            metadata: ObjectMeta {
                name: Some("auth-tls-ingress".to_string()),
                namespace: Some(ns.to_string()),
                annotations: Some(annotations),
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
    fn reconcile_client_certs_registers_config_for_owned_ingress() {
        use coxswain_core::tls::ClientCertConfigState;
        let secrets = secret_store(vec![make_auth_tls_secret("default", "my-ca", FAKE_CA_PEM)]);
        let ingress = make_ingress_with_auth_tls(
            "default",
            "coxswain",
            "default/my-ca",
            vec![IngressTLS {
                hosts: Some(vec!["example.com".to_string()]),
                secret_name: Some("server-cert".to_string()),
            }],
        );
        let mut builder = ClientCertStoreBuilder::new();
        reconcile_client_certs_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        let store = builder.build();
        assert!(store.find_config(443, "example.com").is_some());
        assert!(matches!(
            store.find_config(443, "example.com").unwrap().as_ref(),
            ClientCertConfigState::Config(_)
        ));
    }

    #[test]
    fn reconcile_client_certs_absent_annotation_registers_nothing() {
        let secrets = secret_store(vec![make_auth_tls_secret("default", "my-ca", FAKE_CA_PEM)]);
        // Ingress without auth-tls-* annotations
        let ingress = make_ingress_with_tls(
            "default",
            "coxswain",
            vec![IngressTLS {
                hosts: Some(vec!["example.com".to_string()]),
                secret_name: Some("server-cert".to_string()),
            }],
        );
        let mut builder = ClientCertStoreBuilder::new();
        reconcile_client_certs_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        assert!(builder.build().find_config(443, "example.com").is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn reconcile_client_certs_missing_secret_produces_unavailable() {
        use coxswain_core::tls::ClientCertConfigState;
        let secrets = secret_store(vec![]); // empty reflector
        let ingress = make_ingress_with_auth_tls(
            "default",
            "coxswain",
            "default/missing-ca",
            vec![IngressTLS {
                hosts: Some(vec!["example.com".to_string()]),
                secret_name: Some("server-cert".to_string()),
            }],
        );
        let mut builder = ClientCertStoreBuilder::new();
        reconcile_client_certs_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        let store = builder.build();
        assert!(matches!(
            store.find_config(443, "example.com").unwrap().as_ref(),
            ClientCertConfigState::Unavailable
        ));
        assert!(logs_contain("auth-tls-secret not found"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn reconcile_client_certs_unlabeled_secret_produces_unavailable() {
        use coxswain_core::tls::ClientCertConfigState;
        let mut secret = make_auth_tls_secret("default", "my-ca", FAKE_CA_PEM);
        secret.metadata.labels = None; // strip the label
        let secrets = secret_store(vec![secret]);
        let ingress = make_ingress_with_auth_tls(
            "default",
            "coxswain",
            "default/my-ca",
            vec![IngressTLS {
                hosts: Some(vec!["example.com".to_string()]),
                secret_name: Some("server-cert".to_string()),
            }],
        );
        let mut builder = ClientCertStoreBuilder::new();
        reconcile_client_certs_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        let store = builder.build();
        assert!(matches!(
            store.find_config(443, "example.com").unwrap().as_ref(),
            ClientCertConfigState::Unavailable
        ));
        assert!(logs_contain("missing label"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn reconcile_client_certs_no_ca_crt_produces_unavailable() {
        use coxswain_core::tls::ClientCertConfigState;
        let mut secret = make_auth_tls_secret("default", "my-ca", FAKE_CA_PEM);
        secret.data.as_mut().unwrap().remove("ca.crt");
        let secrets = secret_store(vec![secret]);
        let ingress = make_ingress_with_auth_tls(
            "default",
            "coxswain",
            "default/my-ca",
            vec![IngressTLS {
                hosts: Some(vec!["example.com".to_string()]),
                secret_name: Some("server-cert".to_string()),
            }],
        );
        let mut builder = ClientCertStoreBuilder::new();
        reconcile_client_certs_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        let store = builder.build();
        assert!(matches!(
            store.find_config(443, "example.com").unwrap().as_ref(),
            ClientCertConfigState::Unavailable
        ));
        assert!(logs_contain("no 'ca.crt' data key"));
    }

    #[test]
    fn reconcile_client_certs_skips_unowned_ingress() {
        let secrets = secret_store(vec![make_auth_tls_secret("default", "my-ca", FAKE_CA_PEM)]);
        let ingress = make_ingress_with_auth_tls(
            "default",
            "nginx", // not owned by coxswain
            "default/my-ca",
            vec![IngressTLS {
                hosts: Some(vec!["example.com".to_string()]),
                secret_name: Some("server-cert".to_string()),
            }],
        );
        let mut builder = ClientCertStoreBuilder::new();
        reconcile_client_certs_no_default(&ingress, &secrets, &owned(&["coxswain"]), &mut builder);
        assert!(builder.build().find_config(443, "example.com").is_none());
    }
}
