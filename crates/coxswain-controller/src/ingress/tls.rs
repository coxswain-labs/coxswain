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
