//! Gateway frontend client-certificate validation (GEP-91, #86).
//!
//! Parses `spec.tls.frontend.default.validation` on each owned HTTPS Gateway,
//! resolves the CA bundle from the referenced ConfigMap(s), and registers the
//! resulting [`ClientCertConfigState`] under every HTTPS listener's hostname in
//! the [`ClientCertStoreBuilder`].
//!
//! **Core support only**: a single `core/ConfigMap` reference with key `ca.crt`
//! in the same namespace as the Gateway.  Non-ConfigMap kinds, cross-namespace
//! refs, and multiple refs (Extended support) are planned as follow-ups and
//! fail-closed with `ClientCertConfigState::Unavailable` in the meantime.
//!
//! **perPort** (`spec.tls.frontend.perPort`) is intentionally out of scope: it
//! maps port overrides, but Coxswain's shared :443 listener is SNI-keyed, not
//! port-keyed.  Both GEP-91 feature flags advertise `spec.tls.frontend.default`
//! behaviour only.

use crate::gw_types::v::gateways::{
    Gateway, GatewayTlsFrontendDefaultValidationCaCertificateRefs,
    GatewayTlsFrontendDefaultValidationMode,
};
use coxswain_core::listener_health::{FrontendValidationHealth, GatewayListenerHealth};
use coxswain_core::tls::{ClientCertConfig, ClientCertConfigState, ClientCertStoreBuilder};
use k8s_openapi::api::core::v1::ConfigMap;
use kube::runtime::reflector;
use std::sync::Arc;

/// Resolve the frontend client-cert validation config for one Gateway and
/// register it in `builder` and `health`.
///
/// # No-op conditions
///
/// - `spec.tls` is absent.
/// - `spec.tls.frontend` is absent.
/// - `spec.tls.frontend.default.validation` is absent.
/// - The listener is not HTTPS (skipped per listener).
///
/// # Errors (→ `Unavailable`, `resolved_refs = false`)
///
/// - `caCertificateRefs` is empty.
/// - Any ref is not `core/ConfigMap`.
/// - The referenced ConfigMap is missing from the store.
/// - The ConfigMap has no `ca.crt` data key.
/// - The `ca.crt` bytes do not contain a PEM header.
pub(crate) fn reconcile_frontend_validation(
    gateway: &Gateway,
    configmaps: &reflector::Store<ConfigMap>,
    builder: &mut ClientCertStoreBuilder,
    health: &mut GatewayListenerHealth,
) {
    let gw_ns = gateway.metadata.namespace.as_deref().unwrap_or("default");
    let gw_name = gateway.metadata.name.as_deref().unwrap_or("unknown");

    // Walk the gateway-level spec.tls.frontend.default.validation.
    let Some(gw_tls) = &gateway.spec.tls else {
        return;
    };
    let Some(frontend) = &gw_tls.frontend else {
        return;
    };
    let Some(validation) = &frontend.default.validation else {
        return;
    };

    let insecure_fallback = matches!(
        validation.mode,
        Some(GatewayTlsFrontendDefaultValidationMode::AllowInsecureFallback)
    );

    // Resolve CA PEM from the caCertificateRefs (Core: single core/ConfigMap).
    let ca_result = resolve_ca_pem(gw_ns, gw_name, &validation.ca_certificate_refs, configmaps);
    let resolved_refs = ca_result.is_some();

    // Build the ClientCertConfigState: Config on success, Unavailable on failure (fail-closed).
    //
    // Default verify_depth=1 (leaf only, Istio MUTUAL convention).  Gateway API has no
    // pass_to_upstream equivalent, so that flag is always false for Gateway-sourced configs.
    let state = Arc::new(match ca_result {
        Some(ca_pem) => ClientCertConfigState::Config(
            ClientCertConfig::new(ca_pem, 1, false).with_insecure_fallback(insecure_fallback),
        ),
        None => ClientCertConfigState::Unavailable,
    });

    let message = if resolved_refs {
        String::new()
    } else {
        format!(
            "gateway {gw_ns}/{gw_name}: frontend CA ref resolution failed — \
             proxy fail-closes all HTTPS handshakes until corrected"
        )
    };

    let mut fv_health = FrontendValidationHealth::default();
    fv_health.insecure_fallback = insecure_fallback;
    fv_health.resolved_refs = resolved_refs;
    fv_health.message = message;
    health.frontend_validation = Some(fv_health);

    // Register the config_state under every HTTPS listener's hostname.
    //
    // Empty hostname → default slot in ClientCertStore (matches any SNI not
    // covered by an exact or wildcard entry).
    for listener in &gateway.spec.listeners {
        if listener.protocol != "HTTPS" {
            continue;
        }
        let hostname = listener.hostname.as_deref().unwrap_or("");
        builder.add_client_cert(hostname, Arc::clone(&state));
    }
}

/// Attempt to resolve a CA PEM bundle from the first `caCertificateRef`.
///
/// Returns `Some(pem_bytes)` on success, or `None` on any failure (fail-closed).
/// Logs a structured `warn!` on each failure path.
///
/// Core support: single `core/ConfigMap`, same-namespace, key `ca.crt`.
fn resolve_ca_pem(
    gw_ns: &str,
    gw_name: &str,
    refs: &[GatewayTlsFrontendDefaultValidationCaCertificateRefs],
    configmaps: &reflector::Store<ConfigMap>,
) -> Option<Vec<u8>> {
    if refs.is_empty() {
        tracing::warn!(
            ns = gw_ns,
            name = gw_name,
            "frontend validation has no caCertificateRefs — fail-closing"
        );
        return None;
    }

    // Core support: single ref.  Multiple refs = Extended; log and use only the first.
    if refs.len() > 1 {
        tracing::warn!(
            ns = gw_ns,
            name = gw_name,
            count = refs.len(),
            "frontend validation has multiple caCertificateRefs; \
             only the first is resolved (Extended support not yet implemented)"
        );
    }

    let ca_ref = &refs[0];
    let kind = ca_ref.kind.as_str();
    let group = ca_ref.group.as_str();

    // Core support: kind=ConfigMap, group="" or "core".
    if kind != "ConfigMap" || (!group.is_empty() && group != "core") {
        tracing::warn!(
            ns = gw_ns,
            name = gw_name,
            kind,
            group,
            "frontend caCertificateRef kind is not core/ConfigMap \
             (Extended support not yet implemented) — fail-closing"
        );
        return None;
    }

    // Cross-namespace refs require a ReferenceGrant; not implemented yet → same-ns only.
    let ref_ns = ca_ref.namespace.as_deref().unwrap_or(gw_ns);
    if ref_ns != gw_ns {
        tracing::warn!(
            ns = gw_ns,
            name = gw_name,
            ref_ns,
            ref_name = %ca_ref.name,
            "cross-namespace frontend caCertificateRef requires ReferenceGrant \
             (not yet implemented) — fail-closing"
        );
        return None;
    }

    let ref_key = reflector::ObjectRef::<ConfigMap>::new(&ca_ref.name).within(gw_ns);
    let Some(cm) = configmaps.get(&ref_key) else {
        tracing::warn!(
            ns = gw_ns,
            name = gw_name,
            ref_name = %ca_ref.name,
            "frontend caCertificateRef ConfigMap not found — fail-closing"
        );
        return None;
    };

    let Some(pem_str) = cm.data.as_ref().and_then(|d| d.get("ca.crt")) else {
        tracing::warn!(
            ns = gw_ns,
            name = gw_name,
            ref_name = %ca_ref.name,
            "frontend caCertificateRef ConfigMap missing 'ca.crt' key — fail-closing"
        );
        return None;
    };

    let pem = pem_str.as_bytes();
    if !pem.windows(10).any(|w| w == b"-----BEGIN") {
        tracing::warn!(
            ns = gw_ns,
            name = gw_name,
            ref_name = %ca_ref.name,
            "frontend caCertificateRef 'ca.crt' does not look like PEM — fail-closing"
        );
        return None;
    }

    Some(pem.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::tls::ClientCertStoreBuilder;
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::runtime::reflector::{self, store};
    use std::collections::BTreeMap;

    fn make_gateway(
        ns: &str,
        name: &str,
        listeners: Vec<(&str, &str)>, // (name, hostname)
        ca_ref_name: Option<&str>,
        mode: Option<GatewayTlsFrontendDefaultValidationMode>,
    ) -> Gateway {
        use crate::gw_types::v::gateways::{
            GatewayListeners, GatewaySpec, GatewayTls, GatewayTlsFrontend,
            GatewayTlsFrontendDefault, GatewayTlsFrontendDefaultValidation,
            GatewayTlsFrontendDefaultValidationCaCertificateRefs,
        };
        let validation = ca_ref_name.map(|n| GatewayTlsFrontendDefaultValidation {
            ca_certificate_refs: vec![GatewayTlsFrontendDefaultValidationCaCertificateRefs {
                group: String::new(),
                kind: "ConfigMap".to_string(),
                name: n.to_string(),
                namespace: None,
            }],
            mode,
        });
        Gateway {
            metadata: kube::core::ObjectMeta {
                namespace: Some(ns.to_string()),
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: String::new(),
                listeners: listeners
                    .into_iter()
                    .map(|(lname, hostname)| GatewayListeners {
                        name: lname.to_string(),
                        protocol: "HTTPS".to_string(),
                        port: 443,
                        hostname: if hostname.is_empty() {
                            None
                        } else {
                            Some(hostname.to_string())
                        },
                        ..Default::default()
                    })
                    .collect(),
                tls: Some(GatewayTls {
                    backend: None,
                    frontend: Some(GatewayTlsFrontend {
                        default: GatewayTlsFrontendDefault { validation },
                        per_port: None,
                    }),
                }),
                ..Default::default()
            },
            status: None,
        }
    }

    fn empty_cm_store() -> reflector::Store<ConfigMap> {
        let (reader, _writer) = store::store::<ConfigMap>();
        reader
    }

    fn cm_store_with(ns: &str, name: &str, ca_pem: &str) -> reflector::Store<ConfigMap> {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        let (reader, mut writer) = store::store::<ConfigMap>();
        let mut data = BTreeMap::new();
        data.insert("ca.crt".to_string(), ca_pem.to_string());
        writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(ConfigMap {
            metadata: ObjectMeta {
                namespace: Some(ns.to_string()),
                name: Some(name.to_string()),
                resource_version: Some("1".to_string()),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        }));
        reader
    }

    #[test]
    fn no_frontend_validation_is_no_op() {
        let gw = make_gateway("default", "gw", vec![("l1", "example.com")], None, None);
        let cms = empty_cm_store();
        let mut builder = ClientCertStoreBuilder::new();
        let mut health = GatewayListenerHealth::default();
        reconcile_frontend_validation(&gw, &cms, &mut builder, &mut health);
        assert!(health.frontend_validation.is_none());
        assert_eq!(builder.build().host_count(), 0);
    }

    #[test]
    fn valid_configmap_produces_config_state() {
        const FAKE_PEM: &str = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n";
        let gw = make_gateway(
            "default",
            "gw",
            vec![("l1", "example.com")],
            Some("my-ca"),
            None,
        );
        let cms = cm_store_with("default", "my-ca", FAKE_PEM);
        let mut builder = ClientCertStoreBuilder::new();
        let mut health = GatewayListenerHealth::default();
        reconcile_frontend_validation(&gw, &cms, &mut builder, &mut health);

        let fv = health.frontend_validation.as_ref().unwrap();
        assert!(fv.resolved_refs, "resolved_refs should be true");
        assert!(!fv.insecure_fallback);

        let store = builder.build();
        assert_eq!(store.host_count(), 1);
        let state = store.find_config("example.com").unwrap();
        assert!(
            matches!(state.as_ref(), ClientCertConfigState::Config(cfg) if !cfg.allow_insecure_fallback),
            "AllowValidOnly: allow_insecure_fallback should be false"
        );
    }

    #[test]
    fn missing_configmap_produces_unavailable() {
        let gw = make_gateway(
            "default",
            "gw",
            vec![("l1", "example.com")],
            Some("missing-ca"),
            None,
        );
        let cms = empty_cm_store();
        let mut builder = ClientCertStoreBuilder::new();
        let mut health = GatewayListenerHealth::default();
        reconcile_frontend_validation(&gw, &cms, &mut builder, &mut health);

        let fv = health.frontend_validation.as_ref().unwrap();
        assert!(!fv.resolved_refs, "resolved_refs should be false");
        assert!(!fv.message.is_empty(), "failure message should be set");

        let store = builder.build();
        assert_eq!(store.host_count(), 1);
        let state = store.find_config("example.com").unwrap();
        assert!(
            matches!(state.as_ref(), ClientCertConfigState::Unavailable),
            "missing ConfigMap should produce Unavailable"
        );
    }

    #[test]
    fn insecure_fallback_mode_sets_flag() {
        const FAKE_PEM: &str = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n";
        let gw = make_gateway(
            "default",
            "gw",
            vec![("l1", "example.com")],
            Some("my-ca"),
            Some(GatewayTlsFrontendDefaultValidationMode::AllowInsecureFallback),
        );
        let cms = cm_store_with("default", "my-ca", FAKE_PEM);
        let mut builder = ClientCertStoreBuilder::new();
        let mut health = GatewayListenerHealth::default();
        reconcile_frontend_validation(&gw, &cms, &mut builder, &mut health);

        let fv = health.frontend_validation.as_ref().unwrap();
        assert!(fv.insecure_fallback, "insecure_fallback should be true");
        assert!(fv.resolved_refs);

        let store = builder.build();
        let state = store.find_config("example.com").unwrap();
        assert!(
            matches!(state.as_ref(), ClientCertConfigState::Config(cfg) if cfg.allow_insecure_fallback),
            "allow_insecure_fallback should be set on the config"
        );
    }

    #[test]
    fn non_configmap_kind_produces_unavailable() {
        use crate::gw_types::v::gateways::{
            GatewayListeners, GatewaySpec, GatewayTls, GatewayTlsFrontend,
            GatewayTlsFrontendDefault, GatewayTlsFrontendDefaultValidation,
            GatewayTlsFrontendDefaultValidationCaCertificateRefs,
        };
        let gw = Gateway {
            metadata: kube::core::ObjectMeta {
                namespace: Some("default".to_string()),
                name: Some("gw".to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: String::new(),
                listeners: vec![GatewayListeners {
                    name: "l1".to_string(),
                    protocol: "HTTPS".to_string(),
                    port: 443,
                    hostname: Some("example.com".to_string()),
                    ..Default::default()
                }],
                tls: Some(GatewayTls {
                    backend: None,
                    frontend: Some(GatewayTlsFrontend {
                        default: GatewayTlsFrontendDefault {
                            validation: Some(GatewayTlsFrontendDefaultValidation {
                                ca_certificate_refs: vec![
                                    GatewayTlsFrontendDefaultValidationCaCertificateRefs {
                                        group: String::new(),
                                        kind: "Secret".to_string(), // wrong kind — non-ConfigMap
                                        name: "my-secret".to_string(),
                                        namespace: None,
                                    },
                                ],
                                mode: None,
                            }),
                        },
                        per_port: None,
                    }),
                }),
                ..Default::default()
            },
            status: None,
        };
        let cms = empty_cm_store();
        let mut builder = ClientCertStoreBuilder::new();
        let mut health = GatewayListenerHealth::default();
        reconcile_frontend_validation(&gw, &cms, &mut builder, &mut health);

        let fv = health.frontend_validation.as_ref().unwrap();
        assert!(!fv.resolved_refs);
        let state = builder.build().find_config("example.com").unwrap();
        assert!(
            matches!(state.as_ref(), ClientCertConfigState::Unavailable),
            "non-ConfigMap kind should produce Unavailable"
        );
    }
}
