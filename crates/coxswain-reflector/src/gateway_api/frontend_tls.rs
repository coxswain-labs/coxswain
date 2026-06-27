//! Gateway frontend client-certificate validation (GEP-91, #86).
//!
//! Parses `spec.tls.frontend` on each owned HTTPS Gateway, resolves the CA
//! bundle from the referenced ConfigMap, and registers the resulting
//! [`ClientCertConfigState`] under the listener's hostname in the
//! [`ClientCertStoreBuilder`]. Validation is resolved **per listener**: the
//! effective config is the `perPort[listener.port]` override if present, else
//! the gateway-wide `default`.
//!
//! **Core support**: a single `core/ConfigMap` reference with key `ca.crt`.
//! Cross-namespace refs are permitted via a `Gateway → ConfigMap`
//! [`ReferenceGrant`](crate::reference_grants). Each resolution failure is
//! classified into the per-listener [`FrontendValidationOutcome`] that drives
//! the listener's GEP-91 status conditions:
//! - kind not `ConfigMap` → `InvalidCACertificateKind`
//! - cross-namespace without a grant → `RefNotPermitted`
//! - missing ConfigMap / no `ca.crt` / not PEM → `InvalidCACertificateRef`

use crate::gw_types::v::gateways::{
    Gateway, GatewayTlsFrontend, GatewayTlsFrontendDefaultValidationMode,
    GatewayTlsFrontendPerPortTlsValidationMode,
};
use coxswain_core::listener_health::{
    FrontendValidationHealth, FrontendValidationOutcome, GatewayListenerHealth, ListenerHealthKey,
};
use coxswain_core::reference_grants::{ReferenceGrantKey, backend_ref_allowed};
use coxswain_core::tls::{ClientCertConfig, ClientCertConfigState, ClientCertStoreBuilder};
use k8s_openapi::api::core::v1::ConfigMap;
use kube::runtime::reflector;
use std::collections::HashSet;
use std::sync::Arc;

/// One `caCertificateRefs` entry normalized across the `default` and `perPort`
/// ref types (which are distinct generated structs with identical fields).
struct NormalizedRef<'a> {
    group: &'a str,
    kind: &'a str,
    name: &'a str,
    namespace: Option<&'a str>,
}

/// The effective validation config for one listener: its CA refs and whether
/// the mode is `AllowInsecureFallback`.
struct EffectiveValidation<'a> {
    refs: Vec<NormalizedRef<'a>>,
    insecure_fallback: bool,
}

/// Resolution result for a listener's CA ref, mapped 1:1 onto
/// [`FrontendValidationOutcome`].
enum CaResolution {
    Ok(Vec<u8>),
    InvalidKind(String),
    RefNotPermitted(String),
    InvalidRef(String),
}

/// Resolve per-listener frontend client-cert validation for one Gateway and
/// register it in `builder`, annotating per-listener [`FrontendValidationOutcome`]
/// and the gateway-wide [`FrontendValidationHealth`] in `health`.
///
/// For every HTTPS listener the effective validation is `perPort[port]` if a
/// matching entry exists, else `default`. Listeners with no effective validation
/// are left untouched (`FrontendValidationOutcome::NotApplicable`).
///
/// # No-op conditions
///
/// - `spec.tls` / `spec.tls.frontend` is absent.
/// - No HTTPS listener has an effective validation config.
pub(crate) fn reconcile_frontend_validation(
    gateway: &Gateway,
    configmaps: &reflector::Store<ConfigMap>,
    ca_grants: &HashSet<ReferenceGrantKey>,
    builder: &mut ClientCertStoreBuilder,
    health: &mut GatewayListenerHealth,
) {
    let gw_ns = gateway.metadata.namespace.as_deref().unwrap_or("default");
    let gw_name = gateway.metadata.name.as_deref().unwrap_or("unknown");

    let Some(gw_tls) = &gateway.spec.tls else {
        return;
    };
    let Some(frontend) = &gw_tls.frontend else {
        return;
    };

    let mut any_validation = false;
    let mut any_insecure_fallback = false;
    let mut any_failed = false;

    for listener in &gateway.spec.listeners {
        if listener.protocol != "HTTPS" {
            continue;
        }
        let Some(effective) = effective_validation(frontend, listener.port) else {
            continue;
        };
        any_validation = true;
        if effective.insecure_fallback {
            any_insecure_fallback = true;
        }

        let (state, outcome) =
            match resolve_ca(gw_ns, gw_name, &effective.refs, configmaps, ca_grants) {
                CaResolution::Ok(ca_pem) => (
                    ClientCertConfigState::Config(
                        ClientCertConfig::new(ca_pem, 1, false)
                            .with_insecure_fallback(effective.insecure_fallback),
                    ),
                    FrontendValidationOutcome::Resolved,
                ),
                CaResolution::InvalidKind(message) => (
                    ClientCertConfigState::Unavailable,
                    FrontendValidationOutcome::InvalidCACertificateKind { message },
                ),
                CaResolution::RefNotPermitted(message) => (
                    ClientCertConfigState::Unavailable,
                    FrontendValidationOutcome::RefNotPermitted { message },
                ),
                CaResolution::InvalidRef(message) => (
                    ClientCertConfigState::Unavailable,
                    FrontendValidationOutcome::InvalidCACertificateRef { message },
                ),
            };
        if outcome.is_failed() {
            any_failed = true;
        }

        // Empty hostname → default slot in ClientCertStore (matches any SNI not
        // covered by an exact or wildcard entry).
        let hostname = listener.hostname.as_deref().unwrap_or("");
        builder.add_client_cert(hostname, Arc::new(state));

        // Record the per-listener outcome. The entry was created by build_tls;
        // or_default() keeps this robust if the ordering ever changes.
        health
            .listeners
            .entry(ListenerHealthKey::gateway(listener.name.clone()))
            .or_default()
            .frontend_outcome = outcome;
    }

    if any_validation {
        let mut fv_health = FrontendValidationHealth::default();
        fv_health.insecure_fallback = any_insecure_fallback;
        fv_health.resolved_refs = !any_failed;
        fv_health.message = if any_failed {
            format!(
                "gateway {gw_ns}/{gw_name}: one or more frontend CA refs failed to resolve — \
                 affected HTTPS listeners fail-close until corrected"
            )
        } else {
            String::new()
        };
        health.frontend_validation = Some(fv_health);
    }
}

/// Compute the effective validation config for a listener on `port`: the
/// `perPort` entry whose port matches (overriding the default for that port),
/// else the gateway-wide `default`. A `perPort` entry that exists but carries no
/// `validation` overrides the default to "no validation" for that port.
fn effective_validation(
    frontend: &GatewayTlsFrontend,
    port: i32,
) -> Option<EffectiveValidation<'_>> {
    if let Some(pp) = frontend
        .per_port
        .as_ref()
        .and_then(|entries| entries.iter().find(|e| e.port == port))
    {
        let v = pp.tls.validation.as_ref()?;
        return Some(EffectiveValidation {
            insecure_fallback: matches!(
                v.mode,
                Some(GatewayTlsFrontendPerPortTlsValidationMode::AllowInsecureFallback)
            ),
            refs: v
                .ca_certificate_refs
                .iter()
                .map(|r| NormalizedRef {
                    group: &r.group,
                    kind: &r.kind,
                    name: &r.name,
                    namespace: r.namespace.as_deref(),
                })
                .collect(),
        });
    }

    let v = frontend.default.validation.as_ref()?;
    Some(EffectiveValidation {
        insecure_fallback: matches!(
            v.mode,
            Some(GatewayTlsFrontendDefaultValidationMode::AllowInsecureFallback)
        ),
        refs: v
            .ca_certificate_refs
            .iter()
            .map(|r| NormalizedRef {
                group: &r.group,
                kind: &r.kind,
                name: &r.name,
                namespace: r.namespace.as_deref(),
            })
            .collect(),
    })
}

/// Resolve a CA PEM bundle from the first `caCertificateRef`, classifying any
/// failure into a [`CaResolution`] variant.
///
/// Core support: a single `core/ConfigMap`, key `ca.crt`. Cross-namespace refs
/// require a `Gateway → ConfigMap` [`ReferenceGrant`](crate::reference_grants).
fn resolve_ca(
    gw_ns: &str,
    gw_name: &str,
    refs: &[NormalizedRef<'_>],
    configmaps: &reflector::Store<ConfigMap>,
    ca_grants: &HashSet<ReferenceGrantKey>,
) -> CaResolution {
    let Some(ca_ref) = refs.first() else {
        return CaResolution::InvalidRef(
            "frontend validation has no caCertificateRefs".to_string(),
        );
    };
    if refs.len() > 1 {
        tracing::warn!(
            ns = gw_ns,
            name = gw_name,
            count = refs.len(),
            "frontend validation has multiple caCertificateRefs; \
             only the first is resolved (Extended support not yet implemented)"
        );
    }

    // Core support: kind=ConfigMap, group="" or "core".
    if ca_ref.kind != "ConfigMap" || (!ca_ref.group.is_empty() && ca_ref.group != "core") {
        return CaResolution::InvalidKind(format!(
            "frontend caCertificateRef kind {}/{} is not core/ConfigMap",
            ca_ref.group, ca_ref.kind
        ));
    }

    // Cross-namespace refs require a Gateway → ConfigMap ReferenceGrant.
    let ref_ns = ca_ref.namespace.unwrap_or(gw_ns);
    if ref_ns != gw_ns && !backend_ref_allowed(gw_ns, ref_ns, ca_ref.name, ca_grants) {
        return CaResolution::RefNotPermitted(format!(
            "cross-namespace frontend caCertificateRef {ref_ns}/{} is not permitted by any ReferenceGrant",
            ca_ref.name
        ));
    }

    let ref_key = reflector::ObjectRef::<ConfigMap>::new(ca_ref.name).within(ref_ns);
    let Some(cm) = configmaps.get(&ref_key) else {
        return CaResolution::InvalidRef(format!(
            "frontend caCertificateRef ConfigMap {ref_ns}/{} not found",
            ca_ref.name
        ));
    };

    let Some(pem_str) = cm.data.as_ref().and_then(|d| d.get("ca.crt")) else {
        return CaResolution::InvalidRef(format!(
            "frontend caCertificateRef ConfigMap {ref_ns}/{} has no 'ca.crt' key",
            ca_ref.name
        ));
    };

    let pem = pem_str.as_bytes();
    if !pem.windows(10).any(|w| w == b"-----BEGIN") {
        return CaResolution::InvalidRef(format!(
            "frontend caCertificateRef ConfigMap {ref_ns}/{} 'ca.crt' is not PEM",
            ca_ref.name
        ));
    }

    CaResolution::Ok(pem.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::tls::ClientCertStoreBuilder;
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::runtime::reflector::{self, store};
    use std::collections::{BTreeMap, HashSet};

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
        reconcile_frontend_validation(&gw, &cms, &HashSet::new(), &mut builder, &mut health);
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
        reconcile_frontend_validation(&gw, &cms, &HashSet::new(), &mut builder, &mut health);

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
        reconcile_frontend_validation(&gw, &cms, &HashSet::new(), &mut builder, &mut health);

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
        reconcile_frontend_validation(&gw, &cms, &HashSet::new(), &mut builder, &mut health);

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
        reconcile_frontend_validation(&gw, &cms, &HashSet::new(), &mut builder, &mut health);

        let fv = health.frontend_validation.as_ref().unwrap();
        assert!(!fv.resolved_refs);
        let outcome = &health
            .listeners
            .get(&ListenerHealthKey::gateway("l1"))
            .unwrap()
            .frontend_outcome;
        assert!(
            matches!(
                outcome,
                FrontendValidationOutcome::InvalidCACertificateKind { .. }
            ),
            "non-ConfigMap kind → InvalidCACertificateKind, got {outcome:?}"
        );
        let state = builder.build().find_config("example.com").unwrap();
        assert!(
            matches!(state.as_ref(), ClientCertConfigState::Unavailable),
            "non-ConfigMap kind should produce Unavailable"
        );
    }

    // ── perPort + cross-namespace tests ──────────────────────────────────────

    use crate::gw_types::v::gateways::{
        GatewayListeners, GatewaySpec, GatewayTls, GatewayTlsFrontend, GatewayTlsFrontendDefault,
        GatewayTlsFrontendDefaultValidation, GatewayTlsFrontendDefaultValidationCaCertificateRefs,
        GatewayTlsFrontendPerPort, GatewayTlsFrontendPerPortTls,
        GatewayTlsFrontendPerPortTlsValidation,
        GatewayTlsFrontendPerPortTlsValidationCaCertificateRefs,
    };

    fn ca_ref(
        kind: &str,
        name: &str,
        namespace: Option<&str>,
    ) -> GatewayTlsFrontendDefaultValidationCaCertificateRefs {
        GatewayTlsFrontendDefaultValidationCaCertificateRefs {
            group: String::new(),
            kind: kind.to_string(),
            name: name.to_string(),
            namespace: namespace.map(str::to_string),
        }
    }

    fn pp_ca_ref(
        kind: &str,
        name: &str,
        namespace: Option<&str>,
    ) -> GatewayTlsFrontendPerPortTlsValidationCaCertificateRefs {
        GatewayTlsFrontendPerPortTlsValidationCaCertificateRefs {
            group: String::new(),
            kind: kind.to_string(),
            name: name.to_string(),
            namespace: namespace.map(str::to_string),
        }
    }

    /// Build a Gateway with one HTTPS listener (`lname`/`hostname`/`port`), a
    /// `default` validation ref, and an optional `perPort` entry for `port`.
    fn gw_per_port(
        ns: &str,
        lname: &str,
        hostname: &str,
        port: i32,
        default_ref: GatewayTlsFrontendDefaultValidationCaCertificateRefs,
        per_port: Option<GatewayTlsFrontendPerPortTlsValidationCaCertificateRefs>,
    ) -> Gateway {
        Gateway {
            metadata: kube::core::ObjectMeta {
                namespace: Some(ns.to_string()),
                name: Some("gw".to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: String::new(),
                listeners: vec![GatewayListeners {
                    name: lname.to_string(),
                    protocol: "HTTPS".to_string(),
                    port,
                    hostname: Some(hostname.to_string()),
                    ..Default::default()
                }],
                tls: Some(GatewayTls {
                    backend: None,
                    frontend: Some(GatewayTlsFrontend {
                        default: GatewayTlsFrontendDefault {
                            validation: Some(GatewayTlsFrontendDefaultValidation {
                                ca_certificate_refs: vec![default_ref],
                                mode: None,
                            }),
                        },
                        per_port: per_port.map(|r| {
                            vec![GatewayTlsFrontendPerPort {
                                port,
                                tls: GatewayTlsFrontendPerPortTls {
                                    validation: Some(GatewayTlsFrontendPerPortTlsValidation {
                                        ca_certificate_refs: vec![r],
                                        mode: None,
                                    }),
                                },
                            }]
                        }),
                    }),
                }),
                ..Default::default()
            },
            status: None,
        }
    }

    #[test]
    fn per_port_overrides_default_ca() {
        const PEM: &str = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n";
        // Listener on 8443 has a perPort override pointing at `pp-ca`; default is `def-ca`.
        let gw = gw_per_port(
            "ns",
            "l1",
            "second-example.org",
            8443,
            ca_ref("ConfigMap", "def-ca", None),
            Some(pp_ca_ref("ConfigMap", "pp-ca", None)),
        );
        let cms = cm_store_with("ns", "pp-ca", PEM); // only the perPort CA exists
        let mut builder = ClientCertStoreBuilder::new();
        let mut health = GatewayListenerHealth::default();
        reconcile_frontend_validation(&gw, &cms, &HashSet::new(), &mut builder, &mut health);

        // The listener resolved against the perPort CA (which exists), not the default.
        let outcome = &health
            .listeners
            .get(&ListenerHealthKey::gateway("l1"))
            .unwrap()
            .frontend_outcome;
        assert!(
            matches!(outcome, FrontendValidationOutcome::Resolved),
            "perPort CA should resolve, got {outcome:?}"
        );
        assert!(matches!(
            builder
                .build()
                .find_config("second-example.org")
                .unwrap()
                .as_ref(),
            ClientCertConfigState::Config(_)
        ));
    }

    #[test]
    fn cross_namespace_ref_without_grant_is_ref_not_permitted() {
        let gw = gw_per_port(
            "ns",
            "l1",
            "example.org",
            443,
            ca_ref("ConfigMap", "other-ca", Some("other-ns")),
            None,
        );
        let cms = empty_cm_store();
        let mut builder = ClientCertStoreBuilder::new();
        let mut health = GatewayListenerHealth::default();
        reconcile_frontend_validation(&gw, &cms, &HashSet::new(), &mut builder, &mut health);

        let outcome = &health
            .listeners
            .get(&ListenerHealthKey::gateway("l1"))
            .unwrap()
            .frontend_outcome;
        assert!(
            matches!(outcome, FrontendValidationOutcome::RefNotPermitted { .. }),
            "cross-ns ref without grant → RefNotPermitted, got {outcome:?}"
        );
    }

    #[test]
    fn cross_namespace_ref_with_grant_resolves() {
        const PEM: &str = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n";
        let gw = gw_per_port(
            "ns",
            "l1",
            "example.org",
            443,
            ca_ref("ConfigMap", "other-ca", Some("other-ns")),
            None,
        );
        let cms = cm_store_with("other-ns", "other-ca", PEM);
        let mut grants = HashSet::new();
        grants.insert(ReferenceGrantKey::wildcard("ns", "other-ns"));
        let mut builder = ClientCertStoreBuilder::new();
        let mut health = GatewayListenerHealth::default();
        reconcile_frontend_validation(&gw, &cms, &grants, &mut builder, &mut health);

        let outcome = &health
            .listeners
            .get(&ListenerHealthKey::gateway("l1"))
            .unwrap()
            .frontend_outcome;
        assert!(
            matches!(outcome, FrontendValidationOutcome::Resolved),
            "cross-ns ref with grant should resolve, got {outcome:?}"
        );
    }

    #[test]
    fn unresolved_ref_sets_invalid_ca_certificate_ref() {
        let gw = gw_per_port(
            "ns",
            "l1",
            "example.org",
            443,
            ca_ref("ConfigMap", "does-not-exist", None),
            None,
        );
        let cms = empty_cm_store();
        let mut builder = ClientCertStoreBuilder::new();
        let mut health = GatewayListenerHealth::default();
        reconcile_frontend_validation(&gw, &cms, &HashSet::new(), &mut builder, &mut health);

        let outcome = &health
            .listeners
            .get(&ListenerHealthKey::gateway("l1"))
            .unwrap()
            .frontend_outcome;
        assert!(
            matches!(
                outcome,
                FrontendValidationOutcome::InvalidCACertificateRef { .. }
            ),
            "missing ConfigMap → InvalidCACertificateRef, got {outcome:?}"
        );
    }
}
