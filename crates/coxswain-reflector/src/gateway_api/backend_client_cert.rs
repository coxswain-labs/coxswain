//! Gateway backend client-certificate resolution (GEP-3155, #87).
//!
//! Parses `spec.tls.backend.clientCertificateRef` on each owned Gateway and
//! resolves the referenced `kubernetes.io/tls` Secret (`tls.crt` + `tls.key`)
//! into a [`BackendClientCert`] the proxy presents on `BackendTLSPolicy`-driven
//! upstream TLS connections.
//!
//! Resolution is **gateway-scoped** (not per-listener): the ref applies to all
//! backend TLS connections the Gateway makes. The outcome drives the Gateway's
//! top-level `ResolvedRefs` condition:
//! - unsupported group/kind, missing Secret, wrong-type or key-less Secret →
//!   [`BackendClientCertOutcome::InvalidClientCertificateRef`]
//! - cross-namespace ref without a `Gateway → Secret`
//!   [`ReferenceGrant`](crate::reference_grants) →
//!   [`BackendClientCertOutcome::RefNotPermitted`]
//! - resolved → [`BackendClientCertOutcome::Resolved`]
//!
//! **Core support**: a `core/Secret` of type `kubernetes.io/tls`. Other kinds and
//! Secret types (e.g. `Opaque`) are implementation-specific and not accepted here.

use crate::MergedStore;
use crate::gw_types::v::gateways::Gateway;
use crate::tls::load_tls_cert;
use coxswain_core::listener_status::BackendClientCertOutcome;
use coxswain_core::reference_grants::{ReferenceGrantKey, backend_ref_allowed};
use coxswain_core::routing::BackendClientCert;
use k8s_openapi::api::core::v1::Secret;
use std::collections::HashSet;
use std::sync::Arc;

/// Resolve `spec.tls.backend.clientCertificateRef` for one Gateway.
///
/// Returns `None` when the ref is absent (no `ResolvedRefs` condition is emitted).
/// Otherwise returns the [`BackendClientCertOutcome`] for the Gateway's status and,
/// on success, the resolved [`BackendClientCert`] for the data plane.
pub(crate) fn reconcile_backend_client_cert(
    gw: &Gateway,
    secrets: &MergedStore<Secret>,
    cert_grants: &HashSet<ReferenceGrantKey>,
) -> Option<(BackendClientCertOutcome, Option<Arc<BackendClientCert>>)> {
    let cref = gw
        .spec
        .tls
        .as_ref()?
        .backend
        .as_ref()?
        .client_certificate_ref
        .as_ref()?;

    let gw_ns = gw.metadata.namespace.as_deref().unwrap_or("default");

    // Core support is a `core/Secret`. Unspecified group/kind default to core Secret.
    let group = cref.group.as_deref().unwrap_or("");
    if !matches!(group, "" | "core") {
        return Some((
            BackendClientCertOutcome::InvalidClientCertificateRef {
                message: format!(
                    "clientCertificateRef group {group:?} is unsupported; only the core Secret is supported"
                ),
            },
            None,
        ));
    }
    let kind = cref.kind.as_deref().unwrap_or("Secret");
    if kind != "Secret" {
        return Some((
            BackendClientCertOutcome::InvalidClientCertificateRef {
                message: format!(
                    "clientCertificateRef kind {kind:?} is unsupported; only Secret is supported"
                ),
            },
            None,
        ));
    }

    let ref_ns = cref.namespace.as_deref().unwrap_or(gw_ns);
    if ref_ns != gw_ns && !backend_ref_allowed(gw_ns, ref_ns, &cref.name, cert_grants) {
        return Some((
            BackendClientCertOutcome::RefNotPermitted {
                message: format!(
                    "cross-namespace clientCertificateRef Secret {ref_ns}/{} requires a ReferenceGrant",
                    cref.name
                ),
            },
            None,
        ));
    }

    match load_tls_cert(ref_ns, &cref.name, secrets) {
        Ok(cert) => {
            let cc = BackendClientCert::new(
                Arc::from(cert.cert_pem.as_slice()),
                Arc::from(cert.key_pem.as_slice()),
                Arc::from(cert.source.as_str()),
            );
            Some((BackendClientCertOutcome::Resolved, Some(Arc::new(cc))))
        }
        Err(e) => Some((
            BackendClientCertOutcome::InvalidClientCertificateRef {
                message: format!("clientCertificateRef Secret {ref_ns}/{}: {e}", cref.name),
            },
            None,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gw_types::v::gateways::{
        Gateway, GatewaySpec, GatewayTls, GatewayTlsBackend, GatewayTlsBackendClientCertificateRef,
    };
    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::Secret;
    use kube::runtime::reflector;
    use std::collections::BTreeMap;

    const CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
    const KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----";

    fn gw_with_ref(ref_: Option<GatewayTlsBackendClientCertificateRef>) -> Gateway {
        let mut gw = Gateway {
            metadata: Default::default(),
            spec: GatewaySpec {
                gateway_class_name: "coxswain".to_string(),
                listeners: vec![],
                ..Default::default()
            },
            status: None,
        };
        gw.metadata.namespace = Some("gw-ns".to_string());
        gw.metadata.name = Some("gw".to_string());
        gw.spec.tls = Some(GatewayTls {
            backend: ref_.map(|r| GatewayTlsBackend {
                client_certificate_ref: Some(r),
            }),
            frontend: None,
        });
        gw
    }

    fn client_ref(
        name: &str,
        ns: Option<&str>,
        group: Option<&str>,
        kind: Option<&str>,
    ) -> GatewayTlsBackendClientCertificateRef {
        GatewayTlsBackendClientCertificateRef {
            group: group.map(str::to_string),
            kind: kind.map(str::to_string),
            name: name.to_string(),
            namespace: ns.map(str::to_string),
        }
    }

    fn secret_store(secrets: Vec<Secret>) -> MergedStore<Secret> {
        let mut writer = reflector::store::Writer::<Secret>::default();
        for secret in secrets {
            writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(secret));
        }
        MergedStore::single(writer.as_reader())
    }

    fn tls_secret(ns: &str, name: &str) -> Secret {
        let mut data = BTreeMap::new();
        data.insert("tls.crt".to_string(), ByteString(CERT_PEM.to_vec()));
        data.insert("tls.key".to_string(), ByteString(KEY_PEM.to_vec()));
        let mut s = Secret {
            type_: Some("kubernetes.io/tls".to_string()),
            data: Some(data),
            ..Default::default()
        };
        s.metadata.namespace = Some(ns.to_string());
        s.metadata.name = Some(name.to_string());
        s
    }

    #[test]
    fn absent_ref_yields_no_condition() {
        let gw = gw_with_ref(None);
        let store = secret_store(vec![]);
        assert!(reconcile_backend_client_cert(&gw, &store, &HashSet::new()).is_none());
    }

    #[test]
    fn valid_same_namespace_ref_resolves() {
        let gw = gw_with_ref(Some(client_ref("cc", None, None, None)));
        let store = secret_store(vec![tls_secret("gw-ns", "cc")]);
        let (outcome, cert) =
            reconcile_backend_client_cert(&gw, &store, &HashSet::new()).expect("ref present");
        assert_eq!(outcome, BackendClientCertOutcome::Resolved);
        let cert = cert.expect("cert resolved");
        assert_eq!(&*cert.cert_pem, CERT_PEM);
        assert_eq!(&*cert.source, "gw-ns/cc");
    }

    #[test]
    fn nonexistent_secret_is_invalid() {
        let gw = gw_with_ref(Some(client_ref("missing", None, None, None)));
        let store = secret_store(vec![]);
        let (outcome, cert) =
            reconcile_backend_client_cert(&gw, &store, &HashSet::new()).expect("ref present");
        assert!(matches!(
            outcome,
            BackendClientCertOutcome::InvalidClientCertificateRef { .. }
        ));
        assert!(cert.is_none());
    }

    #[test]
    fn unsupported_group_is_invalid() {
        let gw = gw_with_ref(Some(client_ref(
            "cc",
            None,
            Some("wrong.group.company.io"),
            Some("Secret"),
        )));
        let store = secret_store(vec![tls_secret("gw-ns", "cc")]);
        let (outcome, _) =
            reconcile_backend_client_cert(&gw, &store, &HashSet::new()).expect("ref present");
        assert!(matches!(
            outcome,
            BackendClientCertOutcome::InvalidClientCertificateRef { .. }
        ));
    }

    #[test]
    fn unsupported_kind_is_invalid() {
        let gw = gw_with_ref(Some(client_ref("cc", None, Some(""), Some("WrongKind"))));
        let store = secret_store(vec![tls_secret("gw-ns", "cc")]);
        let (outcome, _) =
            reconcile_backend_client_cert(&gw, &store, &HashSet::new()).expect("ref present");
        assert!(matches!(
            outcome,
            BackendClientCertOutcome::InvalidClientCertificateRef { .. }
        ));
    }

    #[test]
    fn malformed_opaque_secret_is_invalid() {
        let gw = gw_with_ref(Some(client_ref("cc", None, None, None)));
        let mut s = Secret {
            type_: Some("Opaque".to_string()),
            data: Some(BTreeMap::new()),
            ..Default::default()
        };
        s.metadata.namespace = Some("gw-ns".to_string());
        s.metadata.name = Some("cc".to_string());
        let store = secret_store(vec![s]);
        let (outcome, _) =
            reconcile_backend_client_cert(&gw, &store, &HashSet::new()).expect("ref present");
        assert!(matches!(
            outcome,
            BackendClientCertOutcome::InvalidClientCertificateRef { .. }
        ));
    }

    #[test]
    fn cross_namespace_without_grant_is_ref_not_permitted() {
        let gw = gw_with_ref(Some(client_ref("cc", Some("other-ns"), None, None)));
        let store = secret_store(vec![tls_secret("other-ns", "cc")]);
        let (outcome, _) =
            reconcile_backend_client_cert(&gw, &store, &HashSet::new()).expect("ref present");
        assert!(matches!(
            outcome,
            BackendClientCertOutcome::RefNotPermitted { .. }
        ));
    }

    #[test]
    fn cross_namespace_with_grant_resolves() {
        let gw = gw_with_ref(Some(client_ref("cc", Some("other-ns"), None, None)));
        let store = secret_store(vec![tls_secret("other-ns", "cc")]);
        let mut grants = HashSet::new();
        grants.insert(ReferenceGrantKey::wildcard("gw-ns", "other-ns"));
        let (outcome, cert) =
            reconcile_backend_client_cert(&gw, &store, &grants).expect("ref present");
        assert_eq!(outcome, BackendClientCertOutcome::Resolved);
        assert!(cert.is_some());
    }
}
