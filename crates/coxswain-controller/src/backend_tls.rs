use crate::gw_types::v::backendtlspolicies::{
    BackendTLSPolicy, BackendTlsPolicyValidationCaCertificateRefs,
};
use coxswain_core::routing::{BackendCaSource, BackendTlsConfig};
use k8s_openapi::api::core::v1::{ConfigMap, Service};
use kube::runtime::reflector;
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;

/// Result of resolving a single `BackendTLSPolicy` target.
#[derive(Clone, Debug)]
pub struct PolicyHealthOutcome {
    pub accepted: bool,
    pub accepted_reason: &'static str,
    pub accepted_message: String,
    pub resolved_refs: bool,
    pub resolved_refs_reason: &'static str,
    pub resolved_refs_message: String,
}

impl PolicyHealthOutcome {
    fn accepted(message: impl Into<String>) -> Self {
        Self {
            accepted: true,
            accepted_reason: "Accepted",
            accepted_message: message.into(),
            resolved_refs: true,
            resolved_refs_reason: "ResolvedRefs",
            resolved_refs_message: String::new(),
        }
    }

    fn conflicted(message: impl Into<String>) -> Self {
        Self {
            accepted: false,
            accepted_reason: "Conflicted",
            accepted_message: message.into(),
            resolved_refs: true,
            resolved_refs_reason: "ResolvedRefs",
            resolved_refs_message: String::new(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self {
            accepted: false,
            accepted_reason: "Invalid",
            accepted_message: message.into(),
            resolved_refs: true,
            resolved_refs_reason: "ResolvedRefs",
            resolved_refs_message: String::new(),
        }
    }

    fn invalid_ca_cert_ref(ref_name: &str, cause: impl std::fmt::Display) -> Self {
        let msg = format!("{ref_name}: {cause}");
        Self {
            accepted: false,
            accepted_reason: "NoValidCACertificate",
            accepted_message: "All caCertificateRefs are invalid".to_string(),
            resolved_refs: false,
            resolved_refs_reason: "InvalidCACertificateRef",
            resolved_refs_message: msg,
        }
    }

    fn invalid_kind(ref_name: &str) -> Self {
        Self {
            accepted: false,
            accepted_reason: "NoValidCACertificate",
            accepted_message: "All caCertificateRefs are invalid".to_string(),
            resolved_refs: false,
            resolved_refs_reason: "InvalidKind",
            resolved_refs_message: format!(
                "{ref_name}: only ConfigMap (group \"\") is supported for caCertificateRefs"
            ),
        }
    }
}

/// Composite key uniquely identifying one BackendTLSPolicy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyKey {
    pub ns: String,
    pub name: String,
}

/// Look-up key: a Service endpoint that a BackendTLSPolicy may target.
///
/// A policy with no `sectionName` (port name) applies to the whole Service.
/// A policy with a `sectionName` applies to a specific named port.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ServicePortKey {
    pub ns: String,
    pub svc: String,
    /// Port name from `sectionName`. `None` ⇒ policy targets the whole Service.
    pub port_name: Option<String>,
}

/// The service target a policy is attached to — kept for ancestor resolution.
#[derive(Clone, Debug)]
pub struct PolicyServiceTarget {
    /// Namespace of the targeted Service (same as the policy's namespace).
    pub ns: String,
    /// Name of the targeted Service.
    pub svc: String,
}

/// The policy index: maps `(ns, svc, port_name?)` to a resolved `BackendTlsConfig`.
///
/// Built once per reconcile cycle from the current `BackendTLSPolicy` and `ConfigMap` stores.
pub struct BackendTlsIndex {
    by_service: HashMap<ServicePortKey, Arc<BackendTlsConfig>>,
    pub health: HashMap<PolicyKey, PolicyHealthOutcome>,
    /// Per-policy service target used to correlate policies with their ancestor gateways.
    pub targets: HashMap<PolicyKey, PolicyServiceTarget>,
}

impl BackendTlsIndex {
    /// Look up the TLS config for a backend reference.
    ///
    /// First tries an exact `(ns, svc, Some(port_name))` entry, then falls back
    /// to a whole-service `(ns, svc, None)` entry.
    pub fn lookup(
        &self,
        ns: &str,
        svc: &str,
        port_name: Option<&str>,
    ) -> Option<Arc<BackendTlsConfig>> {
        if let Some(name) = port_name {
            let key = ServicePortKey {
                ns: ns.to_string(),
                svc: svc.to_string(),
                port_name: Some(name.to_string()),
            };
            if let Some(cfg) = self.by_service.get(&key) {
                return Some(Arc::clone(cfg));
            }
        }
        let whole_key = ServicePortKey {
            ns: ns.to_string(),
            svc: svc.to_string(),
            port_name: None,
        };
        self.by_service.get(&whole_key).map(Arc::clone)
    }
}

/// Build a `BackendTlsIndex` from the current store snapshots.
///
/// `system_ca_available` indicates whether the platform system CA bundle was loaded
/// at startup. If `false`, policies requesting `wellKnownCACertificates: System` are
/// rejected with `Invalid`.
pub fn build_backend_tls_index(
    policies: &reflector::Store<BackendTLSPolicy>,
    configmaps: &reflector::Store<ConfigMap>,
    services: &reflector::Store<Service>,
    system_ca_available: bool,
) -> BackendTlsIndex {
    let mut by_service: HashMap<ServicePortKey, Arc<BackendTlsConfig>> = HashMap::new();
    let mut health: HashMap<PolicyKey, PolicyHealthOutcome> = HashMap::new();
    let mut targets: HashMap<PolicyKey, PolicyServiceTarget> = HashMap::new();

    // Collect all policies.
    let mut all: Vec<Arc<BackendTLSPolicy>> = policies.state();

    // Sort for deterministic conflict resolution:
    // oldest creationTimestamp first, then alphabetical "{ns}/{name}".
    all.sort_by(|a, b| {
        let ta = a.metadata.creation_timestamp.as_ref().map(|t| t.0);
        let tb = b.metadata.creation_timestamp.as_ref().map(|t| t.0);
        ta.cmp(&tb).then_with(|| {
            let ka = format!(
                "{}/{}",
                a.metadata.namespace.as_deref().unwrap_or(""),
                a.metadata.name.as_deref().unwrap_or("")
            );
            let kb = format!(
                "{}/{}",
                b.metadata.namespace.as_deref().unwrap_or(""),
                b.metadata.name.as_deref().unwrap_or("")
            );
            ka.cmp(&kb)
        })
    });

    for policy in &all {
        let policy_ns = policy.metadata.namespace.as_deref().unwrap_or("default");
        let policy_name = policy.metadata.name.as_deref().unwrap_or("unknown");
        let policy_key = PolicyKey {
            ns: policy_ns.to_string(),
            name: policy_name.to_string(),
        };

        // Only Service targets (group "" / "core", kind "Service", same namespace).
        let target = match policy.spec.target_refs.first() {
            Some(t) => t,
            None => {
                health.insert(
                    policy_key,
                    PolicyHealthOutcome::invalid("targetRefs is empty"),
                );
                continue;
            }
        };
        let t_group = target.group.as_str();
        let t_kind = target.kind.as_str();
        if t_kind != "Service" || (!t_group.is_empty() && t_group != "core") {
            health.insert(
                policy_key,
                PolicyHealthOutcome::invalid(format!(
                    "unsupported targetRef {t_group}/{t_kind}: only Service is supported"
                )),
            );
            continue;
        }

        let service_key = ServicePortKey {
            ns: policy_ns.to_string(),
            svc: target.name.clone(),
            port_name: target.section_name.clone(),
        };

        // Conflict: a higher-priority policy already claimed this slot.
        if by_service.contains_key(&service_key) {
            health.insert(
                policy_key,
                PolicyHealthOutcome::conflicted(format!(
                    "Another BackendTLSPolicy with higher precedence already targets {}/{} sectionName={:?}",
                    policy_ns, target.name, target.section_name
                )),
            );
            continue;
        }

        // Validate and build the TLS config.
        let outcome = build_tls_config(
            policy_ns,
            policy_name,
            &policy.spec.validation.ca_certificate_refs,
            policy.spec.validation.well_known_ca_certificates.as_deref(),
            &policy.spec.validation.hostname,
            configmaps,
            services,
            &service_key,
            system_ca_available,
        );

        match outcome {
            Ok(cfg) => {
                targets.insert(
                    policy_key.clone(),
                    PolicyServiceTarget {
                        ns: policy_ns.to_string(),
                        svc: target.name.clone(),
                    },
                );
                by_service.insert(service_key, Arc::clone(&cfg));
                health.insert(policy_key, PolicyHealthOutcome::accepted(""));
            }
            Err(h) => {
                // Also track the target for failed policies so the ancestor walk can
                // still populate status with the correct Accepted=False conditions.
                targets.insert(
                    policy_key.clone(),
                    PolicyServiceTarget {
                        ns: policy_ns.to_string(),
                        svc: target.name.clone(),
                    },
                );
                health.insert(policy_key, h);
            }
        }
    }

    BackendTlsIndex {
        by_service,
        health,
        targets,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_tls_config(
    _policy_ns: &str,
    _policy_name: &str,
    ca_refs: &Option<Vec<BackendTlsPolicyValidationCaCertificateRefs>>,
    well_known: Option<&str>,
    hostname: &str,
    configmaps: &reflector::Store<ConfigMap>,
    _services: &reflector::Store<Service>,
    _service_key: &ServicePortKey,
    system_ca_available: bool,
) -> Result<Arc<BackendTlsConfig>, PolicyHealthOutcome> {
    let ca_refs_non_empty = ca_refs.as_deref().map(|r| !r.is_empty()).unwrap_or(false);
    let well_known_set = well_known.map(|s| !s.is_empty()).unwrap_or(false);

    if ca_refs_non_empty && well_known_set {
        return Err(PolicyHealthOutcome::invalid(
            "exactly one of caCertificateRefs or wellKnownCACertificates must be set, not both",
        ));
    }
    if !ca_refs_non_empty && !well_known_set {
        return Err(PolicyHealthOutcome::invalid(
            "one of caCertificateRefs or wellKnownCACertificates must be set",
        ));
    }

    let ca_source = if well_known_set {
        match well_known {
            Some("System") => {
                if !system_ca_available {
                    return Err(PolicyHealthOutcome::invalid(
                        "wellKnownCACertificates: System requested but no system CA bundle is available",
                    ));
                }
                BackendCaSource::System
            }
            Some(other) => {
                return Err(PolicyHealthOutcome::invalid(format!(
                    "wellKnownCACertificates value '{other}' is not recognised; only 'System' is supported"
                )));
            }
            None => unreachable!(),
        }
    } else {
        // Resolve caCertificateRefs — each must be ConfigMap in the same namespace as the policy.
        let refs = ca_refs.as_deref().unwrap_or(&[]);
        let mut pem_chunks: Vec<u8> = Vec::new();

        for ca_ref in refs {
            let ref_group = ca_ref.group.as_str();
            let ref_kind = ca_ref.kind.as_str();
            let ref_name = ca_ref.name.as_str();

            if ref_kind != "ConfigMap" || (!ref_group.is_empty() && ref_group != "core") {
                return Err(PolicyHealthOutcome::invalid_kind(ref_name));
            }

            // ConfigMap must be in the same namespace as the policy (spec restriction).
            let key = reflector::ObjectRef::<ConfigMap>::new(ref_name).within(_policy_ns);
            let cm = match configmaps.get(&key) {
                Some(cm) => cm,
                None => {
                    return Err(PolicyHealthOutcome::invalid_ca_cert_ref(
                        ref_name,
                        "ConfigMap not found",
                    ));
                }
            };

            // Accept the CA bundle from either `data` (string PEM) or
            // `binaryData` (base64-encoded PEM, decoded by Kubernetes before storage).
            let ca_pem_bytes: Vec<u8> = if let Some(data) = &cm.data
                && let Some(ca_crt) = data.get("ca.crt")
            {
                if !ca_crt.contains("-----BEGIN") {
                    return Err(PolicyHealthOutcome::invalid_ca_cert_ref(
                        ref_name,
                        "ca.crt does not appear to be a valid PEM certificate bundle",
                    ));
                }
                ca_crt.as_bytes().to_vec()
            } else if let Some(bin) = &cm.binary_data
                && let Some(ca_bytes) = bin.get("ca.crt")
            {
                if !ca_bytes.0.windows(11).any(|w| w == b"-----BEGIN ") {
                    return Err(PolicyHealthOutcome::invalid_ca_cert_ref(
                        ref_name,
                        "ca.crt (binaryData) does not appear to be a valid PEM certificate bundle",
                    ));
                }
                ca_bytes.0.clone()
            } else {
                return Err(PolicyHealthOutcome::invalid_ca_cert_ref(
                    ref_name,
                    "ConfigMap missing required key 'ca.crt' in data or binaryData",
                ));
            };

            pem_chunks.extend_from_slice(&ca_pem_bytes);
            if !pem_chunks.ends_with(b"\n") {
                pem_chunks.push(b'\n');
            }
        }

        BackendCaSource::Pem(pem_chunks)
    };

    let group_key = stable_hash(hostname, &ca_source);

    Ok(Arc::new(BackendTlsConfig::new(
        hostname.to_string(),
        ca_source,
        group_key,
    )))
}

/// Derive a stable u64 group key from the policy's SNI hostname and CA source.
/// Distinct policies get distinct keys; identical policies share a key (connection pool reuse).
fn stable_hash(sni: &str, ca: &BackendCaSource) -> u64 {
    let mut h = DefaultHasher::new();
    sni.hash(&mut h);
    match ca {
        BackendCaSource::System => {
            0u8.hash(&mut h);
        }
        BackendCaSource::Pem(bytes) => {
            1u8.hash(&mut h);
            bytes.hash(&mut h);
        }
    }
    h.finish()
}
