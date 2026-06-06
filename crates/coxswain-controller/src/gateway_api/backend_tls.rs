//! `BackendTLSPolicy` index builder and health computation.
//!
//! Produces a per-Service lookup table (`BackendTlsIndex`) of resolved TLS
//! configuration, and a per-policy health map for writing `status.ancestors[]`.

use crate::gw_types::{
    BackendTlsPolicy, HttpRoute,
    v::backendtlspolicies::{
        BackendTlsPolicyTargetRefs, BackendTlsPolicyValidationCaCertificateRefs,
    },
};
use crate::k8s_utils::metadata_created_at;
use crate::tls::{BackendTlsPolicyHealth, BackendTlsPolicyHealthMap};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::routing::{UpstreamCa, UpstreamTls};
use k8s_openapi::api::core::v1::ConfigMap;
use kube::runtime::reflector;
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;

/// Resolved TLS configuration for one Service, ready for the routing table.
pub(crate) struct ResolvedPolicy {
    /// The `UpstreamTls` to attach to `BackendGroup`.
    pub(crate) tls: Arc<UpstreamTls>,
    /// Key identifying the winning policy — stored so health computation can
    /// mark losers as `Conflicted`.
    pub(crate) policy_key: ObjectKey,
}

/// Per-Service TLS index: `(svc_namespace, svc_name)` → resolved policy.
///
/// Built once per reconciler rebuild and threaded into the route-building pass.
pub type BackendTlsIndex = HashMap<ObjectKey, ResolvedPolicy>;

/// Build the `BackendTlsIndex` from the current `BackendTlsPolicy` and `ConfigMap` stores.
///
/// For each `BackendTlsPolicy` that targets a `Service`:
/// - Conflict resolution: oldest `creationTimestamp` wins; ties broken by `{ns}/{name}`.
/// - Accepted winner: resolved to `UpstreamTls`; errors (`warn!`) produce a health
///   entry with `ResolvedRefs=False` but do not add to the index.
/// - Losers: added to the returned health map with `Accepted: Conflicted`.
///
/// Returns both the index (for data-plane routing) and the raw health map (for status
/// writes). Call [`compute_policy_health`] to fill in ancestor lists.
#[must_use]
pub fn build_backend_tls_index(
    policies: &reflector::Store<BackendTlsPolicy>,
    configmaps: &reflector::Store<ConfigMap>,
) -> (BackendTlsIndex, BackendTlsPolicyHealthMap) {
    let mut candidates: HashMap<ObjectKey, Vec<Arc<BackendTlsPolicy>>> = HashMap::new();

    for policy in policies.state() {
        let ns = policy.metadata.namespace.as_deref().unwrap_or("default");
        for target in &policy.spec.target_refs {
            if !is_service_ref(target) {
                continue;
            }
            let svc_key = ObjectKey::new(ns, &target.name);
            candidates
                .entry(svc_key)
                .or_default()
                .push(Arc::clone(&policy));
        }
    }

    let mut index = HashMap::new();
    let mut health: BackendTlsPolicyHealthMap = HashMap::new();

    for (svc_key, mut competing) in candidates {
        // Conflict resolution: oldest first, then lexicographic {ns}/{name}.
        competing.sort_by(|a, b| {
            let ta = metadata_created_at(&a.metadata);
            let tb = metadata_created_at(&b.metadata);
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

        let winner = &competing[0];
        let policy_ns = winner.metadata.namespace.as_deref().unwrap_or("default");
        let policy_name = winner.metadata.name.as_deref().unwrap_or("unknown");
        let winner_key = ObjectKey::new(policy_ns, policy_name);

        // Mark losers as Conflicted.
        for loser in &competing[1..] {
            let loser_ns = loser.metadata.namespace.as_deref().unwrap_or("default");
            let loser_name = loser.metadata.name.as_deref().unwrap_or("unknown");
            let loser_key = ObjectKey::new(loser_ns, loser_name);
            let entry = health.entry(loser_key).or_default();
            entry.accepted = false;
            entry.accepted_reason = "Conflicted";
        }

        // Resolve the winner.
        let sni: Arc<str> = Arc::from(winner.spec.validation.hostname.as_str());

        let (ca, ref_ok) = resolve_ca(policy_ns, &winner.spec.validation, configmaps);
        let (ca, resolved_refs, resolved_refs_reason) = match ca {
            Some(ca) => (ca, true, "ResolvedRefs"),
            None => {
                // CA resolution failed; skip from data-plane index.
                let entry = health.entry(winner_key).or_default();
                entry.resolved_refs = false;
                entry.resolved_refs_reason = ref_ok;
                continue;
            }
        };

        let group_key = compute_group_key(&sni, &ca);
        let tls = Arc::new(UpstreamTls::new(sni, ca, group_key));

        index.insert(
            svc_key,
            ResolvedPolicy {
                tls,
                policy_key: winner_key.clone(),
            },
        );
        let entry = health.entry(winner_key).or_default();
        entry.resolved_refs = resolved_refs;
        entry.resolved_refs_reason = resolved_refs_reason;
    }

    (index, health)
}

/// Walk owned routes to find which Gateways use backends covered by each policy,
/// then fill in the `ancestors` field of each health entry.
///
/// This is a separate pass so it can run after the index and health map are built.
pub fn compute_policy_health(
    index: &BackendTlsIndex,
    routes: &[Arc<HttpRoute>],
    owned_gateways: &HashSet<ObjectKey>,
) -> BackendTlsPolicyHealthMap {
    // Start from an empty map — the caller merges with the one from build_backend_tls_index.
    let mut ancestors_per_policy: HashMap<ObjectKey, HashSet<ObjectKey>> = HashMap::new();

    for route in routes {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");

        // Collect which policy keys this route touches.
        let mut touched_policies: HashSet<ObjectKey> = HashSet::new();
        for rule in route.spec.rules.as_deref().unwrap_or(&[]) {
            for bref in rule.backend_refs.as_deref().unwrap_or(&[]) {
                let b_ns = bref.namespace.as_deref().unwrap_or(route_ns);
                let svc_key = ObjectKey::new(b_ns, &bref.name);
                if let Some(resolved) = index.get(&svc_key) {
                    touched_policies.insert(resolved.policy_key.clone());
                }
            }
        }

        if touched_policies.is_empty() {
            continue;
        }

        // Collect owned parent Gateways for this route.
        let owned_parents: Vec<ObjectKey> = route
            .spec
            .parent_refs
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter_map(|pr| {
                let gw_ns = pr.namespace.as_deref().unwrap_or(route_ns);
                let key = ObjectKey::new(gw_ns, &pr.name);
                if owned_gateways.contains(&key) {
                    Some(key)
                } else {
                    None
                }
            })
            .collect();

        for policy_key in touched_policies {
            let set = ancestors_per_policy.entry(policy_key).or_default();
            for gw in &owned_parents {
                set.insert(gw.clone());
            }
        }
    }

    ancestors_per_policy
        .into_iter()
        .map(|(policy_key, gw_set)| {
            let mut health = BackendTlsPolicyHealth::default();
            let mut ancestors: Vec<ObjectKey> = gw_set.into_iter().collect();
            ancestors.sort_by(|a, b| a.ns.cmp(&b.ns).then(a.name.cmp(&b.name)));
            health.ancestors = ancestors;
            (policy_key, health)
        })
        .collect()
}

/// Returns `true` when `target_ref` references a Kubernetes `Service`.
fn is_service_ref(target: &BackendTlsPolicyTargetRefs) -> bool {
    let group = target.group.as_str();
    let kind = target.kind.as_str();
    (group.is_empty() || group == "core") && kind == "Service"
}

/// Resolve the CA source from `validation`.
///
/// Returns `(Some(UpstreamCa), reason)` on success, or `(None, reason)` when the
/// reference cannot be resolved and the policy should be skipped.
fn resolve_ca(
    policy_ns: &str,
    validation: &crate::gw_types::v::backendtlspolicies::BackendTlsPolicyValidation,
    configmaps: &reflector::Store<ConfigMap>,
) -> (Option<UpstreamCa>, &'static str) {
    if let Some(refs) = validation.ca_certificate_refs.as_deref()
        && !refs.is_empty()
    {
        return resolve_ca_from_ref(policy_ns, &refs[0], configmaps);
    }

    if let Some(wk) = validation.well_known_ca_certificates.as_deref() {
        if wk == "System" {
            return (Some(UpstreamCa::System), "ResolvedRefs");
        }
        tracing::warn!(
            ns = policy_ns,
            value = wk,
            "BackendTLSPolicy wellKnownCACertificates value unrecognised — policy skipped"
        );
        return (None, "ResolvedRefs");
    }

    // Neither caCertificateRefs nor wellKnownCACertificates — invalid policy.
    tracing::warn!(
        ns = policy_ns,
        "BackendTLSPolicy has neither caCertificateRefs nor wellKnownCACertificates — skipped"
    );
    (None, "ResolvedRefs")
}

/// Resolve a single `caCertificateRef` to raw PEM bytes.
fn resolve_ca_from_ref(
    policy_ns: &str,
    ca_ref: &BackendTlsPolicyValidationCaCertificateRefs,
    configmaps: &reflector::Store<ConfigMap>,
) -> (Option<UpstreamCa>, &'static str) {
    // Only core/ConfigMap is supported (spec § Core support).
    let kind = ca_ref.kind.as_str();
    let group = ca_ref.group.as_str();
    if kind != "ConfigMap" || (!group.is_empty() && group != "core") {
        tracing::warn!(
            ns = policy_ns,
            kind,
            group,
            "BackendTLSPolicy caCertificateRef kind not supported (only core/ConfigMap) — skipped"
        );
        return (None, "InvalidKind");
    }

    // Cross-namespace refs are not permitted by the spec for BackendTLSPolicy.
    let ref_key = reflector::ObjectRef::<ConfigMap>::new(&ca_ref.name).within(policy_ns);
    let Some(cm) = configmaps.get(&ref_key) else {
        tracing::warn!(
            ns = policy_ns,
            name = %ca_ref.name,
            "BackendTLSPolicy caCertificateRef ConfigMap not found — skipped"
        );
        return (None, "InvalidCACertificateRef");
    };

    let pem_bytes = cm
        .data
        .as_ref()
        .and_then(|d| d.get("ca.crt"))
        .map(|s| s.as_bytes());

    let Some(pem) = pem_bytes else {
        tracing::warn!(
            ns = policy_ns,
            name = %ca_ref.name,
            "BackendTLSPolicy caCertificateRef ConfigMap missing 'ca.crt' key — skipped"
        );
        return (None, "InvalidCACertificateRef");
    };

    // Lightweight pre-validation: the bytes must contain a PEM header. Full X.509
    // parsing happens in the proxy's UpstreamCaCache; a bad cert there yields a 502
    // and a warn! rather than silently breaking routing.
    if !pem.windows(10).any(|w| w == b"-----BEGIN") {
        tracing::warn!(
            ns = policy_ns,
            name = %ca_ref.name,
            "BackendTLSPolicy caCertificateRef 'ca.crt' does not look like PEM — skipped"
        );
        return (None, "InvalidCACertificateRef");
    }

    (Some(UpstreamCa::Bundle(Arc::from(pem))), "ResolvedRefs")
}

/// Compute a stable `u64` pool-isolation key from SNI and CA content.
///
/// `System` CA uses `0` as the CA discriminant; bundle CA uses a hash of its PEM bytes.
/// This ensures connections with distinct CAs are never pooled together by Pingora.
fn compute_group_key(sni: &str, ca: &UpstreamCa) -> u64 {
    let mut h = DefaultHasher::new();
    sni.hash(&mut h);
    match ca {
        UpstreamCa::System => 0u64.hash(&mut h),
        UpstreamCa::Bundle(pem) => pem.hash(&mut h),
        _ => {}
    }
    h.finish()
}
