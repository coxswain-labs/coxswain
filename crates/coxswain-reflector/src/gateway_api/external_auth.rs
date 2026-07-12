//! `CoxswainExternalAuth` resolution (#23): shared spec→config translation and
//! `backendRef` endpoint resolution used by the route-level `ExtensionRef`
//! filter (in [`super::filters`]), the Gateway-attached policy index, and the
//! Ingress `ext-auth` annotation (`crate::ingress`, #549).
//!
//! The auth-service `backendRef` is resolved to pod endpoints exactly like any
//! other backend ([`crate::endpoints::resolve`]); a cross-namespace ref is gated
//! by a `ReferenceGrant`, mirroring `BasicAuth`'s `secretRef` handling (#520).
//! An endpoint-less or ungranted ref fails **closed**
//! ([`IngressAuthConfig::Unavailable`] → 503).

use crate::duration::parse_duration;
use crate::endpoints::pool::EndpointCache;
use crate::k8s_utils::metadata_created_at;
use crate::status::CoxswainExternalAuthStatusMap;
use coxswain_core::crd::{CoxswainExternalAuth, CoxswainExternalAuthSpec, ExternalAuthProtocol};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::reference_grants::{self, ReferenceGrantKey};
use coxswain_core::routing::{
    ExtAuthConfig, ExtAuthTransport, GrpcExtAuthConfig, HttpExtAuthConfig, IngressAuthConfig,
};
use k8s_openapi::api::core::v1::Service;
use kube::runtime::reflector;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Default auth timeout when `spec.timeout` is absent or unparseable.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// Resolve a `CoxswainExternalAuth` spec into the runtime [`IngressAuthConfig`]
/// the proxy enforces, resolving its `backendRef` to endpoints.
///
/// Returns [`IngressAuthConfig::Unavailable`] (fail-closed 503) when the
/// backend has no ready endpoints, a cross-namespace ref lacks a
/// `ReferenceGrant`, or the requested protocol is not yet supported. An
/// operator who attached ext-auth expects enforcement, so a broken backend must
/// never silently open the route.
///
/// `pub(crate)` (not `pub(super)` like most Gateway API spec resolvers) —
/// reused directly by [`crate::ingress::reconcile_helpers`] so the Ingress
/// `ext-auth` annotation resolves to the identical [`IngressAuthConfig`] the
/// HTTPRoute `ExtensionRef` filter produces (Gateway API parity, #549).
/// `policy_ns` is the namespace of the `CoxswainExternalAuth` CR itself —
/// callers pass the route's namespace when the ref is same-namespace-only
/// (the `ExtensionRef` filter), or the referenced CR's own namespace when the
/// ref can cross namespaces (the Ingress annotation).
pub(crate) fn resolve_spec(
    spec: &CoxswainExternalAuthSpec,
    policy_ns: &str,
    services: &reflector::Store<Service>,
    endpoint_cache: &EndpointCache,
    grants: &HashSet<ReferenceGrantKey>,
) -> IngressAuthConfig {
    let Some(endpoints) = resolve_backend(spec, policy_ns, services, endpoint_cache, grants) else {
        return IngressAuthConfig::Unavailable;
    };

    let timeout = spec
        .timeout
        .as_deref()
        .and_then(parse_duration)
        .unwrap_or(DEFAULT_TIMEOUT);
    let fail_closed = spec.fail_closed.unwrap_or(true);

    // GEP-1494 `allowedResponseHeaders` → the headers copied from the auth
    // allow-response onto the upstream request; lower-cased for the proxy's
    // case-insensitive lookup. Shared by both transports.
    let response_headers: Arc<[Box<str>]> = spec
        .allowed_response_headers
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|h| h.to_ascii_lowercase().into_boxed_str())
        .collect();

    let transport = match spec.protocol {
        ExternalAuthProtocol::Http => {
            ExtAuthTransport::Http(HttpExtAuthConfig::new(response_headers, false))
        }
        ExternalAuthProtocol::Grpc => {
            // Envoy `envoy.service.auth.v3.Authorization/Check` (#23 P4). The proxy
            // sends the request context and maps the CheckResponse.
            ExtAuthTransport::Grpc(GrpcExtAuthConfig::new(response_headers))
        }
        // `ExternalAuthProtocol` is #[non_exhaustive]: a future protocol variant
        // must fail closed, never open, until it is wired here.
        _ => {
            tracing::warn!(
                policy_ns,
                "unknown CoxswainExternalAuth protocol — failing closed (503)"
            );
            return IngressAuthConfig::Unavailable;
        }
    };
    IngressAuthConfig::External(ExtAuthConfig::new(
        timeout,
        endpoints,
        fail_closed,
        transport,
    ))
}

/// Resolve the auth-service `backendRef` to ready pod endpoints.
///
/// `None` (fail-closed at the caller) when: the ref is not a core `Service`, a
/// cross-namespace ref has no matching `ReferenceGrant`, or the Service has no
/// ready endpoints.
fn resolve_backend(
    spec: &CoxswainExternalAuthSpec,
    policy_ns: &str,
    services: &reflector::Store<Service>,
    endpoint_cache: &EndpointCache,
    grants: &HashSet<ReferenceGrantKey>,
) -> Option<Arc<[SocketAddr]>> {
    let b = &spec.backend_ref;
    // Only core Services are valid auth backends.
    if b.kind != "Service" || (!b.group.is_empty() && b.group != "core") {
        tracing::warn!(
            group = %b.group,
            kind = %b.kind,
            "CoxswainExternalAuth backendRef is not a core Service — failing closed"
        );
        return None;
    }
    let ns = b.namespace.as_deref().unwrap_or(policy_ns);
    if ns != policy_ns && !reference_grants::backend_ref_allowed(policy_ns, ns, &b.name, grants) {
        tracing::warn!(
            from_ns = policy_ns,
            to_ns = ns,
            svc = %b.name,
            "cross-namespace CoxswainExternalAuth backendRef denied — no matching ReferenceGrant"
        );
        return None;
    }
    let resolved = endpoint_cache.get(ns, &b.name, i32::from(b.port), services);
    if resolved.addrs.is_empty() {
        tracing::warn!(
            auth_ns = ns,
            auth_svc = %b.name,
            auth_port = b.port,
            "CoxswainExternalAuth backendRef resolved to no ready endpoints — failing closed"
        );
        return None;
    }
    Some(resolved.addrs.clone().into())
}

/// Per-Gateway resolved ext-auth mandate from `CoxswainExternalAuth` policies
/// attached via `targetRefs` (#23, GEP-713 direct policy attachment).
///
/// Keyed by the targeted `Gateway`'s [`ObjectKey`]. Every `HTTPRoute` bound to a
/// Gateway present here has this policy's check **prepended** to its auth chain —
/// an additive, non-removable mandate: a route filter can add checks but never
/// drop the Gateway-level one.
pub type ExternalAuthGatewayIndex = HashMap<ObjectKey, Arc<IngressAuthConfig>>;

/// Total ordering for `Option<SystemTime>`: `None` sorts last (an unknown
/// `creationTimestamp` loses conflict resolution to any known one). Mirrors
/// [`super::client_traffic_policy`]'s `earlier`.
fn earlier(a: Option<SystemTime>, b: Option<SystemTime>) -> bool {
    match (a, b) {
        (Some(ta), Some(tb)) => ta < tb,
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => false,
    }
}

/// Resolve every `CoxswainExternalAuth` that attaches to an owned Gateway via
/// `targetRefs` into a per-Gateway ext-auth mandate plus a per-policy status map.
///
/// One Gateway can be targeted by at most one policy: on a collision the older
/// `creationTimestamp` wins (ties broken by `(namespace, name)`) and the loser is
/// marked `Accepted=False, reason=Conflicted` — the same oldest-wins rule as
/// [`super::client_traffic_policy::resolve_client_traffic_policies`]. Only
/// same-namespace `targetRefs` are honoured (the CRD constrains the target to the
/// policy's own namespace); a `targetRef` to an unowned or foreign-namespace
/// Gateway is ignored and produces no status entry.
///
/// The resolved [`IngressAuthConfig`] fails **closed** (503) when the policy's
/// `backendRef` has no endpoints or the protocol is unsupported — an accepted but
/// broken Gateway mandate denies rather than silently opening every route.
///
/// # Errors
///
/// No errors are returned; a policy that resolves to no owned Gateway simply
/// contributes nothing to either map.
#[must_use = "caller must wire the index into route building and publish the status map"]
pub fn resolve_gateway_policies(
    policies: &reflector::Store<CoxswainExternalAuth>,
    owned_gateways: &HashSet<ObjectKey>,
    services: &reflector::Store<Service>,
    endpoint_cache: &EndpointCache,
    grants: &HashSet<ReferenceGrantKey>,
) -> (ExternalAuthGatewayIndex, CoxswainExternalAuthStatusMap) {
    // Candidate per Gateway: (creationTimestamp, policy_key, resolved-config).
    type Candidate = (Option<SystemTime>, ObjectKey, Arc<IngressAuthConfig>);
    let mut candidates: HashMap<ObjectKey, Candidate> = HashMap::new();
    let mut status_map: CoxswainExternalAuthStatusMap = HashMap::new();

    for policy in policies.state() {
        let policy: &CoxswainExternalAuth = &policy;
        if policy.spec.target_refs.is_empty() {
            // extensionRef-only policy — resolved on the route surface, not here.
            continue;
        }
        let policy_ns = policy.metadata.namespace.as_deref().unwrap_or("default");
        let Some(policy_name) = policy.metadata.name.as_deref() else {
            continue;
        };
        let policy_key = ObjectKey::new(policy_ns, policy_name);
        let created_at = metadata_created_at(&policy.metadata);

        // Resolve the mandate once per policy — shared across every Gateway it
        // targets (one refcount bump each). Fails closed on a broken backendRef.
        let config = Arc::new(resolve_spec(
            &policy.spec,
            policy_ns,
            services,
            endpoint_cache,
            grants,
        ));

        let mut matched_owned = false;
        for target in &policy.spec.target_refs {
            if target.group != "gateway.networking.k8s.io" || target.kind != "Gateway" {
                continue;
            }
            // The CRD constrains a targetRef to the policy's own namespace.
            let gw_key = ObjectKey::new(policy_ns, &target.name);
            if !owned_gateways.contains(&gw_key) {
                continue;
            }
            matched_owned = true;

            match candidates.entry(gw_key) {
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert((created_at, policy_key.clone(), Arc::clone(&config)));
                }
                std::collections::hash_map::Entry::Occupied(mut o) => {
                    let slot = o.get_mut();
                    // Only resolve a conflict against a *different* policy — a policy
                    // that lists the same Gateway twice in `targetRefs` is not in
                    // conflict with itself.
                    if slot.1 != policy_key {
                        if earlier(created_at, slot.0)
                            || (created_at == slot.0 && policy_key < slot.1)
                        {
                            let loser = slot.1.clone();
                            *slot = (created_at, policy_key.clone(), Arc::clone(&config));
                            mark_conflicted(&mut status_map, loser);
                        } else {
                            mark_conflicted(&mut status_map, policy_key.clone());
                        }
                    }
                }
            }
        }

        if matched_owned {
            status_map.entry(policy_key).or_default();
        }
    }

    let index: ExternalAuthGatewayIndex = candidates
        .into_iter()
        .map(|(gw_key, (_, _, config))| (gw_key, config))
        .collect();
    (index, status_map)
}

/// Mark a policy `Accepted=False, reason=Conflicted` (lost oldest-wins on a Gateway).
fn mark_conflicted(map: &mut CoxswainExternalAuthStatusMap, key: ObjectKey) {
    let entry = map.entry(key).or_default();
    entry.accepted = false;
    entry.accepted_reason = "Conflicted";
    entry.conflicted = true;
    entry.conflicted_reason = "TargetConflict";
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use kube::runtime::watcher;

    /// Build a `CoxswainExternalAuth` from YAML, optionally with a `creationTimestamp`
    /// and `targetRefs` list.
    fn make_policy(
        ns: &str,
        name: &str,
        created: Option<&str>,
        target_gateways: &[&str],
    ) -> CoxswainExternalAuth {
        let ts = created
            .map(|t| format!("  creationTimestamp: {t}\n"))
            .unwrap_or_default();
        let targets = if target_gateways.is_empty() {
            String::new()
        } else {
            let mut s = String::from("  targetRefs:\n");
            for gw in target_gateways {
                s.push_str(&format!(
                    "  - group: gateway.networking.k8s.io\n    kind: Gateway\n    name: {gw}\n"
                ));
            }
            s
        };
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: CoxswainExternalAuth\n\
             metadata:\n  namespace: {ns}\n  name: {name}\n{ts}\
             spec:\n  protocol: HTTP\n  backendRef:\n    name: authz\n    port: 4180\n{targets}",
        );
        serde_yaml::from_str(&yaml).unwrap_or_else(|e| panic!("bad yaml: {e}\n---\n{yaml}"))
    }

    fn store_from(policies: Vec<CoxswainExternalAuth>) -> reflector::Store<CoxswainExternalAuth> {
        let (reader, mut writer) = reflector::store();
        writer.apply_watcher_event(&watcher::Event::InitDone);
        for p in policies {
            writer.apply_watcher_event(&watcher::Event::Apply(p));
        }
        reader
    }

    fn empty_svc() -> reflector::Store<Service> {
        let (reader, mut writer) = reflector::store();
        writer.apply_watcher_event(&watcher::Event::InitDone);
        reader
    }

    fn empty_endpoint_cache() -> EndpointCache {
        EndpointCache::default()
    }

    fn owned(gws: &[(&str, &str)]) -> HashSet<ObjectKey> {
        gws.iter().map(|(ns, n)| ObjectKey::new(*ns, *n)).collect()
    }

    #[test]
    fn no_policies_yields_empty() {
        let (index, status) = resolve_gateway_policies(
            &store_from(vec![]),
            &owned(&[("ns", "gw")]),
            &empty_svc(),
            &empty_endpoint_cache(),
            &HashSet::new(),
        );
        assert!(index.is_empty());
        assert!(status.is_empty());
    }

    #[test]
    fn extension_ref_only_policy_is_not_indexed() {
        // A policy with no targetRefs is a route-surface filter — it must never
        // appear in the Gateway index or the status map.
        let (index, status) = resolve_gateway_policies(
            &store_from(vec![make_policy("ns", "p", None, &[])]),
            &owned(&[("ns", "gw")]),
            &empty_svc(),
            &empty_endpoint_cache(),
            &HashSet::new(),
        );
        assert!(
            index.is_empty(),
            "extensionRef-only policy must not be indexed"
        );
        assert!(
            status.is_empty(),
            "extensionRef-only policy gets no ancestor status"
        );
    }

    #[test]
    fn gateway_targeted_policy_is_indexed_and_accepted() {
        let (index, status) = resolve_gateway_policies(
            &store_from(vec![make_policy("ns", "p", None, &["gw"])]),
            &owned(&[("ns", "gw")]),
            &empty_svc(),
            &empty_endpoint_cache(),
            &HashSet::new(),
        );
        assert!(
            index.contains_key(&ObjectKey::new("ns", "gw")),
            "targeted Gateway must be in the index"
        );
        // Backend has no endpoints in this test → the resolved mandate fails closed
        // (Unavailable), but the Gateway is still covered.
        assert!(matches!(
            index[&ObjectKey::new("ns", "gw")].as_ref(),
            IngressAuthConfig::Unavailable
        ));
        let s = status
            .get(&ObjectKey::new("ns", "p"))
            .expect("status entry for the targeting policy");
        assert!(s.accepted);
        assert!(!s.conflicted);
    }

    #[test]
    fn unowned_gateway_target_is_ignored() {
        let (index, status) = resolve_gateway_policies(
            &store_from(vec![make_policy("ns", "p", None, &["other-gw"])]),
            &owned(&[("ns", "gw")]),
            &empty_svc(),
            &empty_endpoint_cache(),
            &HashSet::new(),
        );
        assert!(index.is_empty());
        assert!(
            status.is_empty(),
            "a policy targeting only unowned Gateways gets no status"
        );
    }

    #[test]
    fn older_policy_wins_conflict_newer_is_conflicted() {
        // Two policies target the same Gateway; the older creationTimestamp wins the
        // index slot and the newer is marked Conflicted (oldest-wins, GEP-713).
        let older = make_policy("ns", "older", Some("2020-01-01T00:00:00Z"), &["gw"]);
        let newer = make_policy("ns", "newer", Some("2024-01-01T00:00:00Z"), &["gw"]);
        let (index, status) = resolve_gateway_policies(
            &store_from(vec![newer, older]),
            &owned(&[("ns", "gw")]),
            &empty_svc(),
            &empty_endpoint_cache(),
            &HashSet::new(),
        );
        assert_eq!(index.len(), 1, "one Gateway → one index entry");
        let older_status = status
            .get(&ObjectKey::new("ns", "older"))
            .expect("older status");
        assert!(older_status.accepted, "older policy wins → Accepted");
        assert!(!older_status.conflicted);
        let newer_status = status
            .get(&ObjectKey::new("ns", "newer"))
            .expect("newer status");
        assert!(!newer_status.accepted, "newer policy loses → not Accepted");
        assert!(newer_status.conflicted);
        assert_eq!(newer_status.conflicted_reason, "TargetConflict");
    }

    #[test]
    fn duplicate_target_ref_to_same_gateway_does_not_self_conflict() {
        // A policy listing the same Gateway twice in targetRefs is not in conflict
        // with itself: it stays Accepted and is indexed once.
        let policy = make_policy("ns", "p", None, &["gw", "gw"]);
        let (index, status) = resolve_gateway_policies(
            &store_from(vec![policy]),
            &owned(&[("ns", "gw")]),
            &empty_svc(),
            &empty_endpoint_cache(),
            &HashSet::new(),
        );
        assert_eq!(index.len(), 1, "one Gateway → one index entry");
        let s = status
            .get(&ObjectKey::new("ns", "p"))
            .expect("status entry");
        assert!(
            s.accepted,
            "duplicate self-target must not conflict → Accepted"
        );
        assert!(!s.conflicted);
    }
}
