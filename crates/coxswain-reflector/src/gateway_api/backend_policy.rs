//! `CoxswainBackendPolicy` resolver: per-`Service` connection-policy index.
//!
//! Resolves `CoxswainBackendPolicy` resources against the Services they target
//! and returns:
//! - A per-Service [`BackendPolicyIndex`] of parsed connect/idle timeouts (#354),
//!   load-balancing algorithm (#389), and circuit-breaker config (#478), consumed
//!   during Gateway API route building to set `BackendGroup::with_connect_timeout`
//!   / `with_keepalive_timeout` / `with_load_balance` and `RouteEntry::with_circuit_breaker`.
//! - A per-policy status map consumed by the controller to patch
//!   `status.ancestors[]`.
//!
//! Precedence follows GEP-713 direct-policy attachment: when two policies target
//! the same Service, the older `creationTimestamp` wins (ties broken by
//! `{ns}/{name}`); the loser receives `Accepted=False, reason=Conflicted`.
//!
//! All values are parsed leniently: a malformed duration, an unknown LB selector,
//! or an out-of-range breaker threshold WARNs and degrades to the default
//! behaviour rather than erroring the connection or rejecting the resource.

use crate::duration::parse_duration;
use crate::k8s_utils::metadata_created_at;
use crate::status::CoxswainBackendPolicyStatusMap;
use coxswain_core::crd::coxswain_backend_policy::{BackendCircuitBreaker, CoxswainBackendPolicy};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::routing::{CircuitBreakerConfig, LoadBalance};
use kube::runtime::reflector;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Default circuit-breaker EWMA window when the policy omits `window` (#478).
/// Mirrors the Ingress `circuit-breaker-window` annotation default.
const CB_DEFAULT_WINDOW: Duration = Duration::from_secs(10);
/// Default circuit-breaker open duration when the policy omits `openDuration`.
const CB_DEFAULT_OPEN: Duration = Duration::from_secs(5);
/// Default minimum-requests gate when the policy omits `minRequests`.
const CB_DEFAULT_MIN_REQUESTS: u32 = 10;

/// Resolved per-`Service` connection policy from the winning policy.
#[non_exhaustive]
pub struct ResolvedBackendPolicy {
    /// Upstream TCP-connect timeout, if the policy set a parseable `connect`.
    pub(crate) connect: Option<Duration>,
    /// Upstream keepalive idle timeout, if the policy set a parseable `idle`.
    pub(crate) idle: Option<Duration>,
    /// Upstream load-balancing algorithm, if the policy set a recognised
    /// `loadBalancer.algorithm` other than round-robin (#389).
    pub(crate) load_balance: Option<LoadBalance>,
    /// Upstream circuit-breaker config, if the policy set a valid
    /// `circuitBreaker.threshold` (#478).
    pub(crate) circuit_breaker: Option<Arc<CircuitBreakerConfig>>,
}

/// Per-`Service` timeout index. Keyed by the targeted Service's [`ObjectKey`].
///
/// Built once per reconciler rebuild and threaded into the Gateway API route
/// build pass. A Service with no attached policy has no entry and retains the
/// default connection behaviour.
pub type BackendPolicyIndex = HashMap<ObjectKey, ResolvedBackendPolicy>;

/// `true` when a `CoxswainBackendPolicy` targetRef points at a core `Service`.
fn is_service_ref(group: &str, kind: &str) -> bool {
    (group.is_empty() || group == "core") && kind == "Service"
}

/// Resolve `CoxswainBackendPolicy` resources from the store into a per-Service
/// timeout index and a per-policy status map.
///
/// Only `targetRefs` pointing at a core `Service` are processed; refs to other
/// kinds are ignored. A policy that targets at least one Service gets a status
/// entry (default `Accepted`); conflict losers are marked `Conflicted`.
#[must_use = "caller must wire the index into route building and publish the status map"]
pub fn build_backend_policy_index(
    policies: &reflector::Store<CoxswainBackendPolicy>,
) -> (BackendPolicyIndex, CoxswainBackendPolicyStatusMap) {
    // Group competing policies by their target Service so conflict resolution is
    // per-Service.
    let mut candidates: HashMap<ObjectKey, Vec<std::sync::Arc<CoxswainBackendPolicy>>> =
        HashMap::new();
    let mut status_map: CoxswainBackendPolicyStatusMap = HashMap::new();

    for policy in policies.state() {
        let ns = policy.metadata.namespace.as_deref().unwrap_or("default");
        let Some(name) = policy.metadata.name.as_deref() else {
            continue;
        };
        let policy_key = ObjectKey::new(ns, name);
        let mut targets_a_service = false;
        for target in &policy.spec.target_refs {
            if !is_service_ref(&target.group, &target.kind) {
                continue;
            }
            targets_a_service = true;
            let svc_key = ObjectKey::new(ns, &target.name);
            candidates
                .entry(svc_key)
                .or_default()
                .push(std::sync::Arc::clone(&policy));
        }
        // A policy targeting at least one Service is one we report on; seed it as
        // Accepted (conflict losers are downgraded below).
        if targets_a_service {
            status_map.entry(policy_key).or_default();
        }
    }

    let mut index: BackendPolicyIndex = HashMap::new();

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
        let winner_ns = winner.metadata.namespace.as_deref().unwrap_or("default");

        // Mark losers Conflicted.
        for loser in &competing[1..] {
            let loser_ns = loser.metadata.namespace.as_deref().unwrap_or("default");
            let loser_name = loser.metadata.name.as_deref().unwrap_or("unknown");
            mark_conflicted(&mut status_map, ObjectKey::new(loser_ns, loser_name));
        }

        // Parse the winner's timeouts (WARN + fall back to None on bad values).
        let (connect, idle) = match winner.spec.timeouts.as_ref() {
            Some(t) => (
                t.connect.as_deref().and_then(parse_with_warn(winner_ns)),
                t.idle.as_deref().and_then(parse_with_warn(winner_ns)),
            ),
            None => (None, None),
        };

        // Resolve the LB algorithm (#389) and circuit breaker (#478), each
        // WARN + fall back on bad values.
        let winner_name = winner.metadata.name.as_deref().unwrap_or("unknown");
        let load_balance =
            resolve_load_balance(winner.spec.load_balancer.as_ref(), winner_ns, winner_name);
        let circuit_breaker =
            resolve_circuit_breaker(winner.spec.circuit_breaker.as_ref(), winner_ns, winner_name);

        // Only index Services whose winning policy sets at least one knob; a
        // no-op policy leaves default behaviour untouched.
        if connect.is_some()
            || idle.is_some()
            || load_balance.is_some()
            || circuit_breaker.is_some()
        {
            index.insert(
                svc_key,
                ResolvedBackendPolicy {
                    connect,
                    idle,
                    load_balance,
                    circuit_breaker,
                },
            );
        }
    }

    (index, status_map)
}

/// Resolve `loadBalancer.algorithm` (#389) into a [`LoadBalance`].
///
/// Returns `None` for an absent policy, an unrecognised value (WARN + fall back
/// to round-robin), or an explicit `RoundRobin` (the default — no override
/// needed). The shared [`LoadBalance::parse_lenient`] keeps this vocabulary
/// identical to the Ingress `load-balance` annotation.
fn resolve_load_balance(
    lb: Option<&coxswain_core::crd::coxswain_backend_policy::BackendLoadBalancer>,
    ns: &str,
    name: &str,
) -> Option<LoadBalance> {
    let algorithm = lb?.algorithm.as_str();
    match LoadBalance::parse_lenient(algorithm) {
        // RoundRobin is the default; indexing it would be a no-op.
        Ok(LoadBalance::RoundRobin) => None,
        Ok(parsed) => Some(parsed),
        Err(e) => {
            tracing::warn!(
                namespace = ns,
                policy = name,
                value = algorithm,
                error = %e,
                "CoxswainBackendPolicy: unrecognised loadBalancer.algorithm; falling back to round_robin"
            );
            None
        }
    }
}

/// Resolve `circuitBreaker` (#478) into a [`CircuitBreakerConfig`].
///
/// `threshold` is the gate: absent or outside `1..=100` disables the breaker
/// (WARN + `None`). The remaining knobs default to the same values as the Ingress
/// `circuit-breaker-*` annotations (window `10s`, open `5s`, min-requests `10`);
/// an unparseable duration WARNs and falls back to the per-field default.
fn resolve_circuit_breaker(
    cb: Option<&BackendCircuitBreaker>,
    ns: &str,
    name: &str,
) -> Option<Arc<CircuitBreakerConfig>> {
    let cb = cb?;
    let threshold = match cb.threshold {
        Some(t) if (1..=100).contains(&t) => t,
        other => {
            tracing::warn!(
                namespace = ns,
                policy = name,
                threshold = ?other,
                "CoxswainBackendPolicy: circuitBreaker.threshold absent or out of 1..=100; breaker disabled"
            );
            return None;
        }
    };

    let dur = |raw: Option<&str>, default: Duration| -> Duration {
        match raw {
            None => default,
            Some(s) => parse_with_warn(ns)(s).unwrap_or(default),
        }
    };

    let window = dur(cb.window.as_deref(), CB_DEFAULT_WINDOW);
    let open_duration = dur(cb.open_duration.as_deref(), CB_DEFAULT_OPEN);
    let min_requests = cb.min_requests.unwrap_or(CB_DEFAULT_MIN_REQUESTS);
    // max_open_duration is optional: a bad value falls back to None (constant backoff).
    let max_open_duration = cb
        .max_open_duration
        .as_deref()
        .and_then(parse_with_warn(ns));

    Some(Arc::new(CircuitBreakerConfig::new(
        threshold,
        min_requests,
        window,
        open_duration,
        max_open_duration,
    )))
}

/// Returns a closure that parses a duration string and WARNs on malformed input,
/// tagging the warning with the policy namespace for operator triage.
fn parse_with_warn(ns: &str) -> impl Fn(&str) -> Option<Duration> + '_ {
    move |raw: &str| {
        let parsed = parse_duration(raw);
        if parsed.is_none() {
            tracing::warn!(
                namespace = ns,
                value = raw,
                "CoxswainBackendPolicy: unparseable timeout; falling back to default"
            );
        }
        parsed
    }
}

fn mark_conflicted(map: &mut CoxswainBackendPolicyStatusMap, key: ObjectKey) {
    let entry = map.entry(key).or_default();
    entry.accepted = false;
    entry.accepted_reason = "Conflicted";
    entry.conflicted = true;
    entry.conflicted_reason = "SameServiceConflict";
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::runtime::reflector;

    fn make_policy(
        ns: &str,
        name: &str,
        svc: &str,
        connect: Option<&str>,
        idle: Option<&str>,
    ) -> CoxswainBackendPolicy {
        let mut timeouts = String::new();
        if connect.is_some() || idle.is_some() {
            timeouts.push_str("  timeouts:\n");
            if let Some(c) = connect {
                timeouts.push_str(&format!("    connect: {c}\n"));
            }
            if let Some(i) = idle {
                timeouts.push_str(&format!("    idle: {i}\n"));
            }
        }
        let yaml = format!(
            concat!(
                "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n",
                "kind: CoxswainBackendPolicy\n",
                "metadata:\n",
                "  namespace: {ns}\n",
                "  name: {name}\n",
                "spec:\n",
                "  targetRefs:\n",
                "  - group: \"\"\n",
                "    kind: Service\n",
                "    name: {svc}\n",
                "{timeouts}",
            ),
            ns = ns,
            name = name,
            svc = svc,
            timeouts = timeouts,
        );
        serde_yaml::from_str(&yaml).unwrap_or_else(|e| panic!("bad yaml: {e}\n---\n{yaml}"))
    }

    fn store_from(policies: Vec<CoxswainBackendPolicy>) -> reflector::Store<CoxswainBackendPolicy> {
        let (reader, mut writer) = reflector::store();
        writer.apply_watcher_event(&kube::runtime::watcher::Event::InitDone);
        for p in policies {
            writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(p));
        }
        reader
    }

    #[test]
    fn no_policies_returns_empty() {
        let store = store_from(vec![]);
        let (index, status) = build_backend_policy_index(&store);
        assert!(index.is_empty());
        assert!(status.is_empty());
    }

    #[test]
    fn timeouts_parsed_and_indexed_by_service() {
        let store = store_from(vec![make_policy(
            "ns",
            "p1",
            "svc",
            Some("500ms"),
            Some("60s"),
        )]);
        let (index, status) = build_backend_policy_index(&store);
        let resolved = index.get(&ObjectKey::new("ns", "svc")).expect("indexed");
        assert_eq!(resolved.connect, Some(Duration::from_millis(500)));
        assert_eq!(resolved.idle, Some(Duration::from_secs(60)));
        let s = status.get(&ObjectKey::new("ns", "p1")).expect("status");
        assert!(s.accepted);
        assert!(!s.conflicted);
    }

    #[test]
    fn invalid_value_falls_back_to_none_but_policy_accepted() {
        let store = store_from(vec![make_policy(
            "ns",
            "p1",
            "svc",
            Some("not-a-duration"),
            None,
        )]);
        let (index, status) = build_backend_policy_index(&store);
        // No parseable timeout → no index entry (default behaviour retained).
        assert!(!index.contains_key(&ObjectKey::new("ns", "svc")));
        // Policy is still accepted — a bad value is a WARN, not a rejection.
        let s = status.get(&ObjectKey::new("ns", "p1")).expect("status");
        assert!(s.accepted);
    }

    /// Parse a policy from a raw `spec:` body fragment (already indented two
    /// spaces under `spec:`), for the LB/circuit-breaker cases the timeout-only
    /// `make_policy` helper does not cover.
    fn policy_from_spec(ns: &str, name: &str, spec_body: &str) -> CoxswainBackendPolicy {
        let yaml = format!(
            concat!(
                "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n",
                "kind: CoxswainBackendPolicy\n",
                "metadata:\n",
                "  namespace: {ns}\n",
                "  name: {name}\n",
                "spec:\n",
                "{spec_body}",
            ),
            ns = ns,
            name = name,
            spec_body = spec_body,
        );
        serde_yaml::from_str(&yaml).unwrap_or_else(|e| panic!("bad yaml: {e}\n---\n{yaml}"))
    }

    const SVC_TARGET: &str = "  targetRefs:\n  - kind: Service\n    name: svc\n";

    #[test]
    fn load_balance_algorithm_resolved_and_indexed() {
        let spec = format!("{SVC_TARGET}  loadBalancer:\n    algorithm: least_conn\n");
        let store = store_from(vec![policy_from_spec("ns", "p1", &spec)]);
        let (index, _) = build_backend_policy_index(&store);
        let resolved = index.get(&ObjectKey::new("ns", "svc")).expect("indexed");
        assert_eq!(resolved.load_balance, Some(LoadBalance::LeastConn));
    }

    #[test]
    fn unknown_load_balance_algorithm_falls_back_and_not_indexed() {
        // Only knob is an unknown algorithm → no override → no index entry.
        let spec = format!("{SVC_TARGET}  loadBalancer:\n    algorithm: bogus\n");
        let store = store_from(vec![policy_from_spec("ns", "p1", &spec)]);
        let (index, status) = build_backend_policy_index(&store);
        assert!(!index.contains_key(&ObjectKey::new("ns", "svc")));
        // Bad value is a WARN, not a rejection.
        assert!(
            status
                .get(&ObjectKey::new("ns", "p1"))
                .expect("status")
                .accepted
        );
    }

    #[test]
    fn round_robin_algorithm_is_a_noop_and_not_indexed() {
        let spec = format!("{SVC_TARGET}  loadBalancer:\n    algorithm: round_robin\n");
        let store = store_from(vec![policy_from_spec("ns", "p1", &spec)]);
        let (index, _) = build_backend_policy_index(&store);
        assert!(!index.contains_key(&ObjectKey::new("ns", "svc")));
    }

    #[test]
    fn circuit_breaker_resolved_with_defaults() {
        let spec = format!("{SVC_TARGET}  circuitBreaker:\n    threshold: 50\n");
        let store = store_from(vec![policy_from_spec("ns", "p1", &spec)]);
        let (index, _) = build_backend_policy_index(&store);
        let resolved = index.get(&ObjectKey::new("ns", "svc")).expect("indexed");
        let cb = resolved.circuit_breaker.as_ref().expect("breaker present");
        assert_eq!(cb.threshold_pct, 50);
        assert_eq!(cb.min_requests, CB_DEFAULT_MIN_REQUESTS);
        assert_eq!(cb.window, CB_DEFAULT_WINDOW);
        assert_eq!(cb.open_duration, CB_DEFAULT_OPEN);
        assert_eq!(cb.max_open_duration, None);
    }

    #[test]
    fn circuit_breaker_out_of_range_threshold_disables_and_not_indexed() {
        // threshold 0 is the disabled gate → no breaker, no index entry.
        let spec = format!("{SVC_TARGET}  circuitBreaker:\n    threshold: 0\n");
        let store = store_from(vec![policy_from_spec("ns", "p1", &spec)]);
        let (index, status) = build_backend_policy_index(&store);
        assert!(!index.contains_key(&ObjectKey::new("ns", "svc")));
        assert!(
            status
                .get(&ObjectKey::new("ns", "p1"))
                .expect("status")
                .accepted
        );
    }

    #[test]
    fn oldest_policy_wins_loser_conflicted() {
        // Same creationTimestamp (unset) → tie broken by name: "p1" < "p2".
        let store = store_from(vec![
            make_policy("ns", "p2", "svc", Some("2s"), None),
            make_policy("ns", "p1", "svc", Some("1s"), None),
        ]);
        let (index, status) = build_backend_policy_index(&store);
        // Winner p1 → connect 1s.
        let resolved = index.get(&ObjectKey::new("ns", "svc")).expect("indexed");
        assert_eq!(resolved.connect, Some(Duration::from_secs(1)));
        // p1 accepted, p2 conflicted.
        assert!(status.get(&ObjectKey::new("ns", "p1")).unwrap().accepted);
        let loser = status.get(&ObjectKey::new("ns", "p2")).unwrap();
        assert!(!loser.accepted);
        assert!(loser.conflicted);
    }
}
