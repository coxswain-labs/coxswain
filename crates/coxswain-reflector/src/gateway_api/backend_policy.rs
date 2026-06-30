//! `CoxswainBackendPolicy` resolver: per-`Service` connect/idle timeout index (#354).
//!
//! Resolves `CoxswainBackendPolicy` resources against the Services they target
//! and returns:
//! - A per-Service [`BackendPolicyIndex`] of parsed connect/idle timeouts,
//!   consumed during Gateway API route building to set
//!   `BackendGroup::with_connect_timeout` / `with_keepalive_timeout`.
//! - A per-policy status map consumed by the controller to patch
//!   `status.ancestors[]`.
//!
//! Precedence follows GEP-713 direct-policy attachment: when two policies target
//! the same Service, the older `creationTimestamp` wins (ties broken by
//! `{ns}/{name}`); the loser receives `Accepted=False, reason=Conflicted`.
//!
//! Duration strings are parsed with [`crate::duration::parse_duration`], which
//! WARNs and yields `None` on malformed input — so a bad value degrades to the
//! default connection behaviour rather than erroring the connection (#354).

use crate::duration::parse_duration;
use crate::k8s_utils::metadata_created_at;
use crate::status::CoxswainBackendPolicyStatusMap;
use coxswain_core::crd::coxswain_backend_policy::CoxswainBackendPolicy;
use coxswain_core::ownership::ObjectKey;
use kube::runtime::reflector;
use std::collections::HashMap;
use std::time::Duration;

/// Resolved per-`Service` connect/idle timeouts from the winning policy.
#[non_exhaustive]
pub struct ResolvedBackendPolicy {
    /// Upstream TCP-connect timeout, if the policy set a parseable `connect`.
    pub(crate) connect: Option<Duration>,
    /// Upstream keepalive idle timeout, if the policy set a parseable `idle`.
    pub(crate) idle: Option<Duration>,
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

        // Only index Services whose winning policy actually sets a timeout; a
        // no-op policy leaves default behaviour untouched.
        if connect.is_some() || idle.is_some() {
            index.insert(svc_key, ResolvedBackendPolicy { connect, idle });
        }
    }

    (index, status_map)
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
        assert!(index.get(&ObjectKey::new("ns", "svc")).is_none());
        // Policy is still accepted — a bad value is a WARN, not a rejection.
        let s = status.get(&ObjectKey::new("ns", "p1")).expect("status");
        assert!(s.accepted);
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
