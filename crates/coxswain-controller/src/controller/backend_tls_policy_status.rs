use crate::gw_types::v::backendtlspolicies::{
    BackendTLSPolicy, BackendTlsPolicyStatusAncestors, BackendTlsPolicyStatusAncestorsAncestorRef,
};
use crate::tls::BackendTlsPolicyAncestorHealth;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

/// Returns `true` when the live policy status already reflects the desired conditions,
/// allowing the controller to skip a no-op patch.
pub fn policy_needs_status_patch(
    policy: &BackendTLSPolicy,
    health: &BackendTlsPolicyAncestorHealth,
    controller_name: &str,
) -> bool {
    let desired = build_desired_ancestors(policy, health, controller_name, None);
    let actual = policy
        .status
        .as_ref()
        .map(|s| s.ancestors.as_slice())
        .unwrap_or(&[]);

    // Compare ignoring `lastTransitionTime`.
    if desired.len() != actual.len() {
        return true;
    }
    for (d, a) in desired.iter().zip(actual.iter()) {
        if d.controller_name != a.controller_name {
            return true;
        }
        if ancestor_ref_differs(&d.ancestor_ref, &a.ancestor_ref) {
            return true;
        }
        if conditions_differ(&d.conditions, &a.conditions) {
            return true;
        }
    }
    false
}

fn ancestor_ref_differs(
    a: &BackendTlsPolicyStatusAncestorsAncestorRef,
    b: &BackendTlsPolicyStatusAncestorsAncestorRef,
) -> bool {
    a.name != b.name || a.namespace != b.namespace || a.group != b.group || a.kind != b.kind
}

fn conditions_differ(want: &[Condition], have: &[Condition]) -> bool {
    if want.len() != have.len() {
        return true;
    }
    for (w, h) in want.iter().zip(have.iter()) {
        if w.type_ != h.type_
            || w.status != h.status
            || w.reason != h.reason
            || w.observed_generation != h.observed_generation
        {
            return true;
        }
    }
    false
}

/// Build the JSON-merge patch value for `BackendTLSPolicy.status`.
pub fn build_backend_tls_policy_status_patch(
    policy: &BackendTLSPolicy,
    health: &BackendTlsPolicyAncestorHealth,
    controller_name: &str,
    now: &Time,
) -> serde_json::Value {
    let ancestors = build_desired_ancestors(policy, health, controller_name, Some(now));
    serde_json::json!({ "status": { "ancestors": ancestors } })
}

fn build_desired_ancestors(
    policy: &BackendTLSPolicy,
    health: &BackendTlsPolicyAncestorHealth,
    controller_name: &str,
    now: Option<&Time>,
) -> Vec<BackendTlsPolicyStatusAncestors> {
    let generation = policy.metadata.generation.unwrap_or(0);
    let now = now
        .cloned()
        .unwrap_or(Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH));

    let outcome = match &health.outcome {
        Some(o) => o,
        None => return vec![],
    };

    health
        .gateway_keys
        .iter()
        .map(|gw_key| {
            let accepted_cond = make_condition(
                "Accepted",
                if outcome.accepted { "True" } else { "False" },
                outcome.accepted_reason,
                &outcome.accepted_message,
                generation,
                now.clone(),
            );
            let resolved_refs_cond = make_condition(
                "ResolvedRefs",
                if outcome.resolved_refs {
                    "True"
                } else {
                    "False"
                },
                outcome.resolved_refs_reason,
                &outcome.resolved_refs_message,
                generation,
                now.clone(),
            );

            BackendTlsPolicyStatusAncestors {
                controller_name: controller_name.to_string(),
                ancestor_ref: BackendTlsPolicyStatusAncestorsAncestorRef {
                    group: Some("gateway.networking.k8s.io".to_string()),
                    kind: Some("Gateway".to_string()),
                    name: gw_key.name.clone(),
                    namespace: Some(gw_key.ns.clone()),
                    port: None,
                    section_name: None,
                },
                conditions: vec![accepted_cond, resolved_refs_cond],
            }
        })
        .collect()
}

fn make_condition(
    type_: &str,
    status: &str,
    reason: &str,
    message: &str,
    observed_generation: i64,
    last_transition_time: Time,
) -> Condition {
    Condition {
        type_: type_.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation: Some(observed_generation),
        last_transition_time,
    }
}
