//! Kubernetes API calls that write `BackendTLSPolicy` status patches.
//!
//! Writes `status.ancestors[]` with `Accepted` and `ResolvedRefs` conditions
//! for each owned Gateway that is an ancestor of the policy's target Service.

use super::conditions::make_condition;
use coxswain_core::ownership::ObjectKey;
use coxswain_reflector::gw_types::BackendTlsPolicy;
use coxswain_reflector::gw_types::v::backendtlspolicies::{
    BackendTlsPolicyStatusAncestors, BackendTlsPolicyStatusAncestorsAncestorRef,
};
use coxswain_reflector::status::{BackendTlsPolicyStatus, BackendTlsPolicyStatusMap};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
};

/// Patch `status.ancestors[]` on a `BackendTLSPolicy` when the controller is leader.
///
/// Skips the patch when the policy has no ancestor Gateways (i.e. its target Service
/// is not referenced by any owned route), to avoid writing meaningless status.
pub(super) async fn patch_backend_tls_policy_status(
    client: &Client,
    policy: &BackendTlsPolicy,
    controller_name: &str,
    policy_status: &BackendTlsPolicyStatusMap,
) {
    let name = match policy.metadata.name.as_deref() {
        Some(n) => n,
        None => return,
    };
    let ns = policy.metadata.namespace.as_deref().unwrap_or("default");
    let policy_key = ObjectKey::new(ns, name);

    let Some(health) = policy_status.get(&policy_key) else {
        return;
    };

    // Skip if there are no ancestor Gateways — nothing useful to report yet.
    if health.ancestors.is_empty() && health.accepted {
        return;
    }

    let Some(observed_gen) = policy.metadata.generation else {
        return;
    };

    let api: Api<BackendTlsPolicy> = Api::namespaced(client.clone(), ns);
    let now = Time(k8s_openapi::jiff::Timestamp::now());

    let ancestors = build_ancestors(health, controller_name, observed_gen, now);

    let patch = serde_json::json!({ "status": { "ancestors": ancestors } });
    let started = std::time::Instant::now();
    let result = api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await;
    crate::metrics::observe_status_patch("backend_tls_policy", started, &result);
    match result {
        Ok(_) => tracing::debug!(name, ns, "BackendTLSPolicy status patched"),
        Err(e) => {
            tracing::warn!(name, ns, error = %e, "Failed to patch BackendTLSPolicy status")
        }
    }
}

/// Build the `status.ancestors[]` list for a policy.
///
/// When `health.ancestors` is empty but the policy was rejected (e.g. `Conflicted`),
/// we write a single entry with an empty ancestor ref so the condition is visible.
fn build_ancestors(
    health: &BackendTlsPolicyStatus,
    controller_name: &str,
    observed_gen: i64,
    now: Time,
) -> Vec<BackendTlsPolicyStatusAncestors> {
    let acc_status = if health.accepted { "True" } else { "False" };
    let acc_reason = health.accepted_reason;
    let res_status = if health.resolved_refs {
        "True"
    } else {
        "False"
    };
    let res_reason = health.resolved_refs_reason;

    let make_entry = |ancestor_ref: BackendTlsPolicyStatusAncestorsAncestorRef| {
        let accepted_cond = make_condition(
            "Accepted",
            acc_status,
            acc_reason,
            "",
            observed_gen,
            now.clone(),
        );
        let resolved_refs_cond = make_condition(
            "ResolvedRefs",
            res_status,
            res_reason,
            "",
            observed_gen,
            now.clone(),
        );
        BackendTlsPolicyStatusAncestors {
            ancestor_ref,
            controller_name: controller_name.to_string(),
            conditions: vec![accepted_cond, resolved_refs_cond],
        }
    };

    if health.ancestors.is_empty() {
        // Policy is rejected (e.g. Conflicted) with no known ancestor. Write one entry
        // with a placeholder ref so the condition is visible to the user.
        vec![make_entry(BackendTlsPolicyStatusAncestorsAncestorRef {
            group: Some("gateway.networking.k8s.io".to_string()),
            kind: Some("Gateway".to_string()),
            name: String::new(),
            namespace: None,
            port: None,
            section_name: None,
        })]
    } else {
        health
            .ancestors
            .iter()
            .map(|gw| {
                make_entry(BackendTlsPolicyStatusAncestorsAncestorRef {
                    group: Some("gateway.networking.k8s.io".to_string()),
                    kind: Some("Gateway".to_string()),
                    name: gw.name.clone(),
                    namespace: Some(gw.ns.clone()),
                    port: None,
                    section_name: None,
                })
            })
            .collect()
    }
}
