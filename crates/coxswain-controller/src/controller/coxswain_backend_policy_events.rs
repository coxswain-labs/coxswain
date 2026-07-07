//! Kubernetes API calls that write `CoxswainBackendPolicy` status patches (#354).
//!
//! Writes `status.ancestors[]` with an `Accepted` condition for each `Service`
//! targeted by the policy (the ancestor is the targeted Service itself).

use super::conditions::{CoxswainConditionType, make_condition};
use coxswain_core::crd::coxswain_backend_policy::CoxswainBackendPolicy;
use coxswain_core::ownership::ObjectKey;
use coxswain_reflector::gw_types::constants::PolicyConditionType;
use coxswain_reflector::status::{CoxswainBackendPolicyStatus, CoxswainBackendPolicyStatusMap};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
};

/// Patch `status.ancestors[]` on a `CoxswainBackendPolicy` when the controller is leader.
///
/// Skips the patch when the policy has no entry in the status map (does not
/// target a Service), when `metadata.generation` is unset, or when no
/// `targetRefs` point at a core `Service`.
pub(super) async fn patch_coxswain_backend_policy_status(
    client: &Client,
    policy: &CoxswainBackendPolicy,
    controller_name: &str,
    cbp_status: &CoxswainBackendPolicyStatusMap,
) {
    let name = match policy.metadata.name.as_deref() {
        Some(n) => n,
        None => return,
    };
    let ns = policy.metadata.namespace.as_deref().unwrap_or("default");
    let policy_key = ObjectKey::new(ns, name);

    let Some(health) = cbp_status.get(&policy_key) else {
        return;
    };

    let Some(observed_gen) = policy.metadata.generation else {
        return;
    };

    let now = Time(k8s_openapi::jiff::Timestamp::now());
    let ancestors = build_ancestors(health, policy, ns, controller_name, observed_gen, now);

    if ancestors.is_empty() {
        return;
    }

    let api: Api<CoxswainBackendPolicy> = Api::namespaced(client.clone(), ns);
    let patch = serde_json::json!({ "status": { "ancestors": ancestors } });
    let started = std::time::Instant::now();
    let result = api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await;
    crate::metrics::observe_status_patch("coxswain_backend_policy", started, &result);
    match result {
        Ok(_) => tracing::debug!(name, ns, "CoxswainBackendPolicy status patched"),
        Err(e) => {
            tracing::warn!(name, ns, error = %e, "Failed to patch CoxswainBackendPolicy status")
        }
    }
}

/// Build the `status.ancestors[]` JSON list for a policy.
///
/// One ancestor per `targetRef` pointing at a core `Service`. Uses raw
/// `serde_json::Value` to avoid struct-literal construction of `#[non_exhaustive]`
/// types across crate boundaries.
fn build_ancestors(
    health: &CoxswainBackendPolicyStatus,
    policy: &CoxswainBackendPolicy,
    policy_ns: &str,
    controller_name: &str,
    observed_gen: i64,
    now: Time,
) -> Vec<serde_json::Value> {
    let acc_status = if health.accepted { "True" } else { "False" };
    let acc_reason = health.accepted_reason;
    let con_status = if health.conflicted { "True" } else { "False" };
    let con_reason = health.conflicted_reason;

    let accepted_val = serde_json::to_value(make_condition(
        PolicyConditionType::Accepted,
        acc_status,
        acc_reason,
        "",
        observed_gen,
        now.clone(),
    ))
    .unwrap_or(serde_json::Value::Null);
    // See `CoxswainConditionType` for why this isn't a `PolicyConditionType`
    // variant.
    let conflicted_val = serde_json::to_value(make_condition(
        CoxswainConditionType::Conflicted,
        con_status,
        con_reason,
        "",
        observed_gen,
        now,
    ))
    .unwrap_or(serde_json::Value::Null);

    policy
        .spec
        .target_refs
        .iter()
        .filter(|tr| (tr.group.is_empty() || tr.group == "core") && tr.kind == "Service")
        .map(|tr| {
            let ancestor_ref = serde_json::json!({
                "group": "",
                "kind": "Service",
                "namespace": policy_ns,
                "name": tr.name,
            });
            serde_json::json!({
                "ancestorRef": ancestor_ref,
                "controllerName": controller_name,
                "conditions": [&accepted_val, &conflicted_val],
            })
        })
        .collect()
}
