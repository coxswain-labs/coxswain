//! Kubernetes API calls that write `ClientTrafficPolicy` status patches.
//!
//! Writes `status.ancestors[]` with `Accepted` and `Conflicted` conditions
//! for each Gateway (and optional listener) targeted by the policy.

use super::conditions::make_condition;
use coxswain_core::crd::client_traffic_policy::ClientTrafficPolicy;
use coxswain_core::ownership::ObjectKey;
use coxswain_reflector::gw_types::constants::PolicyConditionType;
use coxswain_reflector::status::{ClientTrafficPolicyStatus, ClientTrafficPolicyStatusMap};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
};

/// Patch `status.ancestors[]` on a `ClientTrafficPolicy` when the controller is leader.
///
/// Skips the patch when the policy has no entry in the status map (not
/// targeting an owned Gateway), when `metadata.generation` is unset, or when
/// no `targetRefs` point at a `gateway.networking.k8s.io/Gateway`.
pub(super) async fn patch_client_traffic_policy_status(
    client: &Client,
    policy: &ClientTrafficPolicy,
    controller_name: &str,
    ctp_status: &ClientTrafficPolicyStatusMap,
) {
    let name = match policy.metadata.name.as_deref() {
        Some(n) => n,
        None => return,
    };
    let ns = policy.metadata.namespace.as_deref().unwrap_or("default");
    let policy_key = ObjectKey::new(ns, name);

    let Some(health) = ctp_status.get(&policy_key) else {
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

    let api: Api<ClientTrafficPolicy> = Api::namespaced(client.clone(), ns);
    let patch = serde_json::json!({ "status": { "ancestors": ancestors } });
    let started = std::time::Instant::now();
    let result = api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await;
    crate::metrics::observe_status_patch("client_traffic_policy", started, &result);
    match result {
        Ok(_) => tracing::debug!(name, ns, "ClientTrafficPolicy status patched"),
        Err(e) => {
            tracing::warn!(name, ns, error = %e, "Failed to patch ClientTrafficPolicy status")
        }
    }
}

/// Build the `status.ancestors[]` JSON list for a policy.
///
/// Filters to `targetRefs` that point at `gateway.networking.k8s.io/Gateway`
/// only; other kinds are not ours to write. Uses raw `serde_json::Value` to
/// avoid struct-literal construction of `#[non_exhaustive]` types across crate
/// boundaries.
fn build_ancestors(
    health: &ClientTrafficPolicyStatus,
    policy: &ClientTrafficPolicy,
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
    // "Conflicted" is not a GEP-713 `PolicyConditionType` (the spec only
    // defines ResolvedRefs/Accepted; Conflicted is documented there as a
    // *reason* on Accepted) — coxswain models it as its own condition type,
    // a pre-existing design choice out of scope for #510 (type source only).
    let conflicted_val = serde_json::to_value(make_condition(
        "Conflicted",
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
        .filter(|tr| tr.group == "gateway.networking.k8s.io" && tr.kind == "Gateway")
        .map(|tr| {
            let mut ancestor_ref = serde_json::json!({
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "namespace": policy_ns,
                "name": tr.name,
            });
            if let Some(sn) = &tr.section_name {
                ancestor_ref["sectionName"] = serde_json::json!(sn);
            }
            serde_json::json!({
                "ancestorRef": ancestor_ref,
                "controllerName": controller_name,
                "conditions": [&accepted_val, &conflicted_val],
            })
        })
        .collect()
}
