//! Kubernetes API calls that write `CoxswainExternalAuth` status patches (#23).
//!
//! Writes `status.ancestors[]` with `Accepted` / `Conflicted` conditions for each
//! `Gateway` targeted by the policy (the ancestor is the targeted Gateway). Mirrors
//! [`super::coxswain_backend_policy_events`] — the only difference is the ancestor
//! kind (a Gateway rather than a Service).

use super::conditions::{CoxswainConditionType, make_condition};
use coxswain_core::crd::coxswain_external_auth::CoxswainExternalAuth;
use coxswain_core::ownership::ObjectKey;
use coxswain_reflector::gw_types::constants::PolicyConditionType;
use coxswain_reflector::status::{CoxswainExternalAuthStatus, CoxswainExternalAuthStatusMap};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
};

/// Patch `status.ancestors[]` on a `CoxswainExternalAuth` when the controller is leader.
///
/// Skips the patch when the policy has no entry in the status map (does not attach
/// to any owned Gateway via `targetRefs`), when `metadata.generation` is unset, or
/// when no `targetRefs` point at a `Gateway`.
pub(super) async fn patch_coxswain_external_auth_status(
    client: &Client,
    policy: &CoxswainExternalAuth,
    controller_name: &str,
    external_auth_status: &CoxswainExternalAuthStatusMap,
) {
    let name = match policy.metadata.name.as_deref() {
        Some(n) => n,
        None => return,
    };
    let ns = policy.metadata.namespace.as_deref().unwrap_or("default");
    let policy_key = ObjectKey::new(ns, name);

    let Some(health) = external_auth_status.get(&policy_key) else {
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

    let api: Api<CoxswainExternalAuth> = Api::namespaced(client.clone(), ns);
    let patch = serde_json::json!({ "status": { "ancestors": ancestors } });
    let started = std::time::Instant::now();
    let result = api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await;
    crate::metrics::observe_status_patch("coxswain_external_auth", started, &result);
    match result {
        Ok(_) => tracing::debug!(name, ns, "CoxswainExternalAuth status patched"),
        Err(e) => {
            tracing::warn!(name, ns, error = %e, "Failed to patch CoxswainExternalAuth status")
        }
    }
}

/// Build the `status.ancestors[]` JSON list for a policy.
///
/// One ancestor per `targetRef` pointing at a `Gateway`.
fn build_ancestors(
    health: &CoxswainExternalAuthStatus,
    policy: &CoxswainExternalAuth,
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
    // See `CoxswainConditionType` for why this isn't a `PolicyConditionType` variant.
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
        .filter(|tr| tr.group == "gateway.networking.k8s.io" && tr.kind == "Gateway")
        .map(|tr| {
            let ancestor_ref = serde_json::json!({
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
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
