//! Patch helper for the `gateway.coxswain-labs.dev/DedicatedProxyReady`
//! status condition (#210).
//!
//! This condition is the cut-over signal the shared-proxy reflector reads
//! (in [`coxswain_reflector::reconciler::shared_proxy::gateway_is_cut_over`]):
//! when True, the shared pool stops serving the Gateway's routes because the
//! dedicated proxy has at least one Ready Pod and can take traffic itself.
//!
//! ## Conditions array coordination
//!
//! The status writer in [`crate::controller::gateway_status`] patches
//! `Gateway.status.conditions` with the standard `Accepted` + `Programmed`
//! conditions via JSON merge patches that REPLACE the whole array. This
//! module's writes must preserve those entries (and vice versa), or the two
//! writers would clobber each other. The convention:
//!
//! - This module writes `gateway.coxswain-labs.dev/`-prefixed conditions and
//!   preserves everything else.
//! - The status writer writes standard Gateway-API conditions and preserves
//!   anything whose type starts with `gateway.coxswain-labs.dev/`.
//!
//! Each writer reads the Gateway's current conditions, rebuilds the full
//! list preserving the OTHER manager's entries, and writes back via Merge.

use coxswain_reflector::gw_types::v::gateways::Gateway;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::{
    Api, Client,
    api::{Patch, PatchParams},
};

/// Condition type for the dedicated-proxy-ready cut-over signal.
pub(crate) const CONDITION_TYPE: &str = "gateway.coxswain-labs.dev/DedicatedProxyReady";
/// Reason set when the dedicated proxy has at least one Ready Pod.
pub(crate) const REASON_READY: &str = "Ready";
/// Reason set when the dedicated proxy has zero Ready Pods (provisioning,
/// restarting, crashed, drained).
pub(crate) const REASON_PROVISIONING: &str = "Provisioning";

/// Patch `Gateway.status.conditions` to set [`CONDITION_TYPE`] to the given
/// readiness. Preserves any condition whose type is not [`CONDITION_TYPE`]
/// (the status writer's `Accepted` / `Programmed` and any other operator
/// conditions added in future).
///
/// Idempotent: if the current Gateway already carries the desired condition
/// state with `observed_generation >= metadata.generation`, returns Ok(())
/// without patching. This keeps the operator from creating watch-feedback
/// loops on every reconcile.
///
/// # Errors
///
/// Returns the underlying [`kube::Error`] if the apiserver rejects the patch.
pub(super) async fn patch_dedicated_proxy_ready(
    client: &Client,
    gw: &Gateway,
    ready: bool,
) -> Result<(), kube::Error> {
    let (status, reason, message): (&str, &str, &str) = if ready {
        (
            "True",
            REASON_READY,
            "Dedicated proxy has at least one Ready pod",
        )
    } else {
        (
            "False",
            REASON_PROVISIONING,
            "Dedicated proxy has zero Ready pods",
        )
    };
    let generation = gw.metadata.generation.unwrap_or(0);

    if current_condition_matches(gw, status, reason, generation) {
        return Ok(());
    }

    let now = Time(k8s_openapi::jiff::Timestamp::now());
    let desired = Condition {
        type_: CONDITION_TYPE.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation: Some(generation),
        last_transition_time: now,
    };

    let mut full: Vec<Condition> = preserved_conditions(gw);
    full.push(desired);

    write_conditions_patch(client, gw, full).await
}

/// Patch `Gateway.status.conditions` to remove any [`CONDITION_TYPE`] entry,
/// preserving everything else. Called on demotion out of dedicated mode (the
/// `params::resolve` cleanup path in [`super::reconciler`]) so the Gateway's
/// status returns to the shared-pool default once the dedicated resources
/// have been GC'd.
///
/// No-op when the Gateway carries no such condition.
///
/// # Errors
///
/// Returns the underlying [`kube::Error`] if the apiserver rejects the patch.
pub(super) async fn clear_dedicated_proxy_ready(
    client: &Client,
    gw: &Gateway,
) -> Result<(), kube::Error> {
    let preserved = preserved_conditions(gw);
    let current_len = gw
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_deref())
        .map(<[Condition]>::len)
        .unwrap_or(0);
    if preserved.len() == current_len {
        return Ok(());
    }
    write_conditions_patch(client, gw, preserved).await
}

fn preserved_conditions(gw: &Gateway) -> Vec<Condition> {
    gw.status
        .as_ref()
        .and_then(|s| s.conditions.as_deref())
        .unwrap_or(&[])
        .iter()
        .filter(|c| c.type_ != CONDITION_TYPE)
        .cloned()
        .collect()
}

fn current_condition_matches(gw: &Gateway, status: &str, reason: &str, generation: i64) -> bool {
    gw.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == CONDITION_TYPE))
        .is_some_and(|c| {
            c.status == status
                && c.reason == reason
                && c.observed_generation.unwrap_or(0) >= generation
        })
}

async fn write_conditions_patch(
    client: &Client,
    gw: &Gateway,
    conditions: Vec<Condition>,
) -> Result<(), kube::Error> {
    let namespace = gw.metadata.namespace.as_deref().unwrap_or_else(|| {
        panic!("invariant: Gateway has no namespace; the API server requires it")
    });
    let name =
        gw.metadata.name.as_deref().unwrap_or_else(|| {
            panic!("invariant: Gateway has no name; the API server requires it")
        });
    let patch = serde_json::json!({ "status": { "conditions": conditions } });
    let api: Api<Gateway> = Api::namespaced(client.clone(), namespace);
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_reflector::gw_types::v::gateways::GatewayStatus;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use kube::api::ObjectMeta;

    fn gw_with_conditions(conds: Vec<Condition>) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some("gw".into()),
                namespace: Some("ns".into()),
                generation: Some(2),
                ..Default::default()
            },
            spec: Default::default(),
            status: Some(GatewayStatus {
                conditions: Some(conds),
                ..Default::default()
            }),
        }
    }

    fn cond(type_: &str, status: &str, reason: &str, generation: i64) -> Condition {
        Condition {
            type_: type_.into(),
            status: status.into(),
            reason: reason.into(),
            message: String::new(),
            observed_generation: Some(generation),
            last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
        }
    }

    #[test]
    fn preserved_conditions_drops_only_our_type() {
        let gw = gw_with_conditions(vec![
            cond("Accepted", "True", "Accepted", 2),
            cond("Programmed", "True", "Programmed", 2),
            cond(CONDITION_TYPE, "True", REASON_READY, 2),
        ]);
        let preserved = preserved_conditions(&gw);
        assert_eq!(preserved.len(), 2);
        assert!(preserved.iter().any(|c| c.type_ == "Accepted"));
        assert!(preserved.iter().any(|c| c.type_ == "Programmed"));
        assert!(!preserved.iter().any(|c| c.type_ == CONDITION_TYPE));
    }

    #[test]
    fn current_condition_matches_true_state() {
        let gw = gw_with_conditions(vec![cond(CONDITION_TYPE, "True", REASON_READY, 2)]);
        assert!(current_condition_matches(&gw, "True", REASON_READY, 2));
        assert!(!current_condition_matches(
            &gw,
            "False",
            REASON_PROVISIONING,
            2
        ));
    }

    #[test]
    fn current_condition_does_not_match_stale_generation() {
        let gw = gw_with_conditions(vec![cond(CONDITION_TYPE, "True", REASON_READY, 1)]);
        // metadata.generation=2 but condition.observed_generation=1 → stale
        assert!(!current_condition_matches(&gw, "True", REASON_READY, 2));
    }

    #[test]
    fn current_condition_no_match_when_absent() {
        let gw = gw_with_conditions(vec![cond("Accepted", "True", "Accepted", 2)]);
        assert!(!current_condition_matches(&gw, "True", REASON_READY, 2));
    }
}
