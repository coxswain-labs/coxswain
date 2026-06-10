use super::super::AcceptedReason;
use super::super::gateway_status::gateway_needs_status_patch;
use coxswain_reflector::tls::GatewayListenerHealth;
use gateway_api::apis::standard::gateways::{
    Gateway, GatewaySpec, GatewayStatus, GatewayStatusListeners,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

fn condition(type_: &str, observed_gen: i64) -> Condition {
    // Reason matches what `build_gateway_status_patch` writes in the
    // override-is-None case: `Accepted` and `Programmed` carry the type name
    // as the reason. The Accepted-override path uses different reasons (e.g.
    // `InvalidParameters`); those tests build their conditions explicitly.
    Condition {
        type_: type_.to_string(),
        status: "True".to_string(),
        reason: type_.to_string(),
        message: String::new(),
        observed_generation: Some(observed_gen),
        last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            k8s_openapi::jiff::Timestamp::UNIX_EPOCH,
        ),
    }
}

fn listener_status(name: &str, cond_gen: i64) -> GatewayStatusListeners {
    GatewayStatusListeners {
        name: name.to_string(),
        attached_routes: 0,
        supported_kinds: None,
        conditions: vec![
            condition("Accepted", cond_gen),
            condition("Programmed", cond_gen),
            condition("ResolvedRefs", cond_gen),
        ],
    }
}

fn gateway(
    meta_gen: i64,
    top_conds: Option<Vec<Condition>>,
    listeners: Option<Vec<GatewayStatusListeners>>,
) -> Gateway {
    Gateway {
        metadata: kube::api::ObjectMeta {
            generation: Some(meta_gen),
            ..Default::default()
        },
        spec: GatewaySpec {
            listeners: vec![gateway_api::apis::standard::gateways::GatewayListeners {
                name: "http".to_string(),
                port: 80,
                protocol: "HTTP".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        },
        status: Some(GatewayStatus {
            conditions: top_conds,
            listeners,
            ..Default::default()
        }),
    }
}

fn default_health() -> GatewayListenerHealth {
    GatewayListenerHealth::default()
}

#[test]
fn needs_patch_when_no_status() {
    let gw = Gateway {
        status: None,
        ..Default::default()
    };
    assert!(gateway_needs_status_patch(&gw, &default_health(), None));
}

#[test]
fn needs_patch_when_accepted_missing() {
    let gw = gateway(1, Some(vec![condition("Programmed", 1)]), None);
    assert!(gateway_needs_status_patch(&gw, &default_health(), None));
}

#[test]
fn needs_patch_when_programmed_missing() {
    let gw = gateway(1, Some(vec![condition("Accepted", 1)]), None);
    assert!(gateway_needs_status_patch(&gw, &default_health(), None));
}

#[test]
fn needs_patch_when_top_level_condition_stale() {
    // Both Accepted and Programmed are True but at gen 0; metadata says gen 2.
    let gw = gateway(
        2,
        Some(vec![condition("Accepted", 0), condition("Programmed", 0)]),
        Some(vec![listener_status("http", 2)]),
    );
    assert!(gateway_needs_status_patch(&gw, &default_health(), None));
}

#[test]
fn needs_patch_when_listener_condition_stale() {
    // Top-level conditions are current; one listener condition is at stale gen.
    let gw = gateway(
        2,
        Some(vec![condition("Accepted", 2), condition("Programmed", 2)]),
        Some(vec![listener_status("http", 0)]),
    );
    assert!(gateway_needs_status_patch(&gw, &default_health(), None));
}

#[test]
fn needs_patch_when_listener_count_mismatch() {
    // Gateway spec has one listener but status reports none.
    let gw = gateway(
        1,
        Some(vec![condition("Accepted", 1), condition("Programmed", 1)]),
        Some(vec![]),
    );
    assert!(gateway_needs_status_patch(&gw, &default_health(), None));
}

#[test]
fn no_patch_needed_when_fully_up_to_date() {
    let gw = gateway(
        1,
        Some(vec![condition("Accepted", 1), condition("Programmed", 1)]),
        Some(vec![listener_status("http", 1)]),
    );
    assert!(!gateway_needs_status_patch(&gw, &default_health(), None));
}

/// Override active but current status still has `Accepted=True` from a prior
/// reconcile cycle → status writer must repatch.
#[test]
fn needs_patch_when_override_disagrees_with_current_accepted() {
    let gw = gateway(
        1,
        Some(vec![condition("Accepted", 1), condition("Programmed", 1)]),
        Some(vec![listener_status("http", 1)]),
    );
    assert!(gateway_needs_status_patch(
        &gw,
        &default_health(),
        Some(AcceptedReason::InvalidParameters)
    ));
}

/// Override matches current status (steady state of an invalid-parameters
/// Gateway) → no patch needed.
#[test]
fn no_patch_needed_when_override_matches_current_accepted_false() {
    let mut accepted_false = condition("Accepted", 1);
    accepted_false.status = "False".to_string();
    accepted_false.reason = "InvalidParameters".to_string();
    let mut programmed_false = condition("Programmed", 1);
    programmed_false.status = "False".to_string();
    programmed_false.reason = "Invalid".to_string();
    let gw = gateway(
        1,
        Some(vec![accepted_false, programmed_false]),
        Some(vec![listener_status("http", 1)]),
    );
    assert!(!gateway_needs_status_patch(
        &gw,
        &default_health(),
        Some(AcceptedReason::InvalidParameters)
    ));
}

/// Override has just cleared but current status still carries
/// `Accepted=False, reason=InvalidParameters` → status writer must repatch
/// to restore `Accepted=True`.
#[test]
fn needs_patch_when_override_cleared_but_status_still_false() {
    let mut accepted_false = condition("Accepted", 1);
    accepted_false.status = "False".to_string();
    accepted_false.reason = "InvalidParameters".to_string();
    let mut programmed_false = condition("Programmed", 1);
    programmed_false.status = "False".to_string();
    programmed_false.reason = "Invalid".to_string();
    let gw = gateway(
        1,
        Some(vec![accepted_false, programmed_false]),
        Some(vec![listener_status("http", 1)]),
    );
    assert!(gateway_needs_status_patch(&gw, &default_health(), None));
}
