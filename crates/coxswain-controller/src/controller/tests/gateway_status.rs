use super::super::gateway_status::gateway_needs_status_patch;
use crate::tls::GatewayListenerHealth;
use gateway_api::apis::standard::gateways::{
    Gateway, GatewaySpec, GatewayStatus, GatewayStatusListeners,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

fn condition(type_: &str, observed_gen: i64) -> Condition {
    Condition {
        type_: type_.to_string(),
        status: "True".to_string(),
        reason: String::new(),
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
    assert!(gateway_needs_status_patch(&gw, &default_health()));
}

#[test]
fn needs_patch_when_accepted_missing() {
    let gw = gateway(1, Some(vec![condition("Programmed", 1)]), None);
    assert!(gateway_needs_status_patch(&gw, &default_health()));
}

#[test]
fn needs_patch_when_programmed_missing() {
    let gw = gateway(1, Some(vec![condition("Accepted", 1)]), None);
    assert!(gateway_needs_status_patch(&gw, &default_health()));
}

#[test]
fn needs_patch_when_top_level_condition_stale() {
    // Both Accepted and Programmed are True but at gen 0; metadata says gen 2.
    let gw = gateway(
        2,
        Some(vec![condition("Accepted", 0), condition("Programmed", 0)]),
        Some(vec![listener_status("http", 2)]),
    );
    assert!(gateway_needs_status_patch(&gw, &default_health()));
}

#[test]
fn needs_patch_when_listener_condition_stale() {
    // Top-level conditions are current; one listener condition is at stale gen.
    let gw = gateway(
        2,
        Some(vec![condition("Accepted", 2), condition("Programmed", 2)]),
        Some(vec![listener_status("http", 0)]),
    );
    assert!(gateway_needs_status_patch(&gw, &default_health()));
}

#[test]
fn needs_patch_when_listener_count_mismatch() {
    // Gateway spec has one listener but status reports none.
    let gw = gateway(
        1,
        Some(vec![condition("Accepted", 1), condition("Programmed", 1)]),
        Some(vec![]),
    );
    assert!(gateway_needs_status_patch(&gw, &default_health()));
}

#[test]
fn no_patch_needed_when_fully_up_to_date() {
    let gw = gateway(
        1,
        Some(vec![condition("Accepted", 1), condition("Programmed", 1)]),
        Some(vec![listener_status("http", 1)]),
    );
    assert!(!gateway_needs_status_patch(&gw, &default_health()));
}
