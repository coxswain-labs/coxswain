//! `Gateway` status patch builder and staleness check (GEP-1364).

use super::conditions::{has_condition, make_condition};
use super::config::StatusAddress;
use crate::status_common::{
    OPERATOR_OWNED_CONDITION_TYPE_PREFIX, build_listener_status, listener_route_kind_info,
};
use coxswain_reflector::gw_types::v::gateways::{Gateway, GatewayStatusListeners};
use coxswain_reflector::tls::GatewayListenerHealth;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

/// Returns true when the Gateway's current status does not yet reflect the
/// desired state computed from `health`. Prevents redundant patches and
/// watch-feedback loops.
pub(super) fn gateway_needs_status_patch(gw: &Gateway, health: &GatewayListenerHealth) -> bool {
    if !accepted_is_true(gw) {
        return true;
    }
    if !super::conditions::gateway_programmed(gw) {
        return true;
    }
    let current_listener_count = gw
        .status
        .as_ref()
        .and_then(|s| s.listeners.as_deref())
        .map(<[GatewayStatusListeners]>::len)
        .unwrap_or(0);
    if current_listener_count != gw.spec.listeners.len() {
        return true;
    }
    let current_listeners = gw
        .status
        .as_ref()
        .and_then(|s| s.listeners.as_ref())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for listener in &gw.spec.listeners {
        let (has_invalid_kinds, _) = listener_route_kind_info(listener);
        let info = health.listeners.get(&listener.name);
        let desired_healthy =
            !has_invalid_kinds && info.map(|i| i.tls_outcome.is_healthy()).unwrap_or(true);
        let current_listener = current_listeners.iter().find(|sl| sl.name == listener.name);
        let current_resolved = current_listener
            .map(|sl| has_condition(Some(sl.conditions.as_slice()), "ResolvedRefs"))
            .unwrap_or(false);
        if desired_healthy != current_resolved {
            return true;
        }
        let desired_attached = info.map(|i| i.attached_routes).unwrap_or(0);
        let current_attached = current_listener.map(|sl| sl.attached_routes).unwrap_or(0);
        if desired_attached != current_attached {
            return true;
        }
    }
    // GEP-1364: every condition's observedGeneration must reflect the generation
    // the controller last processed. A spec-only change bumps .metadata.generation
    // without changing programmed-ness, leaving existing conditions stale.
    //
    // Operator-owned conditions (`gateway.coxswain-labs.dev/` prefix) have
    // their own observed-generation lifecycle driven by the operator's
    // reconcile, so the status writer ignores their staleness here.
    let expected_gen = gw.metadata.generation.unwrap_or(0);
    if let Some(conds) = gw.status.as_ref().and_then(|s| s.conditions.as_deref())
        && any_status_writer_owned_condition_stale(conds, expected_gen)
    {
        return true;
    }
    for sl in current_listeners {
        if any_condition_stale(&sl.conditions, expected_gen) {
            return true;
        }
    }
    false
}

fn any_condition_stale(conditions: &[Condition], expected_gen: i64) -> bool {
    conditions
        .iter()
        .any(|c| c.observed_generation.unwrap_or(0) < expected_gen)
}

/// Skip operator-owned conditions whose observed-generation lifecycle is
/// driven separately by the operator's reconcile loop.
fn any_status_writer_owned_condition_stale(conditions: &[Condition], expected_gen: i64) -> bool {
    conditions
        .iter()
        .filter(|c| !c.type_.starts_with(OPERATOR_OWNED_CONDITION_TYPE_PREFIX))
        .any(|c| c.observed_generation.unwrap_or(0) < expected_gen)
}

/// Returns true iff the Gateway's current `Accepted` condition is the canonical
/// `(True, reason=Accepted)` pair. The shared-pool writer is the sole writer
/// of `Accepted` for non-dedicated Gateways; any other state requires a patch.
fn accepted_is_true(gw: &Gateway) -> bool {
    gw.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == "Accepted"))
        .is_some_and(|c| c.status == "True" && c.reason == "Accepted")
}

pub(super) fn build_gateway_status_patch(
    gw: &Gateway,
    health: &GatewayListenerHealth,
    generation: i64,
    now: &Time,
    addr: Option<&StatusAddress>,
    ingress_ports: coxswain_reflector::ingress::IngressPorts,
) -> serde_json::Value {
    // Preserve any operator-owned conditions (those whose type starts with
    // `gateway.coxswain-labs.dev/`) so the merge patch below doesn't clobber
    // them. The operator side mirrors the convention by preserving everything
    // NOT prefixed with that domain. See `crate::operator::status` for the
    // counterparty.
    let mut conditions = vec![
        make_condition("Accepted", "True", "Accepted", "", generation, now.clone()),
        make_condition(
            "Programmed",
            "True",
            "Programmed",
            "",
            generation,
            now.clone(),
        ),
    ];
    if let Some(existing) = gw.status.as_ref().and_then(|s| s.conditions.as_deref()) {
        conditions.extend(
            existing
                .iter()
                .filter(|c| c.type_.starts_with(OPERATOR_OWNED_CONDITION_TYPE_PREFIX))
                .cloned(),
        );
    }

    let listener_statuses: Vec<GatewayStatusListeners> = gw
        .spec
        .listeners
        .iter()
        .map(|l| {
            let info = health.listeners.get(&l.name);
            build_listener_status(l, info, ingress_ports, generation, now)
        })
        .collect();

    let mut patch = serde_json::json!({
        "status": {
            "conditions": conditions,
            "listeners": listener_statuses,
        }
    });
    if let Some(addr) = addr {
        let (type_str, value_str) = match addr {
            StatusAddress::Ip(ip) => ("IPAddress", ip.to_string()),
            StatusAddress::Hostname(h) => ("Hostname", h.clone()),
        };
        patch["status"]["addresses"] = serde_json::json!([{
            "type": type_str,
            "value": value_str,
        }]);
    }
    patch
}

#[cfg(test)]
mod tests {
    use super::super::gateway_status::gateway_needs_status_patch;
    use coxswain_reflector::gw_types::v::gateways::{
        Gateway, GatewaySpec, GatewayStatus, GatewayStatusListeners,
    };
    use coxswain_reflector::tls::GatewayListenerHealth;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;

    fn condition(type_: &str, observed_gen: i64) -> Condition {
        // Reason matches what `build_gateway_status_patch` writes: `Accepted` and
        // `Programmed` carry the type name as the reason for the shared-pool
        // happy path.
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
                listeners: vec![
                    coxswain_reflector::gw_types::v::gateways::GatewayListeners {
                        name: "http".to_string(),
                        port: 80,
                        protocol: "HTTP".to_string(),
                        ..Default::default()
                    },
                ],
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
}
