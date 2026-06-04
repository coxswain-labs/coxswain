use super::conditions::{has_condition, make_condition};
use super::config::StatusAddress;
use crate::tls::{GatewayListenerHealth, ListenerTlsOutcome};
use gateway_api::apis::standard::gateways::{
    Gateway, GatewayListeners, GatewayStatusListeners, GatewayStatusListenersSupportedKinds,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

/// Returns true when the Gateway's current status does not yet reflect the desired
/// state computed from `health`. Prevents redundant patches and watch-feedback loops.
pub(super) fn gateway_needs_status_patch(gw: &Gateway, health: &GatewayListenerHealth) -> bool {
    if !super::conditions::gateway_accepted(gw) {
        return true;
    }
    if !super::conditions::gateway_programmed(gw) {
        return true;
    }
    let current_listener_count = gw
        .status
        .as_ref()
        .and_then(|s| s.listeners.as_deref())
        .map(|l| l.len())
        .unwrap_or(0);
    if current_listener_count != gw.spec.listeners.len() {
        return true;
    }
    let current_listeners = gw
        .status
        .as_ref()
        .and_then(|s| s.listeners.as_ref())
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    for listener in &gw.spec.listeners {
        let (has_invalid_kinds, _) = listener_route_kind_info(listener);
        let desired_healthy = !has_invalid_kinds
            && health
                .by_listener
                .get(&listener.name)
                .map(|o| o.is_healthy())
                .unwrap_or(true);
        let current_listener = current_listeners.iter().find(|sl| sl.name == listener.name);
        let current_resolved = current_listener
            .map(|sl| has_condition(Some(sl.conditions.as_slice()), "ResolvedRefs"))
            .unwrap_or(false);
        if desired_healthy != current_resolved {
            return true;
        }
        let desired_attached = health
            .attached_routes
            .get(&listener.name)
            .copied()
            .unwrap_or(0);
        let current_attached = current_listener.map(|sl| sl.attached_routes).unwrap_or(0);
        if desired_attached != current_attached {
            return true;
        }
    }
    // GEP-1364: every condition's observedGeneration must reflect the generation
    // the controller last processed. A spec-only change bumps .metadata.generation
    // without changing programmed-ness, leaving existing conditions stale.
    let expected_gen = gw.metadata.generation.unwrap_or(0);
    if let Some(conds) = gw.status.as_ref().and_then(|s| s.conditions.as_deref())
        && any_condition_stale(conds, expected_gen)
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

/// Returns `(has_any_invalid, supported_kinds)` for a listener's `allowedRoutes.kinds`.
///
/// - `has_any_invalid`: true if any listed kind is not supported by this controller.
///   When true, `ResolvedRefs: False, reason: InvalidRouteKinds` must be set.
/// - `supported_kinds`: intersection of the listed kinds with what we support (currently
///   only `HTTPRoute`). Empty list when all listed kinds are unsupported. When
///   `allowedRoutes.kinds` is absent or empty, returns `[HTTPRoute]` with `has_any_invalid=false`.
pub(super) fn listener_route_kind_info(
    listener: &GatewayListeners,
) -> (bool, Vec<GatewayStatusListenersSupportedKinds>) {
    const HTTP_ROUTE_GROUP: &str = "gateway.networking.k8s.io";
    let http_route_kind = || GatewayStatusListenersSupportedKinds {
        group: Some(HTTP_ROUTE_GROUP.to_string()),
        kind: "HTTPRoute".to_string(),
    };
    let allowed = match listener
        .allowed_routes
        .as_ref()
        .and_then(|ar| ar.kinds.as_deref())
    {
        Some(k) if !k.is_empty() => k,
        _ => return (false, vec![http_route_kind()]),
    };
    let mut has_invalid = false;
    let mut includes_http_route = false;
    for k in allowed {
        let is_http_route = k.kind == "HTTPRoute"
            && k.group
                .as_deref()
                .is_none_or(|g| g.is_empty() || g == HTTP_ROUTE_GROUP);
        if is_http_route {
            includes_http_route = true;
        } else {
            has_invalid = true;
        }
    }
    let supported = if includes_http_route {
        vec![http_route_kind()]
    } else {
        vec![]
    };
    (has_invalid, supported)
}

pub(super) fn build_gateway_status_patch(
    gw: &Gateway,
    health: &GatewayListenerHealth,
    generation: i64,
    now: &Time,
    addr: Option<&StatusAddress>,
) -> serde_json::Value {
    // Gateway-level Programmed is always True once the controller has processed the
    // Gateway. Per-listener conditions (ListenerConditionProgrammed, ResolvedRefs)
    // express individual listener health. This matches what the conformance suite
    // expects: the setup waits for Programmed=True on all Gateways, including ones
    // with invalid TLS refs, and the per-listener tests check listener conditions.
    let (prog_status, prog_reason, prog_message) = ("True", "Programmed", "");

    let conditions = vec![
        make_condition("Accepted", "True", "Accepted", "", generation, now.clone()),
        make_condition(
            "Programmed",
            prog_status,
            prog_reason,
            prog_message,
            generation,
            now.clone(),
        ),
    ];

    let listener_statuses: Vec<GatewayStatusListeners> = gw
        .spec
        .listeners
        .iter()
        .map(|l| {
            let outcome = health
                .by_listener
                .get(&l.name)
                .cloned()
                .unwrap_or(ListenerTlsOutcome::NotApplicable);
            let (has_invalid_kinds, supported_kinds_list) = listener_route_kind_info(l);
            let (resolved_refs_status, resolved_refs_reason, resolved_refs_msg) =
                if has_invalid_kinds {
                    (
                        "False",
                        "InvalidRouteKinds",
                        "One or more specified route kinds are not supported by this implementation",
                    )
                } else if outcome.is_healthy() {
                    ("True", "ResolvedRefs", "")
                } else {
                    ("False", outcome.reason(), outcome.message())
                };
            let (listener_prog_status, listener_prog_reason, listener_prog_msg) =
                if outcome.is_healthy() {
                    ("True", "Programmed", "")
                } else {
                    ("False", outcome.reason(), outcome.message())
                };
            let attached = health.attached_routes.get(&l.name).copied().unwrap_or(0);
            tracing::debug!(
                listener = %l.name,
                resolved_refs = resolved_refs_status,
                programmed = listener_prog_status,
                attached_routes = attached,
                supported_kinds = supported_kinds_list.len(),
                "Listener status"
            );
            let listener_conditions = vec![
                make_condition("Accepted", "True", "Accepted", "", generation, now.clone()),
                make_condition(
                    "ResolvedRefs",
                    resolved_refs_status,
                    resolved_refs_reason,
                    resolved_refs_msg,
                    generation,
                    now.clone(),
                ),
                make_condition(
                    "Programmed",
                    listener_prog_status,
                    listener_prog_reason,
                    listener_prog_msg,
                    generation,
                    now.clone(),
                ),
            ];
            GatewayStatusListeners {
                name: l.name.clone(),
                attached_routes: attached,
                supported_kinds: Some(supported_kinds_list),
                conditions: listener_conditions,
            }
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
    use super::*;
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
}
