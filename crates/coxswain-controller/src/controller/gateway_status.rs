//! `Gateway` status patch builder and staleness check (GEP-1364).

use super::conditions::{has_condition, make_condition};
use super::config::StatusAddress;
use crate::gw_types::v::gateways::{
    Gateway, GatewayListeners, GatewayStatusListeners, GatewayStatusListenersSupportedKinds,
};
use crate::tls::GatewayListenerHealth;
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
                .listeners
                .get(&l.name)
                .map(|i| i.tls_outcome.clone())
                .unwrap_or_default();
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
            let attached = health.listeners.get(&l.name).map(|i| i.attached_routes).unwrap_or(0);
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
