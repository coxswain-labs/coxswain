//! Helpers shared between the shared-pool status writer
//! ([`crate::controller::gateway_status`]) and the dedicated-mode status writer
//! ([`crate::operator::status`]).
//!
//! Per-listener condition semantics — `Accepted`, `ResolvedRefs`, `Programmed`
//! — are listener-intrinsic: they derive from the listener's TLS outcome, its
//! `allowedRoutes.kinds` validation, and the controller-level
//! `IngressPorts` reservation. None of these depend on whether the parent
//! Gateway is served by the shared proxy pool or by a dedicated proxy. Living
//! the per-listener stanza in one place keeps both writers byte-identical on
//! listener conditions, which is what Gateway-API conformance checks.
//!
//! Visibility is `pub(crate)` throughout — downstream crates have no business
//! constructing condition objects, and the two consumers are siblings under
//! `crate::`.

use coxswain_reflector::gw_types::v::gateways::{
    GatewayListeners, GatewayStatusListeners, GatewayStatusListenersSupportedKinds,
};
use coxswain_reflector::ingress::IngressPorts;
use coxswain_reflector::tls::{FrontendValidationOutcome, ListenerInfo};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

/// Conditions whose `type` starts with this prefix are owned by the
/// dedicated-mode operator path (currently
/// `gateway.coxswain-labs.dev/DedicatedProxyReady`, with more reserved for
/// future Coxswain-owned conditions). The shared-pool status writer preserves
/// them when rebuilding `status.conditions` so a JSON-merge patch from one
/// writer doesn't clobber writes from the other. See `crate::operator::status`
/// for the counterparty preservation logic.
pub(crate) const OPERATOR_OWNED_CONDITION_TYPE_PREFIX: &str = "gateway.coxswain-labs.dev/";

/// Build a `metav1.Condition` with `observed_generation` set.
///
/// Single source of truth for condition construction across both status
/// writers — avoid `Condition { ... }` struct literals elsewhere so any
/// future field convention (e.g. `last_transition_time` clamping) lands in
/// one place.
#[must_use]
pub(crate) fn make_condition(
    type_: &str,
    status: &str,
    reason: &str,
    message: &str,
    generation: i64,
    now: Time,
) -> Condition {
    Condition {
        type_: type_.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation: Some(generation),
        last_transition_time: now,
    }
}

/// Returns `(has_any_invalid, supported_kinds)` for a listener's
/// `allowedRoutes.kinds`.
///
/// - `has_any_invalid`: true if any listed kind is not supported by this
///   controller. When true, `ResolvedRefs: False, reason: InvalidRouteKinds`
///   must be set on the listener.
/// - `supported_kinds`: intersection of the listed kinds with what we support
///   (currently only `HTTPRoute`). Empty list when all listed kinds are
///   unsupported. When `allowedRoutes.kinds` is absent or empty, returns
///   `[HTTPRoute]` with `has_any_invalid=false`.
pub(crate) fn listener_route_kind_info(
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

/// Build the per-listener status stanza: `(Accepted, ResolvedRefs, Programmed)`
/// conditions plus `attached_routes` and `supported_kinds`.
///
/// Conditions are derived from:
/// - **Accepted**: always `True, reason=Accepted` (listener-level acceptance
///   is granted at the Gateway level today; per-listener `Accepted=False`
///   reasons like `UnsupportedProtocol` are not yet implemented).
/// - **ResolvedRefs**: `False, reason=InvalidRouteKinds` if any
///   `allowedRoutes.kinds` is unsupported; else `True, reason=ResolvedRefs`
///   if the listener's TLS outcome is healthy; else
///   `False, reason=<outcome.reason()>` reflecting the cert-ref failure.
/// - **Programmed**: `False, reason=PortUnavailable` when the listener's
///   port collides with the Ingress data plane reservation (#201); else
///   mirrors the TLS outcome — `True, reason=Programmed` when healthy,
///   `False, reason=<outcome.reason()>` otherwise.
///
/// `frontend_validation` is the Gateway-wide GEP-91 client-cert validation
/// health (`spec.tls.frontend.default.validation`). When it failed to resolve
/// its CA ref, **every HTTPS listener** is impacted (the listener can no longer
/// validate clients): `ResolvedRefs=False/InvalidCACertificateRef`,
/// `Accepted=False/NoValidCACertificate`, `Programmed=False`. HTTP listeners
/// are untouched — frontend validation only gates TLS-terminating listeners.
/// This is what the `GatewayFrontendInvalidDefaultClientCertificateValidation`
/// conformance test asserts.
///
/// `info` is the snapshot for this listener from
/// `SharedGatewayListenerHealth.load()`; pass `None` for listeners the
/// reflector hasn't yet computed (initial sync, or a Gateway whose class
/// isn't claimed) — the defaults degrade to the healthy/empty case.
#[must_use]
pub(crate) fn build_listener_status(
    listener: &GatewayListeners,
    info: Option<&ListenerInfo>,
    ingress_ports: IngressPorts,
    generation: i64,
    now: &Time,
) -> GatewayStatusListeners {
    let outcome = info.map(|i| i.tls_outcome.clone()).unwrap_or_default();
    let (has_invalid_kinds, supported_kinds_list) = listener_route_kind_info(listener);
    // GEP-91: this listener's frontend client-cert CA ref (perPort override or
    // gateway default) failed to resolve. It takes precedence over the
    // per-listener cert outcome — even a listener with a valid server
    // certificate cannot validate clients without a usable CA, so it is not
    // Programmed. `frontend_outcome` is NotApplicable for non-HTTPS listeners
    // and for HTTPS listeners with no frontend validation configured.
    let frontend_outcome = info.map(|i| &i.frontend_outcome);
    let frontend_ca_failed = frontend_outcome.is_some_and(FrontendValidationOutcome::is_failed);
    let frontend_reason = frontend_outcome
        .map(FrontendValidationOutcome::resolved_refs_reason)
        .unwrap_or("ResolvedRefs");
    let frontend_msg = frontend_outcome
        .map(FrontendValidationOutcome::message)
        .unwrap_or("");
    let (resolved_refs_status, resolved_refs_reason, resolved_refs_msg) = if frontend_ca_failed {
        ("False", frontend_reason, frontend_msg)
    } else if has_invalid_kinds {
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
    // Accepted is True/Accepted unless the frontend CA failed, in which case the
    // HTTPS listener has no valid CA to terminate mutual TLS with.
    let (accepted_status, accepted_reason, accepted_msg) = if frontend_ca_failed {
        ("False", "NoValidCACertificate", frontend_msg)
    } else {
        ("True", "Accepted", "")
    };
    // Port-conflict detection (#201): a Gateway listener whose port is
    // reserved by the Ingress data plane (--proxy-http-port / --proxy-https-port)
    // cannot be bound by GatewayProxy. Surface Programmed=False with
    // reason=PortUnavailable so operators see the conflict without trawling logs.
    let listener_port = u16::try_from(listener.port).unwrap_or(0);
    let port_conflict =
        ingress_ports.http == Some(listener_port) || ingress_ports.https == Some(listener_port);
    let port_conflict_msg = format!(
        "port {listener_port} is reserved by the Ingress proxy (set via --proxy-http-port or --proxy-https-port)"
    );
    let (listener_prog_status, listener_prog_reason, listener_prog_msg) = if port_conflict {
        ("False", "PortUnavailable", port_conflict_msg.as_str())
    } else if frontend_ca_failed {
        ("False", "NoValidCACertificate", frontend_msg)
    } else if outcome.is_healthy() {
        ("True", "Programmed", "")
    } else {
        ("False", outcome.reason(), outcome.message())
    };
    let attached = info.map(|i| i.attached_routes).unwrap_or(0);
    tracing::debug!(
        listener = %listener.name,
        resolved_refs = resolved_refs_status,
        programmed = listener_prog_status,
        attached_routes = attached,
        supported_kinds = supported_kinds_list.len(),
        "Listener status"
    );
    let listener_conditions = vec![
        make_condition(
            "Accepted",
            accepted_status,
            accepted_reason,
            accepted_msg,
            generation,
            now.clone(),
        ),
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
        name: listener.name.clone(),
        attached_routes: attached,
        supported_kinds: Some(supported_kinds_list),
        conditions: listener_conditions,
    }
}
