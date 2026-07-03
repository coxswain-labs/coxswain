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

pub(crate) mod addresses;

use coxswain_reflector::gw_types::constants::{ListenerConditionReason, ListenerConditionType};
use coxswain_reflector::gw_types::v::gateways::{
    GatewayListeners, GatewayStatusListeners, GatewayStatusListenersSupportedKinds,
};
use coxswain_reflector::ingress::IngressPorts;
use coxswain_reflector::status::{FrontendValidationOutcome, ListenerInfo, ListenerReadiness};
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
///
/// `type_` and `reason` accept `impl Display` rather than `&str` (#510) so
/// call sites pass the Go-derived typed constants from
/// `coxswain_reflector::gw_types::constants` (e.g.
/// `GatewayConditionReason::ResolvedRefs`) instead of hand-typed string
/// literals wherever the value is a fixed Gateway API condition/reason — a
/// typo or a drifted-from-spec string is now a compile error, not a silent
/// wire-format bug. Values with no upstream Go-source constant (a
/// reflector-computed reason, or a Coxswain-owned condition like
/// `gateway.coxswain-labs.dev/DedicatedProxyReady`) keep passing `&str`.
#[must_use]
pub(crate) fn make_condition(
    type_: impl std::fmt::Display,
    status: &str,
    reason: impl std::fmt::Display,
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
///   (`HTTPRoute`, and `TLSRoute` on `protocol: TLS` listeners regardless of
///   mode). Empty list when all listed kinds are unsupported. When
///   `allowedRoutes.kinds` is absent or empty, returns the default kind for
///   the listener protocol (`TLSRoute` for `protocol: TLS`, `HTTPRoute`
///   otherwise) with `has_any_invalid=false`.
pub(crate) fn listener_route_kind_info(
    listener: &GatewayListeners,
) -> (bool, Vec<GatewayStatusListenersSupportedKinds>) {
    const GW_GROUP: &str = "gateway.networking.k8s.io";
    let http_route_kind = || GatewayStatusListenersSupportedKinds {
        group: Some(GW_GROUP.to_string()),
        kind: "HTTPRoute".to_string(),
    };
    let tls_route_kind = || GatewayStatusListenersSupportedKinds {
        group: Some(GW_GROUP.to_string()),
        kind: "TLSRoute".to_string(),
    };
    // Any `protocol: TLS` listener (Passthrough or Terminate) carries TLSRoute
    // as its natural route kind. `protocol: HTTPS` is distinct — TLS terminated
    // at the gateway but with HTTP/GRPC parsing — so it falls through to the
    // HTTPRoute default.
    let is_tls_listener = listener.protocol == "TLS";

    let allowed = match listener
        .allowed_routes
        .as_ref()
        .and_then(|ar| ar.kinds.as_deref())
    {
        Some(k) if !k.is_empty() => k,
        _ => {
            if is_tls_listener {
                return (false, vec![tls_route_kind()]);
            }
            return (false, vec![http_route_kind()]);
        }
    };
    let mut has_invalid = false;
    let mut includes_http_route = false;
    let mut includes_tls_route = false;
    for k in allowed {
        let group_ok = k
            .group
            .as_deref()
            .is_none_or(|g| g.is_empty() || g == GW_GROUP);
        if k.kind == "HTTPRoute" && group_ok {
            includes_http_route = true;
        } else if k.kind == "TLSRoute" && group_ok && is_tls_listener {
            includes_tls_route = true;
        } else {
            has_invalid = true;
        }
    }
    let mut supported = Vec::new();
    if includes_http_route {
        supported.push(http_route_kind());
    }
    if includes_tls_route {
        supported.push(tls_route_kind());
    }
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
/// `SharedGatewayListenerStatus.load()`; pass `None` for listeners the
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
    let (has_invalid_kinds, supported_kinds_list) = listener_route_kind_info(listener);
    let listener_conditions = listener_condition_triplet(
        &listener.name,
        listener.port,
        info,
        has_invalid_kinds,
        ingress_ports,
        generation,
        now,
    );
    GatewayStatusListeners {
        name: listener.name.clone(),
        attached_routes: info.map(|i| i.attached_routes).unwrap_or(0),
        supported_kinds: Some(supported_kinds_list),
        conditions: listener_conditions,
    }
}

/// Build the `(Accepted, ResolvedRefs, Programmed)` condition triplet for one
/// listener — the conformance-critical reason mapping shared by the Gateway and
/// ListenerSet status writers (GEP-1713). The conditions are listener-intrinsic:
/// they derive only from the listener's port, TLS outcome, GEP-91 frontend
/// validation outcome, `allowedRoutes.kinds` validity (`has_invalid_kinds`), and
/// the Ingress data-plane port reservation — none of which depend on whether the
/// listener belongs to a Gateway or a ListenerSet.
///
/// See [`build_listener_status`] for the per-condition semantics.
#[must_use]
pub(crate) fn listener_condition_triplet(
    listener_name: &str,
    listener_port: i32,
    info: Option<&ListenerInfo>,
    has_invalid_kinds: bool,
    ingress_ports: IngressPorts,
    generation: i64,
    now: &Time,
) -> Vec<Condition> {
    let outcome = info.map(|i| i.readiness.clone()).unwrap_or_default();
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
    // `resolved_refs_reason` (and the other two reason bindings below) unify to
    // `String`: most arms are fixed Gateway API reasons (typed via
    // `ListenerConditionReason`, so a typo or spec drift is a compile error),
    // but the fallback arm forwards `outcome.reason()` — a reflector-computed
    // `&'static str` from `coxswain_core::ListenerReadiness`, already
    // exhaustively matched there (#510 doesn't thread the Go-derived enum
    // through `coxswain-core`, which stays Gateway-API-agnostic by design).
    let (resolved_refs_status, resolved_refs_reason, resolved_refs_msg) = if frontend_ca_failed {
        ("False", frontend_reason.to_string(), frontend_msg)
    } else if has_invalid_kinds {
        (
            "False",
            ListenerConditionReason::InvalidRouteKinds.to_string(),
            "One or more specified route kinds are not supported by this implementation",
        )
    } else if outcome.is_healthy() {
        (
            "True",
            ListenerConditionReason::ResolvedRefs.to_string(),
            "",
        )
    } else {
        ("False", outcome.reason().to_string(), outcome.message())
    };
    // Accepted is False when the listener uses an unsupported protocol/mode combination,
    // when the frontend CA failed to resolve, or True/Accepted otherwise.
    let (accepted_status, accepted_reason, accepted_msg) = if frontend_ca_failed {
        (
            "False",
            ListenerConditionReason::NoValidCACertificate.to_string(),
            frontend_msg,
        )
    } else if let ListenerReadiness::Unsupported { message } = &outcome {
        (
            "False",
            ListenerConditionReason::UnsupportedValue.to_string(),
            message.as_str(),
        )
    } else {
        ("True", ListenerConditionReason::Accepted.to_string(), "")
    };
    // Port-conflict detection (#201): a listener whose port is reserved by the
    // Ingress data plane (--proxy-http-port / --proxy-https-port) cannot be bound
    // by GatewayProxy. Surface Programmed=False with reason=PortUnavailable so
    // operators see the conflict without trawling logs.
    let listener_port_u16 = u16::try_from(listener_port).unwrap_or(0);
    let port_conflict = ingress_ports.http == Some(listener_port_u16)
        || ingress_ports.https == Some(listener_port_u16);
    let port_conflict_msg = format!(
        "port {listener_port_u16} is reserved by the Ingress proxy (set via --proxy-http-port or --proxy-https-port)"
    );
    let (listener_prog_status, listener_prog_reason, listener_prog_msg) = if port_conflict {
        (
            "False",
            ListenerConditionReason::PortUnavailable.to_string(),
            port_conflict_msg.as_str(),
        )
    } else if frontend_ca_failed {
        (
            "False",
            ListenerConditionReason::NoValidCACertificate.to_string(),
            frontend_msg,
        )
    } else if outcome.is_healthy() {
        ("True", ListenerConditionReason::Programmed.to_string(), "")
    } else {
        ("False", outcome.reason().to_string(), outcome.message())
    };
    tracing::debug!(
        listener = %listener_name,
        resolved_refs = resolved_refs_status,
        programmed = listener_prog_status,
        "Listener status"
    );
    vec![
        make_condition(
            ListenerConditionType::Accepted,
            accepted_status,
            accepted_reason,
            accepted_msg,
            generation,
            now.clone(),
        ),
        make_condition(
            ListenerConditionType::ResolvedRefs,
            resolved_refs_status,
            resolved_refs_reason,
            resolved_refs_msg,
            generation,
            now.clone(),
        ),
        make_condition(
            ListenerConditionType::Programmed,
            listener_prog_status,
            listener_prog_reason,
            listener_prog_msg,
            generation,
            now.clone(),
        ),
    ]
}
