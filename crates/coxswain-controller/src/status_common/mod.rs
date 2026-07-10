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
    Gateway, GatewayListeners, GatewayStatusListeners, GatewayStatusListenersSupportedKinds,
};
use coxswain_reflector::ingress::IngressPorts;
use coxswain_reflector::status::{
    FrontendValidationOutcome, ListenerInfo, ListenerReadiness, is_supported_listener_protocol,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

/// Conditions whose `type` starts with this prefix are owned by the
/// dedicated-mode operator path (currently
/// `gateway.coxswain-labs.dev/DedicatedProxyReady`, with more reserved for
/// future Coxswain-owned conditions). The shared-pool status writer preserves
/// them when rebuilding `status.conditions` so a JSON-merge patch from one
/// writer doesn't clobber writes from the other. See `crate::operator::status`
/// for the counterparty preservation logic.
pub(crate) const OPERATOR_OWNED_CONDITION_TYPE_PREFIX: &str = "gateway.coxswain-labs.dev/";

/// `true` when `conditions` carries `type_` with `status: "True"` observed at
/// or after `min_gen`. `min_gen = 0` degrades to a plain presence check.
#[must_use]
pub(crate) fn has_condition_at_gen(
    conditions: Option<&[Condition]>,
    type_: &str,
    min_gen: i64,
) -> bool {
    conditions
        .map(|conds| {
            conds.iter().any(|c| {
                c.type_ == type_
                    && c.status == "True"
                    && c.observed_generation.unwrap_or(0) >= min_gen
            })
        })
        .unwrap_or(false)
}

/// `true` when the Gateway already reports top-level `Programmed=True` observed
/// at (or after) its current generation.
///
/// The anti-flap latch on both writers' convergence gates (#533, #531): once a
/// Gateway is `Programmed` for its live spec, data-plane churn — pool rollouts,
/// a leader failover emptying the node registry, a dedicated pod replacing
/// itself — must never downgrade it back to `Pending`. Only a spec change (new
/// generation) re-arms the gate. Shared by the shared-pool status writer and
/// the dedicated operator writer so their latch semantics cannot drift.
#[must_use]
pub(crate) fn gateway_programmed_at_current_gen(gw: &Gateway) -> bool {
    has_condition_at_gen(
        gw.status.as_ref().and_then(|s| s.conditions.as_deref()),
        "Programmed",
        gw.metadata.generation.unwrap_or(0),
    )
}

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

/// Condition `type` values coxswain writes that have no Gateway API constant.
///
/// `Programmed` on a route's per-parent status is not a valid
/// `RouteConditionType` — the spec defines that type only for Gateways and
/// Listeners, not routes — and `Conflicted` on a policy's `status.ancestors[]`
/// is not a valid `PolicyConditionType` — GEP-713 documents `Conflicted` as a
/// *reason* on `Accepted`, not its own condition type. Both are pre-existing
/// coxswain design choices (#510 left them as string literals rather than
/// force a nonexistent spec-enum variant); this only gives the literal a
/// typed, single-definition home instead of five duplicated hand-typed
/// strings and cross-referencing comments.
///
/// Distinct from the *Gateway*-level `Programmed`
/// (`GatewayConditionType::Programmed` in `gateway-api-types`) — same wire
/// string, different condition. Do not substitute one for the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoxswainConditionType {
    Programmed,
    Conflicted,
}

impl std::fmt::Display for CoxswainConditionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A condition `reason` that is either a typed Gateway-API-spec constant or a
/// dynamic string with no upstream constant — a reflector-computed value, or
/// a Coxswain-owned reason like `DedicatedProxyReady`'s `Ready`/`Provisioning`.
///
/// `make_condition`'s `reason` parameter already accepts `impl Display`; this
/// type lets a single `(status, reason, message)` outcome mix both
/// provenances and hand it straight to `make_condition` without an eager
/// per-arm `.to_string()`. Replaces two independent hand-rolled unifications:
/// `listener_condition_triplet`'s `.to_string()` fan-out across every arm, and
/// the dedicated-mode operator's `ConditionOutcome`/`CutOverOutcome` split —
/// `CutOverOutcome` is gone; `ConditionOutcome.reason` is now
/// `Reason<GatewayConditionReason>` (see `crate::operator::status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason<T> {
    /// A typed reason constant from `coxswain_reflector::gw_types::constants`.
    Typed(T),
    /// A reflector-computed or Coxswain-owned reason with no upstream
    /// Go-source constant.
    Raw(&'static str),
}

impl<T: std::fmt::Display> std::fmt::Display for Reason<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Typed(t) => std::fmt::Display::fmt(t, f),
            Self::Raw(s) => f.write_str(s),
        }
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
    // GatewayListenerUnsupportedProtocol (#517): a listener whose protocol is
    // not one coxswain routes supports no route kinds — the conformance suite
    // asserts `supportedKinds: []` on the unaccepted listener.
    if !is_supported_listener_protocol(&listener.protocol) {
        return (false, Vec::new());
    }
    let http_route_kind = || GatewayStatusListenersSupportedKinds {
        group: Some(GW_GROUP.to_string()),
        kind: "HTTPRoute".to_string(),
    };
    let tls_route_kind = || GatewayStatusListenersSupportedKinds {
        group: Some(GW_GROUP.to_string()),
        kind: "TLSRoute".to_string(),
    };
    let tcp_route_kind = || GatewayStatusListenersSupportedKinds {
        group: Some(GW_GROUP.to_string()),
        kind: "TCPRoute".to_string(),
    };
    // Any `protocol: TLS` listener (Passthrough or Terminate) carries TLSRoute
    // as its natural route kind. `protocol: HTTPS` is distinct — TLS terminated
    // at the gateway but with HTTP/GRPC parsing — so it falls through to the
    // HTTPRoute default.
    let is_tls_listener = listener.protocol == "TLS";
    // `protocol: TCP` (GEP-1901) carries TCPRoute as its only route kind — no
    // passthrough/terminate split, unlike TLS.
    let is_tcp_listener = listener.protocol == "TCP";

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
            if is_tcp_listener {
                return (false, vec![tcp_route_kind()]);
            }
            return (false, vec![http_route_kind()]);
        }
    };
    let mut has_invalid = false;
    let mut includes_http_route = false;
    let mut includes_tls_route = false;
    let mut includes_tcp_route = false;
    for k in allowed {
        let group_ok = k
            .group
            .as_deref()
            .is_none_or(|g| g.is_empty() || g == GW_GROUP);
        if k.kind == "HTTPRoute" && group_ok {
            includes_http_route = true;
        } else if k.kind == "TLSRoute" && group_ok && is_tls_listener {
            includes_tls_route = true;
        } else if k.kind == "TCPRoute" && group_ok && is_tcp_listener {
            includes_tcp_route = true;
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
    if includes_tcp_route {
        supported.push(tcp_route_kind());
    }
    (has_invalid, supported)
}

/// Build the per-listener status stanza: `(Accepted, ResolvedRefs, Programmed)`
/// conditions plus `attached_routes` and `supported_kinds`.
///
/// Conditions are derived from:
/// - **Accepted**: `True, reason=Accepted` unless the listener's frontend CA
///   failed (`NoValidCACertificate`), it uses an unsupported protocol/mode
///   (`UnsupportedValue`), or it declares a protocol coxswain does not route
///   (`UnsupportedProtocol`, #517). See [`listener_is_accepted`] for the
///   Gateway-level rollup that mirrors this.
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
    // `resolved_refs_reason` (and the other two reason bindings below) mix
    // typed Gateway API reasons (via `ListenerConditionReason`, so a typo or
    // spec drift is a compile error) with a fallback that forwards
    // `outcome.reason()` — a reflector-computed `&'static str` from
    // `coxswain_core::ListenerReadiness`, already exhaustively matched there
    // (#510 doesn't thread the Go-derived enum through `coxswain-core`, which
    // stays Gateway-API-agnostic by design). `Reason` unifies both without an
    // eager `.to_string()` per arm.
    let (resolved_refs_status, resolved_refs_reason, resolved_refs_msg) = if frontend_ca_failed {
        ("False", Reason::Raw(frontend_reason), frontend_msg)
    } else if has_invalid_kinds {
        (
            "False",
            Reason::Typed(ListenerConditionReason::InvalidRouteKinds),
            "One or more specified route kinds are not supported by this implementation",
        )
    } else if outcome.is_healthy() {
        (
            "True",
            Reason::Typed(ListenerConditionReason::ResolvedRefs),
            "",
        )
    } else {
        ("False", Reason::Raw(outcome.reason()), outcome.message())
    };
    // Accepted is False when the listener uses an unsupported protocol/mode combination,
    // when the frontend CA failed to resolve, or True/Accepted otherwise.
    let (accepted_status, accepted_reason, accepted_msg) = if frontend_ca_failed {
        (
            "False",
            Reason::Typed(ListenerConditionReason::NoValidCACertificate),
            frontend_msg,
        )
    } else if let ListenerReadiness::Unsupported { message } = &outcome {
        (
            "False",
            Reason::Typed(ListenerConditionReason::UnsupportedValue),
            message.as_str(),
        )
    } else if let ListenerReadiness::UnsupportedProtocol { message } = &outcome {
        // GatewayListenerUnsupportedProtocol (#517): the listener's protocol is
        // not one coxswain routes.
        (
            "False",
            Reason::Typed(ListenerConditionReason::UnsupportedProtocol),
            message.as_str(),
        )
    } else {
        ("True", Reason::Typed(ListenerConditionReason::Accepted), "")
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
            Reason::Typed(ListenerConditionReason::PortUnavailable),
            port_conflict_msg.as_str(),
        )
    } else if frontend_ca_failed {
        (
            "False",
            Reason::Typed(ListenerConditionReason::NoValidCACertificate),
            frontend_msg,
        )
    } else if outcome.is_healthy() {
        (
            "True",
            Reason::Typed(ListenerConditionReason::Programmed),
            "",
        )
    } else {
        ("False", Reason::Raw(outcome.reason()), outcome.message())
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

/// Whether one listener's `Accepted` condition is `True`, given its health
/// snapshot and `allowedRoutes.kinds` validity.
///
/// Mirrors the `accepted_status` computation in [`listener_condition_triplet`]
/// (a listener is not accepted when its frontend CA failed, or its readiness is
/// [`ListenerReadiness::Unsupported`] / [`ListenerReadiness::UnsupportedProtocol`])
/// so the Gateway-level `Accepted` rollup and the per-listener condition can
/// never disagree. `has_invalid_kinds` does **not** flip `Accepted` — it drives
/// `ResolvedRefs` only — so it is intentionally not consulted here.
///
/// Used by both status writers to compute the Gateway/ListenerSet `Accepted`
/// condition: `False` iff **every** listener is unaccepted, and reason
/// `ListenersNotValid` iff **any** listener is unaccepted
/// (`GatewayListenerUnsupportedProtocol`, #517).
#[must_use]
pub(crate) fn listener_is_accepted(info: Option<&ListenerInfo>) -> bool {
    let readiness = info.map(|i| i.readiness.clone()).unwrap_or_default();
    let frontend_ca_failed = info
        .map(|i| &i.frontend_outcome)
        .is_some_and(FrontendValidationOutcome::is_failed);
    !(frontend_ca_failed
        || matches!(
            readiness,
            ListenerReadiness::Unsupported { .. } | ListenerReadiness::UnsupportedProtocol { .. }
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coxswain_condition_type_displays_the_exact_wire_string() {
        // These are the literal `Condition.type` values written to the API
        // server — a `Debug`/rename drift here is a wire-format bug, not just
        // a cosmetic one.
        assert_eq!(CoxswainConditionType::Programmed.to_string(), "Programmed");
        assert_eq!(CoxswainConditionType::Conflicted.to_string(), "Conflicted");
    }

    #[test]
    fn reason_displays_both_typed_and_raw_arms() {
        // Both arms must round-trip through Display to the exact wire string
        // `make_condition` writes as `Condition.reason` — that's the whole
        // point of unifying them behind one type.
        let typed: Reason<ListenerConditionReason> =
            Reason::Typed(ListenerConditionReason::Programmed);
        assert_eq!(typed.to_string(), "Programmed");
        let raw: Reason<ListenerConditionReason> = Reason::Raw("SomeReflectorReason");
        assert_eq!(raw.to_string(), "SomeReflectorReason");
    }
}
