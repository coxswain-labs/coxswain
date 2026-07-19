//! `Gateway` status patch builder and staleness check (GEP-1364).

use super::conditions::{has_condition, make_condition};
use super::config::StatusAddress;
use crate::status_common::addresses::StaticAddressOutcome;
use crate::status_common::{
    OPERATOR_OWNED_CONDITION_TYPE_PREFIX, build_listener_status, listener_is_accepted,
    listener_route_kind_info,
};
use coxswain_core::ownership::ObjectKey;
use coxswain_reflector::gw_types::constants::{GatewayConditionReason, GatewayConditionType};
use coxswain_reflector::gw_types::v::gateways::{Gateway, GatewayStatusListeners};
use coxswain_reflector::status::{GatewayListenerStatus, ListenerSource, ListenerStatusKey};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

/// The shared-pool address inputs for one Gateway reconcile: the legacy
/// auto-derived VIP/global address (used when `spec.addresses` is absent or
/// requests only empty values) plus the validated `GatewayStaticAddresses`
/// outcome (#260). Grouped into one struct so the patch builder and the
/// needs-patch check share the same inputs and stay under the 7-arg ceiling.
pub(super) struct SharedAddressDecision {
    /// The auto-derived address (per-Gateway VIP or global `--status-address`).
    /// Written to `status.addresses` only when the static-address feature is not
    /// engaged.
    pub(super) legacy_addr: Option<StatusAddress>,
    /// Result of validating `Gateway.spec.addresses` against the resolved VIP.
    pub(super) static_outcome: StaticAddressOutcome,
    /// `true` when the Gateway carries a `spec.infrastructure.parametersRef` that
    /// this implementation does not support (conformance
    /// `GatewayInvalidParametersRef`). The shared-pool writer only ever sees
    /// non-dedicated Gateways — the reconcile dispatch skips any Gateway whose
    /// `parametersRef` targets coxswain's own `CoxswainGatewayParameters`
    /// (`is_dedicated_mode`, `controller/mod.rs`), routing it to the operator's
    /// `InvalidParameters` handling instead. So a `parametersRef` present *here*
    /// is by construction an unsupported kind → `Accepted=False`. Existence of
    /// the ref is the whole signal; no target resolution is needed.
    pub(super) params_ref_unsupported: bool,
    /// Whether the Gateway is fully converged for its current generation:
    /// its own VIP address has resolved (#533) AND every connected shared-pool
    /// proxy node has bound the VIP's internal ports (#531). `false` holds the
    /// top-level `Programmed` condition at `False/Pending` with an
    /// `observedGeneration` below the current generation, so a one-shot
    /// "conditions are latest" check waits until the address lands, the data
    /// plane binds, and `Programmed=True@N` is published in the same patch that
    /// carries `status.addresses`. A settled *negative* address outcome
    /// (`programmed_override`) is unaffected — it is a real result for the
    /// current generation.
    pub(super) converged: bool,
    /// `true` when the Gateway's terminal outcome is already decided negative
    /// for its current generation (#570): an unsupported `parametersRef`, or
    /// every listener terminally unserviceable. Drives `Programmed=False,
    /// reason=Invalid` stamped at the CURRENT generation — never the
    /// `Pending`/`gen-1` hold, whose data-plane wait may never complete for
    /// these states. Always set together with `converged = true`.
    pub(super) settled_negative: bool,
    /// Human-readable cause for a `Programmed=False/Pending` hold beyond the
    /// generic address wait — the proxy-pool bind gate (#531): which/how many
    /// connected nodes have not yet bound which internal ports. Message only:
    /// `gateway_needs_status_patch` compares `(status, reason)` and
    /// `observedGeneration`, never the message, so detail drift (a node count
    /// changing) causes zero patch churn. `None` = use the reason's canonical
    /// message.
    pub(super) pending_detail: Option<String>,
}

impl SharedAddressDecision {
    /// Whether the top-level `Programmed` condition must be held at
    /// `False/Pending` because the Gateway is not yet fully converged (#533):
    /// there is no settled negative address outcome, and the reconcile has not
    /// yet observed the Gateway's VIP address resolve.
    fn programmed_pending(&self) -> bool {
        self.static_outcome.programmed_override.is_none() && !self.converged
    }

    /// Desired `(status, reason)` for the top-level `Programmed` condition:
    /// `(False, AddressNotUsable | Invalid)` when a requested address could not
    /// be honored; `(False, Invalid)` when the Gateway has settled negative
    /// (#570 — unsupported `parametersRef` or all listeners terminally
    /// unserviceable); `(False, Pending)` while not yet converged (#533);
    /// else the canonical `(True, Programmed)`.
    fn desired_programmed(&self) -> (&'static str, GatewayConditionReason) {
        match self.static_outcome.programmed_override {
            Some(reason) => ("False", reason),
            None if self.settled_negative => ("False", GatewayConditionReason::Invalid),
            None if !self.converged => ("False", GatewayConditionReason::Pending),
            None => ("True", GatewayConditionReason::Programmed),
        }
    }
}

/// Desired `(status, reason)` for the top-level Gateway `Accepted` condition,
/// folding three sources in precedence order:
///
/// 1. An unsupported `spec.infrastructure.parametersRef` — `InvalidParameters`,
///    a spec-level rejection that outranks everything (#517).
/// 2. A requested `spec.addresses` type this implementation cannot honor —
///    `UnsupportedAddress` (#260).
/// 3. The per-listener rollup — `ListenersNotValid` whenever **any** listener is
///    unaccepted, with `status=False` only when **every** listener is unaccepted
///    (`GatewayListenerUnsupportedProtocol`, #517). A Gateway with no listeners,
///    or with all listeners accepted, stays `(True, Accepted)`.
///
/// Shared by [`gateway_needs_status_patch`] and [`build_gateway_status_patch`]
/// so the staleness check and the emitted patch can never disagree on the
/// Accepted condition.
fn desired_gateway_accepted(
    gw: &Gateway,
    health: &GatewayListenerStatus,
    decision: &SharedAddressDecision,
) -> (&'static str, GatewayConditionReason) {
    if decision.params_ref_unsupported {
        return ("False", GatewayConditionReason::InvalidParameters);
    }
    if let Some(reason) = decision.static_outcome.accepted_override {
        return ("False", reason);
    }
    let mut any_accepted = false;
    let mut any_unaccepted = false;
    for l in &gw.spec.listeners {
        let info = health.listeners.get(&ListenerStatusKey::gateway(&l.name));
        if listener_is_accepted(info) {
            any_accepted = true;
        } else {
            any_unaccepted = true;
        }
    }
    if any_unaccepted {
        let status = if any_accepted { "True" } else { "False" };
        return (status, GatewayConditionReason::ListenersNotValid);
    }
    ("True", GatewayConditionReason::Accepted)
}

/// Returns true when the Gateway's current status does not yet reflect the
/// desired state computed from `health`. Prevents redundant patches and
/// watch-feedback loops.
pub(super) fn gateway_needs_status_patch(
    gw: &Gateway,
    health: &GatewayListenerStatus,
    decision: &SharedAddressDecision,
) -> bool {
    // GatewayStaticAddresses (#260): Accepted/Programmed are no longer always
    // True — a requested `spec.addresses` can drive them to False. Compare the
    // current condition's `(status, reason)` against the desired pair so a
    // True→False flip (or a reason change) forces a patch.
    let (want_acc_status, want_acc_reason) = desired_gateway_accepted(gw, health, decision);
    if !condition_matches(gw, "Accepted", want_acc_status, want_acc_reason) {
        return true;
    }
    let (want_prog_status, want_prog_reason) = decision.desired_programmed();
    if !condition_matches(gw, "Programmed", want_prog_status, want_prog_reason) {
        return true;
    }
    // The per-Gateway VIP address (#472) is provisioned asynchronously and lands
    // AFTER conditions have already settled. A Gateway whose conditions/listeners
    // are otherwise up to date but whose `status.addresses` does not yet reflect
    // the resolved VIP still needs a patch — without this, a Gateway with stable
    // health (e.g. a TLS-passthrough listener whose conditions never flip after
    // the first reconcile) would never get its address written once the VIP
    // resolves on a later reconcile.
    if !gateway_addresses_up_to_date(gw, decision) {
        return true;
    }
    // GEP-91: a mode flip to/from AllowInsecureFallback must add/remove the
    // InsecureFrontendValidationMode condition, which in turn requires a patch.
    let desired_insecure = health
        .frontend_validation
        .as_ref()
        .is_some_and(|fv| fv.insecure_fallback);
    let current_insecure = has_condition(
        gw.status.as_ref().and_then(|s| s.conditions.as_deref()),
        "InsecureFrontendValidationMode",
    );
    if desired_insecure != current_insecure {
        return true;
    }
    // GEP-3155: the gateway-level ResolvedRefs condition mirrors backend
    // client-cert resolution. A change in its presence, status, or reason
    // requires a patch (a frontend/listener change alone would otherwise miss it).
    let current_resolved_refs = gw
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_deref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == "ResolvedRefs"));
    match health.backend_client_cert.as_ref() {
        Some(outcome) => {
            let up_to_date = current_resolved_refs.is_some_and(|c| {
                c.status == outcome.resolved_refs_status()
                    && c.reason == outcome.resolved_refs_reason()
            });
            if !up_to_date {
                return true;
            }
        }
        None => {
            if current_resolved_refs.is_some() {
                return true;
            }
        }
    }
    // GEP-1713: detect drift in attachedListenerSets count.
    let desired_attached_ls: i32 = {
        let mut ls_valid: std::collections::HashMap<&ObjectKey, bool> =
            std::collections::HashMap::new();
        for (k, info) in &health.listeners {
            if let ListenerSource::ListenerSet(ls_key) = &k.source {
                let has_valid = ls_valid.entry(ls_key).or_insert(false);
                if !info.conflict.is_conflicted() {
                    *has_valid = true;
                }
            }
        }
        ls_valid.values().filter(|&&v| v).count() as i32
    };
    let current_attached_ls = gw
        .status
        .as_ref()
        .and_then(|s| s.attached_listener_sets)
        .unwrap_or(0);
    if current_attached_ls != desired_attached_ls {
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
    // GEP-91: a per-listener frontend CA ref that failed to resolve drives that
    // listener to ResolvedRefs=False, so it must be folded into the
    // desired-health comparison or a frontend-only failure would never patch.
    for listener in &gw.spec.listeners {
        let (has_invalid_kinds, _) = listener_route_kind_info(listener);
        let info = health
            .listeners
            .get(&ListenerStatusKey::gateway(&listener.name));
        let frontend_impacts = info.is_some_and(|i| i.frontend_outcome.is_failed());
        let desired_healthy = !has_invalid_kinds
            && info.map(|i| i.readiness.is_healthy()).unwrap_or(true)
            && !frontend_impacts;
        let current_listener = current_listeners.iter().find(|sl| sl.name == listener.name);
        let current_resolved = current_listener
            .map(|sl| has_condition(Some(sl.conditions.as_slice()), "ResolvedRefs"))
            .unwrap_or(false);
        if desired_healthy != current_resolved {
            return true;
        }
        // GEP-2643 / #517: a listener's Accepted flips to False for a TLS/Terminate
        // Unsupported outcome, a frontend CA failure, or an UnsupportedProtocol —
        // all computed only after the reflector processes the Gateway, *after* the
        // controller's first reconcile wrote Accepted=True from empty health. Reuse
        // `listener_is_accepted` (the single source of truth shared with
        // `build_listener_status`) so this staleness check can never drift from the
        // written condition — a mismatch would repatch on every reconcile forever.
        let desired_accepted_false = !listener_is_accepted(info);
        let current_accepted_false = current_listener
            .and_then(|sl| sl.conditions.iter().find(|c| c.type_ == "Accepted"))
            .is_some_and(|c| c.status != "True");
        if desired_accepted_false != current_accepted_false {
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

/// Returns true iff the Gateway's current top-level condition named `type_`
/// matches the desired `(status, reason)` pair. Used for `Accepted`/`Programmed`,
/// which the static-address feature (#260) can drive to `False`.
fn condition_matches(
    gw: &Gateway,
    type_: &str,
    want_status: &str,
    want_reason: impl std::fmt::Display,
) -> bool {
    let want_reason = want_reason.to_string();
    gw.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == type_))
        .is_some_and(|c| c.status == want_status && c.reason == want_reason)
}

/// True iff `gw.status.addresses` already matches the desired set.
///
/// When the static-address feature is engaged (#260), the desired set is the
/// validated `static_outcome.status_addresses` (compared order-independently,
/// including the empty set so a stale address is cleared). Otherwise the desired
/// state is the single legacy auto-derived address: `None` (feature off, or VIP
/// still pending) never forces a patch on address grounds; a `Some` that differs
/// from the current first address returns false so the patch lands.
fn gateway_addresses_up_to_date(gw: &Gateway, decision: &SharedAddressDecision) -> bool {
    let current = gw.status.as_ref().and_then(|s| s.addresses.as_ref());
    if decision.static_outcome.feature_engaged {
        use std::collections::BTreeSet;
        let current_set: BTreeSet<(String, String)> = current
            .map(|a| {
                a.iter()
                    .map(|e| (e.r#type.clone().unwrap_or_default(), e.value.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let desired_set: BTreeSet<(String, String)> = decision
            .static_outcome
            .status_addresses
            .iter()
            .map(|a| (a.type_.as_str().to_string(), a.value.clone()))
            .collect();
        return current_set == desired_set;
    }
    let Some(desired) = decision.legacy_addr.as_ref() else {
        return true;
    };
    let (desired_type, desired_value) = match desired {
        StatusAddress::Ip(ip) => ("IPAddress", ip.to_string()),
        StatusAddress::Hostname(h) => ("Hostname", h.clone()),
    };
    current.and_then(|a| a.first()).is_some_and(|cur| {
        cur.value == desired_value && cur.r#type.as_deref() == Some(desired_type)
    })
}

pub(super) fn build_gateway_status_patch(
    gw: &Gateway,
    health: &GatewayListenerStatus,
    generation: i64,
    now: &Time,
    decision: &SharedAddressDecision,
    ingress_ports: coxswain_reflector::ingress::IngressPorts,
) -> serde_json::Value {
    // Preserve any operator-owned conditions (those whose type starts with
    // `gateway.coxswain-labs.dev/`) so the merge patch below doesn't clobber
    // them. The operator side mirrors the convention by preserving everything
    // NOT prefixed with that domain. See `crate::operator::status` for the
    // counterparty.
    // GatewayStaticAddresses (#260) + GatewayInvalidParametersRef /
    // GatewayListenerUnsupportedProtocol (#517): a requested `spec.addresses`, an
    // unsupported `parametersRef`, or an unaccepted listener can drive Accepted
    // to False / a non-`Accepted` reason. `desired_gateway_accepted` folds all
    // three; `desired_programmed` returns the canonical True pair when no address
    // override applies, so the legacy happy path is unchanged.
    let (acc_status, acc_reason) = desired_gateway_accepted(gw, health, decision);
    let (prog_status, prog_reason) = decision.desired_programmed();
    // #533: while the Gateway is not yet converged, hold the `Programmed`
    // condition's `observedGeneration` one below the current generation so a
    // one-shot "conditions are latest" check (conformance
    // `GatewayMustHaveLatestConditions`) keeps waiting until the VIP address has
    // landed AND the data plane has ack'd — at which point the same patch that
    // flips `Programmed` to `True@generation` also carries `status.addresses`.
    // `Accepted` always advances immediately; a settled negative Programmed
    // outcome stamps at the current generation.
    let prog_generation = if decision.programmed_pending() {
        generation.saturating_sub(1)
    } else {
        generation
    };
    let mut conditions = vec![
        make_condition(
            GatewayConditionType::Accepted,
            acc_status,
            acc_reason,
            static_address_message(acc_reason),
            generation,
            now.clone(),
        ),
        make_condition(
            GatewayConditionType::Programmed,
            prog_status,
            prog_reason,
            // #531: while pending on the proxy-pool bind gate, surface the
            // specific wait (which nodes / which ports) instead of the generic
            // reason message. Message-only — never compared for patch staleness.
            decision
                .pending_detail
                .as_deref()
                .filter(|_| decision.programmed_pending())
                .unwrap_or_else(|| static_address_message(prog_reason)),
            prog_generation,
            now.clone(),
        ),
    ];
    // GEP-91: emit InsecureFrontendValidationMode=True when mode is AllowInsecureFallback.
    // The condition is omitted entirely when mode is AllowValidOnly (its absence = valid).
    if let Some(fv) = health.frontend_validation.as_ref()
        && fv.insecure_fallback
    {
        conditions.push(make_condition(
            GatewayConditionType::InsecureFrontendValidationMode,
            "True",
            GatewayConditionReason::ConfigurationChanged,
            "Gateway spec.tls.frontend.default.validation.mode is AllowInsecureFallback; \
             client certificates are requested but not enforced. \
             Authorization is delegated to backends.",
            generation,
            now.clone(),
        ));
    }
    // GEP-3155: emit a gateway-level ResolvedRefs condition reflecting
    // spec.tls.backend.clientCertificateRef resolution. Emitted only when the ref is
    // present (`Some`); its absence means no backend client cert is configured. This
    // is independent of Accepted/Programmed, which stay True — the invalid-config
    // conformance gateways keep Accepted=True while ResolvedRefs goes False.
    if let Some(outcome) = health.backend_client_cert.as_ref() {
        conditions.push(make_condition(
            GatewayConditionType::ResolvedRefs,
            outcome.resolved_refs_status(),
            outcome.resolved_refs_reason(),
            outcome.message(),
            generation,
            now.clone(),
        ));
    }
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
            let info = health.listeners.get(&ListenerStatusKey::gateway(&l.name));
            build_listener_status(l, info, ingress_ports, generation, now)
        })
        .collect();

    // GEP-1713: count accepted ListenerSets. A LS is "accepted" iff it has
    // at least one non-conflicted listener in the merged health map. A LS where
    // every listener lost a conflict (all programmed=False) reports
    // Accepted=False/ListenersNotValid and must NOT be counted.
    let attached_listener_sets: i32 = {
        let mut ls_valid: std::collections::HashMap<&ObjectKey, bool> =
            std::collections::HashMap::new();
        for (k, info) in &health.listeners {
            if let ListenerSource::ListenerSet(ls_key) = &k.source {
                let has_valid = ls_valid.entry(ls_key).or_insert(false);
                if !info.conflict.is_conflicted() {
                    *has_valid = true;
                }
            }
        }
        ls_valid.values().filter(|&&v| v).count() as i32
    };

    let mut patch = serde_json::json!({
        "status": {
            "conditions": conditions,
            "listeners": listener_statuses,
            "attachedListenerSets": attached_listener_sets,
        }
    });
    if decision.static_outcome.feature_engaged {
        // GatewayStaticAddresses (#260): publish only the usable bound addresses
        // (possibly an empty array, which clears any stale auto-derived address).
        let addrs: Vec<serde_json::Value> = decision
            .static_outcome
            .status_addresses
            .iter()
            .map(|a| {
                serde_json::json!({
                    "type": a.type_.as_str(),
                    "value": a.value,
                })
            })
            .collect();
        patch["status"]["addresses"] = serde_json::Value::Array(addrs);
    } else if let Some(addr) = decision.legacy_addr.as_ref() {
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

/// Human-readable `message` for a static-address condition reason (#260). The
/// happy-path reasons (`Accepted`/`Programmed`) carry an empty message, matching
/// the legacy behaviour.
fn static_address_message(reason: GatewayConditionReason) -> &'static str {
    match reason {
        GatewayConditionReason::InvalidParameters => {
            "spec.infrastructure.parametersRef targets a kind this implementation does not support"
        }
        GatewayConditionReason::ListenersNotValid => {
            "one or more listeners are not accepted; see the per-listener conditions"
        }
        GatewayConditionReason::UnsupportedAddress => {
            "spec.addresses contains an address type this implementation does not support"
        }
        GatewayConditionReason::AddressNotUsable => {
            "one or more requested spec.addresses could not be assigned to the Gateway"
        }
        GatewayConditionReason::Invalid => {
            "Gateway spec is invalid; see the Accepted condition for details"
        }
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::StatusAddress;
    use super::super::gateway_status::{
        SharedAddressDecision, build_gateway_status_patch, desired_gateway_accepted,
        gateway_needs_status_patch,
    };
    use crate::status_common::addresses::StaticAddressOutcome;
    use coxswain_reflector::gw_types::constants::GatewayConditionReason;
    use coxswain_reflector::status::{ListenerInfo, ListenerReadiness, ListenerStatusKey};

    /// A not-engaged decision with no legacy address — the common case for tests
    /// that pre-date GatewayStaticAddresses (#260).
    fn no_addr() -> SharedAddressDecision {
        SharedAddressDecision {
            legacy_addr: None,
            static_outcome: StaticAddressOutcome::not_engaged(),
            params_ref_unsupported: false,
            converged: true,
            settled_negative: false,
            pending_detail: None,
        }
    }

    /// A not-engaged decision carrying a single legacy auto-derived address.
    fn legacy_addr(addr: StatusAddress) -> SharedAddressDecision {
        SharedAddressDecision {
            legacy_addr: Some(addr),
            static_outcome: StaticAddressOutcome::not_engaged(),
            params_ref_unsupported: false,
            converged: true,
            settled_negative: false,
            pending_detail: None,
        }
    }
    use coxswain_reflector::gw_types::v::gateways::{
        Gateway, GatewaySpec, GatewayStatus, GatewayStatusListeners,
    };
    use coxswain_reflector::ingress::IngressPorts;
    use coxswain_reflector::status::{BackendClientCertOutcome, GatewayListenerStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

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

    fn default_status() -> GatewayListenerStatus {
        GatewayListenerStatus::default()
    }

    #[test]
    fn needs_patch_when_no_status() {
        let gw = Gateway {
            status: None,
            ..Default::default()
        };
        assert!(gateway_needs_status_patch(
            &gw,
            &default_status(),
            &no_addr()
        ));
    }

    #[test]
    fn needs_patch_when_accepted_missing() {
        let gw = gateway(1, Some(vec![condition("Programmed", 1)]), None);
        assert!(gateway_needs_status_patch(
            &gw,
            &default_status(),
            &no_addr()
        ));
    }

    #[test]
    fn needs_patch_when_programmed_missing() {
        let gw = gateway(1, Some(vec![condition("Accepted", 1)]), None);
        assert!(gateway_needs_status_patch(
            &gw,
            &default_status(),
            &no_addr()
        ));
    }

    #[test]
    fn needs_patch_when_top_level_condition_stale() {
        // Both Accepted and Programmed are True but at gen 0; metadata says gen 2.
        let gw = gateway(
            2,
            Some(vec![condition("Accepted", 0), condition("Programmed", 0)]),
            Some(vec![listener_status("http", 2)]),
        );
        assert!(gateway_needs_status_patch(
            &gw,
            &default_status(),
            &no_addr()
        ));
    }

    #[test]
    fn needs_patch_when_listener_condition_stale() {
        // Top-level conditions are current; one listener condition is at stale gen.
        let gw = gateway(
            2,
            Some(vec![condition("Accepted", 2), condition("Programmed", 2)]),
            Some(vec![listener_status("http", 0)]),
        );
        assert!(gateway_needs_status_patch(
            &gw,
            &default_status(),
            &no_addr()
        ));
    }

    #[test]
    fn needs_patch_when_listener_count_mismatch() {
        // Gateway spec has one listener but status reports none.
        let gw = gateway(
            1,
            Some(vec![condition("Accepted", 1), condition("Programmed", 1)]),
            Some(vec![]),
        );
        assert!(gateway_needs_status_patch(
            &gw,
            &default_status(),
            &no_addr()
        ));
    }

    #[test]
    fn no_patch_needed_when_fully_up_to_date() {
        let gw = gateway(
            1,
            Some(vec![condition("Accepted", 1), condition("Programmed", 1)]),
            Some(vec![listener_status("http", 1)]),
        );
        assert!(!gateway_needs_status_patch(
            &gw,
            &default_status(),
            &no_addr()
        ));
    }

    // ── #472 per-Gateway VIP address divergence ──────────────────────────────

    #[test]
    fn needs_patch_when_vip_address_not_yet_written() {
        // Conditions + listeners fully up to date, but status.addresses is empty
        // while the resolved VIP address is Some — the patch must still fire so
        // the address lands (the TLS-passthrough convergence bug, #472).
        let gw = gateway(
            1,
            Some(vec![condition("Accepted", 1), condition("Programmed", 1)]),
            Some(vec![listener_status("http", 1)]),
        );
        let addr = StatusAddress::Ip(std::net::IpAddr::from([10, 0, 0, 5]));
        assert!(gateway_needs_status_patch(
            &gw,
            &default_status(),
            &legacy_addr(addr)
        ));
    }

    #[test]
    fn no_patch_when_vip_address_already_matches() {
        use coxswain_reflector::gw_types::v::gateways::GatewayStatusAddresses;
        let mut gw = gateway(
            1,
            Some(vec![condition("Accepted", 1), condition("Programmed", 1)]),
            Some(vec![listener_status("http", 1)]),
        );
        if let Some(st) = gw.status.as_mut() {
            st.addresses = Some(vec![GatewayStatusAddresses {
                r#type: Some("IPAddress".to_string()),
                value: "10.0.0.5".to_string(),
            }]);
        }
        let addr = StatusAddress::Ip(std::net::IpAddr::from([10, 0, 0, 5]));
        assert!(!gateway_needs_status_patch(
            &gw,
            &default_status(),
            &legacy_addr(addr)
        ));
    }

    // ── GEP-3155 gateway-level ResolvedRefs (backend client cert) ─────────────

    fn epoch() -> Time {
        Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH)
    }

    fn health_with_backend(outcome: BackendClientCertOutcome) -> GatewayListenerStatus {
        GatewayListenerStatus {
            backend_client_cert: Some(outcome),
            ..Default::default()
        }
    }

    #[test]
    fn needs_patch_when_backend_resolvedrefs_missing() {
        // Ref configured (Resolved) but status has no top-level ResolvedRefs yet.
        let gw = gateway(
            1,
            Some(vec![condition("Accepted", 1), condition("Programmed", 1)]),
            Some(vec![listener_status("http", 1)]),
        );
        assert!(gateway_needs_status_patch(
            &gw,
            &health_with_backend(BackendClientCertOutcome::Resolved),
            &no_addr()
        ));
    }

    #[test]
    fn needs_patch_when_backend_resolvedrefs_reason_changed() {
        // Status says True/ResolvedRefs but desired is False/InvalidClientCertificateRef.
        let gw = gateway(
            1,
            Some(vec![
                condition("Accepted", 1),
                condition("Programmed", 1),
                condition("ResolvedRefs", 1),
            ]),
            Some(vec![listener_status("http", 1)]),
        );
        let desired = BackendClientCertOutcome::InvalidClientCertificateRef {
            message: "Secret gw-ns/missing: secret not found in store".to_string(),
        };
        assert!(gateway_needs_status_patch(
            &gw,
            &health_with_backend(desired),
            &no_addr()
        ));
    }

    #[test]
    fn no_patch_when_backend_resolvedrefs_resolved_and_present() {
        let gw = gateway(
            1,
            Some(vec![
                condition("Accepted", 1),
                condition("Programmed", 1),
                condition("ResolvedRefs", 1),
            ]),
            Some(vec![listener_status("http", 1)]),
        );
        assert!(!gateway_needs_status_patch(
            &gw,
            &health_with_backend(BackendClientCertOutcome::Resolved),
            &no_addr()
        ));
    }

    #[test]
    fn needs_patch_when_backend_resolvedrefs_removed() {
        // Status still carries ResolvedRefs but the ref is no longer configured.
        let gw = gateway(
            1,
            Some(vec![
                condition("Accepted", 1),
                condition("Programmed", 1),
                condition("ResolvedRefs", 1),
            ]),
            Some(vec![listener_status("http", 1)]),
        );
        assert!(gateway_needs_status_patch(
            &gw,
            &default_status(),
            &no_addr()
        ));
    }

    #[test]
    fn patch_emits_resolvedrefs_false_keeping_accepted_true() {
        let gw = gateway(1, None, None);
        let health = health_with_backend(BackendClientCertOutcome::InvalidClientCertificateRef {
            message: "Secret gw-ns/missing: secret not found in store".to_string(),
        });
        let patch = build_gateway_status_patch(
            &gw,
            &health,
            1,
            &epoch(),
            &no_addr(),
            IngressPorts::default(),
        );
        let conds = patch["status"]["conditions"]
            .as_array()
            .expect("conditions array");
        let accepted = conds
            .iter()
            .find(|c| c["type"] == "Accepted")
            .expect("Accepted present");
        assert_eq!(accepted["status"], "True");
        assert_eq!(accepted["reason"], "Accepted");
        let rr = conds
            .iter()
            .find(|c| c["type"] == "ResolvedRefs")
            .expect("ResolvedRefs present");
        assert_eq!(rr["status"], "False");
        assert_eq!(rr["reason"], "InvalidClientCertificateRef");
    }

    #[test]
    fn patch_emits_resolvedrefs_true_when_resolved() {
        let gw = gateway(1, None, None);
        let health = health_with_backend(BackendClientCertOutcome::Resolved);
        let patch = build_gateway_status_patch(
            &gw,
            &health,
            1,
            &epoch(),
            &no_addr(),
            IngressPorts::default(),
        );
        let rr = patch["status"]["conditions"]
            .as_array()
            .expect("conditions array")
            .iter()
            .find(|c| c["type"] == "ResolvedRefs")
            .expect("ResolvedRefs present")
            .clone();
        assert_eq!(rr["status"], "True");
        assert_eq!(rr["reason"], "ResolvedRefs");
    }

    // ── GatewayStaticAddresses (#260) ────────────────────────────────────────

    use crate::status_common::addresses::{SupportedAddressType, TypedAddress};

    fn engaged(
        accepted_override: Option<GatewayConditionReason>,
        programmed_override: Option<GatewayConditionReason>,
        status_addresses: Vec<TypedAddress>,
    ) -> SharedAddressDecision {
        SharedAddressDecision {
            legacy_addr: None,
            static_outcome: StaticAddressOutcome {
                accepted_override,
                programmed_override,
                status_addresses,
                feature_engaged: true,
                requests_pinnable_ip: true,
            },
            params_ref_unsupported: false,
            converged: true,
            settled_negative: false,
            pending_detail: None,
        }
    }

    #[test]
    fn patch_sets_accepted_false_on_unsupported_address() {
        let gw = gateway(1, None, None);
        let decision = engaged(
            Some(GatewayConditionReason::UnsupportedAddress),
            Some(GatewayConditionReason::Invalid),
            vec![],
        );
        let patch = build_gateway_status_patch(
            &gw,
            &default_status(),
            1,
            &epoch(),
            &decision,
            IngressPorts::default(),
        );
        let conds = patch["status"]["conditions"]
            .as_array()
            .expect("conditions");
        let acc = conds
            .iter()
            .find(|c| c["type"] == "Accepted")
            .expect("Accepted");
        assert_eq!(acc["status"], "False");
        assert_eq!(acc["reason"], "UnsupportedAddress");
        let prog = conds
            .iter()
            .find(|c| c["type"] == "Programmed")
            .expect("Programmed");
        assert_eq!(prog["status"], "False");
        assert_eq!(prog["reason"], "Invalid");
        // No usable address → empty array clears any stale address.
        assert_eq!(patch["status"]["addresses"], serde_json::json!([]));
    }

    #[test]
    fn patch_sets_accepted_false_on_invalid_parameters_ref() {
        // GatewayInvalidParametersRef (#517): a Gateway that reaches the
        // shared-pool writer carrying a `spec.infrastructure.parametersRef`
        // (necessarily an unsupported kind — dedicated Gateways are dispatched
        // elsewhere) must report `Accepted=False, reason=InvalidParameters`. The
        // reason outranks the address override, so pair it with an unsupported
        // address to prove precedence.
        let gw = gateway(1, None, None);
        let decision = SharedAddressDecision {
            legacy_addr: None,
            static_outcome: StaticAddressOutcome {
                accepted_override: Some(GatewayConditionReason::UnsupportedAddress),
                programmed_override: None,
                status_addresses: vec![],
                feature_engaged: true,
                requests_pinnable_ip: false,
            },
            params_ref_unsupported: true,
            converged: true,
            settled_negative: false,
            pending_detail: None,
        };
        let patch = build_gateway_status_patch(
            &gw,
            &default_status(),
            1,
            &epoch(),
            &decision,
            IngressPorts::default(),
        );
        let conds = patch["status"]["conditions"]
            .as_array()
            .expect("conditions");
        let acc = conds
            .iter()
            .find(|c| c["type"] == "Accepted")
            .expect("Accepted");
        assert_eq!(acc["status"], "False");
        assert_eq!(
            acc["reason"], "InvalidParameters",
            "unsupported parametersRef must outrank the address override"
        );
    }

    // ── GatewayListenerUnsupportedProtocol (#517) ────────────────────────────

    /// A Gateway whose spec carries the given `(listener_name, protocol)` pairs.
    fn gateway_with_listeners(pairs: &[(&str, &str)]) -> Gateway {
        Gateway {
            metadata: kube::api::ObjectMeta {
                generation: Some(1),
                ..Default::default()
            },
            spec: GatewaySpec {
                listeners: pairs
                    .iter()
                    .enumerate()
                    .map(|(i, (name, protocol))| {
                        coxswain_reflector::gw_types::v::gateways::GatewayListeners {
                            name: (*name).to_string(),
                            // Distinct ports so listeners don't port-conflict.
                            port: 80 + i as i32,
                            protocol: (*protocol).to_string(),
                            ..Default::default()
                        }
                    })
                    .collect(),
                ..Default::default()
            },
            status: None,
        }
    }

    /// Health map assigning each named listener the given readiness.
    fn health_with_readiness(pairs: &[(&str, ListenerReadiness)]) -> GatewayListenerStatus {
        let mut h = GatewayListenerStatus::default();
        for (name, readiness) in pairs {
            let info = ListenerInfo {
                readiness: readiness.clone(),
                ..Default::default()
            };
            h.listeners.insert(ListenerStatusKey::gateway(*name), info);
        }
        h
    }

    fn unsupported() -> ListenerReadiness {
        ListenerReadiness::UnsupportedProtocol {
            message: "protocol \"INVALID\" is not supported".to_string(),
        }
    }

    #[test]
    fn gateway_accepted_false_when_all_listeners_unsupported_protocol() {
        // Single listener with an unsupported protocol → the Gateway has no
        // accepted listener, so Accepted=False/ListenersNotValid, and the
        // listener reports Accepted=False/UnsupportedProtocol with empty
        // supportedKinds.
        let gw = gateway_with_listeners(&[("invalid", "INVALID")]);
        let health = health_with_readiness(&[("invalid", unsupported())]);

        assert_eq!(
            desired_gateway_accepted(&gw, &health, &no_addr()),
            ("False", GatewayConditionReason::ListenersNotValid)
        );

        let patch = build_gateway_status_patch(
            &gw,
            &health,
            1,
            &epoch(),
            &no_addr(),
            IngressPorts::default(),
        );
        let acc = patch["status"]["conditions"]
            .as_array()
            .expect("conditions")
            .iter()
            .find(|c| c["type"] == "Accepted")
            .expect("Accepted");
        assert_eq!(acc["status"], "False");
        assert_eq!(acc["reason"], "ListenersNotValid");

        let listener = patch["status"]["listeners"]
            .as_array()
            .expect("listeners")
            .iter()
            .find(|l| l["name"] == "invalid")
            .expect("invalid listener");
        assert_eq!(
            listener["supportedKinds"],
            serde_json::json!([]),
            "unsupported-protocol listener must advertise no supported kinds"
        );
        let l_acc = listener["conditions"]
            .as_array()
            .expect("listener conditions")
            .iter()
            .find(|c| c["type"] == "Accepted")
            .expect("listener Accepted");
        assert_eq!(l_acc["status"], "False");
        assert_eq!(l_acc["reason"], "UnsupportedProtocol");
    }

    #[test]
    fn gateway_accepted_true_listenersnotvalid_when_mixed() {
        // One valid HTTP listener + one unsupported-protocol listener → the
        // Gateway is still Accepted (status True) because at least one listener
        // is accepted, but the reason is ListenersNotValid.
        let gw = gateway_with_listeners(&[("http", "HTTP"), ("invalid", "INVALID")]);
        // The HTTP listener has no health entry (defaults to accepted); the
        // invalid one is unaccepted.
        let health = health_with_readiness(&[("invalid", unsupported())]);

        assert_eq!(
            desired_gateway_accepted(&gw, &health, &no_addr()),
            ("True", GatewayConditionReason::ListenersNotValid)
        );

        let patch = build_gateway_status_patch(
            &gw,
            &health,
            1,
            &epoch(),
            &no_addr(),
            IngressPorts::default(),
        );
        let acc = patch["status"]["conditions"]
            .as_array()
            .expect("conditions")
            .iter()
            .find(|c| c["type"] == "Accepted")
            .expect("Accepted");
        assert_eq!(acc["status"], "True");
        assert_eq!(acc["reason"], "ListenersNotValid");
    }

    #[test]
    fn gateway_accepted_when_all_listeners_supported() {
        // Sanity: an all-HTTP/HTTPS Gateway with healthy listeners stays
        // (True, Accepted) — the rollup does not regress the happy path.
        let gw = gateway_with_listeners(&[("http", "HTTP"), ("https", "HTTPS")]);
        let health = health_with_readiness(&[("https", ListenerReadiness::Resolved)]);
        assert_eq!(
            desired_gateway_accepted(&gw, &health, &no_addr()),
            ("True", GatewayConditionReason::Accepted)
        );
    }

    #[test]
    fn needs_patch_is_idempotent_for_unsupported_protocol_listener() {
        // Regression (#517): build the status patch for a Gateway with an
        // unsupported-protocol listener, apply it back, and confirm
        // gateway_needs_status_patch is then False. A mirror-drift between the
        // written per-listener Accepted condition and the staleness check would
        // otherwise repatch on every reconcile forever.
        let gw = gateway_with_listeners(&[("http", "HTTP"), ("invalid", "INVALID")]);
        let health = health_with_readiness(&[("invalid", unsupported())]);
        let patch = build_gateway_status_patch(
            &gw,
            &health,
            1,
            &epoch(),
            &no_addr(),
            IngressPorts::default(),
        );
        let status: GatewayStatus =
            serde_json::from_value(patch["status"].clone()).expect("status deserializes");
        let mut patched = gw.clone();
        patched.status = Some(status);
        assert!(
            !gateway_needs_status_patch(&patched, &health, &no_addr()),
            "status must converge: needs_patch should be False after applying its own patch"
        );
    }

    #[test]
    fn patch_sets_programmed_address_not_usable_keeping_accepted_true() {
        let gw = gateway(1, None, None);
        let decision = engaged(None, Some(GatewayConditionReason::AddressNotUsable), vec![]);
        let patch = build_gateway_status_patch(
            &gw,
            &default_status(),
            1,
            &epoch(),
            &decision,
            IngressPorts::default(),
        );
        let conds = patch["status"]["conditions"]
            .as_array()
            .expect("conditions");
        let acc = conds
            .iter()
            .find(|c| c["type"] == "Accepted")
            .expect("Accepted");
        assert_eq!(acc["status"], "True");
        assert_eq!(acc["reason"], "Accepted");
        let prog = conds
            .iter()
            .find(|c| c["type"] == "Programmed")
            .expect("Programmed");
        assert_eq!(prog["status"], "False");
        assert_eq!(prog["reason"], "AddressNotUsable");
    }

    #[test]
    fn patch_publishes_only_usable_static_address() {
        let gw = gateway(1, None, None);
        let decision = engaged(
            None,
            None,
            vec![TypedAddress::new(
                SupportedAddressType::IpAddress,
                "10.96.0.10",
            )],
        );
        let patch = build_gateway_status_patch(
            &gw,
            &default_status(),
            1,
            &epoch(),
            &decision,
            IngressPorts::default(),
        );
        assert_eq!(
            patch["status"]["addresses"],
            serde_json::json!([{ "type": "IPAddress", "value": "10.96.0.10" }])
        );
        let prog = patch["status"]["conditions"]
            .as_array()
            .expect("conditions")
            .iter()
            .find(|c| c["type"] == "Programmed")
            .expect("Programmed")
            .clone();
        assert_eq!(prog["status"], "True");
    }

    // ── convergence gate (#533) ───────────────────────────────────────

    /// A decision that is otherwise the happy path but not yet converged.
    fn not_converged() -> SharedAddressDecision {
        SharedAddressDecision {
            legacy_addr: None,
            static_outcome: StaticAddressOutcome::not_engaged(),
            params_ref_unsupported: false,
            converged: false,
            settled_negative: false,
            pending_detail: None,
        }
    }

    #[test]
    fn patch_holds_programmed_pending_below_generation_until_converged() {
        // Not converged (VIP unresolved and/or proxy not ack'd): Programmed is
        // held at False/Pending with observedGeneration BELOW the current
        // generation so `GatewayMustHaveLatestConditions` keeps waiting, while
        // Accepted advances immediately.
        let gw = gateway(3, None, None);
        let patch = build_gateway_status_patch(
            &gw,
            &default_status(),
            3,
            &epoch(),
            &not_converged(),
            IngressPorts::default(),
        );
        let conds = patch["status"]["conditions"]
            .as_array()
            .expect("conditions");
        let acc = conds
            .iter()
            .find(|c| c["type"] == "Accepted")
            .expect("Accepted");
        assert_eq!(acc["status"], "True", "Accepted advances immediately");
        assert_eq!(acc["observedGeneration"], 3);
        let prog = conds
            .iter()
            .find(|c| c["type"] == "Programmed")
            .expect("Programmed");
        assert_eq!(prog["status"], "False");
        assert_eq!(prog["reason"], "Pending");
        assert_eq!(
            prog["observedGeneration"], 2,
            "Programmed held one generation below current until converged"
        );
    }

    #[test]
    fn patch_settles_programmed_false_invalid_at_current_generation() {
        // #570: a settled negative (unsupported parametersRef / all listeners
        // terminally unserviceable) must NOT be held at Pending/gen-1 — the
        // verdict is decided, so Programmed=False/Invalid stamps at the
        // CURRENT generation and `GatewayMustHaveLatestConditions` passes.
        let gw = gateway(3, None, None);
        let mut decision = not_converged();
        decision.converged = true;
        decision.settled_negative = true;
        let patch = build_gateway_status_patch(
            &gw,
            &default_status(),
            3,
            &epoch(),
            &decision,
            IngressPorts::default(),
        );
        let conds = patch["status"]["conditions"]
            .as_array()
            .expect("conditions");
        let prog = conds
            .iter()
            .find(|c| c["type"] == "Programmed")
            .expect("Programmed");
        assert_eq!(prog["status"], "False");
        assert_eq!(prog["reason"], "Invalid");
        assert_eq!(
            prog["observedGeneration"], 3,
            "settled negative stamps at the current generation, never the gen-1 hold"
        );
        let acc = conds
            .iter()
            .find(|c| c["type"] == "Accepted")
            .expect("Accepted");
        assert_eq!(acc["observedGeneration"], 3);
    }

    #[test]
    fn patch_carries_pool_bind_detail_while_pending() {
        // #531: while the hold is caused by the proxy-pool bind gate, the
        // Programmed message names the wait (nodes/ports) instead of the
        // generic Pending text — message only, never part of staleness.
        let gw = gateway(3, None, None);
        let mut decision = not_converged();
        decision.pending_detail = Some(
            "waiting for 1/2 connected shared proxy node(s) to bind internal port(s) [30001]"
                .to_owned(),
        );
        let patch = build_gateway_status_patch(
            &gw,
            &default_status(),
            3,
            &epoch(),
            &decision,
            IngressPorts::default(),
        );
        let prog = patch["status"]["conditions"]
            .as_array()
            .expect("conditions")
            .iter()
            .find(|c| c["type"] == "Programmed")
            .expect("Programmed")
            .clone();
        assert_eq!(prog["status"], "False");
        assert_eq!(prog["reason"], "Pending");
        assert_eq!(
            prog["message"],
            "waiting for 1/2 connected shared proxy node(s) to bind internal port(s) [30001]"
        );
    }

    #[test]
    fn pending_detail_ignored_once_converged() {
        // A stale detail on a converged decision must not leak into the
        // canonical True/Programmed message.
        let gw = gateway(3, None, None);
        let mut decision = no_addr(); // converged
        decision.pending_detail = Some("stale detail".to_owned());
        let patch = build_gateway_status_patch(
            &gw,
            &default_status(),
            3,
            &epoch(),
            &decision,
            IngressPorts::default(),
        );
        let prog = patch["status"]["conditions"]
            .as_array()
            .expect("conditions")
            .iter()
            .find(|c| c["type"] == "Programmed")
            .expect("Programmed")
            .clone();
        assert_eq!(prog["status"], "True");
        assert_ne!(prog["message"], "stale detail");
    }

    #[test]
    fn patch_flips_programmed_true_at_generation_once_converged() {
        let gw = gateway(3, None, None);
        let patch = build_gateway_status_patch(
            &gw,
            &default_status(),
            3,
            &epoch(),
            &no_addr(), // converged
            IngressPorts::default(),
        );
        let prog = patch["status"]["conditions"]
            .as_array()
            .expect("conditions")
            .iter()
            .find(|c| c["type"] == "Programmed")
            .expect("Programmed")
            .clone();
        assert_eq!(prog["status"], "True");
        assert_eq!(prog["reason"], "Programmed");
        assert_eq!(
            prog["observedGeneration"], 3,
            "converged Programmed stamps the current generation"
        );
    }

    #[test]
    fn needs_patch_when_pending_flips_to_converged() {
        // A Gateway currently Programmed=False/Pending must re-patch when it
        // converges (Pending → True/Programmed), even though Accepted is
        // unchanged — otherwise Programmed would never advance to True.
        let pending = Condition {
            type_: "Programmed".to_string(),
            status: "False".to_string(),
            reason: "Pending".to_string(),
            message: String::new(),
            observed_generation: Some(1),
            last_transition_time: epoch(),
        };
        let gw = gateway(
            2,
            Some(vec![condition("Accepted", 2), pending]),
            Some(vec![listener_status("http", 2)]),
        );
        assert!(
            gateway_needs_status_patch(&gw, &default_status(), &no_addr()),
            "a pending→converged transition must force a patch"
        );
    }

    #[test]
    fn settled_negative_programmed_stamps_current_generation_even_if_not_converged() {
        // A real negative outcome (AddressNotUsable) is settled for the current
        // generation — the not-yet-converged hold must NOT apply to it.
        let gw = gateway(4, None, None);
        let mut decision = engaged(None, Some(GatewayConditionReason::AddressNotUsable), vec![]);
        decision.converged = false;
        let patch = build_gateway_status_patch(
            &gw,
            &default_status(),
            4,
            &epoch(),
            &decision,
            IngressPorts::default(),
        );
        let prog = patch["status"]["conditions"]
            .as_array()
            .expect("conditions")
            .iter()
            .find(|c| c["type"] == "Programmed")
            .expect("Programmed")
            .clone();
        assert_eq!(prog["status"], "False");
        assert_eq!(prog["reason"], "AddressNotUsable");
        assert_eq!(
            prog["observedGeneration"], 4,
            "settled negative stamps the current generation, not held"
        );
    }

    #[test]
    fn needs_patch_when_accepted_flips_to_unsupported_address() {
        // Status currently reports Accepted=True but the request is now invalid.
        let gw = gateway(
            1,
            Some(vec![condition("Accepted", 1), condition("Programmed", 1)]),
            Some(vec![listener_status("http", 1)]),
        );
        let decision = engaged(
            Some(GatewayConditionReason::UnsupportedAddress),
            Some(GatewayConditionReason::Invalid),
            vec![],
        );
        assert!(gateway_needs_status_patch(
            &gw,
            &default_status(),
            &decision
        ));
    }

    #[test]
    fn patch_omits_resolvedrefs_when_ref_absent() {
        let gw = gateway(1, None, None);
        let patch = build_gateway_status_patch(
            &gw,
            &default_status(),
            1,
            &epoch(),
            &no_addr(),
            IngressPorts::default(),
        );
        let conds = patch["status"]["conditions"]
            .as_array()
            .expect("conditions array");
        assert!(conds.iter().all(|c| c["type"] != "ResolvedRefs"));
    }
}
