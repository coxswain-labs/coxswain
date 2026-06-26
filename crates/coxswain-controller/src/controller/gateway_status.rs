//! `Gateway` status patch builder and staleness check (GEP-1364).

use super::conditions::{has_condition, make_condition};
use super::config::StatusAddress;
use crate::status_common::{
    OPERATOR_OWNED_CONDITION_TYPE_PREFIX, build_listener_status, listener_route_kind_info,
};
use coxswain_reflector::gw_types::v::gateways::{Gateway, GatewayStatusListeners};
use coxswain_reflector::tls::{GatewayListenerHealth, ListenerTlsOutcome};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

/// Returns true when the Gateway's current status does not yet reflect the
/// desired state computed from `health`. Prevents redundant patches and
/// watch-feedback loops.
pub(super) fn gateway_needs_status_patch(
    gw: &Gateway,
    health: &GatewayListenerHealth,
    addr: Option<&StatusAddress>,
) -> bool {
    if !accepted_is_true(gw) {
        return true;
    }
    if !super::conditions::gateway_programmed(gw) {
        return true;
    }
    // The per-Gateway VIP address (#472) is provisioned asynchronously and lands
    // AFTER conditions have already settled. A Gateway whose conditions/listeners
    // are otherwise up to date but whose `status.addresses` does not yet reflect
    // the resolved VIP still needs a patch — without this, a Gateway with stable
    // health (e.g. a TLS-passthrough listener whose conditions never flip after
    // the first reconcile) would never get its address written once the VIP
    // resolves on a later reconcile.
    if !gateway_address_up_to_date(gw, addr) {
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
        let info = health.listeners.get(&listener.name);
        let frontend_impacts = info.is_some_and(|i| i.frontend_outcome.is_failed());
        let desired_healthy = !has_invalid_kinds
            && info.map(|i| i.tls_outcome.is_healthy()).unwrap_or(true)
            && !frontend_impacts;
        let current_listener = current_listeners.iter().find(|sl| sl.name == listener.name);
        let current_resolved = current_listener
            .map(|sl| has_condition(Some(sl.conditions.as_slice()), "ResolvedRefs"))
            .unwrap_or(false);
        if desired_healthy != current_resolved {
            return true;
        }
        // GEP-2643: a TLS/Terminate listener is computed Unsupported only after the
        // reflector processes the Gateway, *after* the controller's first reconcile
        // wrote Accepted=True from an empty health. Mirror build_listener_status'
        // Accepted logic (frontend CA failure or an Unsupported outcome → False) so
        // the transition True→False is detected and patched, not left stuck.
        let desired_accepted_false = frontend_impacts
            || info
                .is_some_and(|i| matches!(i.tls_outcome, ListenerTlsOutcome::Unsupported { .. }));
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

/// True iff `gw.status.addresses[0]` already matches the desired `addr`.
///
/// `addr == None` (feature off, or VIP address still pending) never forces a
/// patch on address grounds — the status writer simply leaves the address
/// untouched until the VIP resolves. A `Some` desired address that differs from
/// (or is absent in) the current status returns false so the patch lands.
fn gateway_address_up_to_date(gw: &Gateway, addr: Option<&StatusAddress>) -> bool {
    let Some(desired) = addr else {
        return true;
    };
    let (desired_type, desired_value) = match desired {
        StatusAddress::Ip(ip) => ("IPAddress", ip.to_string()),
        StatusAddress::Hostname(h) => ("Hostname", h.clone()),
    };
    gw.status
        .as_ref()
        .and_then(|s| s.addresses.as_ref())
        .and_then(|a| a.first())
        .is_some_and(|cur| {
            cur.value == desired_value && cur.r#type.as_deref() == Some(desired_type)
        })
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
    // GEP-91: emit InsecureFrontendValidationMode=True when mode is AllowInsecureFallback.
    // The condition is omitted entirely when mode is AllowValidOnly (its absence = valid).
    if let Some(fv) = health.frontend_validation.as_ref()
        && fv.insecure_fallback
    {
        conditions.push(make_condition(
            "InsecureFrontendValidationMode",
            "True",
            "ConfigurationChanged",
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
            "ResolvedRefs",
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
    use super::super::gateway_status::{build_gateway_status_patch, gateway_needs_status_patch};
    use coxswain_reflector::gw_types::v::gateways::{
        Gateway, GatewaySpec, GatewayStatus, GatewayStatusListeners,
    };
    use coxswain_reflector::ingress::IngressPorts;
    use coxswain_reflector::tls::{BackendClientCertOutcome, GatewayListenerHealth};
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

    // ── #472 per-Gateway VIP address divergence ──────────────────────────────

    #[test]
    fn needs_patch_when_vip_address_not_yet_written() {
        use super::super::config::StatusAddress;
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
            &default_health(),
            Some(&addr)
        ));
    }

    #[test]
    fn no_patch_when_vip_address_already_matches() {
        use super::super::config::StatusAddress;
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
            &default_health(),
            Some(&addr)
        ));
    }

    // ── GEP-3155 gateway-level ResolvedRefs (backend client cert) ─────────────

    fn epoch() -> Time {
        Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH)
    }

    fn health_with_backend(outcome: BackendClientCertOutcome) -> GatewayListenerHealth {
        let mut h = GatewayListenerHealth::default();
        h.backend_client_cert = Some(outcome);
        h
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
            None
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
            None
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
            None
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
        assert!(gateway_needs_status_patch(&gw, &default_health(), None));
    }

    #[test]
    fn patch_emits_resolvedrefs_false_keeping_accepted_true() {
        let gw = gateway(1, None, None);
        let health = health_with_backend(BackendClientCertOutcome::InvalidClientCertificateRef {
            message: "Secret gw-ns/missing: secret not found in store".to_string(),
        });
        let patch =
            build_gateway_status_patch(&gw, &health, 1, &epoch(), None, IngressPorts::default());
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
        let patch =
            build_gateway_status_patch(&gw, &health, 1, &epoch(), None, IngressPorts::default());
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

    #[test]
    fn patch_omits_resolvedrefs_when_ref_absent() {
        let gw = gateway(1, None, None);
        let patch = build_gateway_status_patch(
            &gw,
            &default_health(),
            1,
            &epoch(),
            None,
            IngressPorts::default(),
        );
        let conds = patch["status"]["conditions"]
            .as_array()
            .expect("conditions array");
        assert!(conds.iter().all(|c| c["type"] != "ResolvedRefs"));
    }
}
