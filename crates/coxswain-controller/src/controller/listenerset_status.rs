//! `ListenerSet.status` patch builder and staleness check (GEP-1713).
//!
//! Mirrors [`super::gateway_status`] for the `ListenerSet` resource. A ListenerSet
//! attaches listeners to a parent Gateway; its per-listener health lives in the
//! parent Gateway's [`GatewayListenerHealth`] keyed by
//! [`ListenerHealthKey`]`{ source: ListenerSet(ls_key), name }`. The
//! per-listener `Accepted`/`ResolvedRefs`/`Programmed` conditions reuse the exact
//! same reason mapping as Gateway listeners via
//! [`crate::status_common::listener_condition_triplet`]; a `Conflicted` condition
//! is added on top, and the ListenerSet carries top-level `Accepted`/`Programmed`.

use crate::status_common::{listener_condition_triplet, make_condition};
use coxswain_core::ownership::ObjectKey;
use coxswain_reflector::gw_types::ListenerSet;
use coxswain_reflector::gw_types::v::listenersets::{
    ListenerSetListeners, ListenerSetListenersTlsMode,
};
use coxswain_reflector::ingress::IngressPorts;
use coxswain_reflector::tls::{
    GatewayListenerHealth, ListenerHealthKey, ListenerInfo, ListenerSource, ListenerTlsOutcome,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

const GW_GROUP: &str = "gateway.networking.k8s.io";

/// The ListenerSet's own `{namespace}/{name}` key.
fn listenerset_key(ls: &ListenerSet) -> ObjectKey {
    ObjectKey::new(
        ls.metadata.namespace.clone().unwrap_or_default(),
        ls.metadata.name.clone().unwrap_or_default(),
    )
}

/// `true` when this ListenerSet was accepted (merged) by its parent Gateway: the
/// parent's health holds at least one listener tagged with this ListenerSet's
/// source, or the ListenerSet declares no listeners (vacuously accepted). A
/// ListenerSet rejected by the parent's `allowedListeners` contributes no health
/// entries, so its absence signals rejection (GEP-1713 opt-in gate).
#[must_use]
pub(super) fn listenerset_accepted(
    ls: &ListenerSet,
    parent_health: Option<&GatewayListenerHealth>,
) -> bool {
    if ls.spec.listeners.is_empty() {
        return true;
    }
    let ls_key = listenerset_key(ls);
    let Some(health) = parent_health else {
        return false;
    };
    health
        .listeners
        .keys()
        .any(|k| k.source == ListenerSource::ListenerSet(ls_key.clone()))
}

/// Look up the health for one ListenerSet listener in its parent Gateway's map.
fn listener_info<'a>(
    health: Option<&'a GatewayListenerHealth>,
    ls_key: &ObjectKey,
    name: &str,
) -> Option<&'a ListenerInfo> {
    health.and_then(|h| {
        h.listeners.get(&ListenerHealthKey {
            source: ListenerSource::ListenerSet(ls_key.clone()),
            name: name.to_string(),
        })
    })
}

/// Whether a ListenerSet listener is `protocol: TLS, tls.mode: Passthrough`.
fn is_passthrough(l: &ListenerSetListeners) -> bool {
    l.protocol == "TLS"
        && l.tls
            .as_ref()
            .and_then(|t| t.mode.as_ref())
            .is_some_and(|m| matches!(m, ListenerSetListenersTlsMode::Passthrough))
}

/// `(has_any_invalid, supported_kinds)` for a ListenerSet listener's
/// `allowedRoutes.kinds` — the ListenerSet analogue of
/// [`crate::status_common::listener_route_kind_info`].
fn route_kind_info(l: &ListenerSetListeners) -> (bool, Vec<(Option<String>, String)>) {
    let passthrough = is_passthrough(l);
    let default_kind = || {
        vec![(
            Some(GW_GROUP.to_string()),
            if passthrough { "TLSRoute" } else { "HTTPRoute" }.to_string(),
        )]
    };
    let allowed = match l.allowed_routes.as_ref().and_then(|ar| ar.kinds.as_deref()) {
        Some(k) if !k.is_empty() => k,
        _ => return (false, default_kind()),
    };
    let mut has_invalid = false;
    let mut includes_http = false;
    let mut includes_tls = false;
    for k in allowed {
        let group_ok = k
            .group
            .as_deref()
            .is_none_or(|g| g.is_empty() || g == GW_GROUP);
        if k.kind == "HTTPRoute" && group_ok {
            includes_http = true;
        } else if k.kind == "TLSRoute" && group_ok && passthrough {
            includes_tls = true;
        } else {
            has_invalid = true;
        }
    }
    let mut supported = Vec::new();
    if includes_http {
        supported.push((Some(GW_GROUP.to_string()), "HTTPRoute".to_string()));
    }
    if includes_tls {
        supported.push((Some(GW_GROUP.to_string()), "TLSRoute".to_string()));
    }
    (has_invalid, supported)
}

/// Build the per-listener condition list (the shared triplet plus a `Conflicted`
/// condition) for one ListenerSet listener.
fn listener_conditions(
    l: &ListenerSetListeners,
    info: Option<&ListenerInfo>,
    has_invalid_kinds: bool,
    ingress_ports: IngressPorts,
    generation: i64,
    now: &Time,
) -> Vec<Condition> {
    let mut conds = listener_condition_triplet(
        &l.name,
        l.port,
        info,
        has_invalid_kinds,
        ingress_ports,
        generation,
        now,
    );
    let conflicted = info.is_some_and(|i| i.conflicted);
    let (status, reason, msg) = if conflicted {
        (
            "True",
            "HostnameConflict",
            "listener lost a port-compatibility conflict to a higher-precedence listener",
        )
    } else {
        ("False", "NoConflicts", "")
    };
    // A conflicted listener is not programmed; the shared triplet derives Programmed
    // from the TLS outcome (NotApplicable for a conflicted listener → would read
    // healthy), so override it here to reflect the conflict.
    if conflicted && let Some(prog) = conds.iter_mut().find(|c| c.type_ == "Programmed") {
        prog.status = "False".to_string();
        prog.reason = "HostnameConflict".to_string();
        prog.message = msg.to_string();
    }
    conds.push(make_condition(
        "Conflicted",
        status,
        reason,
        msg,
        generation,
        now.clone(),
    ));
    conds
}

/// Build the desired `ListenerSet.status` JSON merge patch (GEP-1713).
///
/// `accepted` is the parent Gateway's `allowedListeners` decision (see
/// [`listenerset_accepted`]); `parent_health` is the parent Gateway's listener
/// health snapshot, from which each ListenerSet listener's per-listener health is
/// read by source-tagged key.
#[must_use]
pub(super) fn build_listenerset_status_patch(
    ls: &ListenerSet,
    parent_health: Option<&GatewayListenerHealth>,
    accepted: bool,
    ingress_ports: IngressPorts,
    generation: i64,
    now: &Time,
) -> serde_json::Value {
    let ls_key = listenerset_key(ls);

    let mut all_programmed = accepted;
    let listener_statuses: Vec<serde_json::Value> = ls
        .spec
        .listeners
        .iter()
        .map(|l| {
            let info = listener_info(parent_health, &ls_key, &l.name);
            let (has_invalid_kinds, supported_kinds) = route_kind_info(l);
            let conds =
                listener_conditions(l, info, has_invalid_kinds, ingress_ports, generation, now);
            let programmed = conds
                .iter()
                .find(|c| c.type_ == "Programmed")
                .is_some_and(|c| c.status == "True");
            if !programmed {
                all_programmed = false;
            }
            let supported: Vec<serde_json::Value> = supported_kinds
                .into_iter()
                .map(|(group, kind)| serde_json::json!({ "group": group, "kind": kind }))
                .collect();
            // ListenerSetStatusListeners has no `port` field (only name,
            // attachedRoutes, conditions, supportedKinds) — emitting one would be
            // rejected by the CRD's structural schema.
            serde_json::json!({
                "name": l.name,
                "attachedRoutes": info.map(|i| i.attached_routes).unwrap_or(0),
                "supportedKinds": supported,
                "conditions": conds,
            })
        })
        .collect();

    let (accepted_status, accepted_reason, accepted_msg) = if accepted {
        ("True", "Accepted", "")
    } else {
        (
            "False",
            "NotAllowed",
            "the parent Gateway's spec.allowedListeners does not permit this ListenerSet",
        )
    };
    let (prog_status, prog_reason, prog_msg) = if !accepted {
        (
            "False",
            "Pending",
            "ListenerSet not accepted by the parent Gateway",
        )
    } else if all_programmed {
        ("True", "Programmed", "")
    } else {
        (
            "False",
            "Invalid",
            "one or more listeners are not programmed",
        )
    };
    let conditions = vec![
        make_condition(
            "Accepted",
            accepted_status,
            accepted_reason,
            accepted_msg,
            generation,
            now.clone(),
        ),
        make_condition(
            "Programmed",
            prog_status,
            prog_reason,
            prog_msg,
            generation,
            now.clone(),
        ),
    ];

    serde_json::json!({
        "status": {
            "conditions": conditions,
            "listeners": listener_statuses,
        }
    })
}

/// Returns true when the ListenerSet's current status does not yet reflect the
/// desired state — prevents redundant patches and watch-feedback loops.
#[must_use]
pub(super) fn listenerset_needs_status_patch(
    ls: &ListenerSet,
    parent_health: Option<&GatewayListenerHealth>,
    accepted: bool,
) -> bool {
    let status = ls.status.as_ref();
    let conds = status.and_then(|s| s.conditions.as_deref()).unwrap_or(&[]);
    let cond_true = |cs: &[Condition], type_: &str| {
        cs.iter()
            .find(|c| c.type_ == type_)
            .is_some_and(|c| c.status == "True")
    };
    if cond_true(conds, "Accepted") != accepted {
        return true;
    }

    let ls_key = listenerset_key(ls);
    let current = status.and_then(|s| s.listeners.as_deref()).unwrap_or(&[]);
    if current.len() != ls.spec.listeners.len() {
        return true;
    }
    let expected_gen = ls.metadata.generation.unwrap_or(0);
    if conds
        .iter()
        .any(|c| c.observed_generation.unwrap_or(0) < expected_gen)
    {
        return true;
    }

    // Top-level Programmed mirrors "all listeners programmed" (and acceptance);
    // TLS-health flips change this WITHOUT bumping generation, so it must be
    // compared explicitly (a cert deletion otherwise leaves status stale).
    let mut all_programmed = accepted;
    for l in &ls.spec.listeners {
        let info = listener_info(parent_health, &ls_key, &l.name);
        let (has_invalid_kinds, _) = route_kind_info(l);
        let conflicted = info.is_some_and(|i| i.conflicted);
        let healthy = info.map(|i| i.tls_outcome.is_healthy()).unwrap_or(true);
        // Desired per-listener condition states (port-conflict is config/spec-driven
        // and only changes on a generation-bumping edit, so it is covered by the
        // observedGeneration check above and omitted here — matching the Gateway path).
        let desired_resolved = !has_invalid_kinds && healthy;
        let desired_accepted_listener =
            !info.is_some_and(|i| matches!(i.tls_outcome, ListenerTlsOutcome::Unsupported { .. }));
        let desired_programmed = !conflicted && healthy;
        if !desired_programmed {
            all_programmed = false;
        }
        let desired_attached = info.map(|i| i.attached_routes).unwrap_or(0);

        let Some(cur) = current.iter().find(|sl| sl.name == l.name) else {
            return true;
        };
        if cur.attached_routes != desired_attached {
            return true;
        }
        if cond_true(&cur.conditions, "ResolvedRefs") != desired_resolved
            || cond_true(&cur.conditions, "Accepted") != desired_accepted_listener
            || cond_true(&cur.conditions, "Programmed") != desired_programmed
            || cond_true(&cur.conditions, "Conflicted") != conflicted
        {
            return true;
        }
        if cur
            .conditions
            .iter()
            .any(|c| c.observed_generation.unwrap_or(0) < expected_gen)
        {
            return true;
        }
    }
    if cond_true(conds, "Programmed") != all_programmed {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_reflector::gw_types::v::listenersets::{ListenerSetParentRef, ListenerSetSpec};
    use kube::api::ObjectMeta;

    fn ls(listeners: Vec<ListenerSetListeners>) -> ListenerSet {
        ListenerSet {
            metadata: ObjectMeta {
                name: Some("team".to_string()),
                namespace: Some("apps".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: ListenerSetSpec {
                parent_ref: ListenerSetParentRef {
                    name: "gw".to_string(),
                    namespace: Some("infra".to_string()),
                    ..Default::default()
                },
                listeners,
            },
            status: None,
        }
    }

    fn http_listener(name: &str, port: i32) -> ListenerSetListeners {
        ListenerSetListeners {
            name: name.to_string(),
            port,
            protocol: "HTTP".to_string(),
            ..Default::default()
        }
    }

    /// Health for the parent Gateway holding this LS's listener, optionally conflicted.
    fn parent_health(name: &str, port: u16, conflicted: bool) -> GatewayListenerHealth {
        let mut h = GatewayListenerHealth::default();
        let mut info = ListenerInfo::default();
        info.port = port;
        info.attached_routes = 2;
        info.conflicted = conflicted;
        h.listeners.insert(
            ListenerHealthKey::listener_set(ObjectKey::new("apps", "team"), name),
            info,
        );
        h
    }

    fn now() -> Time {
        Time(k8s_openapi::jiff::Timestamp::from_second(0).expect("epoch"))
    }

    #[test]
    fn accepted_reflects_health_presence() {
        let set = ls(vec![http_listener("web", 8080)]);
        let health = parent_health("web", 8080, false);
        assert!(listenerset_accepted(&set, Some(&health)));
        assert!(!listenerset_accepted(&set, None));
        // A ListenerSet with no listeners is vacuously accepted.
        assert!(listenerset_accepted(&ls(vec![]), None));
    }

    #[test]
    fn accepted_listener_set_programs_and_reports_no_conflict() {
        let set = ls(vec![http_listener("web", 8080)]);
        let health = parent_health("web", 8080, false);
        let patch = build_listenerset_status_patch(
            &set,
            Some(&health),
            true,
            IngressPorts::new(None, None),
            1,
            &now(),
        );
        let conds = &patch["status"]["conditions"];
        assert_eq!(conds[0]["type"], "Accepted");
        assert_eq!(conds[0]["status"], "True");
        assert_eq!(conds[1]["type"], "Programmed");
        assert_eq!(conds[1]["status"], "True");
        let l0 = &patch["status"]["listeners"][0];
        assert_eq!(l0["name"], "web");
        assert_eq!(l0["attachedRoutes"], 2);
        let conflicted = l0["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"] == "Conflicted")
            .unwrap();
        assert_eq!(conflicted["status"], "False");
    }

    #[test]
    fn rejected_listener_set_is_not_accepted() {
        let set = ls(vec![http_listener("web", 8080)]);
        let patch = build_listenerset_status_patch(
            &set,
            None,
            false,
            IngressPorts::new(None, None),
            1,
            &now(),
        );
        assert_eq!(patch["status"]["conditions"][0]["status"], "False");
        assert_eq!(patch["status"]["conditions"][0]["reason"], "NotAllowed");
        assert_eq!(patch["status"]["conditions"][1]["status"], "False");
    }

    #[test]
    fn conflicted_listener_reports_conflicted_true_and_blocks_programmed() {
        let set = ls(vec![http_listener("dup", 80)]);
        let health = parent_health("dup", 80, true);
        let patch = build_listenerset_status_patch(
            &set,
            Some(&health),
            true,
            IngressPorts::new(None, None),
            1,
            &now(),
        );
        let l0 = &patch["status"]["listeners"][0];
        let conflicted = l0["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"] == "Conflicted")
            .unwrap();
        assert_eq!(conflicted["status"], "True");
        // A conflicted (unprogrammed) listener drops the ListenerSet to Programmed=False.
        assert_eq!(patch["status"]["conditions"][1]["status"], "False");
    }

    #[test]
    fn needs_patch_true_on_empty_status_false_when_current() {
        let set = ls(vec![http_listener("web", 8080)]);
        let health = parent_health("web", 8080, false);
        assert!(listenerset_needs_status_patch(&set, Some(&health), true));

        // Apply the desired patch into the object, then it should be satisfied.
        let patch = build_listenerset_status_patch(
            &set,
            Some(&health),
            true,
            IngressPorts::new(None, None),
            1,
            &now(),
        );
        let mut applied = set.clone();
        applied.status =
            Some(serde_json::from_value(patch["status"].clone()).expect("status deserializes"));
        assert!(!listenerset_needs_status_patch(
            &applied,
            Some(&health),
            true
        ));
    }

    #[test]
    fn needs_patch_detects_tls_health_flip_without_generation_bump() {
        // An HTTPS LS listener that was healthy, then its cert is deleted: the TLS
        // outcome flips to unhealthy WITHOUT a generation bump. Status must re-patch
        // (the bug the C7 review caught — needs_patch ignored health-derived flips).
        let mut set = ls(vec![ListenerSetListeners {
            name: "web".to_string(),
            port: 8443,
            protocol: "HTTPS".to_string(),
            ..Default::default()
        }]);
        let mut healthy = GatewayListenerHealth::default();
        let mut info = ListenerInfo::default();
        info.tls_outcome = ListenerTlsOutcome::Resolved;
        info.port = 8443;
        healthy.listeners.insert(
            ListenerHealthKey::listener_set(ObjectKey::new("apps", "team"), "web"),
            info,
        );

        let patch = build_listenerset_status_patch(
            &set,
            Some(&healthy),
            true,
            IngressPorts::new(None, None),
            1,
            &now(),
        );
        set.status =
            Some(serde_json::from_value(patch["status"].clone()).expect("status deserializes"));
        assert!(!listenerset_needs_status_patch(&set, Some(&healthy), true));

        // Cert deleted → outcome unhealthy, same generation. Must require a patch.
        let mut broken = GatewayListenerHealth::default();
        let mut bad = ListenerInfo::default();
        bad.tls_outcome = ListenerTlsOutcome::InvalidCertificateRef {
            message: "secret missing".to_string(),
        };
        bad.port = 8443;
        broken.listeners.insert(
            ListenerHealthKey::listener_set(ObjectKey::new("apps", "team"), "web"),
            bad,
        );
        assert!(
            listenerset_needs_status_patch(&set, Some(&broken), true),
            "a TLS-health flip without a generation bump must re-patch status"
        );
    }
}
