//! Condition helpers: inspect `metav1.Condition` objects on Gateway API resources.
//!
//! The constructor lives in [`crate::status_common::make_condition`] so both
//! the shared-pool status writer and the dedicated-mode status writer use one
//! source of truth for condition layout; this module just re-exports it for
//! call sites that already spell the bare name.

use coxswain_core::ownership::{self, ObjectKey};
use coxswain_reflector::gw_types::v::gatewayclasses::GatewayClass;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use std::collections::HashSet;

pub(super) use crate::status_common::make_condition;

/// Gateway API group, the default for an unset `parentRef.group`.
const GW_GROUP: &str = "gateway.networking.k8s.io";

/// `true` when a `parentRef` targets a `ListenerSet` (GEP-1713): `kind:
/// ListenerSet` in the standard Gateway API group (the group defaults to the
/// standard group when unset). ListenerSet refs are written to route status only
/// when the reflector recorded a health entry for them (see `route_events`).
#[must_use]
pub(super) fn is_listener_set_ref(group: Option<&str>, kind: Option<&str>) -> bool {
    let group = group.unwrap_or(GW_GROUP);
    group == GW_GROUP && kind == Some("ListenerSet")
}

/// Decide whether a route `parentRef` should receive a status entry written by
/// this controller (GEP-1713). A Gateway parentRef is ours iff we own the
/// Gateway. A ListenerSet parentRef is ours iff the reflector recorded a health
/// entry for it (`health_present`) — it does so only for ListenerSets attached
/// to an owned Gateway, so a recorded entry IS the ownership proof. This keeps
/// the HTTP and GRPC status writers' ownership logic identical and unit-testable
/// without a Kubernetes client.
#[must_use]
pub(super) fn route_parent_gets_status(
    group: Option<&str>,
    kind: Option<&str>,
    namespace: Option<&str>,
    name: &str,
    default_ns: &str,
    owned_gateways: &HashSet<ObjectKey>,
    health_present: bool,
) -> bool {
    if is_listener_set_ref(group, kind) {
        health_present
    } else {
        ownership::parent_ref_owned(group, kind, namespace, name, default_ns, owned_gateways)
    }
}

pub(super) fn has_condition(conditions: Option<&[Condition]>, type_: &str) -> bool {
    has_condition_at_gen(conditions, type_, 0)
}

fn has_condition_at_gen(conditions: Option<&[Condition]>, type_: &str, min_gen: i64) -> bool {
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

pub(super) fn gateway_class_accepted(gc: &GatewayClass) -> bool {
    has_condition_at_gen(
        gc.status.as_ref().and_then(|s| s.conditions.as_deref()),
        "Accepted",
        gc.metadata.generation.unwrap_or(0),
    )
}

pub(super) fn gateway_accepted(gw: &Gateway) -> bool {
    has_condition(
        gw.status.as_ref().and_then(|s| s.conditions.as_deref()),
        "Accepted",
    )
}

pub(super) fn gateway_programmed(gw: &Gateway) -> bool {
    has_condition(
        gw.status.as_ref().and_then(|s| s.conditions.as_deref()),
        "Programmed",
    )
}

#[cfg(test)]
mod tests {
    use super::{
        gateway_accepted, gateway_class_accepted, gateway_programmed, has_condition,
        is_listener_set_ref, make_condition, route_parent_gets_status,
    };
    use coxswain_core::ownership::ObjectKey;
    use coxswain_reflector::gw_types::v::gatewayclasses::{GatewayClass, GatewayClassStatus};
    use coxswain_reflector::gw_types::v::gateways::{Gateway, GatewayStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use kube::api::ObjectMeta;
    use std::collections::HashSet;

    fn stub_condition(
        type_: &str,
        status: &str,
    ) -> k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
        k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
            type_: type_.to_string(),
            status: status.to_string(),
            reason: String::new(),
            message: String::new(),
            observed_generation: None,
            last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
        }
    }

    fn now() -> Time {
        Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH)
    }

    #[test]
    fn make_condition_sets_all_fields() {
        let c = make_condition("Programmed", "True", "Ready", "all good", 3, now());
        assert_eq!(c.type_, "Programmed");
        assert_eq!(c.status, "True");
        assert_eq!(c.reason, "Ready");
        assert_eq!(c.message, "all good");
        assert_eq!(c.observed_generation, Some(3));
    }

    #[test]
    fn has_condition_returns_false_when_none() {
        assert!(!has_condition(None, "Programmed"));
    }

    #[test]
    fn has_condition_returns_false_when_slice_empty() {
        assert!(!has_condition(Some(&[]), "Programmed"));
    }

    #[test]
    fn gateway_class_accepted_false_when_generation_stale() {
        // condition exists but observed_generation < metadata.generation — must return false
        let gc = GatewayClass {
            metadata: ObjectMeta {
                generation: Some(5),
                ..Default::default()
            },
            status: Some(GatewayClassStatus {
                conditions: Some(vec![make_condition(
                    "Accepted",
                    "True",
                    "ok",
                    "",
                    2, // stale generation
                    now(),
                )]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!gateway_class_accepted(&gc));
    }

    #[test]
    fn gateway_class_accepted_true_when_generation_current() {
        let gc = GatewayClass {
            metadata: ObjectMeta {
                generation: Some(5),
                ..Default::default()
            },
            status: Some(GatewayClassStatus {
                conditions: Some(vec![make_condition("Accepted", "True", "ok", "", 5, now())]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(gateway_class_accepted(&gc));
    }

    #[test]
    fn is_listener_set_ref_matches_standard_group_kind() {
        // Explicit standard group + ListenerSet kind.
        assert!(is_listener_set_ref(
            Some("gateway.networking.k8s.io"),
            Some("ListenerSet")
        ));
        // Group defaults to the standard group when unset.
        assert!(is_listener_set_ref(None, Some("ListenerSet")));
    }

    #[test]
    fn route_parent_gets_status_owned_gateway_and_listenerset() {
        let owned: HashSet<ObjectKey> = [ObjectKey::new("infra", "gw")].into();
        // Owned Gateway parentRef (default kind) → written regardless of health.
        assert!(route_parent_gets_status(
            None,
            None,
            Some("infra"),
            "gw",
            "apps",
            &owned,
            false,
        ));
        // Unowned Gateway parentRef → never written.
        assert!(!route_parent_gets_status(
            None,
            None,
            Some("infra"),
            "other-gw",
            "apps",
            &owned,
            true, // even if a stale health entry somehow existed
        ));
        // ListenerSet parentRef WITH a reflector health entry → written (kind echoed
        // by the caller). The Gateway-ownership set is irrelevant here.
        assert!(route_parent_gets_status(
            Some("gateway.networking.k8s.io"),
            Some("ListenerSet"),
            Some("apps"),
            "ls",
            "apps",
            &owned,
            true,
        ));
        // ListenerSet parentRef WITHOUT a health entry → not ours → skipped.
        assert!(!route_parent_gets_status(
            None,
            Some("ListenerSet"),
            Some("apps"),
            "ls",
            "apps",
            &owned,
            false,
        ));
    }

    #[test]
    fn is_listener_set_ref_rejects_gateway_and_foreign_group() {
        // A Gateway ref (default kind) is not a ListenerSet.
        assert!(!is_listener_set_ref(None, Some("Gateway")));
        // Unset kind defaults to Gateway elsewhere — here it simply isn't ListenerSet.
        assert!(!is_listener_set_ref(None, None));
        // Right kind, wrong group (e.g. a CRD impersonating the name).
        assert!(!is_listener_set_ref(
            Some("example.com"),
            Some("ListenerSet")
        ));
    }

    // ── Stub-condition-driven tests (migrated from controller/tests/controller.rs) ─

    #[test]
    fn has_condition_returns_true_when_present_and_true() {
        let conds = vec![stub_condition("Programmed", "True")];
        assert!(has_condition(Some(&conds), "Programmed"));
    }

    #[test]
    fn has_condition_returns_false_when_absent() {
        let conds = vec![stub_condition("Accepted", "True")];
        assert!(!has_condition(Some(&conds), "Programmed"));
    }

    #[test]
    fn has_condition_returns_false_when_not_true() {
        let conds = vec![stub_condition("Programmed", "False")];
        assert!(!has_condition(Some(&conds), "Programmed"));
    }

    #[test]
    fn gateway_class_accepted_when_condition_present() {
        let gc = GatewayClass {
            status: Some(GatewayClassStatus {
                conditions: Some(vec![stub_condition("Accepted", "True")]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(gateway_class_accepted(&gc));
    }

    #[test]
    fn gateway_class_not_accepted_when_no_status() {
        let gc = GatewayClass {
            status: None,
            ..Default::default()
        };
        assert!(!gateway_class_accepted(&gc));
    }

    #[test]
    fn gateway_accepted_true_when_condition_present() {
        let gw = Gateway {
            status: Some(GatewayStatus {
                conditions: Some(vec![stub_condition("Accepted", "True")]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(gateway_accepted(&gw));
    }

    #[test]
    fn gateway_accepted_false_when_no_status() {
        let gw = Gateway {
            status: None,
            ..Default::default()
        };
        assert!(!gateway_accepted(&gw));
    }

    #[test]
    fn gateway_accepted_false_when_status_is_false() {
        let gw = Gateway {
            status: Some(GatewayStatus {
                conditions: Some(vec![stub_condition("Accepted", "False")]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!gateway_accepted(&gw));
    }

    #[test]
    fn gateway_programmed_true_when_condition_present() {
        let gw = Gateway {
            status: Some(GatewayStatus {
                conditions: Some(vec![stub_condition("Programmed", "True")]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(gateway_programmed(&gw));
    }

    #[test]
    fn gateway_programmed_false_when_absent() {
        let gw = Gateway {
            status: Some(GatewayStatus {
                conditions: Some(vec![stub_condition("Accepted", "True")]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!gateway_programmed(&gw));
    }

    #[test]
    fn gateway_programmed_false_when_no_status() {
        let gw = Gateway {
            status: None,
            ..Default::default()
        };
        assert!(!gateway_programmed(&gw));
    }
}
