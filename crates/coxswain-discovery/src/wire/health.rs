//! Wire-DTO conversions for node health reports (#677).
//!
//! A proxy or relay pushes its own subsystem health up the discovery stream it
//! has already authenticated, replacing the controller's unauthenticated HTTP
//! probe of that pod's `/statusz`. These functions are the crate boundary that
//! keeps `coxswain-core` free of generated proto types: the core owns
//! [`NodeHealth`], this module owns its encoding.
//!
//! # Decode discipline
//!
//! Unlike a `Snapshot`, a malformed `HealthReport` is never fatal. Health is
//! diagnostic — the controller renders it and nothing else turns on it (the
//! #531 `Programmed` gate reads acked versions and bound ports, not this). So
//! decoding degrades rather than erroring: an unrecognised or absent
//! [`p::CheckState`] discriminant becomes [`CheckState::Pending`] ("not yet
//! reported"), never `Ready`. Dropping a whole stream because a peer sent a
//! check state from a newer build would take out that node's routing to protect
//! a diagnostic field.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use coxswain_core::health::{CheckState, HealthSnapshot, SubsystemSnapshot};
use coxswain_core::node_registry::NodeHealth;

use crate::proto::v1 as p;
use crate::wire::{system_time_to_unix, unix_to_system_time};

/// Serialise a [`HealthSnapshot`] and its reporting build into a wire DTO.
///
/// Subsystems and checks are emitted sorted by name — both come from
/// `BTreeMap`s, so iteration order already is sorted, matching the crate's
/// determinism discipline (no `map<>` on the wire).
///
/// `SubsystemSnapshot::state` is deliberately not encoded: it is always the
/// highest-severity entry in `checks`, so putting it on the wire would create a
/// second source of truth that a partial write could make disagree with the
/// first. The decoder re-derives it.
#[must_use = "the report must be sent as a HealthReport (or folded into a RosterEntry) to reach the server"]
pub(crate) fn health_to_wire(
    version: &str,
    snapshot: &HealthSnapshot,
    reported_at: SystemTime,
) -> p::HealthReport {
    let subsystems = snapshot
        .subsystems
        .iter()
        .map(|(name, sub)| p::SubsystemHealth {
            name: name.to_string(),
            checks: sub
                .checks
                .iter()
                .map(|(check, state)| p::CheckHealth {
                    name: check.to_string(),
                    state: check_state_to_wire(state) as i32,
                    reason: check_reason(state).unwrap_or_default().to_owned(),
                })
                .collect(),
        })
        .collect();
    p::HealthReport {
        version: version.to_owned(),
        subsystems,
        reported_at_unix: system_time_to_unix(reported_at),
    }
}

/// Decode a wire [`p::HealthReport`] into its core form.
///
/// Infallible by design — see the module header. A duplicate subsystem or check
/// name collapses to the last occurrence (`BTreeMap` insert), which is the same
/// resolution the reporter's own registry would have produced.
#[must_use]
pub(crate) fn health_from_wire(dto: &p::HealthReport) -> NodeHealth {
    let mut subsystems: BTreeMap<Arc<str>, SubsystemSnapshot> = BTreeMap::new();
    for sub in &dto.subsystems {
        let mut checks: BTreeMap<Arc<str>, CheckState> = BTreeMap::new();
        for check in &sub.checks {
            checks.insert(Arc::from(check.name.as_str()), check_state_from_wire(check));
        }
        // Re-derive the aggregate rather than trusting a wire field, matching
        // `HealthRegistry::snapshot`. An empty subsystem aggregates to `Ready`.
        let state = checks
            .values()
            .max_by_key(|c| c.severity())
            .cloned()
            .unwrap_or(CheckState::Ready);
        subsystems.insert(
            Arc::from(sub.name.as_str()),
            SubsystemSnapshot { state, checks },
        );
    }
    NodeHealth {
        version: dto.version.clone(),
        snapshot: HealthSnapshot { subsystems },
        reported_at: unix_to_system_time(dto.reported_at_unix),
    }
}

/// Map a core [`CheckState`] to its wire discriminant.
fn check_state_to_wire(state: &CheckState) -> p::CheckState {
    match state {
        CheckState::Pending => p::CheckState::Pending,
        CheckState::Ready => p::CheckState::Ready,
        CheckState::Degraded { .. } => p::CheckState::Degraded,
        CheckState::Failed { .. } => p::CheckState::Failed,
    }
}

/// The human-readable reason a state carries, if any.
fn check_reason(state: &CheckState) -> Option<&str> {
    match state {
        CheckState::Degraded { reason } | CheckState::Failed { reason } => Some(reason.as_ref()),
        CheckState::Pending | CheckState::Ready => None,
    }
}

/// Rebuild a core [`CheckState`] from one wire check.
///
/// An unspecified or unrecognised discriminant decodes to `Pending`, which is
/// the fail-closed reading: "the reporter has not told us this is healthy".
fn check_state_from_wire(check: &p::CheckHealth) -> CheckState {
    let reason = || Arc::from(check.reason.as_str());
    match p::CheckState::try_from(check.state).unwrap_or(p::CheckState::Unspecified) {
        p::CheckState::Ready => CheckState::Ready,
        p::CheckState::Degraded => CheckState::Degraded { reason: reason() },
        p::CheckState::Failed => CheckState::Failed { reason: reason() },
        p::CheckState::Unspecified | p::CheckState::Pending => CheckState::Pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn snapshot_with(checks: &[(&str, CheckState)]) -> HealthSnapshot {
        let checks: BTreeMap<Arc<str>, CheckState> = checks
            .iter()
            .map(|(n, s)| (Arc::from(*n), s.clone()))
            .collect();
        let state = checks
            .values()
            .max_by_key(|c| c.severity())
            .cloned()
            .unwrap_or(CheckState::Ready);
        let mut subsystems = BTreeMap::new();
        subsystems.insert(Arc::from("proxy"), SubsystemSnapshot { state, checks });
        HealthSnapshot { subsystems }
    }

    #[test]
    fn round_trip_preserves_states_reasons_and_version() {
        let snap = snapshot_with(&[
            ("routing_table_loaded", CheckState::Ready),
            (
                "upstream",
                CheckState::Degraded {
                    reason: Arc::from("snapshot stale"),
                },
            ),
        ]);
        let at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        let decoded = health_from_wire(&health_to_wire("1.2.3", &snap, at));

        assert_eq!(decoded.version, "1.2.3");
        assert_eq!(decoded.reported_at, at);
        assert_eq!(decoded.snapshot, snap, "the whole tree must survive");
    }

    #[test]
    fn aggregate_state_is_rederived_not_carried() {
        // The wire has no subsystem-level state field. A subsystem whose worst
        // check is Failed must still aggregate to Failed after decode, or the
        // operator view would show a degraded pod as healthy.
        let snap = snapshot_with(&[
            ("a", CheckState::Ready),
            (
                "b",
                CheckState::Failed {
                    reason: Arc::from("bind refused"),
                },
            ),
        ]);
        let decoded = health_from_wire(&health_to_wire("1.2.3", &snap, UNIX_EPOCH));
        assert_eq!(
            decoded.snapshot.subsystems["proxy"].state,
            CheckState::Failed {
                reason: Arc::from("bind refused")
            }
        );
    }

    #[test]
    fn an_unknown_check_state_decodes_to_pending_never_ready() {
        // A peer on a newer build could send a discriminant this one has no name
        // for. Reading it as Ready would report an unknown state as healthy;
        // Pending is the fail-closed reading, and it must not error out the
        // stream over a diagnostic field.
        let dto = p::HealthReport {
            version: "9.9.9".to_owned(),
            subsystems: vec![p::SubsystemHealth {
                name: "proxy".to_owned(),
                checks: vec![p::CheckHealth {
                    name: "from_the_future".to_owned(),
                    state: 99,
                    reason: String::new(),
                }],
            }],
            reported_at_unix: 0,
        };
        let decoded = health_from_wire(&dto);
        assert_eq!(
            decoded.snapshot.subsystems["proxy"].checks["from_the_future"],
            CheckState::Pending
        );
    }

    #[test]
    fn an_empty_report_decodes_to_an_empty_tree_not_a_failure() {
        // What a pre-#677 peer's absent field looks like once the caller has
        // decided to decode a default-constructed report.
        let decoded = health_from_wire(&p::HealthReport::default());
        assert!(decoded.snapshot.subsystems.is_empty());
        assert!(decoded.version.is_empty());
    }

    #[test]
    fn a_negative_wire_timestamp_clamps_to_the_epoch() {
        // Diagnostic field: a broken clock must not panic the decode path.
        let dto = p::HealthReport {
            reported_at_unix: -1,
            ..p::HealthReport::default()
        };
        assert_eq!(health_from_wire(&dto).reported_at, UNIX_EPOCH);
    }
}
