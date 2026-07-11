//! Subsystem health registry: per-subsystem named checks with aggregate state.
//!
//! The registry is the single source of truth for `/readyz` (aggregate boolean)
//! and `/status` (per-subsystem detail). Each subsystem registers a fixed set of
//! named checks at startup and receives a [`SubsystemHandle`] for posting check
//! transitions. The registry computes a per-subsystem aggregate and a registry-wide
//! readiness boolean from those checks.
//!
//! State precedence (highest wins): `Failed > Degraded > Pending > Ready`. The
//! registry is "ready" iff every subsystem is `Ready` or `Degraded` — `Degraded`
//! keeps `/readyz` at 200 because the data plane is still functional.

use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use parking_lot::Mutex;

const SEV_READY: u8 = 0;
const SEV_PENDING: u8 = 1;
const SEV_DEGRADED: u8 = 2;
const SEV_FAILED: u8 = 3;

/// State of a single named health check.
///
/// `Pending` is the initial value, before any reporter has run the check. The
/// reason carried by `Degraded` and `Failed` is human-readable and not stable
/// for machine parsing.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckState {
    /// The check has not yet been reported.
    Pending,
    /// The check passed.
    Ready,
    /// The check is degraded; the subsystem is still functional.
    Degraded {
        /// Human-readable explanation of the degradation.
        reason: Arc<str>,
    },
    /// The check failed; the subsystem is not functional.
    Failed {
        /// Human-readable explanation of the failure.
        reason: Arc<str>,
    },
}

impl CheckState {
    /// Severity rank: `Failed=3 > Degraded=2 > Pending=1 > Ready=0`.
    ///
    /// Used to compute subsystem aggregates and pack the per-subsystem cached
    /// severity into an `AtomicU8` for lock-free `/readyz` reads.
    #[must_use]
    pub fn severity(&self) -> u8 {
        match self {
            CheckState::Ready => SEV_READY,
            CheckState::Pending => SEV_PENDING,
            CheckState::Degraded { .. } => SEV_DEGRADED,
            CheckState::Failed { .. } => SEV_FAILED,
        }
    }

    /// True iff the state is [`CheckState::Ready`] or [`CheckState::Degraded`].
    ///
    /// `Degraded` keeps `/readyz` at 200: a degraded data plane is still
    /// serving traffic, and removing the pod from kubelet endpoints would
    /// be more disruptive than the degradation itself.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, CheckState::Ready | CheckState::Degraded { .. })
    }
}

impl Serialize for CheckState {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let (state, reason) = match self {
            CheckState::Pending => ("pending", None),
            CheckState::Ready => ("ready", None),
            CheckState::Degraded { reason } => ("degraded", Some(reason.as_ref())),
            CheckState::Failed { reason } => ("failed", Some(reason.as_ref())),
        };
        let len = if reason.is_some() { 2 } else { 1 };
        let mut s = ser.serialize_struct("CheckState", len)?;
        s.serialize_field("state", state)?;
        if let Some(r) = reason {
            s.serialize_field("reason", r)?;
        }
        s.end()
    }
}

/// Snapshot of one subsystem: its aggregate state plus per-check detail.
///
/// `state` is derived from `checks` — it is always the highest-severity entry
/// in the map, preserving the reason if the worst check is `Degraded` or
/// `Failed`. An empty subsystem has aggregate `Ready`.
#[non_exhaustive]
#[derive(Clone, Debug, Serialize)]
pub struct SubsystemSnapshot {
    /// Aggregate state of this subsystem (highest-severity check).
    pub state: CheckState,
    /// Per-check detail keyed by check name.
    pub checks: BTreeMap<Arc<str>, CheckState>,
}

/// Snapshot of every registered subsystem, suitable for `/status` output.
///
/// Iteration order is stable (`BTreeMap`) so the JSON output is reproducible.
#[non_exhaustive]
#[derive(Clone, Debug, Serialize)]
pub struct HealthSnapshot {
    /// Per-subsystem snapshot keyed by subsystem name.
    pub subsystems: BTreeMap<Arc<str>, SubsystemSnapshot>,
}

struct SubsystemInner {
    name: Arc<str>,
    checks: Mutex<BTreeMap<Arc<str>, CheckState>>,
    /// Cached aggregate severity for lock-free readiness checks.
    aggregate_severity: AtomicU8,
}

/// Update handle for a single subsystem.
///
/// Cloneable: multiple reporters can hold a handle to the same subsystem and
/// flip different named checks concurrently. The handle does not provide
/// methods to register new checks — the set of check names is fixed at
/// [`HealthRegistry::register`] time so that misspelled names panic instead
/// of silently creating a check that never flips.
#[non_exhaustive]
#[derive(Clone)]
pub struct SubsystemHandle {
    inner: Arc<SubsystemInner>,
}

impl SubsystemHandle {
    /// Set `check` to `state`, panicking if `check` was not registered.
    ///
    /// # Panics
    ///
    /// Panics if `check` was not declared in the [`HealthRegistry::register`]
    /// call that produced this handle. Check names are fixed at registration
    /// time; transitions to unknown checks are programming errors.
    pub fn set(&self, check: &str, state: CheckState) {
        let mut checks = self.inner.checks.lock();
        let slot = checks.get_mut(check).unwrap_or_else(|| {
            panic!(
                "invariant: check {check:?} not registered on subsystem {:?}",
                self.inner.name
            )
        });
        *slot = state;
        let max = checks
            .values()
            .map(CheckState::severity)
            .max()
            .unwrap_or(SEV_READY);
        self.inner.aggregate_severity.store(max, Ordering::Release);
    }

    /// Mark `check` as [`CheckState::Ready`].
    ///
    /// # Panics
    ///
    /// Panics if `check` was not registered on this subsystem.
    pub fn ready(&self, check: &str) {
        self.set(check, CheckState::Ready);
    }

    /// Mark `check` as [`CheckState::Degraded`] with `reason`.
    ///
    /// # Panics
    ///
    /// Panics if `check` was not registered on this subsystem.
    pub fn degraded(&self, check: &str, reason: impl Into<Arc<str>>) {
        self.set(
            check,
            CheckState::Degraded {
                reason: reason.into(),
            },
        );
    }

    /// Mark `check` as [`CheckState::Failed`] with `reason`.
    ///
    /// # Panics
    ///
    /// Panics if `check` was not registered on this subsystem.
    pub fn failed(&self, check: &str, reason: impl Into<Arc<str>>) {
        self.set(
            check,
            CheckState::Failed {
                reason: reason.into(),
            },
        );
    }
}

/// Registry of subsystem health, shared between updaters and readers.
///
/// Cheap to clone (`Arc`-backed). Construct with [`HealthRegistry::new`] in
/// the binary, register each subsystem at startup, hand the resulting
/// [`SubsystemHandle`]s to the subsystem owners, and share clones of the
/// registry itself with the `/readyz` and `/status` HTTP handlers.
#[non_exhaustive]
#[derive(Clone)]
pub struct HealthRegistry {
    subsystems: Arc<Mutex<BTreeMap<Arc<str>, Arc<SubsystemInner>>>>,
}

impl HealthRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            subsystems: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Register a subsystem with a fixed set of check names.
    ///
    /// Returns a [`SubsystemHandle`] for posting check transitions. Every
    /// check starts at [`CheckState::Pending`], so the subsystem's aggregate
    /// is `Pending` (and the registry is not ready) until the subsystem
    /// reports each check.
    ///
    /// Duplicate names within `checks` are silently deduplicated (a single
    /// entry survives) since the underlying `BTreeMap` enforces uniqueness.
    ///
    /// # Panics
    ///
    /// Panics if a subsystem with `name` is already registered. Registrations
    /// happen at startup from a single call site; duplicates are programming
    /// errors.
    #[must_use]
    pub fn register(&self, name: &str, checks: &[&str]) -> SubsystemHandle {
        let mut subsystems = self.subsystems.lock();
        let name_arc: Arc<str> = Arc::from(name);
        if subsystems.contains_key(&name_arc) {
            panic!("invariant: subsystem {name:?} already registered");
        }
        let mut check_map: BTreeMap<Arc<str>, CheckState> = BTreeMap::new();
        for check in checks {
            check_map.insert(Arc::from(*check), CheckState::Pending);
        }
        let initial_severity = if check_map.is_empty() {
            SEV_READY
        } else {
            SEV_PENDING
        };
        let inner = Arc::new(SubsystemInner {
            name: Arc::clone(&name_arc),
            checks: Mutex::new(check_map),
            aggregate_severity: AtomicU8::new(initial_severity),
        });
        subsystems.insert(name_arc, Arc::clone(&inner));
        SubsystemHandle { inner }
    }

    /// True iff every registered subsystem is `Ready` or `Degraded`.
    ///
    /// Reads the cached `AtomicU8` per subsystem — no per-check walk. Cheap
    /// enough to call on every `/readyz` probe.
    ///
    /// An empty registry (no subsystems registered) returns `true`; callers
    /// that want a stricter answer should check [`Self::is_subsystem_ready`]
    /// for a specific subsystem.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        let subsystems = self.subsystems.lock();
        subsystems
            .values()
            .all(|s| severity_is_ready(s.aggregate_severity.load(Ordering::Acquire)))
    }

    /// True iff the named subsystem is registered and `Ready`/`Degraded`.
    ///
    /// Returns `false` if no subsystem with `name` was registered — callers
    /// asking about a specific subsystem usually want to fail closed on
    /// typos.
    #[must_use]
    pub fn is_subsystem_ready(&self, name: &str) -> bool {
        let subsystems = self.subsystems.lock();
        subsystems
            .get(name)
            .is_some_and(|s| severity_is_ready(s.aggregate_severity.load(Ordering::Acquire)))
    }

    /// Build a full [`HealthSnapshot`] for `/status` output.
    ///
    /// Walks every subsystem and clones its per-check map under each
    /// subsystem's lock. Intended for human/diagnostic consumption, not the
    /// hot path — call [`Self::is_ready`] when you only need the boolean.
    #[must_use]
    pub fn snapshot(&self) -> HealthSnapshot {
        let subsystems = self.subsystems.lock();
        let mut map = BTreeMap::new();
        for (name, inner) in subsystems.iter() {
            let checks = inner.checks.lock();
            let state = checks
                .values()
                .max_by_key(|c| c.severity())
                .cloned()
                .unwrap_or(CheckState::Ready);
            map.insert(
                Arc::clone(name),
                SubsystemSnapshot {
                    state,
                    checks: checks.clone(),
                },
            );
        }
        HealthSnapshot { subsystems: map }
    }
}

impl Default for HealthRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn severity_is_ready(sev: u8) -> bool {
    sev == SEV_READY || sev == SEV_DEGRADED
}

/// Process-liveness backstop consulted by the `/healthz` liveness probe.
///
/// Distinct from [`HealthRegistry`], which gates *readiness* (`/readyz`): a
/// subsystem going `Failed`/`Pending` removes the pod from endpoints but does
/// not restart it. `LivenessGate` is the stronger, one-way signal for faults
/// that only a pod restart can clear.
///
/// It exists for the #573 relist wedge: a reflector whose watch relist never
/// completes leaves the controller serving a stale/empty world while every
/// readiness check still passes (the lease renews, reconciles tick). The
/// primary fix makes that wedge unreachable; this gate is the defense-in-depth
/// backstop — a monitor trips it after a relist stays incomplete past a bounded
/// window, failing `/healthz` so kubelet restarts the pod and its reflectors
/// relist from scratch.
///
/// Tripping is intentionally irreversible: the process cannot self-repair a
/// wedged watch fabric in place, so the gate stays down until the restart
/// replaces the process.
#[non_exhaustive]
#[derive(Clone)]
pub struct LivenessGate {
    alive: Arc<AtomicBool>,
}

impl LivenessGate {
    /// Construct a gate in the live state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            alive: Arc::new(AtomicBool::new(true)),
        }
    }

    /// True while the process is considered live. `/healthz` returns 200 iff
    /// this holds.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Irreversibly trip the gate. Subsequent [`Self::is_alive`] calls return
    /// `false`, so `/healthz` reports unhealthy and kubelet restarts the pod.
    pub fn trip(&self) {
        self.alive.store(false, Ordering::Release);
    }
}

impl Default for LivenessGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use crate::health::{CheckState, HealthRegistry, LivenessGate};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    #[test]
    fn liveness_gate_starts_alive_and_trips_irreversibly() {
        let gate = LivenessGate::new();
        assert!(gate.is_alive(), "a fresh gate is live");
        // A clone shares the same underlying flag.
        let clone = gate.clone();
        gate.trip();
        assert!(!gate.is_alive(), "tripping fails the gate");
        assert!(
            !clone.is_alive(),
            "clones observe the trip (shared flag), so /healthz sees it regardless of which handle tripped"
        );
        // Trip is one-way: no path back to alive.
        clone.trip();
        assert!(!clone.is_alive());
    }

    fn degraded(reason: &str) -> CheckState {
        CheckState::Degraded {
            reason: Arc::from(reason),
        }
    }

    fn failed(reason: &str) -> CheckState {
        CheckState::Failed {
            reason: Arc::from(reason),
        }
    }

    #[test]
    fn severity_order_is_failed_degraded_pending_ready() {
        assert_eq!(CheckState::Ready.severity(), 0);
        assert_eq!(CheckState::Pending.severity(), 1);
        assert_eq!(degraded("x").severity(), 2);
        assert_eq!(failed("x").severity(), 3);
    }

    #[test]
    fn check_is_ready_only_for_ready_and_degraded() {
        assert!(CheckState::Ready.is_ready());
        assert!(degraded("warming up").is_ready());
        assert!(!CheckState::Pending.is_ready());
        assert!(!failed("blown").is_ready());
    }

    #[test]
    fn fresh_subsystem_aggregate_is_pending_until_every_check_reports() {
        let reg = HealthRegistry::new();
        let sub = reg.register("controller", &["httproute", "ingress"]);

        assert!(!reg.is_ready(), "fresh registry must not be ready");
        assert!(!reg.is_subsystem_ready("controller"));

        sub.ready("httproute");
        assert!(!reg.is_ready(), "still Pending on the ingress check");

        sub.ready("ingress");
        assert!(reg.is_ready(), "all checks Ready → registry ready");
        assert!(reg.is_subsystem_ready("controller"));
    }

    #[test]
    fn empty_subsystem_is_immediately_ready() {
        let reg = HealthRegistry::new();
        let _empty = reg.register("proxy", &[]);
        assert!(reg.is_ready());
        assert!(reg.is_subsystem_ready("proxy"));
    }

    #[test]
    fn empty_registry_is_ready() {
        let reg = HealthRegistry::new();
        assert!(reg.is_ready());
    }

    #[test]
    fn unknown_subsystem_is_not_ready() {
        let reg = HealthRegistry::new();
        assert!(
            !reg.is_subsystem_ready("missing"),
            "unknown subsystem must fail closed",
        );
    }

    #[test]
    fn degraded_keeps_readyz_at_ready_but_pending_and_failed_do_not() {
        let reg = HealthRegistry::new();
        let sub = reg.register("controller", &["a", "b"]);
        sub.ready("a");
        sub.degraded("b", "warming up");
        assert!(reg.is_ready(), "Degraded must not flip /readyz to 503");

        sub.set("b", CheckState::Pending);
        assert!(!reg.is_ready(), "Pending must flip /readyz to 503");

        sub.failed("b", "blown");
        assert!(!reg.is_ready(), "Failed must flip /readyz to 503");
    }

    #[test]
    fn registry_is_ready_only_if_every_subsystem_is_ready() {
        let reg = HealthRegistry::new();
        let controller = reg.register("controller", &["a"]);
        let proxy = reg.register("proxy", &["b"]);

        controller.ready("a");
        assert!(!reg.is_ready(), "proxy still Pending");

        proxy.ready("b");
        assert!(reg.is_ready(), "both subsystems Ready");

        controller.failed("a", "boom");
        assert!(!reg.is_ready(), "one Failed propagates to registry");
    }

    #[test]
    fn snapshot_picks_highest_severity_as_aggregate_with_reason() {
        let reg = HealthRegistry::new();
        let sub = reg.register("controller", &["a", "b", "c"]);
        sub.ready("a");
        sub.degraded("b", "warming up");
        sub.failed("c", "cert expired");

        let snap = reg.snapshot();
        let controller = snap
            .subsystems
            .get("controller")
            .expect("controller subsystem must be present");

        // Aggregate state is the highest-severity check, including its reason.
        match &controller.state {
            CheckState::Failed { reason } => assert_eq!(reason.as_ref(), "cert expired"),
            other => panic!("expected Failed aggregate, got {other:?}"),
        }
        assert_eq!(controller.checks.len(), 3);
    }

    #[test]
    fn snapshot_iteration_order_is_stable_btreemap() {
        let reg = HealthRegistry::new();
        let _z = reg.register("zeta", &["c", "a", "b"]);
        let _a = reg.register("alpha", &["b", "a"]);

        let snap = reg.snapshot();
        let subsys: Vec<&str> = snap.subsystems.keys().map(|k| k.as_ref()).collect();
        assert_eq!(subsys, vec!["alpha", "zeta"]);

        let alpha_checks: Vec<&str> = snap.subsystems["alpha"]
            .checks
            .keys()
            .map(|k| k.as_ref())
            .collect();
        assert_eq!(alpha_checks, vec!["a", "b"]);
    }

    #[test]
    fn set_under_concurrent_writers_converges_to_highest_severity() {
        let reg = HealthRegistry::new();
        let sub = reg.register("controller", &["a", "b", "c", "d"]);

        let started = Arc::new(AtomicUsize::new(0));
        let writers: Vec<_> = ["a", "b", "c", "d"]
            .into_iter()
            .map(|name| {
                let h = sub.clone();
                let started = Arc::clone(&started);
                thread::spawn(move || {
                    started.fetch_add(1, Ordering::Relaxed);
                    for _ in 0..200 {
                        h.ready(name);
                        h.degraded(name, "warming");
                    }
                    h.failed(name, "final");
                })
            })
            .collect();
        for w in writers {
            w.join().expect("writer thread panicked");
        }

        let snap = reg.snapshot();
        let controller = &snap.subsystems["controller"];
        assert!(matches!(controller.state, CheckState::Failed { .. }));
        for state in controller.checks.values() {
            assert!(matches!(state, CheckState::Failed { .. }));
        }
        assert!(!reg.is_ready());
    }

    #[test]
    #[should_panic(expected = "not registered")]
    fn set_on_unregistered_check_panics() {
        let reg = HealthRegistry::new();
        let sub = reg.register("controller", &["only_this_one"]);
        sub.ready("typo");
    }

    #[test]
    #[should_panic(expected = "already registered")]
    fn duplicate_subsystem_registration_panics() {
        let reg = HealthRegistry::new();
        let _a = reg.register("controller", &["a"]);
        let _b = reg.register("controller", &["b"]);
    }

    #[test]
    fn check_state_serialize_shape_is_stable() {
        let ready = serde_json::to_value(CheckState::Ready).unwrap();
        assert_eq!(ready, serde_json::json!({ "state": "ready" }));

        let pending = serde_json::to_value(CheckState::Pending).unwrap();
        assert_eq!(pending, serde_json::json!({ "state": "pending" }));

        let degraded = serde_json::to_value(degraded("warming up")).unwrap();
        assert_eq!(
            degraded,
            serde_json::json!({ "state": "degraded", "reason": "warming up" })
        );

        let failed = serde_json::to_value(failed("blown")).unwrap();
        assert_eq!(
            failed,
            serde_json::json!({ "state": "failed", "reason": "blown" })
        );
    }

    #[test]
    fn snapshot_serializes_to_documented_status_shape() {
        let reg = HealthRegistry::new();
        let controller = reg.register("controller", &["httproute", "ingress"]);
        let proxy = reg.register("proxy", &["routing_table_loaded"]);
        controller.ready("httproute");
        controller.ready("ingress");
        proxy.ready("routing_table_loaded");

        let snap = reg.snapshot();
        let json = serde_json::to_value(&snap).unwrap();
        let expected = serde_json::json!({
            "subsystems": {
                "controller": {
                    "state":  { "state": "ready" },
                    "checks": {
                        "httproute": { "state": "ready" },
                        "ingress":   { "state": "ready" },
                    },
                },
                "proxy": {
                    "state":  { "state": "ready" },
                    "checks": {
                        "routing_table_loaded": { "state": "ready" },
                    },
                },
            }
        });
        assert_eq!(json, expected);
    }
}
