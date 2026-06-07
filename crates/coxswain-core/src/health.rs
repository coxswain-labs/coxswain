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
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

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
        let mut checks = self
            .inner
            .checks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let mut subsystems = self
            .subsystems
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            name: name_arc.clone(),
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
        let subsystems = self
            .subsystems
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let subsystems = self
            .subsystems
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let subsystems = self
            .subsystems
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut map = BTreeMap::new();
        for (name, inner) in subsystems.iter() {
            let checks = inner
                .checks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
