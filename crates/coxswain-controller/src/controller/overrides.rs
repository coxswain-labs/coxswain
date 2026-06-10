//! Cross-task overrides for the leader-elected Gateway condition writer.
//!
//! The provisioning operator (see [`crate::operator`]) needs to surface
//! conditions back onto `Gateway.status` — e.g. `Accepted=False,
//! reason=InvalidParameters` when a `parametersRef` target is missing
//! (#208) — but the status writer in [`crate::controller`] is the only
//! place that's allowed to patch `Gateway/status`. This module exposes a
//! shared map both tasks can read/write to coordinate.
//!
//! ## Concurrency
//!
//! Backed by `std::sync::Mutex` rather than `tokio::sync::Mutex`. Every
//! operation is a single hash-map insert/remove/lookup; the lock guard is
//! never held across an `.await`, matching the workspace rule against
//! holding locks across suspension points (CLAUDE.md "Hot path").
//!
//! The contained `HashMap` is bounded by the number of dedicated-mode
//! Gateways in the cluster (a handful by design), so contention is
//! negligible. A more elaborate `watch`/`mpsc` channel would buy nothing
//! over a shared map here.

use coxswain_core::ownership::ObjectKey;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Reason the operator wants the status writer to emit for `Accepted=False`
/// on a given Gateway.
///
/// Extensible — more Gateway-API condition reasons may land here as later
/// steps surface them (see the architecture-plan Step 12 for the full
/// dedicated-mode condition matrix).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptedReason {
    /// `parametersRef` resolves to a missing `CoxswainGatewayParameters`
    /// object. Mapped to `Accepted=False, reason=InvalidParameters` per
    /// Gateway API.
    InvalidParameters,
}

impl AcceptedReason {
    /// Gateway API spec reason string for this override.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::InvalidParameters => "InvalidParameters",
        }
    }

    /// Human-readable message attached to the condition.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidParameters => {
                "parametersRef target CoxswainGatewayParameters object does not exist"
            }
        }
    }
}

/// Shared `Gateway` → `AcceptedReason` map.
///
/// Cloneable: every clone shares the same underlying `Arc<Mutex<…>>`. The
/// operator and the status writer each hold a clone and the bin layer
/// constructs the singleton at startup.
#[derive(Debug, Clone, Default)]
pub struct AcceptedOverrides {
    inner: Arc<Mutex<HashMap<ObjectKey, AcceptedReason>>>,
}

impl AcceptedOverrides {
    /// Construct an empty overrides map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an override for a Gateway. Replaces any prior entry.
    pub fn set(&self, key: ObjectKey, reason: AcceptedReason) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| {
            panic!("invariant: AcceptedOverrides mutex must not be poisoned: {e}")
        });
        guard.insert(key, reason);
    }

    /// Remove the override for a Gateway. No-op if no override was set.
    pub fn clear(&self, key: &ObjectKey) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| {
            panic!("invariant: AcceptedOverrides mutex must not be poisoned: {e}")
        });
        guard.remove(key);
    }

    /// Look up the override for a Gateway, if any.
    #[must_use]
    pub fn get(&self, key: &ObjectKey) -> Option<AcceptedReason> {
        let guard = self.inner.lock().unwrap_or_else(|e| {
            panic!("invariant: AcceptedOverrides mutex must not be poisoned: {e}")
        });
        guard.get(key).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(ns: &str, name: &str) -> ObjectKey {
        ObjectKey::new(ns.to_string(), name.to_string())
    }

    #[test]
    fn set_get_roundtrip() {
        let o = AcceptedOverrides::new();
        o.set(k("ns", "gw"), AcceptedReason::InvalidParameters);
        assert_eq!(
            o.get(&k("ns", "gw")),
            Some(AcceptedReason::InvalidParameters)
        );
    }

    #[test]
    fn clear_removes() {
        let o = AcceptedOverrides::new();
        o.set(k("ns", "gw"), AcceptedReason::InvalidParameters);
        o.clear(&k("ns", "gw"));
        assert_eq!(o.get(&k("ns", "gw")), None);
    }

    #[test]
    fn clones_share_state() {
        let a = AcceptedOverrides::new();
        let b = a.clone();
        a.set(k("ns", "gw"), AcceptedReason::InvalidParameters);
        assert_eq!(
            b.get(&k("ns", "gw")),
            Some(AcceptedReason::InvalidParameters)
        );
    }

    #[test]
    fn reason_strings_match_spec() {
        assert_eq!(
            AcceptedReason::InvalidParameters.reason(),
            "InvalidParameters"
        );
    }
}
