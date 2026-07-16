//! Pure control-loop logic for the dedicated relay tier (#602).
//!
//! The controller re-implements the standard autoscaler loop (HPA sizing + KEDA
//! activation/cooldown) internally, driven by the namespace's **live
//! dedicated-proxy subscriber count** rather than CPU — see
//! [`super::relay_reconcile`] for the I/O loop that feeds this module and acts on
//! its decisions. Everything here is pure and side-effect-free so the transitions
//! are unit-testable without a cluster or a clock: the caller passes `now`.
//!
//! ## Two axes
//!
//! - **On/off (0↔1), KEDA-style:** a relay is provisioned once the signal reaches
//!   the break-even activation threshold `H` (`--relay-min-proxy-replicas`) and
//!   torn down after the signal holds below `H` for the cooldown. A namespace that
//!   genuinely drained (no dedicated Gateways left) tears down immediately; a
//!   transient 0 live subscribers while Gateways remain (relay restart / reconnect)
//!   waits out the cooldown. This replaces the old keep-until-fully-drained hysteresis.
//! - **Sizing (1→N), HPA-style:** an *autoscaled* relay (a `RelayAutoscaling`
//!   with a `maxReplicas` cap) is sized `clamp(ceil(signal / target), min, max)`,
//!   damped by a relative tolerance deadband (ignore usage within ±tolerance of
//!   the target) and an asymmetric scale-down stabilization window (scale up on
//!   the instantaneous signal, scale down only on the trailing-window maximum).
//!   A static relay keeps its fixed `--relay-replicas` count.
//!
//! ## Make-before-break lifecycle
//!
//! [`RelayNsState`] is the level-triggered state machine the reconciler advances.
//! `Provisioning` and `Draining` exist so a relay is authorized to subscribe
//! upstream (and thus can become Ready) *before* leaves repoint onto it, and so
//! leaves repoint *away* before the relay is deleted — the two sets the reconciler
//! derives from this state (`provisioned_relays` for authz, the repoint set for
//! leaves) can therefore diverge in timing without ever pointing a proxy at a
//! not-yet-serving or already-deleted relay.

use std::time::{Duration, Instant};

use coxswain_core::crd::RelayAutoscaling;

use super::relay_params::EffectiveRelayPolicy;

/// Lifecycle state of one namespace's relay in the control loop (#602).
///
/// A namespace with no relay is simply absent from the reconciler's state map;
/// the three variants here are the states in which a relay Deployment exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RelayNsState {
    /// Relay Deployment applied and authorized to subscribe upstream; awaiting
    /// its own registry entry to report Ready (upstream cache loaded). Leaves are
    /// **not** yet repointed onto it.
    Provisioning,
    /// Relay is Ready and serving; leaves are repointed onto it.
    Active,
    /// Teardown decided; leaves have been repointed back to the controller;
    /// awaiting the relay's downstream subscriber count to reach 0 before the
    /// Deployment is deleted.
    Draining,
}

/// The I/O the reconciler must perform for a namespace this pass, decided purely
/// from the current [`RelayNsRecord`] and the live registry inputs (#602).
///
/// The reconciler commits the record's `next_state`/replica count **after** the
/// I/O succeeds, so a failed apply/delete is simply retried on the next tick with
/// the record unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RelayAction {
    /// Nothing to do this pass.
    None,
    /// The relay reported Ready: add the namespace to the repoint set (leaves cut
    /// over) and enter `Active`. Re-entered from `Draining` when demand returns
    /// before the relay was deleted (no apply needed — it is still running).
    Activate,
    /// Resize an already-`Active` relay to `replicas` (SSA).
    Resize { replicas: u32, pdb_ceiling: u32 },
    /// Begin teardown: remove the namespace from the repoint set (leaves reconnect
    /// their control stream to the controller, still serving) and enter `Draining`.
    StartDrain,
    /// Drain complete (0 downstream subscribers): delete the relay resources,
    /// remove the namespace from the authz set, and drop the record.
    Delete,
}

/// Effective, namespace-resolved control-loop tuning (#602): the per-namespace
/// `RelayAutoscaling` overrides layered over the `--relay-*` flag defaults.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct RelayTuning {
    /// Break-even activation threshold `H` (`--relay-min-proxy-replicas`), clamped
    /// ≥ 1. A relay is provisioned once the live signal reaches this.
    pub(super) activation_threshold: u32,
    /// Deactivation cooldown: the signal must hold below `H` this long before an
    /// `Active` relay tears down (a genuinely drained namespace — no dedicated
    /// Gateways — bypasses it and tears down at once).
    pub(super) cooldown: Duration,
    /// Scale-down stabilization window: scale-down sizes on the maximum signal
    /// over this trailing window (scale-up is not damped).
    pub(super) stabilization: Duration,
    /// Relative sizing deadband: hold the replica count while the usage ratio is
    /// within ±this of 1.0.
    pub(super) tolerance: f64,
    /// Target downstream proxies per relay replica (the capacity ratio), clamped ≥ 1.
    pub(super) target: u32,
    /// Static replica count for a non-autoscaled relay (policy `replicas` or
    /// `--relay-replicas`), clamped ≥ 1.
    pub(super) static_replicas: u32,
    /// Per-namespace autoscaling policy, when one caps the relay (`enabled` and a
    /// set `maxReplicas`); `None` leaves the relay statically sized.
    pub(super) autoscaling: Option<RelayAutoscaling>,
    /// `CoxswainRelayPolicy.spec.enabled` tri-state: `Some(true)` force-on
    /// (activation threshold drops to 1), `Some(false)` force-off (never
    /// provisioned; existing relay torn down), `None` automatic.
    pub(super) enabled_override: Option<bool>,
}

/// Flag-derived defaults the [`RelayTuning`] falls back to when a namespace has no
/// `CoxswainRelayPolicy` override (#602). Sourced from the controller's `--relay-*`
/// flags; see [`super::reconciler::ReconcileContext`].
#[derive(Clone, Copy, Debug)]
pub(super) struct RelayTuningDefaults {
    pub(super) activation_threshold: u32,
    pub(super) cooldown: Duration,
    pub(super) stabilization: Duration,
    pub(super) tolerance: f64,
    pub(super) target: u32,
    pub(super) static_replicas: u32,
}

impl RelayTuning {
    /// Resolve the effective tuning for a namespace: `RelayAutoscaling` overrides
    /// (when present) layered over the flag `defaults` (#602).
    pub(super) fn resolve(policy: &EffectiveRelayPolicy, defaults: RelayTuningDefaults) -> Self {
        let autoscaling = policy
            .autoscaling
            .clone()
            .filter(|a| a.enabled && a.max_replicas.is_some());
        let overrides = policy.autoscaling.as_ref();
        Self {
            activation_threshold: defaults.activation_threshold.max(1),
            cooldown: overrides
                .and_then(|a| a.cooldown_seconds)
                .map_or(defaults.cooldown, |s| Duration::from_secs(u64::from(s))),
            stabilization: overrides
                .and_then(|a| a.scale_down_stabilization_seconds)
                .map_or(defaults.stabilization, |s| {
                    Duration::from_secs(u64::from(s))
                }),
            // `.max(0.0)` also normalizes a NaN default (from a garbage
            // `--relay-tolerance`) to 0.0 — `f64::max` returns the non-NaN operand.
            tolerance: overrides
                .and_then(|a| a.tolerance)
                .filter(|t| *t >= 0.0)
                .unwrap_or(defaults.tolerance)
                .max(0.0),
            target: overrides
                .and_then(|a| a.target_proxies_per_replica)
                .unwrap_or(defaults.target)
                .max(1),
            static_replicas: policy.replicas.unwrap_or(defaults.static_replicas).max(1),
            autoscaling,
            enabled_override: policy.enabled,
        }
    }
}

/// Live registry inputs for one namespace this pass (#602).
#[derive(Clone, Copy, Debug)]
pub(super) struct RelayInputs {
    /// Live dedicated-proxy subscriber count in the namespace (the signal).
    pub(super) signal: u32,
    /// Whether the relay has loaded its upstream cache (make-before-break
    /// provision gate). Meaningful only in `Provisioning`/`Draining`.
    pub(super) ready: bool,
    /// Downstream subscribers still folded behind the relay (drain gate).
    pub(super) subscribers: u32,
    /// Whether the namespace still holds ≥1 owned active dedicated Gateway (a
    /// spec-level fact, stable across proxy churn). Distinguishes a namespace that
    /// genuinely drained (no Gateways → tear down at once) from one whose live
    /// subscriber count merely blipped to 0 (relay restart / control-stream
    /// reconnect) while its Gateways remain (→ hold, cooldown applies). Without this
    /// a transient 0 would delete a relay mid-restart.
    pub(super) has_dedicated_gateways: bool,
}

/// Per-namespace control-loop record the reconciler holds across passes (#602).
///
/// Carries the make-before-break [`RelayNsState`], the last-applied replica count
/// (the HPA sizing baseline), the trailing signal history (for scale-down
/// stabilization), and the instant the signal first dropped below `H` (for the
/// deactivation cooldown).
#[derive(Clone, Debug)]
pub(super) struct RelayNsRecord {
    /// Current lifecycle state.
    pub(super) state: RelayNsState,
    /// Replica count last applied to the Deployment — the sizing baseline.
    pub(super) current_replicas: u32,
    /// Trailing `(instant, signal)` samples within the stabilization window.
    history: Vec<(Instant, u32)>,
    /// Instant the signal first fell below `H`, or `None` while at/above it.
    below_since: Option<Instant>,
}

impl RelayNsRecord {
    /// A record for a namespace whose relay already exists at `replicas` and is
    /// treated as `state` (used on rehydration: a running relay is `Active`).
    pub(super) fn existing(state: RelayNsState, replicas: u32) -> Self {
        Self {
            state,
            current_replicas: replicas.max(1),
            history: Vec::new(),
            below_since: None,
        }
    }

    /// Record this pass's `signal` observation: prune history to the
    /// stabilization window, then track the below-`H` cooldown clock. Always
    /// called before [`Self::decide`]; observations advance regardless of the I/O
    /// outcome.
    pub(super) fn observe(&mut self, now: Instant, signal: u32, tuning: &RelayTuning) {
        self.history.push((now, signal));
        let window = tuning.stabilization;
        self.history
            .retain(|(t, _)| now.duration_since(*t) <= window);
        if signal >= tuning.activation_threshold {
            self.below_since = None;
        } else if self.below_since.is_none() {
            self.below_since = Some(now);
        }
    }

    /// Maximum signal over the retained stabilization window (≥ the latest
    /// sample, which [`Self::observe`] just pushed).
    fn stabilized_signal(&self) -> u32 {
        self.history.iter().map(|(_, s)| *s).max().unwrap_or(0)
    }

    /// Whether an existing relay should tear down. Force-off is immediate; a
    /// genuinely drained namespace (no dedicated Gateways left) is immediate;
    /// otherwise the signal must have held below `H` for the whole cooldown.
    ///
    /// Crucially this keys the immediate path on `has_dedicated_gateways` (a stable
    /// spec fact), NOT on `signal == 0`: a relay restart or control-stream reconnect
    /// blips the live subscriber count to 0 while the Gateways remain, and deleting
    /// the relay on that transient would drop it mid-restart. Such a blip instead
    /// waits out the cooldown, by which time the leaves have reconnected.
    fn should_deactivate(
        &self,
        now: Instant,
        signal: u32,
        has_dedicated_gateways: bool,
        tuning: &RelayTuning,
    ) -> bool {
        if tuning.enabled_override == Some(false) {
            return true;
        }
        if !has_dedicated_gateways {
            return true;
        }
        if tuning.enabled_override == Some(true) {
            // Force-on: kept alive as long as any Gateway remains (handled above).
            return false;
        }
        if signal >= tuning.activation_threshold {
            return false;
        }
        self.below_since
            .is_some_and(|since| now.duration_since(since) >= tuning.cooldown)
    }

    /// Whether a namespace with no relay should provision one now.
    fn should_activate(signal: u32, tuning: &RelayTuning) -> bool {
        match tuning.enabled_override {
            Some(false) => false,
            // Force-on: any active demand provisions immediately.
            Some(true) => signal >= 1,
            None => signal >= tuning.activation_threshold,
        }
    }

    /// Decide this pass's action and the state to commit on success — pure over
    /// the record and live `inputs` (#602). Call [`Self::observe`] first.
    pub(super) fn decide(
        &self,
        now: Instant,
        inputs: RelayInputs,
        tuning: &RelayTuning,
    ) -> Decision {
        let signal = inputs.signal;
        match self.state {
            RelayNsState::Provisioning => {
                if self.should_deactivate(now, signal, inputs.has_dedicated_gateways, tuning) {
                    // Demand evaporated (or force-off) before the relay ever served
                    // a leaf: no repoint happened, so tear it down directly.
                    Decision::delete()
                } else if inputs.ready {
                    Decision::new(RelayNsState::Active, RelayAction::Activate)
                } else {
                    Decision::hold(RelayNsState::Provisioning)
                }
            }
            RelayNsState::Active => {
                if self.should_deactivate(now, signal, inputs.has_dedicated_gateways, tuning) {
                    Decision::new(RelayNsState::Draining, RelayAction::StartDrain)
                } else {
                    let (replicas, pdb_ceiling) = self.autoscaled_size(tuning);
                    if replicas == self.current_replicas {
                        Decision::hold(RelayNsState::Active)
                    } else {
                        Decision {
                            next_state: RelayNsState::Active,
                            action: RelayAction::Resize {
                                replicas,
                                pdb_ceiling,
                            },
                            replicas: Some(replicas),
                        }
                    }
                }
            }
            RelayNsState::Draining => {
                // Re-adopt only when demand GENUINELY returns (the signal crosses the
                // activation threshold again with Gateways present) — NOT merely
                // because `should_deactivate` is false: during the drain itself the
                // signal sits below `H` and the cooldown clock makes `should_deactivate`
                // false, which must not be read as "demand returned".
                if inputs.has_dedicated_gateways && Self::should_activate(signal, tuning) {
                    // A relay can lose readiness mid-drain (pod restart / node drain);
                    // repointing leaves onto a not-yet-serving relay is exactly the
                    // make-before-break violation the `Provisioning` gate guards
                    // against, so hold de-repointed (leaves on the controller) until
                    // it is Ready again.
                    if inputs.ready {
                        Decision::new(RelayNsState::Active, RelayAction::Activate)
                    } else {
                        Decision::hold(RelayNsState::Draining)
                    }
                } else if inputs.subscribers == 0 {
                    Decision::delete()
                } else {
                    Decision::hold(RelayNsState::Draining)
                }
            }
        }
    }

    /// HPA sizing for an `Active` relay: `(replicas, pdb_ceiling)` (#602). Static
    /// relays return their fixed count; autoscaled relays apply the tolerance
    /// deadband and scale-down stabilization.
    fn autoscaled_size(&self, tuning: &RelayTuning) -> (u32, u32) {
        let Some(a) = &tuning.autoscaling else {
            return (tuning.static_replicas, tuning.static_replicas);
        };
        // `resolve` only keeps an autoscaling policy with a set cap.
        let Some(max) = a.max_replicas else {
            return (tuning.static_replicas, tuning.static_replicas);
        };
        let max = max.max(1);
        let min = a
            .min_replicas
            .unwrap_or(tuning.static_replicas)
            .clamp(1, max);
        let target = a.target_proxies_per_replica.unwrap_or(tuning.target).max(1);
        let signal = self.latest_signal();
        let current = self.current_replicas.clamp(min, max);
        let up = desired_from_signal(signal, target, min, max, current, tuning.tolerance);
        let replicas = if up >= current {
            // Scale up (or hold) on the instantaneous signal — react promptly.
            up
        } else {
            // Scale down only on the trailing-window maximum — anti-flap.
            desired_from_signal(
                self.stabilized_signal(),
                target,
                min,
                max,
                current,
                tuning.tolerance,
            )
        };
        (replicas, max)
    }

    fn latest_signal(&self) -> u32 {
        self.history.last().map_or(0, |(_, s)| *s)
    }
}

/// The provision-time initial replica count + PDB ceiling for a namespace about to
/// enter `Provisioning` (#602). A fresh relay has no sizing baseline, so it starts
/// at the clamped `ceil(signal/target)` (autoscaled) or the static count.
pub(super) fn initial_size(signal: u32, tuning: &RelayTuning) -> (u32, u32) {
    let Some(a) = &tuning.autoscaling else {
        return (tuning.static_replicas, tuning.static_replicas);
    };
    let Some(max) = a.max_replicas else {
        return (tuning.static_replicas, tuning.static_replicas);
    };
    let max = max.max(1);
    let min = a
        .min_replicas
        .unwrap_or(tuning.static_replicas)
        .clamp(1, max);
    let target = a.target_proxies_per_replica.unwrap_or(tuning.target).max(1);
    (signal.div_ceil(target).clamp(min, max), max)
}

/// Whether a namespace with no relay should provision one this pass (#602) — the
/// activation half of the KEDA on/off model, exposed for the reconciler.
pub(super) fn should_provision(signal: u32, tuning: &RelayTuning) -> bool {
    RelayNsRecord::should_activate(signal, tuning)
}

/// HPA desired replicas from a single signal reading, with the usage-ratio
/// tolerance deadband, clamped to `[min, max]` (#602).
///
/// The deadband is on the **usage ratio** `signal / (current * target)` — HPA's
/// own formulation — so a reading whose implied per-replica load is within
/// ±`tolerance` of the target holds the current count (no churn). Outside the
/// band, `ceil(signal / target)` clamped to the range.
fn desired_from_signal(
    signal: u32,
    target: u32,
    min: u32,
    max: u32,
    current: u32,
    tolerance: f64,
) -> u32 {
    if current >= min && current <= max && current > 0 {
        let capacity = f64::from(current) * f64::from(target);
        if capacity > 0.0 {
            let usage_ratio = f64::from(signal) / capacity;
            if (usage_ratio - 1.0).abs() <= tolerance {
                return current;
            }
        }
    }
    signal.div_ceil(target).clamp(min, max)
}

/// A pure control-loop decision: the action to perform and the state/replica count
/// to commit once it succeeds (#602).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Decision {
    /// State to commit after the action succeeds.
    pub(super) next_state: RelayNsState,
    /// The I/O to perform.
    pub(super) action: RelayAction,
    /// Replica count to commit as the new sizing baseline, when the action changed it.
    pub(super) replicas: Option<u32>,
}

impl Decision {
    fn new(next_state: RelayNsState, action: RelayAction) -> Self {
        Self {
            next_state,
            action,
            replicas: None,
        }
    }

    fn hold(state: RelayNsState) -> Self {
        Self::new(state, RelayAction::None)
    }

    /// Terminal delete: the caller drops the record entirely, so `next_state` is
    /// unused (kept as `Draining` for debug legibility).
    fn delete() -> Self {
        Self::new(RelayNsState::Draining, RelayAction::Delete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> RelayTuningDefaults {
        RelayTuningDefaults {
            activation_threshold: 8,
            cooldown: Duration::from_secs(300),
            stabilization: Duration::from_secs(300),
            tolerance: 0.10,
            target: 50,
            static_replicas: 2,
        }
    }

    fn static_tuning() -> RelayTuning {
        RelayTuning::resolve(&EffectiveRelayPolicy::default(), defaults())
    }

    /// Build a `RelayAutoscaling` via serde — the type is `#[non_exhaustive]`, so a
    /// struct literal is illegal outside `coxswain-core`.
    fn autoscaling(spec: serde_json::Value) -> RelayAutoscaling {
        serde_json::from_value(spec).expect("valid RelayAutoscaling")
    }

    fn autoscaled_tuning(min: Option<u32>, max: u32, target: Option<u32>) -> RelayTuning {
        let policy = EffectiveRelayPolicy {
            autoscaling: Some(autoscaling(serde_json::json!({
                "enabled": true,
                "minReplicas": min,
                "maxReplicas": max,
                "targetProxiesPerReplica": target,
            }))),
            ..Default::default()
        };
        RelayTuning::resolve(&policy, defaults())
    }

    /// Inputs for a namespace that still holds dedicated Gateways (the common case).
    fn inputs(signal: u32, ready: bool, subscribers: u32) -> RelayInputs {
        RelayInputs {
            signal,
            ready,
            subscribers,
            has_dedicated_gateways: true,
        }
    }

    /// Inputs for a namespace that has genuinely drained (no dedicated Gateways).
    fn drained(subscribers: u32) -> RelayInputs {
        RelayInputs {
            signal: 0,
            ready: true,
            subscribers,
            has_dedicated_gateways: false,
        }
    }

    // ── resolve / defaults ──────────────────────────────────────────────────

    #[test]
    fn resolve_uses_flag_defaults_without_policy() {
        let t = static_tuning();
        assert_eq!(t.activation_threshold, 8);
        assert_eq!(t.cooldown, Duration::from_secs(300));
        assert_eq!(t.stabilization, Duration::from_secs(300));
        assert!((t.tolerance - 0.10).abs() < f64::EPSILON);
        assert_eq!(t.target, 50);
        assert_eq!(t.static_replicas, 2);
        assert!(t.autoscaling.is_none(), "no autoscaling block → static");
    }

    #[test]
    fn resolve_layers_autoscaling_overrides_over_flags() {
        let policy = EffectiveRelayPolicy {
            autoscaling: Some(autoscaling(serde_json::json!({
                "enabled": true,
                "minReplicas": 2,
                "maxReplicas": 10,
                "targetProxiesPerReplica": 100,
                "scaleDownStabilizationSeconds": 60,
                "cooldownSeconds": 30,
                "tolerance": 0.25,
            }))),
            ..Default::default()
        };
        let t = RelayTuning::resolve(&policy, defaults());
        assert_eq!(t.cooldown, Duration::from_secs(30));
        assert_eq!(t.stabilization, Duration::from_secs(60));
        assert!((t.tolerance - 0.25).abs() < f64::EPSILON);
        assert_eq!(t.target, 100);
        assert!(t.autoscaling.is_some(), "enabled + capped → autoscaled");
    }

    #[test]
    fn resolve_drops_uncapped_autoscaling() {
        let policy = EffectiveRelayPolicy {
            autoscaling: Some(autoscaling(serde_json::json!({ "enabled": true }))),
            ..Default::default()
        };
        let t = RelayTuning::resolve(&policy, defaults());
        assert!(
            t.autoscaling.is_none(),
            "uncapped autoscaling never runs — falls back to static replicas"
        );
    }

    // ── activation / cooldown ───────────────────────────────────────────────

    #[test]
    fn provisions_only_at_or_above_break_even() {
        let t = static_tuning();
        assert!(!should_provision(7, &t));
        assert!(should_provision(8, &t));
        assert!(should_provision(20, &t));
    }

    #[test]
    fn force_on_provisions_at_any_demand_and_force_off_never() {
        let on = EffectiveRelayPolicy {
            enabled: Some(true),
            ..Default::default()
        };
        let on = RelayTuning::resolve(&on, defaults());
        assert!(
            should_provision(1, &on),
            "force-on ignores the break-even H"
        );
        assert!(
            !should_provision(0, &on),
            "but 0 demand still provisions nothing"
        );

        let off = EffectiveRelayPolicy {
            enabled: Some(false),
            ..Default::default()
        };
        let off = RelayTuning::resolve(&off, defaults());
        assert!(!should_provision(100, &off), "force-off never provisions");
    }

    #[test]
    fn active_relay_holds_until_cooldown_elapses_below_break_even() {
        let t = static_tuning();
        let start = Instant::now();
        let mut rec = RelayNsRecord::existing(RelayNsState::Active, 2);
        // Signal drops below H; the cooldown clock starts.
        rec.observe(start, 5, &t);
        let d = rec.decide(start, inputs(5, true, 2), &t);
        assert_eq!(d.action, RelayAction::None, "within cooldown: keep serving");

        // Still below H, but the cooldown has not elapsed.
        let mid = start + Duration::from_secs(200);
        rec.observe(mid, 5, &t);
        assert_eq!(
            rec.decide(mid, inputs(5, true, 2), &t).action,
            RelayAction::None
        );

        // Cooldown elapsed with the signal held below H → start draining.
        let late = start + Duration::from_secs(301);
        rec.observe(late, 5, &t);
        assert_eq!(
            rec.decide(late, inputs(5, true, 2), &t).action,
            RelayAction::StartDrain,
        );
    }

    #[test]
    fn recovery_above_break_even_resets_the_cooldown_clock() {
        let t = static_tuning();
        let start = Instant::now();
        let mut rec = RelayNsRecord::existing(RelayNsState::Active, 2);
        rec.observe(start, 5, &t); // below H, clock starts
        let recovered = start + Duration::from_secs(200);
        rec.observe(recovered, 9, &t); // back above H → clock resets
        let dip_again = start + Duration::from_secs(400);
        rec.observe(dip_again, 5, &t); // below again, fresh clock
        assert_eq!(
            rec.decide(dip_again, inputs(5, true, 2), &t).action,
            RelayAction::None,
            "the earlier dip must not count — recovery reset the cooldown"
        );
    }

    #[test]
    fn drained_namespace_deactivates_immediately() {
        let t = static_tuning();
        let now = Instant::now();
        let mut rec = RelayNsRecord::existing(RelayNsState::Active, 2);
        rec.observe(now, 0, &t);
        assert_eq!(
            rec.decide(now, drained(3), &t).action,
            RelayAction::StartDrain,
            "no dedicated Gateways left → tear down at once, bypassing the cooldown"
        );
    }

    #[test]
    fn transient_zero_subscribers_holds_while_gateways_remain() {
        // A relay restart / control-stream reconnect blips the live subscriber count
        // to 0 while the namespace's Gateways remain. This must NOT delete the relay
        // (that would drop it mid-restart) — the cooldown applies.
        let t = static_tuning();
        let now = Instant::now();
        let mut rec = RelayNsRecord::existing(RelayNsState::Active, 2);
        rec.observe(now, 0, &t);
        assert_eq!(
            rec.decide(now, inputs(0, true, 0), &t).action,
            RelayAction::None,
            "0 live subscribers but Gateways still present → hold (cooldown), never immediate"
        );
    }

    // ── make-before-break lifecycle ─────────────────────────────────────────

    #[test]
    fn provisioning_waits_for_ready_before_activating() {
        let t = static_tuning();
        let now = Instant::now();
        let mut rec = RelayNsRecord::existing(RelayNsState::Provisioning, 2);
        rec.observe(now, 20, &t);
        assert_eq!(
            rec.decide(now, inputs(20, false, 0), &t).action,
            RelayAction::None,
            "not Ready → no repoint yet",
        );
        let d = rec.decide(now, inputs(20, true, 0), &t);
        assert_eq!(d.action, RelayAction::Activate);
        assert_eq!(d.next_state, RelayNsState::Active);
    }

    #[test]
    fn draining_deletes_only_after_subscribers_reach_zero() {
        let t = static_tuning();
        let now = Instant::now();
        let mut rec = RelayNsRecord::existing(RelayNsState::Draining, 2);
        rec.observe(now, 0, &t);
        assert_eq!(
            rec.decide(now, inputs(0, true, 3), &t).action,
            RelayAction::None,
            "3 subscribers still folded → hold the delete",
        );
        assert_eq!(
            rec.decide(now, inputs(0, true, 0), &t).action,
            RelayAction::Delete,
            "0 subscribers → safe to delete",
        );
    }

    #[test]
    fn draining_readopts_when_demand_returns_and_relay_is_ready() {
        let t = static_tuning();
        let now = Instant::now();
        let mut rec = RelayNsRecord::existing(RelayNsState::Draining, 2);
        rec.observe(now, 20, &t); // demand back above H
        let d = rec.decide(now, inputs(20, true, 1), &t);
        assert_eq!(
            d.action,
            RelayAction::Activate,
            "re-adopt the still-running, Ready relay rather than delete/recreate",
        );
        assert_eq!(d.next_state, RelayNsState::Active);
    }

    #[test]
    fn draining_holds_when_demand_returns_but_relay_not_ready() {
        // A relay that lost readiness mid-drain (pod restart) must NOT be repointed
        // onto even when demand returns — make-before-break holds through re-adopt.
        let t = static_tuning();
        let now = Instant::now();
        let mut rec = RelayNsRecord::existing(RelayNsState::Draining, 2);
        rec.observe(now, 20, &t);
        let d = rec.decide(now, inputs(20, false, 1), &t);
        assert_eq!(
            d.action,
            RelayAction::None,
            "not Ready → leaves stay on the controller until the relay re-syncs",
        );
        assert_eq!(d.next_state, RelayNsState::Draining);
    }

    #[test]
    fn provisioning_aborts_if_namespace_drains_before_ready() {
        let t = static_tuning();
        let now = Instant::now();
        let mut rec = RelayNsRecord::existing(RelayNsState::Provisioning, 2);
        rec.observe(now, 0, &t);
        assert_eq!(
            rec.decide(now, drained(0), &t).action,
            RelayAction::Delete,
            "namespace drained before the relay served anything → tear down directly",
        );
    }

    #[test]
    fn provisioning_holds_on_transient_zero_while_gateways_remain() {
        // A not-yet-Ready relay whose leaves haven't connected yet (signal 0) must
        // NOT be deleted while Gateways remain — it is still coming up.
        let t = static_tuning();
        let now = Instant::now();
        let mut rec = RelayNsRecord::existing(RelayNsState::Provisioning, 2);
        rec.observe(now, 0, &t);
        assert_eq!(
            rec.decide(now, inputs(0, false, 0), &t).action,
            RelayAction::None,
            "0 subscribers but Gateways present → keep waiting for Ready, don't delete",
        );
    }

    // ── HPA sizing: tolerance + stabilization ───────────────────────────────

    #[test]
    fn sizing_scales_up_on_instantaneous_signal() {
        let t = autoscaled_tuning(Some(1), 10, Some(50));
        let now = Instant::now();
        let mut rec = RelayNsRecord::existing(RelayNsState::Active, 1);
        rec.observe(now, 200, &t); // ceil(200/50)=4
        let d = rec.decide(now, inputs(200, true, 200), &t);
        assert_eq!(
            d.action,
            RelayAction::Resize {
                replicas: 4,
                pdb_ceiling: 10
            },
        );
    }

    #[test]
    fn sizing_holds_within_tolerance_deadband() {
        let t = autoscaled_tuning(Some(1), 10, Some(50));
        let now = Instant::now();
        let mut rec = RelayNsRecord::existing(RelayNsState::Active, 4);
        // current=4, target=50 → capacity 200; signal 210 → usage 1.05 ≤ 0.10.
        rec.observe(now, 210, &t);
        assert_eq!(
            rec.decide(now, inputs(210, true, 210), &t).action,
            RelayAction::None,
            "within the ±10% usage deadband: no churn",
        );
    }

    #[test]
    fn sizing_scales_down_only_after_stabilization_window() {
        let policy = EffectiveRelayPolicy {
            autoscaling: Some(autoscaling(serde_json::json!({
                "enabled": true,
                "minReplicas": 1,
                "maxReplicas": 10,
                "targetProxiesPerReplica": 50,
                "scaleDownStabilizationSeconds": 300,
            }))),
            ..Default::default()
        };
        let t = RelayTuning::resolve(&policy, defaults());
        let start = Instant::now();
        let mut rec = RelayNsRecord::existing(RelayNsState::Active, 4); // sized for ~200

        // Signal drops to 50 (→1 replica), but the window still holds the 200 peak.
        rec.observe(start, 200, &t);
        let dip = start + Duration::from_secs(60);
        rec.observe(dip, 50, &t);
        assert_eq!(
            rec.decide(dip, inputs(50, true, 50), &t).action,
            RelayAction::None,
            "scale-down damped: window max is still 200 → hold at 4",
        );

        // The drop persists past the window → the peak ages out, scale down to 1.
        let settled = start + Duration::from_secs(400);
        rec.observe(settled, 50, &t);
        assert_eq!(
            rec.decide(settled, inputs(50, true, 50), &t).action,
            RelayAction::Resize {
                replicas: 1,
                pdb_ceiling: 10
            },
        );
    }

    #[test]
    fn initial_size_autoscaled_and_static() {
        let auto = autoscaled_tuning(Some(2), 8, Some(50));
        assert_eq!(
            initial_size(120, &auto),
            (3, 8),
            "ceil(120/50)=3, clamped [2,8]"
        );
        assert_eq!(initial_size(10, &auto), (2, 8), "below min → floor 2");
        assert_eq!(initial_size(9999, &auto), (8, 8), "above max → cap 8");

        let stat = static_tuning();
        assert_eq!(
            initial_size(500, &stat),
            (2, 2),
            "static → --relay-replicas"
        );
    }
}
