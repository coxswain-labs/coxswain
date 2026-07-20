//! The single relay-convergence state machine both relay tiers run each pass.
//!
//! The per-namespace relay ([`super::relay_reconcile`]) and the shared-pool relay
//! ([`super::shared_install`]) advance the *same* level-triggered [`RelayAction`]
//! machine: observe the live signal, decide, then apply/delete-then-commit — with a
//! failed apply/delete left untouched so the next pass retries it. The two paths
//! differ only in their *substrate*: where the [`RelayRecord`] is stored, which
//! resources are applied/deleted, and the log vocabulary ("leaves" vs "the pool").
//!
//! Those divergences live behind the [`RelayCell`] trait — one impl per tier — so
//! the transition logic exists exactly once in [`advance`]. Duplicating the machine
//! per tier is how the two drifted before; a shared driver keeps them in lockstep.

use std::time::Instant;

use async_trait::async_trait;

use super::apply::ApplyError;
use super::relay_autoscaler::{
    RelayAction, RelayInputs, RelayRecord, RelayState, RelayTuning, initial_size, should_provision,
};

/// The storage substrate, cluster I/O, and log vocabulary one relay cell converges
/// over. Implemented once per tier: the per-namespace cell keyed into the state map
/// ([`super::relay_reconcile`]) and the shared-pool single cell
/// ([`super::shared_install`]).
///
/// Every method is either a trivial state access, a render-and-apply/delete, or a
/// single `tracing` line — the log wording is the only thing that differs in kind
/// between the two tiers, so it is expressed as data (per-impl methods) rather than
/// branched inside [`advance`].
#[async_trait]
pub(super) trait RelayCell {
    /// The record currently held for this cell, or `None` when no relay exists.
    fn load(&self) -> Option<RelayRecord>;
    /// Persist `record` as the cell's current state.
    fn store(&self, record: RelayRecord);
    /// Drop the cell's record — the relay has been deleted.
    fn clear(&self);
    /// Render and server-side-apply the relay Deployment at `replicas`/`pdb_ceiling`.
    ///
    /// # Errors
    ///
    /// Propagates the [`ApplyError`] from the SSA so [`advance`] leaves the record
    /// unchanged and the next pass retries.
    async fn apply(&self, replicas: u32, pdb_ceiling: u32) -> Result<(), ApplyError>;
    /// Delete the relay's rendered resources (idempotent; `NotFound` is success).
    ///
    /// # Errors
    ///
    /// Propagates the [`ApplyError`] from the delete so [`advance`] keeps the record
    /// and the next pass retries.
    async fn delete(&self) -> Result<(), ApplyError>;

    /// The `(scope, namespace)` Prometheus label pair identifying this cell's
    /// series. The shared tier carries an empty namespace — there is exactly one
    /// such cell, so a name would add cardinality without adding information.
    fn metric_labels(&self) -> (&'static str, &str);

    /// Whether this replica still holds the leader lease.
    ///
    /// Checked on both sides of the metric publish rather than trusted from the
    /// top of the pass: the relay loop reads leadership once and then `.await`s
    /// cluster I/O, so a lease lost mid-apply would otherwise have a demoted
    /// replica publish state it is no longer authoritative for — and apiserver
    /// pressure produces the slow apply and the failed renewal at the same time.
    fn is_leader(&self) -> bool;

    /// Log a failed provisioning apply (warn; the pass retries).
    fn log_provision_failed(&self, error: &ApplyError);
    /// Log a completed provision (info; relay applied, awaiting Ready).
    fn log_provisioned(&self, replicas: u32);
    /// Log the make-before-break activation (info; leaves/pool repoint onto the relay).
    fn log_activate(&self);
    /// Log a failed resize apply (warn; the pass retries).
    fn log_resize_failed(&self, error: &ApplyError);
    /// Log a completed resize (info).
    fn log_resized(&self, replicas: u32);
    /// Log the start of teardown drain (info; leaves/pool repoint back to the controller).
    fn log_start_drain(&self);
    /// Log a failed teardown delete (warn; the pass retries).
    fn log_delete_failed(&self, error: &ApplyError);
    /// Log a completed teardown (info; drained and deleted).
    fn log_deleted(&self);
}

/// Outcome of one [`advance`] pass, so a caller can gate its own tail work.
///
/// The shared-pool caller publishes the repoint gate once per pass **unless** an
/// apply/delete failed — a failed I/O changed nothing, so the pre-refactor code
/// skipped the publish and retried next pass. `Retry` preserves that skip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "the shared-pool caller gates publish_shared_relay on this"]
pub(super) enum Converge {
    /// The pass settled (including "nothing to do"); caller tail work may run.
    Done,
    /// An apply/delete failed; the record is unchanged and the pass retries.
    Retry,
}

/// Advance one relay cell's state machine, perform the decided I/O, and publish
/// the resulting state to `coxswain_relay_*`.
///
/// Level-triggered: the record's `next_state`/replica baseline is committed only
/// **after** the I/O succeeds, so a failed apply/delete leaves the record unchanged
/// for the next pass. Shared by both relay tiers; the substrate divergences are the
/// [`RelayCell`] impl.
///
/// The metric publish reads the cell back **after** the transition, on every exit
/// path — including [`Converge::Retry`], where the record is deliberately
/// unchanged and so still describes reality. A cleared cell removes its series
/// here, at the moment of deletion, because the relay pass stops iterating a
/// namespace once its record is gone.
pub(super) async fn advance(
    cell: &impl RelayCell,
    inputs: RelayInputs,
    tuning: &RelayTuning,
    now: Instant,
) -> Converge {
    let outcome = transition(cell, inputs, tuning, now).await;
    let (scope, namespace) = cell.metric_labels();
    if cell.is_leader() {
        let state = cell.load().map(|r| r.state);
        crate::metrics::publish_relay(scope, namespace, state, inputs.subscribers);
        // Re-check AFTER publishing, not only before. A demotion landing between
        // the first check and the write would run its gauge reset first and have
        // this publish re-create the series afterwards — freezing them on a
        // replica whose relay loop will never run again. Re-checking converges
        // that window to cleared; a demotion after this point is covered by the
        // reset on the demotion edge itself.
        if !cell.is_leader() {
            crate::metrics::clear_relay(scope, namespace);
        }
    } else {
        crate::metrics::clear_relay(scope, namespace);
    }
    outcome
}

/// The state machine proper. Split from [`advance`] so the metric publish covers
/// every early return without threading it through each arm.
async fn transition(
    cell: &impl RelayCell,
    inputs: RelayInputs,
    tuning: &RelayTuning,
    now: Instant,
) -> Converge {
    let signal = inputs.signal;
    match cell.load() {
        None => {
            if !should_provision(signal, tuning) {
                return Converge::Done;
            }
            let (replicas, pdb_ceiling) = initial_size(signal, tuning);
            if let Err(e) = cell.apply(replicas, pdb_ceiling).await {
                cell.log_provision_failed(&e);
                return Converge::Retry;
            }
            let mut record = RelayRecord::existing(RelayState::Provisioning, replicas);
            record.observe(now, signal, tuning);
            cell.store(record);
            cell.log_provisioned(replicas);
            Converge::Done
        }
        Some(mut record) => {
            record.observe(now, signal, tuning);
            let decision = record.decide(now, inputs, tuning);
            match decision.action {
                RelayAction::None => {
                    commit(cell, record, decision.next_state, None);
                    Converge::Done
                }
                RelayAction::Activate => {
                    cell.log_activate();
                    commit(cell, record, decision.next_state, None);
                    Converge::Done
                }
                RelayAction::Resize {
                    replicas,
                    pdb_ceiling,
                } => {
                    if let Err(e) = cell.apply(replicas, pdb_ceiling).await {
                        cell.log_resize_failed(&e);
                        return Converge::Retry;
                    }
                    cell.log_resized(replicas);
                    commit(cell, record, decision.next_state, Some(replicas));
                    Converge::Done
                }
                RelayAction::StartDrain => {
                    cell.log_start_drain();
                    commit(cell, record, decision.next_state, None);
                    Converge::Done
                }
                RelayAction::Delete => {
                    if let Err(e) = cell.delete().await {
                        cell.log_delete_failed(&e);
                        return Converge::Retry;
                    }
                    cell.clear();
                    cell.log_deleted();
                    Converge::Done
                }
            }
        }
    }
}

/// Commit a transitioned record back to the cell: set its state and, when the
/// action resized the Deployment, its sizing baseline.
fn commit(
    cell: &impl RelayCell,
    mut record: RelayRecord,
    next_state: RelayState,
    replicas: Option<u32>,
) {
    record.state = next_state;
    if let Some(r) = replicas {
        record.current_replicas = r;
    }
    cell.store(record);
}
