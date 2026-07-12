//! A rate-limiting, de-duplicating work queue — the single trigger primitive
//! for the controller's unified watch fabric (#574).
//!
//! Models Kubernetes' client-go `RateLimitingInterface` in Rust: watch events
//! and the reflector's rebuild pass enqueue changed object keys; a single async
//! consumer drains them one at a time and dispatches to the per-kind status /
//! provisioning handlers. It replaces the fan-out `Subscription` broadcast plus
//! the per-kind `kube::runtime::Controller` work-queues that #574 removes.
//!
//! ## Guarantees (client-go parity)
//!
//! - **De-duplication.** A key present in the ready queue is handed out exactly
//!   once, no matter how many times it is added before it is picked up.
//! - **Re-add while processing.** A key added while its handler is running is
//!   re-queued exactly once, on [`RateLimitingWorkqueue::done`] — so a change
//!   that lands mid-reconcile is never lost, and never double-queued.
//! - **Per-key backoff.** [`RateLimitingWorkqueue::add_rate_limited`] schedules
//!   a re-add after an exponential delay derived from how many times the key has
//!   been rate-limited since the last [`RateLimitingWorkqueue::forget`]. The
//!   shape (`base << attempts`, capped) mirrors the controller's #570/#572
//!   `error_backoff_delay`; the queue is generic, so the base and cap are
//!   injected via [`RateLimitConfig`].
//! - **Delayed re-add.** [`RateLimitingWorkqueue::add_after`] schedules a key
//!   for a fixed future instant — the replacement for the operator's
//!   `Action::requeue(BIND_GATE_REQUEUE)` / migration-handoff requeues.
//!
//! ## Consumer contract
//!
//! [`RateLimitingWorkqueue::get`] is **single-consumer**: call it from exactly
//! one task. Concurrency comes from the caller spawning each handed-out key's
//! handler (which calls `done`/`forget` when finished), not from multiple
//! getters. `add*`, `done`, and `forget` are safe to call from any task. Because
//! a delayed re-add can coincide with an immediate add, **handlers must be
//! idempotent** — the queue may hand a key out once more than strictly
//! necessary, and the controller's status-patch / server-side-apply handlers
//! are idempotent by construction.

use parking_lot::Mutex;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
// `tokio::time::Instant` (not `std::time::Instant`) so the queue's deadlines
// respect a paused test clock (`#[tokio::test(start_paused = true)]`) and share
// one monotonic source with the `sleep_until` the consumer parks on.
use tokio::time::Instant;

/// Backoff shape for [`RateLimitingWorkqueue::add_rate_limited`].
///
/// `base << attempts`, saturating, floored at nothing and capped at `max`. With
/// the controller's `base = 500ms`, `max = 15s` this reproduces the #570/#572
/// per-object error backoff (0.5s, 1s, 2s, 4s, 8s, then 15s).
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Delay for the first rate-limited add of a key (`attempts == 0`).
    pub base: Duration,
    /// Ceiling the exponential ramp saturates at.
    pub max: Duration,
}

impl RateLimitConfig {
    /// Construct a config from the first-attempt `base` delay and the `max` cap.
    #[must_use]
    pub fn new(base: Duration, max: Duration) -> Self {
        Self { base, max }
    }

    /// Delay for the `attempts`-th consecutive rate-limited add: `base <<
    /// attempts`, saturating and capped at `max`. The shift is clamped so the
    /// multiplication can never overflow regardless of attempt count.
    fn delay_for(&self, attempts: u32) -> Duration {
        let factor = 1u32.checked_shl(attempts.min(20)).unwrap_or(u32::MAX);
        self.base.saturating_mul(factor).min(self.max)
    }
}

impl Default for RateLimitConfig {
    /// Matches the controller's `ERROR_BACKOFF_BASE` (500ms) and `ERROR_REQUEUE`
    /// (15s), so a caller that does not care gets the project-standard ramp.
    fn default() -> Self {
        Self::new(Duration::from_millis(500), Duration::from_secs(15))
    }
}

/// A delayed entry ordered by its ready-at instant. `seq` is a monotonic
/// tie-breaker so the heap is a total order without requiring `K: Ord`, and so
/// equal-deadline entries drain in insertion order.
struct Delayed<K> {
    ready_at: Instant,
    seq: u64,
    key: K,
}

impl<K> PartialEq for Delayed<K> {
    fn eq(&self, other: &Self) -> bool {
        self.ready_at == other.ready_at && self.seq == other.seq
    }
}
impl<K> Eq for Delayed<K> {}
impl<K> PartialOrd for Delayed<K> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<K> Ord for Delayed<K> {
    // Reversed: `BinaryHeap` is a max-heap, and we want the soonest deadline
    // (then lowest seq) to be the greatest element so `peek`/`pop` yield it.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .ready_at
            .cmp(&self.ready_at)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

struct Inner<K> {
    /// Keys ready to hand out, in FIFO order. Membership mirrored in `queued`.
    ready: VecDeque<K>,
    /// Keys currently in `ready` — the de-duplication set for pending work.
    queued: HashSet<K>,
    /// Keys handed out via `get` but not yet `done`.
    processing: HashSet<K>,
    /// Keys re-added while processing — re-enqueued once on `done`.
    dirty: HashSet<K>,
    /// Future-scheduled keys (delayed / rate-limited adds), soonest first.
    delayed: BinaryHeap<Delayed<K>>,
    /// Per-key rate-limiter attempt counters; reset by `forget`.
    attempts: HashMap<K, u32>,
    /// Monotonic sequence for delayed-entry tie-breaking.
    seq: u64,
    /// Set once `shutdown` is called; makes `get` return `None`.
    shutdown: bool,
}

impl<K: Eq + Hash + Clone> Inner<K> {
    /// Enqueue `key` for immediate processing, honouring the de-dup and
    /// mid-processing rules. Returns `true` if a getter should be woken.
    fn enqueue(&mut self, key: K) -> bool {
        if self.shutdown {
            return false;
        }
        if self.processing.contains(&key) {
            // Re-queue once when the current handler finishes.
            self.dirty.insert(key);
            return false;
        }
        if !self.queued.insert(key.clone()) {
            // Already pending — de-duplicated.
            return false;
        }
        self.ready.push_back(key);
        true
    }

    /// Move every delayed entry whose deadline has passed into the ready queue.
    /// Returns `true` if any became ready (a getter should be woken).
    fn drain_due(&mut self, now: Instant) -> bool {
        let mut woke = false;
        while let Some(top) = self.delayed.peek() {
            if top.ready_at > now {
                break;
            }
            // `pop` cannot be `None` here — we just peeked `Some`.
            if let Some(entry) = self.delayed.pop() {
                woke |= self.enqueue(entry.key);
            }
        }
        woke
    }

    /// The soonest pending delayed deadline, if any.
    fn next_deadline(&self) -> Option<Instant> {
        self.delayed.peek().map(|d| d.ready_at)
    }
}

/// A rate-limiting, de-duplicating work queue. Cheap to [`Clone`] — every clone
/// shares one underlying queue (an `Arc` handle), so producers and the single
/// consumer hold their own handles.
///
/// See the [module docs](self) for the ordering and consumer guarantees.
#[non_exhaustive]
pub struct RateLimitingWorkqueue<K> {
    inner: Arc<Mutex<Inner<K>>>,
    notify: Arc<Notify>,
    config: RateLimitConfig,
}

impl<K> Clone for RateLimitingWorkqueue<K> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            notify: Arc::clone(&self.notify),
            config: self.config,
        }
    }
}

impl<K: Eq + Hash + Clone> RateLimitingWorkqueue<K> {
    /// Construct an empty queue with the given backoff shape.
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                ready: VecDeque::new(),
                queued: HashSet::new(),
                processing: HashSet::new(),
                dirty: HashSet::new(),
                delayed: BinaryHeap::new(),
                attempts: HashMap::new(),
                seq: 0,
                shutdown: false,
            })),
            notify: Arc::new(Notify::new()),
            config,
        }
    }

    /// Enqueue `key` for immediate processing. De-duplicated against work
    /// already pending; if the key is being processed, it is re-queued once when
    /// that handler calls [`Self::done`].
    pub fn add(&self, key: K) {
        let woke = self.inner.lock().enqueue(key);
        if woke {
            self.notify.notify_one();
        }
    }

    /// Enqueue `key` after `delay`. A zero delay is equivalent to [`Self::add`].
    /// Replaces the operator's fixed `Action::requeue` cadences (bind-gate,
    /// migration handoff).
    pub fn add_after(&self, key: K, delay: Duration) {
        if delay.is_zero() {
            self.add(key);
            return;
        }
        {
            let mut g = self.inner.lock();
            if g.shutdown {
                return;
            }
            let seq = g.seq;
            g.seq = g.seq.wrapping_add(1);
            // `checked_add` guards against a pathological `delay` overflowing the
            // monotonic clock (a caller bug — our own callers pass ≤ the backoff
            // cap or fixed re-queue cadences). An overflow degrades to "due now"
            // rather than panicking; handlers are idempotent, so an early hand-out
            // is safe.
            let ready_at = Instant::now()
                .checked_add(delay)
                .unwrap_or_else(Instant::now);
            g.delayed.push(Delayed { ready_at, seq, key });
        }
        // Wake the consumer so it can shorten its sleep to this new deadline.
        self.notify.notify_one();
    }

    /// Enqueue `key` after an exponential backoff derived from how many times it
    /// has been rate-limited since the last [`Self::forget`]. Use on a handler
    /// error whose class is transient; use [`Self::add_after`] with the flat cap
    /// for persistent classes (RBAC / validation) that a faster retry cannot fix.
    pub fn add_rate_limited(&self, key: K) {
        let delay = {
            let mut g = self.inner.lock();
            let counter = g.attempts.entry(key.clone()).or_insert(0);
            let attempts = *counter;
            *counter = counter.saturating_add(1);
            self.config.delay_for(attempts)
        };
        self.add_after(key, delay);
    }

    /// Await the next ready key, or `None` once the queue is shut down.
    ///
    /// **Single-consumer**: call from exactly one task (see the module docs).
    /// The returned key is marked in-processing until [`Self::done`]; adds for it
    /// meanwhile are coalesced into a single re-queue on `done`.
    pub async fn get(&self) -> Option<K> {
        loop {
            // Register this waiter with the `Notify` *before* inspecting state:
            // `enable()` performs the registration a first poll would, so an add
            // that lands after we drop the lock below — but before we await — is
            // delivered to this waiter rather than lost. (`notify_one` also stores
            // a permit if it somehow races ahead of the registration, so the
            // wakeup is loss-free either way.)
            let mut notified = std::pin::pin!(self.notify.notified());
            notified.as_mut().enable();

            let deadline = {
                let mut g = self.inner.lock();
                g.drain_due(Instant::now());
                if let Some(key) = g.ready.pop_front() {
                    g.queued.remove(&key);
                    g.processing.insert(key.clone());
                    return Some(key);
                }
                if g.shutdown {
                    return None;
                }
                g.next_deadline()
            };

            match deadline {
                Some(at) => {
                    tokio::select! {
                        () = &mut notified => {}
                        () = tokio::time::sleep_until(at) => {}
                    }
                }
                None => notified.await,
            }
        }
    }

    /// Mark the handler for `key` finished. If `key` was re-added while
    /// processing, it is re-enqueued now. Does not reset the rate-limiter — call
    /// [`Self::forget`] on success for that.
    pub fn done(&self, key: &K) {
        let woke = {
            let mut g = self.inner.lock();
            g.processing.remove(key);
            if g.dirty.remove(key) {
                g.enqueue(key.clone())
            } else {
                false
            }
        };
        if woke {
            self.notify.notify_one();
        }
    }

    /// Reset the rate-limiter backoff for `key` — call after a successful
    /// reconcile so the next transient error starts the ramp from the base, and
    /// so the key's attempt counter is released (the counter is the queue's only
    /// per-key state that outlives processing; a key that is rate-limited but
    /// never forgotten retains a small counter entry until the next `forget`).
    pub fn forget(&self, key: &K) {
        self.inner.lock().attempts.remove(key);
    }

    /// Number of keys ready to hand out (excludes in-flight and delayed work).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().ready.len()
    }

    /// Whether no key is ready to hand out right now.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Signal shutdown: [`Self::get`] returns `None` and no further work is
    /// accepted. Wakes a parked consumer so it can observe the shutdown.
    pub fn shutdown(&self) {
        self.inner.lock().shutdown = true;
        self.notify.notify_waiters();
        // Also store a permit in case the consumer is between iterations.
        self.notify.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u32) -> u32 {
        n
    }

    #[tokio::test]
    async fn add_then_get_returns_the_key() {
        let q = RateLimitingWorkqueue::new(RateLimitConfig::default());
        q.add(key(1));
        assert_eq!(q.get().await, Some(1));
        assert!(q.is_empty());
    }

    #[tokio::test]
    async fn duplicate_adds_are_coalesced_into_one() {
        let q = RateLimitingWorkqueue::new(RateLimitConfig::default());
        q.add(key(7));
        q.add(key(7));
        q.add(key(7));
        assert_eq!(q.len(), 1, "three adds of the same key must dedup to one");
        assert_eq!(q.get().await, Some(7));
        q.done(&7);
        assert!(q.is_empty(), "no phantom re-queue after a single get");
    }

    #[tokio::test]
    async fn readd_while_processing_requeues_exactly_once_on_done() {
        let q = RateLimitingWorkqueue::new(RateLimitConfig::default());
        q.add(key(3));
        assert_eq!(q.get().await, Some(3));
        // Two adds land while 3 is in-flight.
        q.add(key(3));
        q.add(key(3));
        assert_eq!(q.len(), 0, "in-flight key must not be in the ready queue");
        q.done(&3);
        assert_eq!(
            q.len(),
            1,
            "re-adds during processing collapse to one requeue"
        );
        assert_eq!(q.get().await, Some(3));
        q.done(&3);
        assert!(q.is_empty());
    }

    #[tokio::test]
    async fn fifo_order_across_distinct_keys() {
        let q = RateLimitingWorkqueue::new(RateLimitConfig::default());
        q.add(key(1));
        q.add(key(2));
        q.add(key(3));
        assert_eq!(q.get().await, Some(1));
        assert_eq!(q.get().await, Some(2));
        assert_eq!(q.get().await, Some(3));
    }

    #[tokio::test(start_paused = true)]
    async fn add_after_delivers_only_once_the_delay_elapses() {
        let q = RateLimitingWorkqueue::new(RateLimitConfig::default());
        q.add_after(key(9), Duration::from_secs(5));
        assert!(q.is_empty(), "not ready before the delay");

        // A getter parked on the delayed deadline wakes when time advances.
        let getter = {
            let q = q.clone();
            tokio::spawn(async move { q.get().await })
        };
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(getter.await.expect("join"), Some(9));
    }

    #[tokio::test(start_paused = true)]
    async fn add_rate_limited_ramps_exponentially_then_forget_resets() {
        let cfg = RateLimitConfig::new(Duration::from_millis(500), Duration::from_secs(15));
        // 0.5s, 1s, 2s ... verify the boundary: after 400ms nothing, after the
        // full 500ms the first rate-limited key is ready.
        let q = RateLimitingWorkqueue::new(cfg);
        q.add_rate_limited(key(1));
        tokio::time::advance(Duration::from_millis(400)).await;
        assert!(q.is_empty(), "still backing off at 400ms < 500ms base");
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(q.get().await, Some(1));
        q.done(&1);

        // Second rate-limited add of the same key doubles to 1s.
        q.add_rate_limited(key(1));
        tokio::time::advance(Duration::from_millis(900)).await;
        assert!(q.is_empty(), "second attempt backs off ~1s");
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(q.get().await, Some(1));
        q.done(&1);

        // forget resets the ramp: next add is back to the 500ms base.
        q.forget(&1);
        q.add_rate_limited(key(1));
        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(q.get().await, Some(1));
    }

    #[test]
    fn backoff_shape_matches_controller_error_policy() {
        let cfg = RateLimitConfig::new(Duration::from_millis(500), Duration::from_secs(15));
        assert_eq!(cfg.delay_for(0), Duration::from_millis(500));
        assert_eq!(cfg.delay_for(1), Duration::from_secs(1));
        assert_eq!(cfg.delay_for(2), Duration::from_secs(2));
        assert_eq!(cfg.delay_for(3), Duration::from_secs(4));
        assert_eq!(cfg.delay_for(4), Duration::from_secs(8));
        assert_eq!(
            cfg.delay_for(5),
            Duration::from_secs(15),
            "500ms<<5=16s caps at 15s"
        );
        assert_eq!(
            cfg.delay_for(50),
            Duration::from_secs(15),
            "large attempts stay capped, no overflow"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_unblocks_a_parked_getter() {
        let q = RateLimitingWorkqueue::<u32>::new(RateLimitConfig::default());
        let getter = {
            let q = q.clone();
            tokio::spawn(async move { q.get().await })
        };
        // Let the getter park with an empty queue.
        tokio::time::advance(Duration::from_millis(1)).await;
        q.shutdown();
        assert_eq!(getter.await.expect("join"), None);
    }

    #[tokio::test]
    async fn add_after_zero_delay_behaves_like_add() {
        let q = RateLimitingWorkqueue::new(RateLimitConfig::default());
        q.add_after(key(5), Duration::ZERO);
        assert_eq!(q.len(), 1, "a zero delay must enqueue immediately");
        assert_eq!(q.get().await, Some(5));
    }

    #[tokio::test]
    async fn adds_after_shutdown_are_rejected() {
        let q = RateLimitingWorkqueue::new(RateLimitConfig::default());
        q.shutdown();
        q.add(key(1));
        q.add_after(key(2), Duration::from_millis(1));
        q.add_rate_limited(key(3));
        assert!(q.is_empty(), "no work is accepted once shut down");
    }

    #[tokio::test]
    async fn done_on_a_non_processing_key_is_a_noop() {
        let q = RateLimitingWorkqueue::new(RateLimitConfig::default());
        // Never handed out — done must not panic or phantom-enqueue.
        q.done(&42);
        assert!(q.is_empty());
    }

    #[tokio::test]
    async fn forget_on_an_unknown_key_is_a_noop() {
        let q = RateLimitingWorkqueue::<u32>::new(RateLimitConfig::default());
        q.forget(&99);
        assert!(q.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn interleaved_delays_drain_in_deadline_order() {
        let q = RateLimitingWorkqueue::new(RateLimitConfig::default());
        // Enqueue out of deadline order; expect ascending-deadline delivery.
        q.add_after(key(30), Duration::from_secs(30));
        q.add_after(key(10), Duration::from_secs(10));
        q.add_after(key(20), Duration::from_secs(20));
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_eq!(q.get().await, Some(10));
        assert_eq!(q.get().await, Some(20));
        assert_eq!(q.get().await, Some(30));
    }

    #[tokio::test(start_paused = true)]
    async fn equal_deadline_entries_drain_in_insertion_order() {
        let q = RateLimitingWorkqueue::new(RateLimitConfig::default());
        // Same delay → same deadline; the `seq` tie-break preserves FIFO.
        q.add_after(key(1), Duration::from_secs(5));
        q.add_after(key(2), Duration::from_secs(5));
        q.add_after(key(3), Duration::from_secs(5));
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(q.get().await, Some(1));
        assert_eq!(q.get().await, Some(2));
        assert_eq!(q.get().await, Some(3));
    }

    #[tokio::test(start_paused = true)]
    async fn a_delayed_readd_of_a_processing_key_surfaces_exactly_once() {
        // A delayed re-add for a key that is still being processed must not be
        // lost and must not double-deliver, whichever order the delayed entry
        // draining and `done` interleave. `drain_due` runs only inside `get`, so
        // a getter must be parked for the delayed entry to be observed while the
        // key is in flight (the realistic worker: parked in `get` between jobs).
        let q = RateLimitingWorkqueue::new(RateLimitConfig::default());
        q.add(key(7));
        assert_eq!(q.get().await, Some(7)); // 7 now processing on this task
        let getter = {
            let q = q.clone();
            tokio::spawn(async move { q.get().await })
        };
        tokio::task::yield_now().await; // let the getter park

        q.add_after(key(7), Duration::from_secs(2));
        tokio::time::advance(Duration::from_secs(2)).await; // delayed entry becomes due
        tokio::task::yield_now().await;
        q.done(&7); // finish processing — either path yields 7 exactly once

        assert_eq!(
            getter.await.expect("join"),
            Some(7),
            "the delayed re-add of an in-flight key surfaces once processing completes"
        );
        q.done(&7);
        assert!(q.is_empty(), "no second copy of the key remains");
    }

    #[tokio::test(start_paused = true)]
    async fn len_excludes_in_flight_and_delayed_work() {
        let q = RateLimitingWorkqueue::new(RateLimitConfig::default());
        q.add(key(1));
        assert_eq!(q.get().await, Some(1)); // 1 now in-flight
        q.add_after(key(2), Duration::from_secs(10)); // 2 delayed
        assert_eq!(q.len(), 0, "len counts only keys ready to hand out");
        assert!(q.is_empty());
    }

    #[tokio::test]
    async fn a_clone_shares_one_underlying_queue() {
        let producer = RateLimitingWorkqueue::new(RateLimitConfig::default());
        let consumer = producer.clone();
        producer.add(key(1));
        assert_eq!(
            consumer.get().await,
            Some(1),
            "a clone observes the same queue"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn earlier_add_after_wakes_a_getter_parked_on_a_later_deadline() {
        let q = RateLimitingWorkqueue::new(RateLimitConfig::default());
        q.add_after(key(1), Duration::from_secs(60));
        let getter = {
            let q = q.clone();
            tokio::spawn(async move { q.get().await })
        };
        tokio::time::advance(Duration::from_millis(1)).await;
        // A nearer deadline must re-arm the parked getter's sleep.
        q.add_after(key(2), Duration::from_secs(1));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(getter.await.expect("join"), Some(2));
    }
}
