//! Adaptive trailing-edge debounce for the reconciler rebuild loop (#512).
//!
//! Replaces the reconciler's original fixed 500 ms coalescing timer with a
//! configurable escalating quiet window: an isolated watch event settles
//! quickly, but each event that interrupts an in-progress quiet window
//! doubles it (capped at a hard ceiling), so sustained churn increasingly
//! resembles the old fixed-window behavior instead of firing a rebuild per
//! event.

use std::time::Duration;
use thiserror::Error;
use tokio::sync::Notify;

/// Bounds for the reconciler's adaptive rebuild debounce.
///
/// `min` is the starting trailing quiet window: an isolated watch event
/// settles this long after it fires. Each subsequent event that interrupts
/// an in-progress quiet window doubles it (capped at `max`), so a cluster of
/// events spaced further apart than the initial window still increasingly
/// coalesces rather than firing one rebuild per event. `max` is also a hard
/// ceiling measured from the *first* event of the cycle — it never resets,
/// so a rebuild fires within `max` even under continuous churn (e.g. a
/// rolling deploy). Setting `min == max` reproduces a fixed-window debounce.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct DebounceSettings {
    min: Duration,
    max: Duration,
}

/// Error returned by [`DebounceSettings::new`].
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum DebounceSettingsError {
    /// `min` exceeds `max` — the quiet window could never fire before the
    /// (smaller) ceiling cuts it off, so `min` would be unreachable.
    #[error("debounce min ({min:?}) must not exceed debounce max ({max:?})")]
    MinExceedsMax {
        /// The configured quiet window.
        min: Duration,
        /// The configured hard ceiling.
        max: Duration,
    },
}

impl DebounceSettings {
    /// Construct validated debounce bounds.
    ///
    /// # Errors
    ///
    /// Returns [`DebounceSettingsError::MinExceedsMax`] if `min > max`.
    #[must_use = "the validated settings must be passed to the reconciler, not dropped"]
    pub fn new(min: Duration, max: Duration) -> Result<Self, DebounceSettingsError> {
        if min > max {
            return Err(DebounceSettingsError::MinExceedsMax { min, max });
        }
        Ok(Self { min, max })
    }

    /// The trailing quiet window.
    #[must_use]
    pub fn min(&self) -> Duration {
        self.min
    }

    /// The hard ceiling measured from the first event of the cycle.
    #[must_use]
    pub fn max(&self) -> Duration {
        self.max
    }
}

impl Default for DebounceSettings {
    /// 20 ms quiet window, 500 ms ceiling. The ceiling matches the fixed
    /// timer this type replaces, so behavior under sustained churn is
    /// unchanged; the quiet window is what lets an isolated edit settle far
    /// sooner than the old fixed floor.
    fn default() -> Self {
        Self {
            min: Duration::from_millis(20),
            max: Duration::from_millis(500),
        }
    }
}

/// Wait for the reconciler's rebuild loop to settle after the first watch
/// event of a cycle. The caller awaits that first `notify.notified()` itself
/// (so its own elapsed-time metric starts exactly there) and calls this
/// function immediately after.
///
/// Fires when either bound elapses first: the current quiet window (starting
/// at `settings.min()`, doubling — capped at `settings.max()` — on every
/// notification that interrupts it), or `settings.max()` since this function
/// was entered. The doubling means events spaced further apart than the
/// initial `min` still increasingly coalesce as churn continues, rather than
/// each firing its own rebuild; the absolute ceiling means a rebuild is never
/// starved by continuous churn.
pub(crate) async fn settle(notify: &Notify, settings: DebounceSettings) {
    let deadline = tokio::time::Instant::now() + settings.max();
    let mut window = settings.min();
    loop {
        tokio::select! {
            _ = notify.notified() => {
                window = (window * 2).min(settings.max());
            }
            _ = tokio::time::sleep(window) => break,
            _ = tokio::time::sleep_until(deadline) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_min_greater_than_max() {
        let err = DebounceSettings::new(Duration::from_millis(600), Duration::from_millis(500))
            .expect_err("min > max must be rejected");
        assert!(matches!(err, DebounceSettingsError::MinExceedsMax { .. }));
    }

    #[test]
    fn new_accepts_min_equal_to_max() {
        let settings =
            DebounceSettings::new(Duration::from_millis(500), Duration::from_millis(500))
                .expect("min == max reproduces a fixed-window debounce");
        assert_eq!(settings.min(), Duration::from_millis(500));
        assert_eq!(settings.max(), Duration::from_millis(500));
    }

    #[test]
    fn default_is_20ms_min_500ms_max() {
        let settings = DebounceSettings::default();
        assert_eq!(settings.min(), Duration::from_millis(20));
        assert_eq!(settings.max(), Duration::from_millis(500));
    }

    #[tokio::test(start_paused = true)]
    async fn settles_after_min_with_no_further_events() {
        let notify = Notify::new();
        let settings = DebounceSettings::new(Duration::from_millis(20), Duration::from_millis(500))
            .expect("valid bounds");

        let start = tokio::time::Instant::now();
        settle(&notify, settings).await;

        assert_eq!(
            start.elapsed(),
            Duration::from_millis(20),
            "an isolated cycle with no further events must settle at exactly `min`"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_notification_within_min_doubles_the_quiet_window() {
        let notify = Notify::new();
        let settings = DebounceSettings::new(Duration::from_millis(20), Duration::from_millis(500))
            .expect("valid bounds");

        let start = tokio::time::Instant::now();
        // `join!` polls both futures in order on entry, so `settle`'s
        // `notified()` waiter is registered before the second future's sleep
        // fires — the notification is guaranteed to land, not race-lost.
        tokio::join!(settle(&notify, settings), async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            notify.notify_waiters();
        });

        assert_eq!(
            start.elapsed(),
            Duration::from_millis(50),
            "one interruption 10ms in must double the window (20ms -> 40ms), settling at 10ms + 40ms"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_interruptions_compound_the_widening() {
        let notify = std::sync::Arc::new(Notify::new());
        let settings = DebounceSettings::new(Duration::from_millis(20), Duration::from_millis(500))
            .expect("valid bounds");

        // Three events 10ms apart, each comfortably inside the
        // then-current (already-doubled) window: 20ms -> 40ms -> 80ms -> a
        // final 160ms quiet window (no more events) settles the cycle.
        let churn_notify = std::sync::Arc::clone(&notify);
        let churner = tokio::spawn(async move {
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                churn_notify.notify_waiters();
            }
        });

        let start = tokio::time::Instant::now();
        settle(&notify, settings).await;
        churner.await.expect("churner task must not panic");

        // Events at t=10,20,30 double the window each time (20->40->80->160);
        // the last, uninterrupted 160ms window (from t=30) settles at t=190 —
        // strictly longer than a single doubling (50ms, see the test above),
        // proving the widening compounds across repeated interruptions.
        assert_eq!(
            start.elapsed(),
            Duration::from_millis(190),
            "three compounding doublings (20->40->80->160) must settle at t=190, not re-arm \
             at a flat 20ms/40ms each time"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn continuous_churn_is_bounded_by_the_max_ceiling() {
        let notify = std::sync::Arc::new(Notify::new());
        let settings = DebounceSettings::new(Duration::from_millis(20), Duration::from_millis(500))
            .expect("valid bounds");

        let churn_notify = std::sync::Arc::clone(&notify);
        let churner = tokio::spawn(async move {
            // Fires every 10ms — always inside `min` — for far longer than
            // `max`, simulating sustained churn (e.g. a rolling deploy).
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                churn_notify.notify_waiters();
            }
        });

        let start = tokio::time::Instant::now();
        tokio::time::timeout(Duration::from_millis(600), settle(&notify, settings))
            .await
            .expect("settle must fire by the max ceiling even under continuous churn");

        assert_eq!(
            start.elapsed(),
            Duration::from_millis(500),
            "the quiet window must never fire under continuous sub-min churn; only the ceiling should"
        );
        churner.abort();
    }
}
