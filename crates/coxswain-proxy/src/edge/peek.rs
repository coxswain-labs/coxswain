//! The retry wait shared by the edge's `MSG_PEEK` loops.
//!
//! Both L4 entry points measure their preamble without consuming it —
//! [`crate::edge::accept`] sizes a PROXY protocol header before draining it, and
//! [`crate::edge::passthrough`] reads the TLS ClientHello SNI while leaving the
//! handshake intact for the backend. Both therefore peek, and both must wait for
//! more bytes when the preamble has not fully arrived.
//!
//! That wait is the whole reason this module exists: it is the one part of the
//! shape that cannot be written the obvious way, and it was written the obvious
//! way twice (#614, #628). [`PeekBackoff`] holds it once so the two loops cannot
//! drift apart again, and `scripts/check-no-peek-readable.sh` fails any peeking
//! file that reaches for readiness instead.

use std::time::Duration;

/// First delay between peek retries, doubling to [`PEEK_POLL_MAX`].
///
/// A fragmented preamble's segments are sent back-to-back by the client, so they
/// arrive microseconds apart — 1ms catches real fragmentation on the first retry
/// while costing a stalled peer only a handful of wakeups.
const PEEK_POLL_MIN: Duration = Duration::from_millis(1);

/// Ceiling on the [`PEEK_POLL_MIN`] backoff, bounding a stalled peer to roughly
/// `timeout / PEEK_POLL_MAX` wakeups before its call site's timeout closes it.
const PEEK_POLL_MAX: Duration = Duration::from_millis(32);

/// Bounded backoff between `MSG_PEEK` retries, reset whenever bytes arrive.
///
/// # Why this is a poll and not a readiness await
///
/// `MSG_PEEK` leaves the bytes in the kernel queue, so `peek` never reports
/// `EWOULDBLOCK` while any byte is queued — and tokio clears read-readiness
/// *only* on `EWOULDBLOCK` (`runtime/io/registration.rs::async_io`). A successful
/// short peek therefore leaves READABLE set, so `readable()` returns
/// `Poll::Ready` instantly, forever: the retry loop spins a core until its
/// timeout fires. Measured on #628, a single peer that sent one byte and stalled
/// drove 1,368,449 iterations in one second.
///
/// There is no "readable beyond n bytes" edge to wait on, and read-and-replay is
/// not open to the edge (`terminate.rs` hands the raw stream to pingora
/// BoringSSL, so the ClientHello must stay queued). A bounded poll is the only
/// correct wait here.
pub(crate) struct PeekBackoff {
    /// Bytes seen at the previous retry; a change means the peer made progress.
    last_n: usize,
    /// Delay for the next [`PeekBackoff::wait`], doubling up to [`PEEK_POLL_MAX`].
    delay: Duration,
}

impl PeekBackoff {
    /// Start a backoff at [`PEEK_POLL_MIN`], having seen no bytes yet.
    pub(crate) fn new() -> Self {
        Self {
            last_n: 0,
            delay: PEEK_POLL_MIN,
        }
    }

    /// Sleep before the caller re-peeks, having just peeked `n` bytes.
    ///
    /// A peer still delivering its preamble resets the delay to [`PEEK_POLL_MIN`]
    /// so fragmentation costs ~1ms, while a peer that has stopped sending decays
    /// to [`PEEK_POLL_MAX`] and idles there until the caller's timeout fires.
    pub(crate) async fn wait(&mut self, n: usize) {
        if n != self.last_n {
            self.last_n = n;
            self.delay = PEEK_POLL_MIN;
        }
        tokio::time::sleep(self.delay).await;
        self.delay = (self.delay * 2).min(PEEK_POLL_MAX);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use tokio::time::Instant;

    use super::*;

    /// Time each `wait` on the paused clock: a stalled peer must decay to the cap
    /// (bounding its wakeups), and an advancing peer must snap back to `MIN` so a
    /// fragmented preamble is not made to wait 32ms for a segment already in
    /// flight.
    #[tokio::test(start_paused = true)]
    async fn peek_backoff_doubles_to_the_cap_and_resets_on_progress() {
        let mut backoff = PeekBackoff::new();

        // Same `n` every time: the peer is stalled, so the delay doubles to the cap
        // and stays there.
        let mut delays = Vec::new();
        for _ in 0..8 {
            let start = Instant::now();
            backoff.wait(4).await;
            delays.push(start.elapsed());
        }
        assert_eq!(
            delays,
            vec![
                Duration::from_millis(1),
                Duration::from_millis(2),
                Duration::from_millis(4),
                Duration::from_millis(8),
                Duration::from_millis(16),
                Duration::from_millis(32),
                Duration::from_millis(32),
                Duration::from_millis(32),
            ],
            "a stalled peer must double to PEEK_POLL_MAX and stay capped"
        );

        // Bytes arrived: the next wait restarts at PEEK_POLL_MIN.
        let start = Instant::now();
        backoff.wait(5).await;
        assert_eq!(
            start.elapsed(),
            PEEK_POLL_MIN,
            "progress (n 4 -> 5) must reset the backoff to PEEK_POLL_MIN"
        );
    }
}
