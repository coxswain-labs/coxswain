//! Canonical waiter.
pub async fn poll_until<T, F, Fut, D, DFut>(timeout: Duration, interval: Duration, on_timeout: D, mut check: F) -> anyhow::Result<T> { todo!() }
