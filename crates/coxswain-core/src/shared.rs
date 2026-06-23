//! Generic lock-free snapshot primitive backed by [`arc_swap::ArcSwap`].

use arc_swap::ArcSwap;
use std::sync::Arc;

/// Generic lock-free shared handle backed by `ArcSwap`.
///
/// A cheaply-cloneable wrapper that allows one writer and many concurrent readers
/// with no locks. The controller stores a new snapshot on every reconcile; readers
/// (proxy hot path, status writer) load atomically on every use.
// No dedicated tests/shared.rs: trivial ArcSwap wrapper exercised transitively.
#[non_exhaustive]
pub struct Shared<T>(Arc<ArcSwap<T>>);

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T: Default> Shared<T> {
    /// Construct a new handle wrapping the default value.
    pub fn new() -> Self {
        Self(Arc::new(ArcSwap::from_pointee(T::default())))
    }
}

impl<T> Shared<T> {
    /// Construct a new handle wrapping an initial `value`.
    ///
    /// Unlike [`Shared::new`], this does not require `T: Default`.
    #[must_use]
    pub fn from_value(value: T) -> Self {
        Self(Arc::new(ArcSwap::from_pointee(value)))
    }

    /// Atomically load the current snapshot (refcount bump, no lock).
    #[must_use]
    pub fn load(&self) -> Arc<T> {
        self.0.load_full()
    }

    /// Atomically replace the current snapshot with `value`.
    pub fn store(&self, value: Arc<T>) {
        self.0.store(value);
    }
}

impl<T: Default> Default for Shared<T> {
    fn default() -> Self {
        Self::new()
    }
}
