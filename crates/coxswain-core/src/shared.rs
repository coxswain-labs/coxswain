use arc_swap::ArcSwap;
use std::sync::Arc;

/// Generic lock-free shared handle backed by `ArcSwap`.
///
/// A cheaply-cloneable wrapper that allows one writer and many concurrent readers
/// with no locks. The controller stores a new snapshot on every reconcile; readers
/// (proxy hot path, status writer) load atomically on every use.
// No dedicated tests/shared.rs: trivial ArcSwap wrapper exercised transitively.
pub struct Shared<T>(Arc<ArcSwap<T>>);

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T: Default> Shared<T> {
    pub fn new() -> Self {
        Self(Arc::new(ArcSwap::from_pointee(T::default())))
    }
}

impl<T> Shared<T> {
    #[must_use]
    pub fn load(&self) -> Arc<T> {
        self.0.load_full()
    }

    pub fn store(&self, value: Arc<T>) {
        self.0.store(value);
    }
}

impl<T: Default> Default for Shared<T> {
    fn default() -> Self {
        Self::new()
    }
}
