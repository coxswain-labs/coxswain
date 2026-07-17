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
    ///
    /// Calls arc-swap's `load_full`, an atomic read-modify-write that clones the
    /// `Arc`. Use only when an owned `Arc<T>` must outlive the read; on the hot
    /// path prefer [`Shared::guard`], which reads without the RMW.
    #[must_use]
    pub fn load(&self) -> Arc<T> {
        self.0.load_full()
    }

    /// Borrow the current snapshot without a refcount bump.
    ///
    /// Returns an [`arc_swap::Guard`] that derefs through `Arc<T>` to `&T`. This
    /// is the hot-path read: arc-swap serves it from a debt slot with no atomic
    /// read-modify-write, unlike [`Shared::load`] (`load_full`). Hold the guard
    /// only for the duration of the read — a long-lived guard can stall the next
    /// writer's `store`. Reach for [`Shared::load`] when the value must escape
    /// the borrow as an owned `Arc<T>`.
    #[must_use]
    pub fn guard(&self) -> arc_swap::Guard<Arc<T>> {
        self.0.load()
    }

    /// Atomically replace the current snapshot with `value`.
    pub fn store(&self, value: Arc<T>) {
        self.0.store(value);
    }

    /// Store `new` only if it differs from the current snapshot.
    ///
    /// Returns `true` if the snapshot was replaced, `false` if it was unchanged.
    /// Use this to suppress spurious hot-reloads on the proxy path: ArcSwap
    /// notifies all readers on every `store`, so skipping equal values prevents
    /// the data plane from re-applying an identical config.
    #[must_use = "callers should log or act on whether the snapshot changed"]
    pub fn store_if_changed(&self, new: T) -> bool
    where
        T: PartialEq,
    {
        if *self.0.load_full() != new {
            self.0.store(Arc::new(new));
            true
        } else {
            false
        }
    }
}

impl<T: Default> Default for Shared<T> {
    fn default() -> Self {
        Self::new()
    }
}
