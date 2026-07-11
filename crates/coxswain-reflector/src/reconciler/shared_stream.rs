//! Lossy shared-store fan-out — the back-pressure-free replacement for kube's
//! `store_shared`/`Dispatcher`/`ReflectHandle` (#573).
//!
//! # Why this exists
//!
//! kube-runtime's shared store fans a single watch out to many subscribers with
//! a *back-pressuring* broadcast: its `reflector()` runs
//! `apply_watcher_event(&ev); dispatch_event(&ev).await;` per event, and
//! `dispatch_event` blocks the root stream whenever any subscriber's buffer is
//! full (kube's own `reflect_applies_backpressure` test asserts this). A
//! subscriber that lags — or is transiently unpolled — therefore freezes the
//! *root reflector*: no more store swaps, `InitDone` never completes, relists
//! never finish, and the store serves a stale/empty world until the pod
//! restarts. Under conformance/e2e churn the controller wedged exactly this way.
//!
//! # The inversion this fixes
//!
//! The store is the authoritative cache that routing rebuilds, status ownership
//! lookups, and `for_shared_stream` readers all consult. A work-queue trigger is
//! the *least* important consumer — it only needs "something changed". kube's
//! design lets that least-important consumer gate the cache's progress. We invert
//! it back to the standard informer/work-queue model (client-go's indexer +
//! lossy dedup queue + resync): the store advances unconditionally via a plain
//! [`reflector::store`], and the trigger is a **lossy** [`tokio::sync::broadcast`]
//! whose sender never blocks. A lagging consumer drops the oldest refs and then
//! [re-syncs the whole store](Subscription::into_stream), so no object is missed —
//! correctness is recovered by resync, not by delivery guarantees.
//!
//! Deletes are intentionally not fanned out (kube's dispatcher never delivered
//! them either — it broadcasts only on `Apply` and `InitDone`); deletion
//! reconcile is finalizer-driven.

use std::hash::Hash;
use std::sync::Arc;

use futures::{Stream, StreamExt, stream};
use kube::runtime::reflector::{self, ObjectRef, Store};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

/// Lossy fan-out sender for one shared store, carrying applied-object refs.
///
/// Fed by [`super::proxy::spawn_reflector`] on every `Apply`/`InitDone`; cloned
/// into each [`Subscription`]'s receiver. [`broadcast::Sender::send`] is
/// synchronous and lossy — it never awaits, so the reflector loop that calls it
/// can never be back-pressured by a slow consumer.
pub(crate) type FanoutSender<K> = broadcast::Sender<ObjectRef<K>>;

/// A status-writer's view of one shared store: a read handle to the synced
/// store plus a lossy trigger subscription driven off the same watch.
///
/// Replaces kube's `ReflectHandle`. [`Clone`] yields an independent subscriber
/// (a fresh [`broadcast::Receiver`] over the same store) for secondary consumers
/// such as the Gateway controller's GatewayClass watch.
#[non_exhaustive]
pub struct Subscription<K>
where
    K: kube::Resource + Clone + 'static,
    K::DynamicType: Eq + Hash + Clone,
{
    reader: Store<K>,
    rx: broadcast::Receiver<ObjectRef<K>>,
}

impl<K> Clone for Subscription<K>
where
    K: kube::Resource + Clone + 'static,
    K::DynamicType: Eq + Hash + Clone,
{
    /// An independent subscriber over the same store. The new receiver sees
    /// events broadcast *after* the clone (via [`broadcast::Receiver::resubscribe`]);
    /// the store it reads is already populated, so a work-queue built from the
    /// clone reconciles the current world on its first `reconcile_all`.
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            rx: self.rx.resubscribe(),
        }
    }
}

impl<K> Subscription<K>
where
    K: kube::Resource + Clone + Send + Sync + 'static,
    K::DynamicType: Eq + Hash + Clone + Default + Send + Sync,
{
    /// Read handle to the synced store, for ownership lookups and secondary
    /// mappers. Cheap `Arc` clone of the shared cache.
    #[must_use]
    pub fn reader(&self) -> Store<K> {
        self.reader.clone()
    }

    /// Consume into a lossy trigger stream of applied objects for
    /// [`kube::runtime::Controller::for_shared_stream`].
    ///
    /// Each broadcast ref is resolved through the store to the live object. On
    /// [`BroadcastStreamRecvError::Lagged`] — the consumer fell behind and the
    /// oldest refs were dropped — the stream **re-emits the entire current
    /// store**, so every object is re-reconciled and nothing is lost. A ref for
    /// an object deleted between broadcast and consumption resolves to nothing
    /// and is skipped.
    pub fn into_stream(self) -> impl Stream<Item = Arc<K>> + Send + 'static {
        let reader = self.reader;
        BroadcastStream::new(self.rx).flat_map(move |res| {
            let items: Vec<Arc<K>> = match res {
                Ok(obj_ref) => reader.get(&obj_ref).into_iter().collect(),
                Err(BroadcastStreamRecvError::Lagged(_)) => reader.state(),
            };
            stream::iter(items)
        })
    }
}

/// The writer side of a [`shared_store`]: the reflector store
/// [`Writer`](reflector::store::Writer) that drives the authoritative cache,
/// plus the [`FanoutSender`] the reflector loop publishes applied-object refs
/// on. Handed to the watch task; the writer is moved into `reflector()` and the
/// sender into the reflector's `ReflectorEffects`.
pub(crate) struct SharedStoreWriter<K>
where
    K: kube::Resource + Clone + 'static,
    K::DynamicType: Eq + Hash + Clone,
{
    /// Drives the plain reflector store (no dispatcher, no back-pressure).
    pub writer: reflector::store::Writer<K>,
    /// Lossy fan-out to every [`Subscription`] over this store.
    pub tx: FanoutSender<K>,
}

/// Create a plain reflector store paired with a lossy fan-out.
///
/// Returns the [`SharedStoreWriter`] (writer + fan-out sender, handed to the
/// reflector task) and one [`Subscription`] for the status-writer. Additional
/// subscribers are obtained by [`Subscription::clone`].
///
/// `buffer` bounds the broadcast backlog; beyond it the oldest refs drop and
/// affected consumers re-sync from the store. It never causes back-pressure.
pub(crate) fn shared_store<K>(buffer: usize) -> (SharedStoreWriter<K>, Subscription<K>)
where
    K: kube::Resource + Clone + 'static,
    K::DynamicType: Eq + Hash + Clone + Default,
{
    let (reader, writer) = reflector::store::<K>();
    let (tx, _rx) = broadcast::channel(buffer);
    let sub = Subscription {
        reader: reader.clone(),
        rx: tx.subscribe(),
    };
    (SharedStoreWriter { writer, tx }, sub)
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]
    use super::*;
    use futures::{FutureExt, StreamExt};
    use k8s_openapi::api::core::v1::Pod;
    use kube::runtime::watcher::Event;

    fn testpod(name: &str) -> Pod {
        let mut pod = Pod::default();
        pod.metadata.name = Some(name.to_string());
        pod.metadata.namespace = Some("default".to_string());
        pod
    }

    /// Populate the store the way a reflector would, then publish the ref — the
    /// ordering [`super::super::proxy::spawn_reflector`] guarantees (apply
    /// before send) so consumers always resolve the object.
    fn apply(writer: &mut reflector::store::Writer<Pod>, tx: &FanoutSender<Pod>, pod: Pod) {
        writer.apply_watcher_event(&Event::Apply(pod.clone()));
        let _ = tx.send(ObjectRef::from_obj(&pod));
    }

    #[tokio::test]
    async fn subscription_yields_applied_object() {
        let (mut sw, sub) = shared_store::<Pod>(16);
        let mut stream = Box::pin(sub.into_stream());
        apply(&mut sw.writer, &sw.tx, testpod("foo"));
        let got = stream
            .next()
            .await
            .expect("stream yields the applied object");
        assert_eq!(
            got.metadata.name.as_deref(),
            Some("foo"),
            "subscription must yield the object that was applied to the store"
        );
    }

    #[tokio::test]
    async fn fanout_send_never_blocks_when_subscriber_full() {
        // The whole point of #573: a subscriber that never drains must not stall
        // the producer. `send` is synchronous and lossy — filling far past the
        // buffer returns immediately every time (no `.await`, no back-pressure).
        let (mut sw, _sub) = shared_store::<Pod>(4);
        for i in 0..1_000 {
            // If this could block on a full subscriber, the test would hang.
            apply(&mut sw.writer, &sw.tx, testpod(&format!("pod-{i}")));
        }
        assert_eq!(
            sw.writer.as_reader().len(),
            1_000,
            "every apply reached the store even though no subscriber drained the fan-out"
        );
    }

    #[tokio::test]
    async fn subscription_resyncs_whole_store_on_lag() {
        // A consumer that lags past the buffer must not silently miss objects:
        // the lag re-emits the entire current store so nothing is lost.
        let (mut sw, sub) = shared_store::<Pod>(4);
        // Overflow the 4-slot buffer with 10 distinct objects before polling.
        for i in 0..10 {
            apply(&mut sw.writer, &sw.tx, testpod(&format!("pod-{i}")));
        }
        let mut stream = Box::pin(sub.into_stream());
        // Drain what the stream offers without blocking; the first item(s) come
        // from the Lagged→resync path, which enumerates the whole store.
        let mut seen = std::collections::HashSet::new();
        while let Some(Some(obj)) = stream.next().now_or_never() {
            if let Some(name) = obj.metadata.name.clone() {
                seen.insert(name);
            }
        }
        for i in 0..10 {
            assert!(
                seen.contains(&format!("pod-{i}")),
                "resync after lag must surface every stored object; missing pod-{i}"
            );
        }
    }
}
