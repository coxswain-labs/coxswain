//! Per-Gateway publish-sequence index for the #531 `Programmed` ack gate.
//!
//! Snapshot versions on the discovery stream are content hashes — unordered —
//! so "has this node applied a snapshot that *contains* Gateway X @ generation
//! N?" cannot be answered from versions alone. This index adds the ordering:
//! the reflector's rebuild loop assigns each rebuild a monotonically
//! increasing sequence number and stamps, per owned Gateway, the sequence at
//! which its **current generation** was first published into the routing
//! cells. The discovery server captures the counter *before* reading the
//! cells for a snapshot build, so `captured >= stamp.seq` proves the built
//! snapshot contains that generation's config (cells are stored before the
//! counter is bumped; later rebuilds only carry equal-or-newer content).
//!
//! Writer: the shared-pool rebuild in `coxswain-reflector` (single writer,
//! full-map replace per rebuild). Readers: the discovery server (counter
//! capture) and both `Programmed` status writers (stamp lookup).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;

use crate::ownership::ObjectKey;

/// The publish stamp for one Gateway: the rebuild sequence at which its
/// current `(generation, content fingerprint)` pair was first included in
/// the published routing cells.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishStamp {
    /// `metadata.generation` of the Gateway as of the stamping rebuild.
    pub generation: i64,
    /// Fingerprint of the Gateway's own published content (its listener
    /// status entry: readiness, frontend-validation resolution, attached
    /// routes, …). A same-generation content change — e.g. a
    /// `frontendValidation` CA ConfigMap resolving one rebuild AFTER the
    /// Gateway's spec was first processed — re-arms the stamp, because the
    /// proxies must apply THAT content before `Programmed=True` is honest.
    pub fingerprint: u64,
    /// Rebuild sequence assigned when this `(generation, fingerprint)` pair
    /// was first published. Stable across rebuilds that leave this Gateway's
    /// own content untouched — unrelated churn (other Gateways' changes)
    /// must not move the gate's target.
    pub seq: u64,
}

/// Shared handle to the publish index. Cheap to clone; one instance per
/// controller process, created in `coxswain-bin`.
#[non_exhaustive]
#[derive(Clone, Default)]
pub struct SharedGatewayPublishIndex(Arc<PublishIndexInner>);

/// Shared state behind [`SharedGatewayPublishIndex`].
#[derive(Default)]
struct PublishIndexInner {
    /// `Gateway key → stamp` map, full-replaced by each rebuild.
    map: ArcSwap<HashMap<ObjectKey, PublishStamp>>,
    /// Monotone rebuild counter. Bumped once per [`stamp_rebuild`] call,
    /// *after* the caller has stored every routing cell for that rebuild —
    /// that ordering is what lets the discovery server's pre-build capture
    /// prove content inclusion.
    ///
    /// [`stamp_rebuild`]: SharedGatewayPublishIndex::stamp_rebuild
    counter: AtomicU64,
}

impl SharedGatewayPublishIndex {
    /// Construct a new, empty index (sequence starts at 0; the first rebuild
    /// stamps sequence 1).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one completed rebuild covering exactly the given
    /// `(gateway, generation, content fingerprint)` triples, and return the
    /// rebuild's sequence.
    ///
    /// Must be called **after** every routing cell of the rebuild has been
    /// stored — the counter bump is the publication fence the discovery
    /// server's capture relies on. Stamps are sticky per
    /// `(generation, fingerprint)`: a Gateway whose own published content is
    /// unchanged keeps its existing (older) sequence so the ack gate's
    /// target stays fixed under unrelated churn; a new generation OR a
    /// same-generation content change gets this rebuild's sequence.
    /// Gateways absent from `published` drop out of the index (deleted or
    /// no longer owned).
    pub fn stamp_rebuild(&self, published: impl IntoIterator<Item = (ObjectKey, i64, u64)>) -> u64 {
        let seq = self.0.counter.fetch_add(1, Ordering::AcqRel) + 1;
        let prior = self.0.map.load();
        let mut next: HashMap<ObjectKey, PublishStamp> = HashMap::new();
        for (key, generation, fingerprint) in published {
            let stamp = match prior.get(&key) {
                Some(existing)
                    if existing.generation == generation && existing.fingerprint == fingerprint =>
                {
                    *existing
                }
                _ => PublishStamp {
                    generation,
                    fingerprint,
                    seq,
                },
            };
            next.insert(key, stamp);
        }
        self.0.map.store(Arc::new(next));
        seq
    }

    /// Look up the publish stamp for a Gateway, if it has been published.
    #[must_use]
    pub fn get(&self, key: &ObjectKey) -> Option<PublishStamp> {
        self.0.map.load().get(key).copied()
    }

    /// The current rebuild sequence: every rebuild stamped at a sequence
    /// `<=` this value has fully stored its routing cells. The discovery
    /// server captures this **before** loading the cells for a snapshot
    /// build (`Acquire` pairs with the `AcqRel` bump in
    /// [`Self::stamp_rebuild`]).
    #[must_use]
    pub fn current_seq(&self) -> u64 {
        self.0.counter.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str) -> ObjectKey {
        ObjectKey::new("ns".to_owned(), name.to_owned())
    }

    #[test]
    fn first_stamp_uses_the_rebuild_seq() {
        let idx = SharedGatewayPublishIndex::new();
        let seq = idx.stamp_rebuild([(key("gw"), 1, 9)]);
        assert_eq!(seq, 1);
        assert_eq!(
            idx.get(&key("gw")),
            Some(PublishStamp {
                generation: 1,
                fingerprint: 9,
                seq: 1
            })
        );
        assert_eq!(idx.current_seq(), 1);
    }

    #[test]
    fn unchanged_generation_keeps_its_original_seq_under_churn() {
        let idx = SharedGatewayPublishIndex::new();
        idx.stamp_rebuild([(key("gw"), 1, 9)]);
        idx.stamp_rebuild([(key("gw"), 1, 9)]);
        idx.stamp_rebuild([(key("gw"), 1, 9)]);
        // Three rebuilds happened, but the gen-1 stamp stays at seq 1 — the
        // ack gate's target must not move on unrelated churn.
        assert_eq!(idx.current_seq(), 3);
        assert_eq!(
            idx.get(&key("gw")),
            Some(PublishStamp {
                generation: 1,
                fingerprint: 9,
                seq: 1
            })
        );
    }

    #[test]
    fn same_generation_content_change_re_stamps_at_the_current_rebuild() {
        let idx = SharedGatewayPublishIndex::new();
        idx.stamp_rebuild([(key("gw"), 1, 9)]);
        idx.stamp_rebuild([(key("gw"), 1, 9)]);
        // Same generation, new content fingerprint (e.g. a frontendValidation
        // CA resolving a rebuild later) — the gate target must move.
        idx.stamp_rebuild([(key("gw"), 1, 10)]);
        assert_eq!(
            idx.get(&key("gw")),
            Some(PublishStamp {
                generation: 1,
                fingerprint: 10,
                seq: 3
            })
        );
    }

    #[test]
    fn new_generation_re_stamps_at_the_current_rebuild() {
        let idx = SharedGatewayPublishIndex::new();
        idx.stamp_rebuild([(key("gw"), 1, 9)]);
        idx.stamp_rebuild([(key("gw"), 1, 9)]);
        idx.stamp_rebuild([(key("gw"), 2, 9)]);
        assert_eq!(
            idx.get(&key("gw")),
            Some(PublishStamp {
                generation: 2,
                fingerprint: 9,
                seq: 3
            })
        );
    }

    #[test]
    fn absent_gateway_drops_out_of_the_index() {
        let idx = SharedGatewayPublishIndex::new();
        idx.stamp_rebuild([(key("gw"), 1, 9), (key("other"), 4, 9)]);
        idx.stamp_rebuild([(key("other"), 4, 9)]);
        assert_eq!(idx.get(&key("gw")), None);
        assert_eq!(
            idx.get(&key("other")),
            Some(PublishStamp {
                generation: 4,
                fingerprint: 9,
                seq: 1
            })
        );
    }

    #[test]
    fn unpublished_gateway_reads_none() {
        let idx = SharedGatewayPublishIndex::new();
        assert_eq!(idx.get(&key("gw")), None);
        assert_eq!(idx.current_seq(), 0);
    }
}
