//! `node_id` collision guard (#682): binds each connected `node_id` to the
//! authenticated identity that claimed it, so a differently-identified peer
//! cannot silently reclaim another node's `node_id` and, on its own
//! disconnect, evict registry state that belongs to the real node.
//!
//! #666 shipped a narrower version of this scoped to rows already marked
//! `is_relay` — sufficient to close the one blast radius that mattered then
//! (a relay's `evict_children` cascade), but leaving an ordinary leaf's
//! `node_id` unauthenticated. This generalizes the same guard to every
//! stream, kept here in `coxswain-discovery` rather than folded into
//! `coxswain-core`'s `NodeEntry` — that type is `pub` and serialized for the
//! admin topology API, and a SPIFFE identity fingerprint has no business
//! riding that surface for a purely server-internal admission check.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

/// `node_id → (identity fingerprint, claim generation)` of the
/// currently-connected holder.
///
/// `None` fingerprint represents the plaintext/no-`PeerSvid` path
/// (test/degraded mode) — every plaintext peer fingerprints identically (see
/// [`crate::auth::PeerSvid::fingerprint`]), so this path is unprotected by
/// design; production discovery mandates mTLS end-to-end.
///
/// The generation exists so [`release_node_id`] can identify *this exact
/// claim*, not merely "a claim with a matching fingerprint" — a same-identity
/// reconnect gets a fresh generation on every [`claim_node_id`] call, so the
/// stale session it replaced can never release the new one out from under it
/// (see [`release_node_id`]'s doc for the race this closes).
pub(super) type LiveNodeIdentities = Arc<Mutex<HashMap<String, (Option<String>, u64)>>>;

/// Monotonic counter minting a unique generation for every granted claim,
/// process-wide. Not reset per `node_id` — uniqueness across the whole
/// process is what makes a stale claim's generation unable to match a fresh
/// one, which is the only property [`release_node_id`] needs.
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Claim `node_id` for `fingerprint`, or refuse if it is already held by a
/// **different** fingerprint.
///
/// Returns `Some(generation)` when the claim is granted — a first claim, or
/// the same identity reconnecting
/// ([`coxswain_core::node_registry::NodeRegistryHandle::connect`]'s
/// documented rapid-reconnect tolerance, preserved here rather than defeated
/// by this guard). The caller must retain `generation` and pass it back to
/// [`release_node_id`] on shutdown — releasing by fingerprint alone would let
/// a stale session's deferred cleanup delete a fresh reconnect's live claim
/// (same fingerprint, different session). Returns `None` when a different
/// identity currently holds `node_id`; the caller must refuse the stream
/// without registering it.
pub(super) fn claim_node_id(
    map: &LiveNodeIdentities,
    node_id: &str,
    fingerprint: &Option<String>,
) -> Option<u64> {
    let mut guard = map.lock();
    if let Some((existing_fp, _)) = guard.get(node_id)
        && existing_fp != fingerprint
    {
        return None;
    }
    let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
    guard.insert(node_id.to_owned(), (fingerprint.clone(), generation));
    Some(generation)
}

/// Release `node_id`'s claim, but only if `generation` still matches the
/// value [`claim_node_id`] returned for it.
///
/// Compare-and-remove **by generation**, not by fingerprint: a same-identity
/// reconnect (session B) is granted a claim while the prior session (A) for
/// that identity is still shutting down — A's stream-close and B's
/// stream-accept are scheduled independently, with no ordering guarantee.
/// When A's deferred shutdown finally calls this, comparing by fingerprint
/// alone would match (A and B share the same identity) and delete B's live
/// claim, reopening the window this guard exists to close: any peer could
/// then win `claim_node_id` on the now-vacant `node_id` and, on its own
/// disconnect, trigger `evict_children` against the real node's row. Each
/// grant gets a fresh generation precisely so A's own (now-stale) generation
/// can never match B's.
///
/// Returns `true` when this call actually removed the entry — i.e. the
/// caller's session was still the one holding the claim. The caller **must**
/// gate every other registry mutation it was about to perform on shutdown
/// (`disconnect`, `evict_children`) on this return value: a superseded
/// session (this returns `false`) is not the current owner of `node_id`'s
/// registry row either — `connect()` already overwrote it for session B — so
/// touching the registry from A's shutdown would corrupt B's live state, not
/// merely leave a stale claim behind.
pub(super) fn release_node_id(map: &LiveNodeIdentities, node_id: &str, generation: u64) -> bool {
    let mut guard = map.lock();
    if guard.get(node_id).is_some_and(|(_, g)| *g == generation) {
        guard.remove(node_id);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_map() -> LiveNodeIdentities {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[test]
    fn first_claim_always_succeeds() {
        let map = empty_map();
        assert!(claim_node_id(&map, "n1", &Some("fp-a".to_owned())).is_some());
    }

    #[test]
    fn same_identity_reclaims_its_own_node_id() {
        let map = empty_map();
        let fp = Some("fp-a".to_owned());
        assert!(claim_node_id(&map, "n1", &fp).is_some());
        assert!(
            claim_node_id(&map, "n1", &fp).is_some(),
            "the same identity reconnecting must not be refused"
        );
    }

    #[test]
    fn same_identity_reconnect_gets_a_fresh_generation() {
        let map = empty_map();
        let fp = Some("fp-a".to_owned());
        let gen_a = claim_node_id(&map, "n1", &fp).expect("first claim");
        let gen_b = claim_node_id(&map, "n1", &fp).expect("reconnect claim");
        assert_ne!(
            gen_a, gen_b,
            "a reconnect must be issued a NEW generation, not inherit the stale one"
        );
    }

    #[test]
    fn different_identity_is_refused() {
        let map = empty_map();
        assert!(claim_node_id(&map, "n1", &Some("fp-a".to_owned())).is_some());
        assert!(
            claim_node_id(&map, "n1", &Some("fp-b".to_owned())).is_none(),
            "a different fingerprint must be refused the same node_id"
        );
    }

    #[test]
    fn plaintext_peers_are_indistinguishable_by_design() {
        let map = empty_map();
        assert!(claim_node_id(&map, "n1", &None).is_some());
        assert!(
            claim_node_id(&map, "n1", &None).is_some(),
            "two absent-PeerSvid claims must not collide with each other"
        );
    }

    #[test]
    fn release_only_clears_the_matching_generation() {
        let map = empty_map();
        let fp = Some("fp-a".to_owned());
        let gen_a = claim_node_id(&map, "n1", &fp).expect("first claim");

        // Same-identity reconnect (session B) wins a fresh claim while A is
        // still shutting down.
        let gen_b = claim_node_id(&map, "n1", &fp).expect("reconnect claim");
        assert_ne!(gen_a, gen_b);

        // A's deferred shutdown releases its OWN (now-stale) generation —
        // this must NOT clear B's live claim, even though they share a
        // fingerprint. The `false` return is load-bearing: the caller must
        // use it to skip mutating the registry, since B's row already
        // superseded A's.
        assert!(
            !release_node_id(&map, "n1", gen_a),
            "a stale generation must report that nothing was released"
        );
        assert!(
            claim_node_id(&map, "n1", &Some("attacker".to_owned())).is_none(),
            "B's live claim must survive A's stale release — a different \
             identity must still be refused"
        );

        // B's own shutdown releases its correct generation — now the
        // node_id is genuinely free.
        assert!(
            release_node_id(&map, "n1", gen_b),
            "the correct generation must report that it released the claim"
        );
        assert!(
            claim_node_id(&map, "n1", &Some("attacker".to_owned())).is_some(),
            "a release with the CORRECT generation must free the node_id"
        );
    }
}
