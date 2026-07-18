//! Content-hash versioning and wire-protocol versioning for discovery.
//!
//! The [`WIRE_VERSION`] constant identifies the binary protocol revision; both
//! the server and the client must agree on it or the stream is rejected with
//! `FAILED_PRECONDITION` before any snapshot is sent.

use sha2::{Digest, Sha256};

/// Wire protocol version spoken by this build.
///
/// Encoded as [`crate::proto::v1::Subscribe::wire_version`] on every stream open.
/// The server rejects any client that presents a different value with
/// `FAILED_PRECONDITION`; the client backs off permanently on that status.
///
/// ## Version history
///
/// - `1` (v0.5): initial SotW snapshot protocol; `Scope` carries a `oneof`
///   discriminator (`SharedPoolScope` / `GatewayScope`) so the server
///   dispatches per-subscriber snapshots.
/// - `2` (v0.6, #383): resource-oriented snapshot. `Snapshot` carries a flat,
///   canonical-key-addressed `repeated Resource resources` set (plus a `full`
///   flag and a `removed_resources` tombstone set) instead of nine whole-table
///   fields; backends reference an EDS-style `EndpointResource` by
///   `(namespace, service, port)` so endpoint churn re-sends only the endpoint
///   resource, not every route. Back-compat with v1 is dropped (no users).
pub const WIRE_VERSION: u32 = 2;

/// Content hash of a per-scope snapshot DTO.
///
/// Doubles as the ACK/NACK flow-control token and the equality oracle for
/// "are the proxy's routing tables current?" (epic design decision #6 in #238).
/// Identical recompiles of the same routing world produce the same hash, so the
/// controller never pushes a snapshot the proxy already holds.
///
/// ## Hash construction
///
/// Per-resource hash: `sha256(message.encode_to_vec())` where `message` is
/// the proto DTO with the `version`/`nonce` fields zeroed (i.e. computed over
/// data content only, not over the envelope header).
///
/// Global hash: `sha256(concat(sorted(per_resource_hex_strings)))` — sorting
/// the per-resource hashes before concatenating ensures the global hash is
/// independent of insertion/iteration order in the runtime HashMap/BTreeMap
/// structures.
///
/// # Construction
///
/// Use [`ContentHash::compute`] — direct construction is intentionally blocked
/// by `#[non_exhaustive]`.
#[non_exhaustive]
pub struct ContentHash(String);

impl ContentHash {
    /// Compute the sha256 content hash of `bytes` and return it as a lowercase
    /// hex string.
    ///
    /// **Per-resource usage:** call with `message.encode_to_vec()` after zeroing
    /// all envelope fields that should not influence the hash (e.g. `version`).
    ///
    /// **Global usage:** call with the concatenation of the *sorted* per-resource
    /// hex strings.  Sorting is the caller's responsibility — this function is
    /// pure over `bytes`.
    #[must_use]
    pub fn compute(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        Self(hex_encode(&digest))
    }

    /// Compute the global hash from a set of per-resource hex hashes.
    ///
    /// Borrows the digests (they live in the caller's `Arc<str>`-valued digest
    /// maps) and sorts a `&str` view before concatenating, so the result is
    /// independent of the order the controller's HashMap/BTreeMap iterators
    /// happened to yield the resources — without cloning any digest string.
    #[must_use]
    pub fn from_per_resource<'a>(hashes: impl IntoIterator<Item = &'a str>) -> Self {
        let mut hashes: Vec<&str> = hashes.into_iter().collect();
        hashes.sort_unstable();
        let mut combined = String::with_capacity(hashes.iter().map(|h| h.len()).sum());
        for h in hashes {
            combined.push_str(h);
        }
        Self::compute(combined.as_bytes())
    }

    /// Return the hash as a `&str` for embedding in proto `version` fields.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Encode raw bytes as a lowercase hex string without pulling in the `hex` crate.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_is_deterministic() {
        let h1 = ContentHash::compute(b"hello world");
        let h2 = ContentHash::compute(b"hello world");
        assert_eq!(h1.as_str(), h2.as_str());
    }

    #[test]
    fn compute_known_vector() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let h = ContentHash::compute(b"");
        assert_eq!(
            h.as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn from_per_resource_is_order_independent() {
        let h1 = ContentHash::from_per_resource(["aaa", "bbb"]);
        let h2 = ContentHash::from_per_resource(["bbb", "aaa"]);
        assert_eq!(h1.as_str(), h2.as_str());
    }
}
