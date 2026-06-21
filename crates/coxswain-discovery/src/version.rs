//! Content-hash versioning for discovery snapshots.

use sha2::{Digest, Sha256};

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
    /// Sorts `hashes` in place before concatenating so the result is
    /// independent of the order the controller's HashMap/BTreeMap iterators
    /// happened to yield the resources.
    #[must_use]
    pub fn from_per_resource(mut hashes: Vec<String>) -> Self {
        hashes.sort_unstable();
        let combined: String = hashes.concat();
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
        let h1 = ContentHash::from_per_resource(vec!["aaa".to_string(), "bbb".to_string()]);
        let h2 = ContentHash::from_per_resource(vec!["bbb".to_string(), "aaa".to_string()]);
        assert_eq!(h1.as_str(), h2.as_str());
    }
}
