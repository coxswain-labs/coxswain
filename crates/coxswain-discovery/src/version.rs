//! Content-hash versioning for discovery snapshots.

/// Content hash of a per-scope snapshot DTO.
///
/// Doubles as the ACK/NACK flow-control token and the equality oracle for
/// "are the proxy's routing tables current?" (epic design decision #6 in #238).
/// Identical recompiles of the same routing world produce the same hash, so the
/// controller never pushes a snapshot the proxy already holds.
///
/// # Construction
///
/// Use [`ContentHash::compute`] — direct construction is intentionally blocked
/// by `#[non_exhaustive]`.
#[non_exhaustive]
pub struct ContentHash(String);

impl ContentHash {
    /// Compute the content hash over a serialised snapshot DTO.
    ///
    /// **Stub:** returns an empty hash until the wire DTO lands in T2 (#238).
    #[must_use]
    pub fn compute(_bytes: &[u8]) -> Self {
        Self(String::new())
    }

    /// Return the hash as a `&str` for embedding in proto `version` fields.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
