//! `ReferenceGrant` key types and cross-namespace backend-ref permission checks.

use std::collections::HashSet;

/// A flattened entry from a `ReferenceGrant`, ready for O(1) lookup.
/// `to_name = None` means the grant covers any resource in `to_ns` (wildcard).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReferenceGrantKey {
    /// Namespace of the referencing resource (e.g. the HTTPRoute's namespace).
    pub from_ns: String,
    /// Namespace of the referenced resource (e.g. the Service's namespace).
    pub to_ns: String,
    /// Specific resource name permitted, or `None` for a wildcard grant.
    pub to_name: Option<String>,
}

impl ReferenceGrantKey {
    /// Build a key that permits access to exactly one named resource in `to_ns`.
    pub fn specific(
        from_ns: impl Into<String>,
        to_ns: impl Into<String>,
        to_name: impl Into<String>,
    ) -> Self {
        Self {
            from_ns: from_ns.into(),
            to_ns: to_ns.into(),
            to_name: Some(to_name.into()),
        }
    }

    /// Build a key that permits access to any resource in `to_ns`.
    pub fn wildcard(from_ns: impl Into<String>, to_ns: impl Into<String>) -> Self {
        Self {
            from_ns: from_ns.into(),
            to_ns: to_ns.into(),
            to_name: None,
        }
    }
}

/// Returns true if `grants` permits an HTTPRoute in `from_ns` to reference
/// a Service named `to_name` in `to_ns`.
pub fn backend_ref_allowed(
    from_ns: &str,
    to_ns: &str,
    to_name: &str,
    grants: &HashSet<ReferenceGrantKey>,
) -> bool {
    grants.contains(&ReferenceGrantKey::wildcard(from_ns, to_ns))
        || grants.contains(&ReferenceGrantKey::specific(from_ns, to_ns, to_name))
}
