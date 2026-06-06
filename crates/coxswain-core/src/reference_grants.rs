use std::collections::HashSet;

/// A flattened entry from a `ReferenceGrant`, ready for O(1) lookup.
/// `to_name = None` means the grant covers any resource in `to_ns` (wildcard).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReferenceGrantKey {
    pub from_ns: String,
    pub to_ns: String,
    pub to_name: Option<String>,
}

impl ReferenceGrantKey {
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
