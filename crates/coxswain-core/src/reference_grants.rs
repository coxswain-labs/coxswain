//! `ReferenceGrant` key types and cross-namespace backend-ref permission checks.

use std::collections::HashSet;
use std::marker::PhantomData;

/// A flattened entry from a `ReferenceGrant`, ready for O(1) lookup.
/// `to_name = None` means the grant covers any resource in `to_ns` (wildcard).
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

/// A [`ReferenceGrantKey`] set flattened for exactly one `(from.group, from.kind,
/// to.kind)` triple — e.g. `HTTPRoute → Service` vs `GRPCRoute → Service` vs
/// `Gateway → Secret`.
///
/// `K` is a zero-sized marker type (never constructed) naming which triple this
/// set was flattened for; it carries no runtime data. Without it, every flattened
/// set is an indistinguishable bare `HashSet<ReferenceGrantKey>` — nothing stops
/// an `HTTPRoute`-flattened set from being passed where a `GRPCRoute`-flattened
/// one is expected, since the two are structurally identical types. That gap is
/// exactly what let `GRPCRoute`, `TLSRoute`, and `CoxswainExternalAuth` backend
/// refs get checked against the `HTTPRoute` grant set for a release (#691).
/// Parameterizing by `K` turns that mistake into a compile error: a
/// `GrantSet<HttpRouteBackend>` cannot be passed where a `GrantSet<GrpcRouteBackend>`
/// is expected. The concrete marker types live in `coxswain-reflector` (the crate
/// that knows about `HTTPRoute`/`GRPCRoute`/etc.) — this crate only provides the
/// generic mechanism.
pub struct GrantSet<K> {
    keys: HashSet<ReferenceGrantKey>,
    _kind: PhantomData<fn() -> K>,
}

// Manual impls, not `#[derive(..)]`: deriving would add a `K: Trait` bound to
// every impl even though `K` is never stored (only `PhantomData<fn() -> K>` is),
// which would wrongly force every marker type to implement Clone/Debug/etc.
impl<K> Clone for GrantSet<K> {
    fn clone(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            _kind: PhantomData,
        }
    }
}

impl<K> std::fmt::Debug for GrantSet<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantSet")
            .field("keys", &self.keys)
            .finish()
    }
}

impl<K> PartialEq for GrantSet<K> {
    fn eq(&self, other: &Self) -> bool {
        self.keys == other.keys
    }
}

impl<K> Eq for GrantSet<K> {}

impl<K> Default for GrantSet<K> {
    fn default() -> Self {
        Self {
            keys: HashSet::new(),
            _kind: PhantomData,
        }
    }
}

impl<K> GrantSet<K> {
    /// An empty grant set — denies every cross-namespace reference.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Number of flattened grant keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when no grant is present — every cross-namespace reference is denied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Iterate the flattened keys, e.g. to fold them into a fingerprint.
    pub fn iter(&self) -> impl Iterator<Item = &ReferenceGrantKey> {
        self.keys.iter()
    }

    /// True when `key` was flattened into this set.
    #[must_use]
    pub fn contains(&self, key: &ReferenceGrantKey) -> bool {
        self.keys.contains(key)
    }
}

impl<K> FromIterator<ReferenceGrantKey> for GrantSet<K> {
    fn from_iter<T: IntoIterator<Item = ReferenceGrantKey>>(iter: T) -> Self {
        Self {
            keys: iter.into_iter().collect(),
            _kind: PhantomData,
        }
    }
}

/// Returns true if a `K`-kinded referrer in `from_ns` is permitted to reference
/// a `to_name` resource in `to_ns`, per `grants`. `K` pins `grants` to the one
/// `(from.kind, to.kind)` triple it was flattened for — see [`GrantSet`].
pub fn backend_ref_allowed<K>(
    from_ns: &str,
    to_ns: &str,
    to_name: &str,
    grants: &GrantSet<K>,
) -> bool {
    grants
        .keys
        .contains(&ReferenceGrantKey::wildcard(from_ns, to_ns))
        || grants
            .keys
            .contains(&ReferenceGrantKey::specific(from_ns, to_ns, to_name))
}

#[cfg(test)]
mod tests {
    use crate::reference_grants::*;

    /// Test-only marker — the kind-isolation the real markers provide isn't
    /// under test here, only the key-matching logic itself.
    struct TestKind;

    fn grants(entries: &[(&str, &str, Option<&str>)]) -> GrantSet<TestKind> {
        entries
            .iter()
            .map(|(f, t, n)| match n {
                Some(name) => ReferenceGrantKey::specific(*f, *t, *name),
                None => ReferenceGrantKey::wildcard(*f, *t),
            })
            .collect()
    }

    #[test]
    fn wildcard_grant_permits_any_service() {
        let g = grants(&[("apps", "billing", None)]);
        assert!(backend_ref_allowed("apps", "billing", "payments", &g));
        assert!(backend_ref_allowed("apps", "billing", "other-svc", &g));
    }

    #[test]
    fn specific_grant_permits_named_service() {
        let g = grants(&[("apps", "billing", Some("payments"))]);
        assert!(backend_ref_allowed("apps", "billing", "payments", &g));
    }

    #[test]
    fn specific_grant_denies_different_service() {
        let g = grants(&[("apps", "billing", Some("payments"))]);
        assert!(!backend_ref_allowed("apps", "billing", "other-svc", &g));
    }

    #[test]
    fn denied_when_from_ns_mismatch() {
        let g = grants(&[("apps", "billing", None)]);
        assert!(!backend_ref_allowed("other", "billing", "payments", &g));
    }

    #[test]
    fn denied_when_to_ns_mismatch() {
        let g = grants(&[("apps", "billing", None)]);
        assert!(!backend_ref_allowed("apps", "other", "payments", &g));
    }

    #[test]
    fn denied_on_empty_grants() {
        assert!(!backend_ref_allowed(
            "apps",
            "billing",
            "payments",
            &GrantSet::<TestKind>::empty()
        ));
    }

    #[test]
    fn wildcard_and_specific_coexist() {
        let g = grants(&[
            ("apps", "billing", None),
            ("apps", "billing", Some("payments")),
        ]);
        assert!(backend_ref_allowed("apps", "billing", "payments", &g));
        assert!(backend_ref_allowed("apps", "billing", "anything", &g));
    }
}
