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

#[cfg(test)]
mod tests {
    use super::*;

    fn grants(entries: &[(&str, &str, Option<&str>)]) -> HashSet<ReferenceGrantKey> {
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
            &HashSet::new()
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
