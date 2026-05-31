use std::collections::HashSet;

/// Returns true if `grants` permits an HTTPRoute in `from_ns` to reference
/// a Service named `to_name` in `to_ns`.
///
/// `grants` is a pre-flattened set of `(from_ns, to_ns, to_name)` tuples
/// derived from `ReferenceGrant` objects.  `None` as the third element
/// represents a wildcard grant (any Service in `to_ns` is permitted).
pub fn backend_ref_allowed(
    from_ns: &str,
    to_ns: &str,
    to_name: &str,
    grants: &HashSet<(String, String, Option<String>)>,
) -> bool {
    let wildcard = (from_ns.to_string(), to_ns.to_string(), None);
    let specific = (
        from_ns.to_string(),
        to_ns.to_string(),
        Some(to_name.to_string()),
    );
    grants.contains(&wildcard) || grants.contains(&specific)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grants(entries: &[(&str, &str, Option<&str>)]) -> HashSet<(String, String, Option<String>)> {
        entries
            .iter()
            .map(|(f, t, n)| (f.to_string(), t.to_string(), n.map(str::to_string)))
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
