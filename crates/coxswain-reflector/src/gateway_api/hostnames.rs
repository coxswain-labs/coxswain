//! Hostname matching and specificity ordering for Gateway API listener isolation.

/// Listener isolation priority: exact hostname > wildcard (longer = more specific) > empty.
/// Returns a numeric rank: 0 = empty, wildcard length, usize::MAX = exact.
pub(super) fn listener_specificity(hostname: &str) -> usize {
    if hostname.is_empty() {
        0
    } else if hostname.starts_with("*.") {
        hostname.len()
    } else {
        usize::MAX
    }
}

/// Returns true when `route_hostnames` and `listener_hostname` have at least one
/// hostname in common, according to Gateway API intersection semantics:
/// - Listener hostname `""` (absent) matches any route hostname.
/// - Route with no hostnames matches any listener hostname.
/// - Wildcard patterns (`*.example.com`) expand to match labels one level deep.
pub(crate) fn hostnames_intersect(route_hostnames: &[&str], listener_hostname: &str) -> bool {
    if listener_hostname.is_empty() {
        return true;
    }
    if route_hostnames.is_empty() {
        return true;
    }
    route_hostnames
        .iter()
        .any(|rh| hostname_matches(rh, listener_hostname))
}

pub(super) fn hostname_matches(route_host: &str, listener_host: &str) -> bool {
    if route_host == listener_host {
        return true;
    }
    // Route wildcard `*.X` matches listener `Y.X` (single label prefix).
    // Require that the prefix ends with a dot so "*.bar.com" does NOT match "foobar.com"
    // (where "bar.com" appears as a substring but not a domain label boundary).
    if let Some(suffix) = route_host.strip_prefix("*.")
        && let Some(prefix) = listener_host.strip_suffix(suffix)
        && let Some(prefix) = prefix.strip_suffix('.')
        && !prefix.is_empty()
        && !prefix.contains('.')
    {
        return true;
    }
    // Listener wildcard `*.X` matches route `Y.X` (any depth — Gateway API GEP-719).
    // Same dot-boundary requirement: "*.wildcard.io" must NOT match "anotherwildcard.io".
    if let Some(suffix) = listener_host.strip_prefix("*.")
        && let Some(prefix) = route_host.strip_suffix(suffix)
        && let Some(prefix) = prefix.strip_suffix('.')
        && !prefix.is_empty()
    {
        return true;
    }
    // Both wildcards: `*.A` and `*.B` intersect when one suffix is a subdomain of the
    // other — e.g. `*.example.com` and `*.com` intersect because any host matching the
    // narrower pattern also matches the wider one.
    if let Some(rs) = route_host.strip_prefix("*.")
        && let Some(ls) = listener_host.strip_prefix("*.")
        && (rs == ls
            || (rs.ends_with(ls) && rs[..rs.len() - ls.len()].ends_with('.'))
            || (ls.ends_with(rs) && ls[..ls.len() - rs.len()].ends_with('.')))
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{hostname_matches, hostnames_intersect, listener_specificity};

    // ── listener_specificity ──────────────────────────────────────────────────────

    #[test]
    fn specificity_empty_hostname_is_zero() {
        assert_eq!(listener_specificity(""), 0);
    }

    #[test]
    fn specificity_exact_hostname_is_max() {
        assert_eq!(listener_specificity("example.com"), usize::MAX);
        assert_eq!(listener_specificity("api.example.com"), usize::MAX);
    }

    #[test]
    fn specificity_wildcard_is_length() {
        let short = "*.io";
        let long = "*.example.com";
        assert_eq!(listener_specificity(short), short.len());
        assert_eq!(listener_specificity(long), long.len());
        assert!(listener_specificity(long) > listener_specificity(short));
        assert!(listener_specificity("example.com") > listener_specificity(long));
    }

    // ── hostnames_intersect ───────────────────────────────────────────────────────

    #[test]
    fn intersect_empty_listener_matches_any_route() {
        assert!(hostnames_intersect(&["example.com", "other.com"], ""));
        assert!(hostnames_intersect(&[], ""));
    }

    #[test]
    fn intersect_empty_route_matches_any_listener() {
        assert!(hostnames_intersect(&[], "example.com"));
        assert!(hostnames_intersect(&[], "*.example.com"));
    }

    #[test]
    fn intersect_exact_match() {
        assert!(hostnames_intersect(&["example.com"], "example.com"));
        assert!(!hostnames_intersect(&["other.com"], "example.com"));
    }

    #[test]
    fn intersect_route_wildcard_matches_listener_exact() {
        assert!(hostnames_intersect(&["*.example.com"], "api.example.com"));
        assert!(!hostnames_intersect(&["*.example.com"], "example.com"));
    }

    #[test]
    fn intersect_listener_wildcard_matches_route_exact() {
        assert!(hostnames_intersect(&["api.example.com"], "*.example.com"));
        assert!(!hostnames_intersect(&["example.com"], "*.example.com"));
    }

    #[test]
    fn intersect_any_of_multiple_routes_matches() {
        assert!(hostnames_intersect(
            &["other.com", "api.example.com"],
            "*.example.com"
        ));
        assert!(!hostnames_intersect(
            &["other.com", "unrelated.io"],
            "*.example.com"
        ));
    }

    // ── hostname_matches ──────────────────────────────────────────────────────────

    #[test]
    fn matches_identical_hostnames() {
        assert!(hostname_matches("example.com", "example.com"));
        assert!(hostname_matches("api.example.com", "api.example.com"));
    }

    #[test]
    fn matches_different_hostnames_returns_false() {
        assert!(!hostname_matches("example.com", "other.com"));
        assert!(!hostname_matches("api.example.com", "web.example.com"));
    }

    #[test]
    fn route_wildcard_matches_single_label_listener() {
        assert!(hostname_matches("*.example.com", "api.example.com"));
        assert!(hostname_matches("*.example.com", "web.example.com"));
    }

    #[test]
    fn route_wildcard_does_not_match_root_domain() {
        assert!(!hostname_matches("*.example.com", "example.com"));
    }

    #[test]
    fn route_wildcard_does_not_cross_label_boundary() {
        // "*.example.com" should not match "a.b.example.com" (multi-label prefix)
        assert!(!hostname_matches("*.example.com", "a.b.example.com"));
    }

    #[test]
    fn route_wildcard_does_not_match_partial_label() {
        // "*.bar.com" must NOT match "foobar.com" (bar.com is a suffix but not a label boundary)
        assert!(!hostname_matches("*.bar.com", "foobar.com"));
    }

    #[test]
    fn listener_wildcard_matches_route_exact() {
        assert!(hostname_matches("api.example.com", "*.example.com"));
        assert!(hostname_matches("web.example.com", "*.example.com"));
    }

    #[test]
    fn listener_wildcard_does_not_match_root_domain() {
        assert!(!hostname_matches("example.com", "*.example.com"));
    }

    #[test]
    fn listener_wildcard_matches_multi_label_route() {
        // Gateway API GEP-719: listener wildcard *.example.com matches
        // a.b.example.com (any depth prefix allowed for listener-side wildcard)
        assert!(hostname_matches("a.b.example.com", "*.example.com"));
    }

    #[test]
    fn listener_wildcard_does_not_match_partial_label() {
        assert!(!hostname_matches("anotherwildcard.io", "*.wildcard.io"));
    }

    #[test]
    fn wildcard_wildcard_same_suffix_intersects() {
        assert!(hostname_matches("*.example.com", "*.example.com"));
    }

    #[test]
    fn wildcard_wildcard_route_more_specific_intersects() {
        // *.example.com (route) is a subdomain of *.com (listener) — they intersect.
        assert!(hostname_matches("*.example.com", "*.com"));
    }

    #[test]
    fn wildcard_wildcard_listener_more_specific_intersects() {
        // *.com (route) overlaps with *.example.com (listener).
        assert!(hostname_matches("*.com", "*.example.com"));
    }

    #[test]
    fn wildcard_wildcard_unrelated_does_not_intersect() {
        assert!(!hostname_matches("*.foo.com", "*.bar.com"));
        assert!(!hostname_matches("*.foo.com", "*.com.bar"));
    }

    #[test]
    fn wildcard_wildcard_partial_suffix_boundary_does_not_intersect() {
        // "*.examplefoo.com" must NOT intersect "*.foo.com" — suffix matches but no dot boundary.
        assert!(!hostname_matches("*.examplefoo.com", "*.foo.com"));
    }
}
