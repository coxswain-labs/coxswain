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
    false
}
