//! Per-host path router: exact, prefix, and regex path matching with predicate filtering.

use super::entry::{
    BackendGroup, FilterAction, RouteConflict, RouteEntry, RouteInfo, RouteKind, RouteTimeouts,
};
use super::predicate::RequestContext;
use matchit::Router;
use regex::RegexSet;
use std::cmp::Reverse;
use std::sync::Arc;
use std::time::SystemTime;

/// Return type of `HostRouter::route`: backend group + filters + timeouts +
/// path pattern + metric route id + optional error status.
pub(super) type RouteMatch = (
    Arc<BackendGroup>,
    Arc<[FilterAction]>,
    RouteTimeouts,
    Arc<str>,
    Arc<str>,
    Option<u16>,
);

/// Compiled path router for a single hostname, supporting exact, prefix, and regex patterns.
#[non_exhaustive]
pub struct HostRouter {
    router: Router<Box<[Arc<RouteEntry>]>>,
    regex_routes: Vec<(RegexSet, Box<[Arc<RouteEntry>]>)>,
    has_query_predicates: bool,
    route_info: Vec<RouteInfo>,
}

impl HostRouter {
    /// All registered path rules, in insertion order, for introspection.
    pub fn routes(&self) -> &[RouteInfo] {
        &self.route_info
    }

    /// Resolves `path` to an upstream, filters, and timeouts, applying predicates from `ctx`.
    ///
    /// Checks matchit exact/prefix routes first, then the regex fallback.
    /// Within each path slot, candidates are evaluated in specificity order;
    /// the first candidate whose predicates all pass is returned.
    pub fn route(&self, path: &str, ctx: &RequestContext<'_>) -> Option<RouteMatch> {
        if let Ok(m) = self.router.at(path) {
            for entry in m.value.iter() {
                if entry.predicates.matches(ctx) {
                    return Some((
                        Arc::clone(&entry.backend_group),
                        Arc::clone(&entry.filters),
                        entry.timeouts.clone(),
                        Arc::clone(&entry.path_pattern),
                        Arc::clone(&entry.metric_route_id),
                        entry.error_status,
                    ));
                }
            }
        }
        // Regex fallback: each slot holds its own RegexSet for a single pattern group;
        // insertion order across patterns is preserved by Vec position.
        for (set, entries) in &self.regex_routes {
            if set.is_match(path) {
                for entry in entries.iter() {
                    if entry.predicates.matches(ctx) {
                        return Some((
                            Arc::clone(&entry.backend_group),
                            Arc::clone(&entry.filters),
                            entry.timeouts.clone(),
                            Arc::clone(&entry.path_pattern),
                            Arc::clone(&entry.metric_route_id),
                            entry.error_status,
                        ));
                    }
                }
            }
        }
        None
    }

    /// Whether any registered route on this host uses query-parameter predicates.
    ///
    /// The proxy uses this to skip query-string parsing when it's unnecessary.
    pub fn has_query_predicates(&self) -> bool {
        self.has_query_predicates
    }
}

/// Sort key for within-path specificity ordering per Gateway API rules.
///
/// Priority: method match > header matches > query matches > oldest timestamp.
/// Method presence outranks header count because the spec defines method matching
/// at a higher precedence tier than header matching.
fn specificity_key(
    entry: &Arc<RouteEntry>,
    insertion_idx: usize,
) -> (
    Reverse<usize>,
    Reverse<usize>,
    Reverse<usize>,
    u128,
    String,
    usize,
) {
    let has_method = entry.predicates.method.is_some() as usize;
    let ts = entry
        .created_at
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_millis())
        .unwrap_or(u128::MAX);
    (
        Reverse(has_method),
        Reverse(entry.predicates.headers.len()),
        Reverse(entry.predicates.query.len()),
        ts,
        entry.route_id.clone(),
        insertion_idx,
    )
}

/// Groups a flat list of `(path, entry)` pairs by path, preserving insertion order
/// within each group for the insertion-index tiebreaker.
type PathGroups = Vec<(String, Vec<(usize, Arc<RouteEntry>)>)>;

fn group_by_path(routes: Vec<(String, Arc<RouteEntry>)>) -> PathGroups {
    let mut groups: PathGroups = Vec::new();
    for (global_idx, (path, entry)) in routes.into_iter().enumerate() {
        if let Some(g) = groups.iter_mut().find(|(p, _)| p == &path) {
            g.1.push((global_idx, entry));
        } else {
            groups.push((path, vec![(global_idx, entry)]));
        }
    }
    groups
}

/// Sorts a group's entries by specificity and freezes them into a boxed slice.
fn sort_and_freeze(entries: Vec<(usize, Arc<RouteEntry>)>) -> Box<[Arc<RouteEntry>]> {
    let mut entries = entries;
    entries.sort_by_key(|(idx, e)| specificity_key(e, *idx));
    entries
        .into_iter()
        .map(|(_, e)| e)
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

/// Builder for a [`HostRouter`]; accumulates routes then compiles them in one pass.
#[non_exhaustive]
#[derive(Default)]
pub struct HostRouterBuilder {
    exact_routes: Vec<(String, Arc<RouteEntry>)>,
    prefix_routes: Vec<(String, Arc<RouteEntry>)>,
    regex_routes: Vec<(String, Arc<RouteEntry>)>,
}

impl HostRouterBuilder {
    /// Register an exact-path route.
    pub fn add_exact_route(&mut self, path: &str, entry: Arc<RouteEntry>) -> &mut Self {
        self.exact_routes.push((path.to_string(), entry));
        self
    }

    /// Register a prefix-path route (Gateway API `PathMatchPathPrefix` semantics).
    pub fn add_prefix_route(&mut self, path: &str, entry: Arc<RouteEntry>) -> &mut Self {
        self.prefix_routes.push((path.to_string(), entry));
        self
    }

    /// Register a regex-path route.
    pub fn add_regex_route(&mut self, pattern: &str, entry: Arc<RouteEntry>) -> &mut Self {
        self.regex_routes.push((pattern.to_string(), entry));
        self
    }

    /// Compiles accumulated routes into an immutable [`HostRouter`], returning any
    /// [`RouteConflict`]s for prefix path groups that were shadowed by an
    /// earlier-inserted pattern (one per shadowed group, with `host`/`port` left
    /// for the caller to stamp).
    ///
    /// # Errors
    /// Returns [`RouterError::MatchitInsert`] if an exact-path pattern is rejected
    /// by the `matchit` router. Returns [`RouterError::Regex`] if a regex pattern
    /// fails to compile.
    pub(crate) fn build(
        self,
    ) -> Result<(HostRouter, Vec<RouteConflict>), super::table::RouterError> {
        let mut router: Router<Box<[Arc<RouteEntry>]>> = Router::new();
        let mut route_info: Vec<RouteInfo> = Vec::new();
        let mut conflicts: Vec<RouteConflict> = Vec::new();
        let mut has_query_predicates = false;

        // Track whether any entry uses query predicates.
        let check_query = |entries: &Vec<(usize, Arc<RouteEntry>)>| {
            entries.iter().any(|(_, e)| !e.predicates.query.is_empty())
        };

        // ── Exact routes ──────────────────────────────────────────────────────
        let exact_groups = group_by_path(self.exact_routes);
        for (path, entries) in exact_groups {
            if check_query(&entries) {
                has_query_predicates = true;
            }
            for (_, e) in &entries {
                route_info.push(RouteInfo {
                    path: path.clone(),
                    kind: RouteKind::Exact,
                    backend_group: Arc::clone(&e.backend_group),
                    route_id: e.route_id.clone(),
                });
            }
            let frozen = sort_and_freeze(entries);
            // Inserting into a fresh router; unique patterns won't conflict.
            router.insert(path, frozen)?;
        }

        // ── Prefix routes ─────────────────────────────────────────────────────
        let log_conflict =
            |entries: &[Arc<RouteEntry>], pattern: &str, err: &matchit::InsertError| {
                use std::collections::BTreeSet;
                let ids: BTreeSet<&str> = entries.iter().map(|e| e.route_id.as_str()).collect();
                let ids: Vec<&str> = ids.into_iter().collect();
                tracing::debug!(
                    pattern = %pattern,
                    routes = ?ids,
                    error = %err,
                    "host router prefix insert shadowed by earlier rule"
                );
            };

        let prefix_groups = group_by_path(self.prefix_routes);
        for (path, entries) in prefix_groups {
            if check_query(&entries) {
                has_query_predicates = true;
            }
            for (_, e) in &entries {
                route_info.push(RouteInfo {
                    path: path.clone(),
                    kind: RouteKind::Prefix,
                    backend_group: Arc::clone(&e.backend_group),
                    route_id: e.route_id.clone(),
                });
            }
            let frozen = sort_and_freeze(entries);

            // A matchit insert failure means this group's pattern collides with an
            // earlier-inserted pattern, so the whole group is shadowed (silently
            // dropped). One group triggers up to three insert attempts; `shadowed`
            // collapses them into a single recorded conflict below.
            let mut shadowed = false;

            // Gateway API prefix semantics:
            //   "/foo"  matches /foo, /foo/, /foo/anything
            //   "/foo/" matches /foo/, /foo/anything (NOT /foo)
            //   "/"     matches everything
            // matchit 0.9.2 does not route "/v2/" to "/v2/{*rest}" — we must
            // insert "/v2/" explicitly to bridge the gap.
            let had_trailing_slash = path.ends_with('/');
            let base = path.trim_end_matches('/');
            if base.is_empty() {
                if let Err(e) = router.insert("/", frozen.clone()) {
                    log_conflict(&frozen, "/", &e);
                    shadowed = true;
                }
                if let Err(e) = router.insert("/{*rest}", frozen.clone()) {
                    log_conflict(&frozen, "/{*rest}", &e);
                    shadowed = true;
                }
            } else {
                if !had_trailing_slash
                    && let Err(e) = router.insert(base.to_string(), frozen.clone())
                {
                    log_conflict(&frozen, base, &e);
                    shadowed = true;
                }
                let with_slash = format!("{base}/");
                if let Err(e) = router.insert(with_slash.clone(), frozen.clone()) {
                    log_conflict(&frozen, &with_slash, &e);
                    shadowed = true;
                }
                let wildcard = format!("{base}/{{*rest}}");
                if let Err(e) = router.insert(wildcard.clone(), frozen.clone()) {
                    log_conflict(&frozen, &wildcard, &e);
                    shadowed = true;
                }
            }

            // Record one conflict per shadowed group, attributed to the
            // highest-precedence entry (`frozen` is already specificity-sorted).
            // `host`/`port` are placeholders; `PortRoutingTableBuilder::build`
            // stamps the real values.
            if shadowed && let Some(rep) = frozen.first() {
                conflicts.push(RouteConflict {
                    port: 0,
                    host: String::new(),
                    path: path.clone(),
                    kind: RouteKind::Prefix,
                    rejected_group: rep.backend_group.name().to_string(),
                    rejected_route_id: rep.route_id.clone(),
                });
            }
        }

        // ── Regex routes ──────────────────────────────────────────────────────
        // Group by pattern so multiple entries for the same regex accumulate.
        let regex_groups = group_by_path(self.regex_routes);
        let mut compiled_regex_routes: Vec<(RegexSet, Box<[Arc<RouteEntry>]>)> = Vec::new();
        for (pattern, entries) in regex_groups {
            if check_query(&entries) {
                has_query_predicates = true;
            }
            for (_, e) in &entries {
                route_info.push(RouteInfo {
                    path: pattern.clone(),
                    kind: RouteKind::Regex,
                    backend_group: Arc::clone(&e.backend_group),
                    route_id: e.route_id.clone(),
                });
            }
            // RegexSet::new already validates the pattern; the second compile is redundant.
            let set = RegexSet::new([&pattern])?;
            let frozen = sort_and_freeze(entries);
            compiled_regex_routes.push((set, frozen));
        }

        Ok((
            HostRouter {
                router,
                regex_routes: compiled_regex_routes,
                has_query_predicates,
                route_info,
            },
            conflicts,
        ))
    }
}

/// How a wildcard hostname pattern matches incoming request hosts.
///
/// The two mainstream specs disagree on wildcard semantics:
/// - **Gateway API** `Hostname` type: `*.example.com` matches any number of
///   subdomain labels (`a.example.com`, `a.b.example.com`, `a.b.c.example.com`).
/// - **Kubernetes Ingress** spec: `*.example.com` matches exactly one DNS label
///   (`a.example.com` only; `a.b.example.com` does not match).
///
/// Routes registered from Ingress resources use `SingleLabel`; routes from
/// Gateway API resources use `MultiLabel`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WildcardKind {
    /// Ingress spec: the wildcard matches exactly one subdomain label.
    SingleLabel,
    /// Gateway API spec: the wildcard matches any number of subdomain labels.
    MultiLabel,
}

/// Returns `true` when `host` matches the wildcard pattern `*.{suffix}` under the given semantics.
///
/// Both kinds require `host` to end with `.{suffix}` and the prefix to be non-empty.
/// `SingleLabel` additionally requires the prefix to contain no dots (one label only).
/// `MultiLabel` accepts any non-empty prefix.
///
/// Listener isolation still works correctly because `wildcard_hosts` is sorted
/// longest-suffix-first: the more specific `*.foo.example.com` is checked
/// before `*.example.com`, so `bar.foo.example.com` hits the more-specific
/// entry first and never falls through to the less-specific one.
pub(super) fn wildcard_matches(host: &str, suffix: &str, kind: WildcardKind) -> bool {
    if let Some(rest) = host.strip_suffix(suffix)
        && let Some(prefix) = rest.strip_suffix('.')
        && !prefix.is_empty()
    {
        return match kind {
            WildcardKind::SingleLabel => !prefix.contains('.'),
            WildcardKind::MultiLabel => true,
        };
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::tests::*;
    use std::sync::Arc;

    #[test]
    fn wildcard_host_multi_label_matches() {
        let up = make_group("svc", "10.0.0.1:80");

        let mut b = RoutingTableBuilder::new();
        b.for_port(PORT)
            .wildcard_host("*.test.com", WildcardKind::MultiLabel)
            .add_exact_route("/", entry(up));

        let table = b.build().unwrap();
        // Single-label subdomain always matches.
        assert!(table.route(PORT, "api.test.com", "/", &ctx_get()).is_some());
        // Bare suffix does not match (prefix must be non-empty).
        assert!(table.route(PORT, "test.com", "/", &ctx_get()).is_none());
        // Gateway API spec: `*` matches any number of subdomain labels.
        assert!(
            table
                .route(PORT, "nested.api.test.com", "/", &ctx_get())
                .is_some()
        );
    }

    #[test]
    fn wildcard_host_single_label_matches() {
        let up = make_group("svc", "10.0.0.1:80");

        let mut b = RoutingTableBuilder::new();
        b.for_port(PORT)
            .wildcard_host("*.test.com", WildcardKind::SingleLabel)
            .add_exact_route("/", entry(up));

        let table = b.build().unwrap();
        // Single-label subdomain matches.
        assert!(table.route(PORT, "api.test.com", "/", &ctx_get()).is_some());
        // Bare suffix does not match.
        assert!(table.route(PORT, "test.com", "/", &ctx_get()).is_none());
        // Ingress spec: multi-label subdomain must NOT match.
        assert!(
            table
                .route(PORT, "nested.api.test.com", "/", &ctx_get())
                .is_none()
        );
    }

    #[test]
    fn prefix_shadow_records_conflict_with_rejected_route() {
        let first = make_group("first", "10.0.0.1:80");
        let second = make_group("second", "10.0.0.2:80");

        let mut b = RoutingTableBuilder::new();
        let host = b.for_port(PORT).exact_host("example.com");
        // /foo (added first) claims /foo, /foo/, /foo/{*rest}; /foo/ (added second)
        // collides on /foo/ and /foo/{*rest} and is the shadowed group.
        host.add_prefix_route(
            "/foo",
            Arc::new(RouteEntry::path_only(
                first,
                "default/first-route".to_string(),
                None,
            )),
        );
        host.add_prefix_route(
            "/foo/",
            Arc::new(RouteEntry::path_only(
                second,
                "default/second-route".to_string(),
                None,
            )),
        );

        let table = b.build().unwrap();
        let conflicts = table.conflicts();
        assert_eq!(
            conflicts.len(),
            1,
            "exactly one conflict for the shadowed group"
        );
        let c = &conflicts[0];
        assert_eq!(c.host, "example.com");
        assert_eq!(c.port, PORT);
        assert_eq!(c.path, "/foo/");
        assert!(matches!(c.kind, RouteKind::Prefix));
        assert_eq!(c.rejected_route_id, "default/second-route");
        assert_eq!(c.rejected_group, "second");
    }

    #[test]
    fn same_path_different_predicates_is_not_a_conflict() {
        // Two routes on the SAME path differentiated by predicates are merged into
        // one group and coexist — legitimate, not a shadow conflict.
        let specific = make_group("specific", "10.0.0.1:80");
        let generic = make_group("generic", "10.0.0.2:80");
        let with_header = Arc::new(RouteEntry::new(
            specific,
            make_predicates(None, &[("x-tenant", "acme")], &[]),
            "default/specific".to_string(),
            None,
        ));
        let plain = Arc::new(RouteEntry::path_only(
            generic,
            "default/generic".to_string(),
            None,
        ));

        let mut b = RoutingTableBuilder::new();
        let host = b.for_port(PORT).exact_host("example.com");
        host.add_prefix_route("/api", with_header);
        host.add_prefix_route("/api", plain);

        let table = b.build().unwrap();
        assert!(
            table.conflicts().is_empty(),
            "same-path predicate coexistence must not be reported as a conflict"
        );
    }

    #[test]
    fn specificity_ordering_more_headers_wins() {
        // Two entries at the same path: one with a header predicate, one without.
        // The one with more predicates should win when its predicate passes.
        let specific_up = make_group("specific", "10.0.0.1:80");
        let generic_up = make_group("generic", "10.0.0.2:80");

        let pred = make_predicates(None, &[("x-tenant", "acme")], &[]);
        let specific = Arc::new(RouteEntry::new(
            Arc::clone(&specific_up),
            pred,
            "default/specific".to_string(),
            None,
        ));
        let generic = Arc::new(RouteEntry::path_only(
            Arc::clone(&generic_up),
            "default/generic".to_string(),
            None,
        ));

        let mut b = RoutingTableBuilder::new();
        // Insert generic first, specific second — specificity sort should reorder.
        let hb = b.for_port(PORT).exact_host("example.com");
        hb.add_exact_route("/", Arc::clone(&generic));
        hb.add_exact_route("/", Arc::clone(&specific));

        let table = b.build().unwrap();
        use crate::routing::tests::headers_from;
        let headers_match = headers_from(&[("x-tenant", "acme")]);
        let headers_no = headers_from(&[]);

        use http::Method;
        let ctx_match = RequestContext {
            method: &Method::GET,
            headers: &headers_match,
            query: None,
        };
        let ctx_no = RequestContext {
            method: &Method::GET,
            headers: &headers_no,
            query: None,
        };

        // With matching header → specific wins (sorted first due to header count).
        assert_eq!(
            table
                .route(PORT, "example.com", "/", &ctx_match)
                .unwrap()
                .name(),
            "specific"
        );
        // Without matching header → specific's predicate fails; falls through to generic.
        assert_eq!(
            table
                .route(PORT, "example.com", "/", &ctx_no)
                .unwrap()
                .name(),
            "generic"
        );
    }

    #[test]
    fn or_semantics_across_multiple_entries() {
        // Two entries at the same path with different header predicates:
        // whichever predicate matches the request wins.
        let up_a = make_group("a", "10.0.0.1:80");
        let up_b = make_group("b", "10.0.0.2:80");

        let pred_a = make_predicates(None, &[("x-tenant", "a")], &[]);
        let pred_b = make_predicates(None, &[("x-tenant", "b")], &[]);

        let entry_a = Arc::new(RouteEntry::new(up_a, pred_a, "default/a".to_string(), None));
        let entry_b = Arc::new(RouteEntry::new(up_b, pred_b, "default/b".to_string(), None));

        let mut b = RoutingTableBuilder::new();
        let hb = b.for_port(PORT).exact_host("example.com");
        hb.add_exact_route("/", Arc::clone(&entry_a));
        hb.add_exact_route("/", Arc::clone(&entry_b));

        let table = b.build().unwrap();

        use crate::routing::tests::headers_from;
        use http::Method;
        let hdrs_a = headers_from(&[("x-tenant", "a")]);
        let hdrs_b = headers_from(&[("x-tenant", "b")]);
        let ctx_a = RequestContext {
            method: &Method::GET,
            headers: &hdrs_a,
            query: None,
        };
        let ctx_b = RequestContext {
            method: &Method::GET,
            headers: &hdrs_b,
            query: None,
        };

        assert_eq!(
            table
                .route(PORT, "example.com", "/", &ctx_a)
                .unwrap()
                .name(),
            "a"
        );
        assert_eq!(
            table
                .route(PORT, "example.com", "/", &ctx_b)
                .unwrap()
                .name(),
            "b"
        );
    }
}
