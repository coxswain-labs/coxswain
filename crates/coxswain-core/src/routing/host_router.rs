use crate::routing::entry::{
    FilterAction, RouteConflict, RouteEntry, RouteInfo, RouteKind, RouteTimeouts, Upstream,
};
use crate::routing::predicate::RequestContext;
use matchit::Router;
use regex::RegexSet;
use std::cmp::Reverse;
use std::sync::Arc;
use std::time::SystemTime;

/// Return type of `HostRouter::route`: upstream + filters + timeouts + optional error status.
pub(super) type RouteMatch = (
    Arc<Upstream>,
    Arc<[FilterAction]>,
    RouteTimeouts,
    Option<u16>,
);

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
                        Arc::clone(&entry.upstream),
                        Arc::clone(&entry.filters),
                        entry.timeouts.clone(),
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
                            Arc::clone(&entry.upstream),
                            Arc::clone(&entry.filters),
                            entry.timeouts.clone(),
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

#[derive(Default)]
pub struct HostRouterBuilder {
    exact_routes: Vec<(String, Arc<RouteEntry>)>,
    prefix_routes: Vec<(String, Arc<RouteEntry>)>,
    regex_routes: Vec<(String, Arc<RouteEntry>)>,
}

impl HostRouterBuilder {
    pub fn add_exact_route(&mut self, path: &str, entry: Arc<RouteEntry>) -> &mut Self {
        self.exact_routes.push((path.to_string(), entry));
        self
    }

    pub fn add_prefix_route(&mut self, path: &str, entry: Arc<RouteEntry>) -> &mut Self {
        self.prefix_routes.push((path.to_string(), entry));
        self
    }

    pub fn add_regex_route(&mut self, pattern: &str, entry: Arc<RouteEntry>) -> &mut Self {
        self.regex_routes.push((pattern.to_string(), entry));
        self
    }

    pub(crate) fn build(self) -> Result<(HostRouter, Vec<RouteConflict>), super::RouterError> {
        let mut router: Router<Box<[Arc<RouteEntry>]>> = Router::new();
        let mut route_info: Vec<RouteInfo> = Vec::new();
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
                    upstream: Arc::clone(&e.upstream),
                });
            }
            let frozen = sort_and_freeze(entries);
            // Inserting into a fresh router; unique patterns won't conflict.
            router.insert(path, frozen)?;
        }

        // ── Prefix routes ─────────────────────────────────────────────────────
        let prefix_groups = group_by_path(self.prefix_routes);
        for (path, entries) in prefix_groups {
            if check_query(&entries) {
                has_query_predicates = true;
            }
            for (_, e) in &entries {
                route_info.push(RouteInfo {
                    path: path.clone(),
                    kind: RouteKind::Prefix,
                    upstream: Arc::clone(&e.upstream),
                });
            }
            let frozen = sort_and_freeze(entries);

            // Gateway API prefix semantics:
            //   "/foo"  matches /foo, /foo/, /foo/anything
            //   "/foo/" matches /foo/, /foo/anything (NOT /foo)
            //   "/"     matches everything
            // matchit 0.9.2 does not route "/v2/" to "/v2/{*rest}" — we must
            // insert "/v2/" explicitly to bridge the gap.
            let had_trailing_slash = path.ends_with('/');
            let base = path.trim_end_matches('/');
            if base.is_empty() {
                let _ = router.insert("/", frozen.clone());
                let _ = router.insert("/{*rest}", frozen);
            } else {
                if !had_trailing_slash {
                    let _ = router.insert(base, frozen.clone());
                }
                let _ = router.insert(format!("{base}/"), frozen.clone());
                let _ = router.insert(format!("{base}/{{*rest}}"), frozen);
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
                    upstream: Arc::clone(&e.upstream),
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
            vec![], // no path-level conflicts in the predicate model
        ))
    }
}

/// Returns `true` when `host` matches the wildcard pattern `*.{suffix}`.
/// Requires exactly one label before the suffix: `api.example.com` matches
/// suffix `example.com`, but `example.com` and `a.b.example.com` do not.
pub(super) fn wildcard_matches(host: &str, suffix: &str) -> bool {
    if let Some(rest) = host.strip_suffix(suffix)
        && let Some(label) = rest.strip_suffix('.')
    {
        return !label.is_empty() && !label.contains('.');
    }
    false
}
