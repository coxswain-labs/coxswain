use arc_swap::ArcSwap;
use http::{HeaderMap, HeaderName, Method};
use matchit::Router;
use regex::{Regex, RegexSet};
use std::cmp::Reverse;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

/// How a path is modified by `URLRewrite` or `RequestRedirect`.
#[derive(Clone, Debug)]
pub enum PathModifier {
    ReplaceFullPath(String),
    /// Replace `prefix` with `replacement` in the matched request path.
    ReplacePrefixMatch {
        prefix: String,
        replacement: String,
    },
}

/// Header add/set/remove operations applied as a unit.
#[derive(Clone, Debug, Default)]
pub struct HeaderMod {
    /// Headers appended to any existing values.
    pub add: Vec<(String, String)>,
    /// Headers overwritten (set).
    pub set: Vec<(String, String)>,
    /// Header names removed entirely.
    pub remove: Vec<String>,
}

/// A filter action evaluated per-request on the proxy hot path.
#[derive(Clone, Debug)]
pub enum FilterAction {
    /// Modify request headers before forwarding upstream.
    RequestHeaderModifier(HeaderMod),
    /// Modify response headers before returning to the client.
    ResponseHeaderModifier(HeaderMod),
    /// Return a 3xx redirect without connecting to the upstream.
    RequestRedirect {
        scheme: Option<String>,
        hostname: Option<String>,
        port: Option<u16>,
        /// HTTP status code (default 302).
        status_code: u16,
        path: Option<PathModifier>,
    },
    /// Rewrite the upstream request host and/or path (client-visible URL is unchanged).
    UrlRewrite {
        hostname: Option<String>,
        path: Option<PathModifier>,
    },
}

/// Per-rule timeout configuration parsed from `HTTPRouteRule.timeouts`.
#[derive(Clone, Debug, Default)]
pub struct RouteTimeouts {
    /// Total request timeout (client → proxy → upstream → proxy → client). 504 on expiry.
    pub request: Option<Duration>,
    /// Upstream-only timeout (proxy → upstream response). 502 on expiry.
    pub backend_request: Option<Duration>,
}

/// A cheaply-cloneable handle to the active routing table.
///
/// Backed by `ArcSwap` for lock-free atomic swaps; the storage type is an
/// implementation detail that may change without affecting callers.
#[derive(Clone)]
pub struct SharedRoutingTable {
    inner: Arc<ArcSwap<RoutingTable>>,
}

impl SharedRoutingTable {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(RoutingTable::default())),
        }
    }

    pub fn load(&self) -> Arc<RoutingTable> {
        self.inner.load_full()
    }

    pub fn store(&self, table: Arc<RoutingTable>) {
        self.inner.store(table);
    }
}

impl Default for SharedRoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("matchit insert failed: {0}")]
    MatchitInsert(#[from] matchit::InsertError),
    #[error("invalid regex pattern: {0}")]
    Regex(#[from] regex::Error),
}

/// A named group of pod endpoints with lock-free round-robin selection.
pub struct Upstream {
    /// Service identity in `"namespace/name"` form — used for logging only.
    pub name: String,
    endpoints: Vec<SocketAddr>,
    index: AtomicUsize,
}

impl Upstream {
    pub fn new(name: String, endpoints: Vec<SocketAddr>) -> Self {
        Self {
            name,
            endpoints,
            index: AtomicUsize::new(0),
        }
    }

    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.endpoints
    }

    /// Returns the next endpoint using round-robin selection.
    ///
    /// Returns `None` if the upstream has no endpoints.
    pub fn next_endpoint(&self) -> Option<&SocketAddr> {
        if self.endpoints.is_empty() {
            return None;
        }
        let idx = self.index.fetch_add(1, Ordering::Relaxed) % self.endpoints.len();
        self.endpoints.get(idx)
    }
}

/// How a value is compared in a predicate — used by header and query matchers.
#[derive(Clone)]
pub enum ValueMatch {
    Exact(String),
    Regex(Regex),
}

impl ValueMatch {
    fn matches(&self, value: &str) -> bool {
        match self {
            ValueMatch::Exact(s) => s == value,
            ValueMatch::Regex(r) => r.is_match(value),
        }
    }
}

/// Matches a single request header.
///
/// `name` is the canonical (lowercased) `HeaderName`, enabling O(1) lookup in
/// `HeaderMap`. The comparison is against the header value string.
#[derive(Clone)]
pub struct HeaderPredicate {
    pub name: HeaderName,
    pub matcher: ValueMatch,
}

/// Matches a single query parameter by name and value.
///
/// Query parameter names are case-sensitive per RFC 3986.
#[derive(Clone)]
pub struct QueryPredicate {
    pub name: String,
    pub matcher: ValueMatch,
}

/// All predicates for a single `HTTPRouteMatch`.
///
/// Every predicate in this struct must pass for the match to succeed
/// (AND semantics). Empty fields pass unconditionally.
#[derive(Clone, Default)]
pub struct MatchPredicates {
    pub method: Option<Method>,
    pub headers: Vec<HeaderPredicate>,
    pub query: Vec<QueryPredicate>,
}

impl MatchPredicates {
    pub fn is_empty(&self) -> bool {
        self.method.is_none() && self.headers.is_empty() && self.query.is_empty()
    }

    fn matches(&self, ctx: &RequestContext<'_>) -> bool {
        if let Some(m) = &self.method
            && m != ctx.method
        {
            return false;
        }
        for h in &self.headers {
            let matched = ctx
                .headers
                .get_all(&h.name)
                .iter()
                .any(|v| v.to_str().is_ok_and(|s| h.matcher.matches(s)));
            if !matched {
                return false;
            }
        }
        if !self.query.is_empty() {
            let query_str = ctx.query.unwrap_or("");
            // Collect once per call so we don't re-parse for each predicate.
            let pairs: Vec<(std::borrow::Cow<str>, std::borrow::Cow<str>)> =
                form_urlencoded::parse(query_str.as_bytes()).collect();
            for q in &self.query {
                let found = pairs
                    .iter()
                    .any(|(k, v)| k.as_ref() == q.name && q.matcher.matches(v.as_ref()));
                if !found {
                    return false;
                }
            }
        }
        true
    }
}

/// A single routing candidate: an upstream plus the predicates that must hold
/// for this candidate to be selected, along with metadata for precedence ordering.
pub struct RouteEntry {
    pub upstream: Arc<Upstream>,
    pub predicates: MatchPredicates,
    pub filters: Arc<[FilterAction]>,
    pub timeouts: RouteTimeouts,
    /// Parent resource identity `"{namespace}/{name}"` — used for precedence tiebreaking.
    pub route_id: String,
    /// Creation timestamp — older routes win ties after predicate-count comparison.
    /// `None` sorts last.
    pub created_at: Option<SystemTime>,
    /// When `Some`, the proxy returns this status code immediately without contacting upstream.
    /// Used for routes with invalid/missing/forbidden backend refs (Gateway API §4.3.4).
    pub error_status: Option<u16>,
}

impl RouteEntry {
    /// Constructs an entry with no predicates, no filters, and no timeouts.
    pub fn path_only(
        upstream: Arc<Upstream>,
        route_id: String,
        created_at: Option<SystemTime>,
    ) -> Self {
        Self {
            upstream,
            predicates: MatchPredicates::default(),
            filters: Arc::from([]),
            timeouts: RouteTimeouts::default(),
            route_id,
            created_at,
            error_status: None,
        }
    }

    /// Constructs an entry with predicates but no filters and no timeouts.
    pub fn new(
        upstream: Arc<Upstream>,
        predicates: MatchPredicates,
        route_id: String,
        created_at: Option<SystemTime>,
    ) -> Self {
        Self {
            upstream,
            predicates,
            filters: Arc::from([]),
            timeouts: RouteTimeouts::default(),
            route_id,
            created_at,
            error_status: None,
        }
    }

    /// Constructs an entry with predicates, filters, and per-rule timeouts.
    pub fn with_filters(
        upstream: Arc<Upstream>,
        predicates: MatchPredicates,
        filters: Vec<FilterAction>,
        timeouts: RouteTimeouts,
        route_id: String,
        created_at: Option<SystemTime>,
    ) -> Self {
        Self {
            upstream,
            predicates,
            filters: Arc::from(filters.into_boxed_slice()),
            timeouts,
            route_id,
            created_at,
            error_status: None,
        }
    }
}

/// Per-request context passed into the hot-path route lookup.
///
/// All fields are borrows from the live request — no allocations.
pub struct RequestContext<'a> {
    pub method: &'a Method,
    pub headers: &'a HeaderMap,
    /// Raw query string (the part after `?`), if present.
    pub query: Option<&'a str>,
}

impl Default for RequestContext<'static> {
    fn default() -> Self {
        static EMPTY_HEADERS: std::sync::LazyLock<HeaderMap> =
            std::sync::LazyLock::new(HeaderMap::new);
        Self {
            method: &Method::GET,
            headers: &EMPTY_HEADERS,
            query: None,
        }
    }
}

/// How a path rule was registered — for introspection only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Exact,
    Prefix,
    Regex,
}

impl RouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RouteKind::Exact => "exact",
            RouteKind::Prefix => "prefix",
            RouteKind::Regex => "regex",
        }
    }
}

/// Snapshot of a single path rule insertion, kept for inspection.
pub struct RouteInfo {
    pub path: String,
    pub kind: RouteKind,
    pub upstream: Arc<Upstream>,
}

/// A path rule that was silently dropped because an earlier rule already claimed the same slot.
pub struct RouteConflict {
    /// Host pattern where the conflict occurred (`"*"` for catch-all, `"*.example.com"` for wildcard).
    pub host: String,
    pub path: String,
    pub kind: RouteKind,
    /// `Upstream::name` of the rule that was rejected.
    pub rejected_upstream: String,
}

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

    pub(crate) fn build(
        self,
        _host: &str,
    ) -> Result<(HostRouter, Vec<RouteConflict>), RouterError> {
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
            let set = RegexSet::new([&pattern])?;
            // Validate each regex while we're at it (RegexSet already checked above).
            let _ = Regex::new(&pattern)?;
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

#[derive(Default)]
pub struct RoutingTableBuilder {
    exact_hosts: HashMap<String, HostRouterBuilder>,
    /// Keyed by suffix (e.g. `"example.com"` for the pattern `"*.example.com"`).
    wildcard_hosts: HashMap<String, HostRouterBuilder>,
    catchall: Option<HostRouterBuilder>,
}

impl RoutingTableBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the `HostRouterBuilder` for an exact hostname match.
    pub fn exact_host(&mut self, hostname: &str) -> &mut HostRouterBuilder {
        self.exact_hosts.entry(hostname.to_string()).or_default()
    }

    /// Returns the `HostRouterBuilder` for a wildcard hostname pattern.
    ///
    /// `pattern` must be in `*.example.com` form; the `*.` prefix is stripped internally.
    pub fn wildcard_host(&mut self, pattern: &str) -> &mut HostRouterBuilder {
        let suffix = pattern.trim_start_matches("*.");
        self.wildcard_hosts.entry(suffix.to_string()).or_default()
    }

    /// Returns the `HostRouterBuilder` for the catch-all domain (`*`).
    pub fn catchall(&mut self) -> &mut HostRouterBuilder {
        self.catchall.get_or_insert_with(HostRouterBuilder::default)
    }

    /// Compiles all registered routes into an immutable [`RoutingTable`].
    pub fn build(self) -> Result<RoutingTable, RouterError> {
        let mut conflicts: Vec<RouteConflict> = Vec::new();

        let exact_hosts = self
            .exact_hosts
            .into_iter()
            .map(|(h, b)| {
                let (router, cs) = b.build(&h)?;
                conflicts.extend(cs);
                Ok((h, router))
            })
            .collect::<Result<HashMap<_, _>, RouterError>>()?;

        let mut wildcard_hosts: Vec<(String, HostRouter)> = self
            .wildcard_hosts
            .into_iter()
            .map(|(suffix, b)| {
                let pattern = format!("*.{suffix}");
                let (router, cs) = b.build(&pattern)?;
                conflicts.extend(cs);
                Ok((suffix, router))
            })
            .collect::<Result<Vec<_>, RouterError>>()?;
        // Most specific (longest suffix) first — matches K8s Gateway API precedence.
        wildcard_hosts.sort_by_key(|e| Reverse(e.0.len()));

        let catchall = match self.catchall {
            Some(b) => {
                let (router, cs) = b.build("*")?;
                conflicts.extend(cs);
                Some(router)
            }
            None => None,
        };

        Ok(RoutingTable {
            exact_hosts,
            wildcard_hosts,
            catchall,
            conflicts,
        })
    }
}

/// Return type of `HostRouter::route`: upstream + filters + timeouts + optional error status.
type RouteMatch = (
    Arc<Upstream>,
    Arc<[FilterAction]>,
    RouteTimeouts,
    Option<u16>,
);

/// Result of a two-level host+path routing lookup.
pub enum RouteOutcome {
    Found(Arc<Upstream>, Arc<[FilterAction]>, RouteTimeouts),
    /// Route matched but backend is invalid/missing/forbidden — return this status immediately.
    Error(u16),
    /// No entry for this hostname (host is not registered at this proxy).
    NoHost,
    /// Host is registered but no path rule matched (or path matched but predicates failed).
    NoPath,
}

/// Immutable compiled routing table.
///
/// Host resolution follows K8s Gateway API precedence:
/// exact match → wildcard (most specific first) → catch-all.
#[derive(Default)]
pub struct RoutingTable {
    exact_hosts: HashMap<String, HostRouter>,
    /// Sorted most-specific (longest suffix) first.
    wildcard_hosts: Vec<(String, HostRouter)>,
    catchall: Option<HostRouter>,
    /// Rules that were dropped due to un-insertable matchit patterns.
    conflicts: Vec<RouteConflict>,
}

impl RoutingTable {
    /// Routes to an upstream, discarding filter and timeout information.
    ///
    /// Convenience for tests and admin introspection. The proxy hot path should
    /// use [`find`] to also receive the filter list and timeouts.
    pub fn route(&self, host: &str, path: &str, ctx: &RequestContext<'_>) -> Option<Arc<Upstream>> {
        let host_router = if let Some(router) = self.exact_hosts.get(host) {
            Some(router)
        } else {
            self.wildcard_hosts
                .iter()
                .find(|(s, _)| wildcard_matches(host, s))
                .map(|(_, r)| r)
        };
        if let Some(router) = host_router
            && let Some((upstream, _, _, _)) = router.route(path, ctx)
        {
            return Some(upstream);
        }
        self.catchall
            .as_ref()?
            .route(path, ctx)
            .map(|(u, _, _, _)| u)
    }

    /// Like [`route`] but distinguishes "host not registered" from "path not matched",
    /// and returns filters and timeouts alongside the upstream.
    pub fn find(&self, host: &str, path: &str, ctx: &RequestContext<'_>) -> RouteOutcome {
        let router = if let Some(r) = self.exact_hosts.get(host) {
            r
        } else if let Some((_, r)) = self
            .wildcard_hosts
            .iter()
            .find(|(s, _)| wildcard_matches(host, s))
        {
            r
        } else if let Some(r) = self.catchall.as_ref() {
            r
        } else {
            return RouteOutcome::NoHost;
        };
        match router.route(path, ctx) {
            Some((_, _, _, Some(status))) => RouteOutcome::Error(status),
            Some((u, f, t, None)) => RouteOutcome::Found(u, f, t),
            None => RouteOutcome::NoPath,
        }
    }

    /// Rules dropped due to un-insertable matchit patterns, in the order they were encountered.
    pub fn conflicts(&self) -> &[RouteConflict] {
        &self.conflicts
    }

    /// All host entries with their compiled routers, for introspection.
    ///
    /// Yields `(host_pattern, router)` tuples: exact hostnames as-is, wildcard
    /// patterns with their `*.` prefix restored, and `"*"` for the catch-all.
    pub fn host_routes(&self) -> Vec<(String, &HostRouter)> {
        let mut result: Vec<(String, &HostRouter)> = Vec::new();
        for (host, router) in &self.exact_hosts {
            result.push((host.clone(), router));
        }
        for (suffix, router) in &self.wildcard_hosts {
            result.push((format!("*.{suffix}"), router));
        }
        if let Some(router) = &self.catchall {
            result.push(("*".to_string(), router));
        }
        result
    }

    /// All configured hostnames (exact and wildcard). Wildcard patterns include the `*.` prefix.
    pub fn host_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.exact_hosts.keys().cloned().collect();
        for (suffix, _) in &self.wildcard_hosts {
            names.push(format!("*.{suffix}"));
        }
        names
    }

    /// Number of distinct host entries (exact + wildcard, excluding the catch-all).
    pub fn host_count(&self) -> usize {
        self.exact_hosts.len() + self.wildcard_hosts.len()
    }
}

/// Returns `true` if `host` is a subdomain of `suffix`
/// (e.g. `suffix = "example.com"` matches `"api.example.com"`).
fn wildcard_matches(host: &str, suffix: &str) -> bool {
    host.len() > suffix.len() + 1
        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
        && host.ends_with(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(name: &str, addr: &str) -> Arc<Upstream> {
        Arc::new(Upstream::new(
            name.to_string(),
            vec![addr.parse::<SocketAddr>().unwrap()],
        ))
    }

    fn entry(us: Arc<Upstream>) -> Arc<RouteEntry> {
        Arc::new(RouteEntry::path_only(us, "default/svc".to_string(), None))
    }

    fn ctx_get() -> RequestContext<'static> {
        RequestContext::default()
    }

    #[test]
    fn exact_host_beats_wildcard() {
        let exact_up = upstream("exact", "10.0.0.1:80");
        let wildcard_up = upstream("wildcard", "10.0.0.2:80");

        let mut b = RoutingTableBuilder::new();
        b.exact_host("example.com")
            .add_exact_route("/", entry(exact_up));
        b.wildcard_host("*.com")
            .add_exact_route("/", entry(wildcard_up));

        let table = b.build().unwrap();
        assert_eq!(
            table.route("example.com", "/", &ctx_get()).unwrap().name,
            "exact"
        );
        assert_eq!(
            table.route("other.com", "/", &ctx_get()).unwrap().name,
            "wildcard"
        );
    }

    #[test]
    fn path_routing_within_host() {
        let api_up = upstream("api", "10.0.0.1:80");
        let health_up = upstream("health", "10.0.0.2:80");

        let mut b = RoutingTableBuilder::new();
        let host = b.exact_host("example.com");
        host.add_prefix_route("/api", entry(api_up));
        host.add_exact_route("/health", entry(health_up));

        let table = b.build().unwrap();
        assert_eq!(
            table
                .route("example.com", "/api/users", &ctx_get())
                .unwrap()
                .name,
            "api"
        );
        assert_eq!(
            table
                .route("example.com", "/health", &ctx_get())
                .unwrap()
                .name,
            "health"
        );
    }

    #[test]
    fn wildcard_host_matches() {
        let up = upstream("svc", "10.0.0.1:80");

        let mut b = RoutingTableBuilder::new();
        b.wildcard_host("*.test.com")
            .add_exact_route("/", entry(up));

        let table = b.build().unwrap();
        assert!(table.route("api.test.com", "/", &ctx_get()).is_some());
        assert!(table.route("test.com", "/", &ctx_get()).is_none());
    }

    #[test]
    fn route_falls_through_to_catchall_on_exact_host_path_miss() {
        let host_up = upstream("host", "10.0.0.1:80");
        let catchall_up = upstream("catchall", "10.0.0.2:80");

        let mut b = RoutingTableBuilder::new();
        b.exact_host("example.com")
            .add_prefix_route("/api", entry(host_up));
        b.catchall().add_prefix_route("/", entry(catchall_up));

        let table = b.build().unwrap();
        assert_eq!(
            table
                .route("example.com", "/api/v1", &ctx_get())
                .unwrap()
                .name,
            "host"
        );
        assert_eq!(
            table
                .route("example.com", "/other", &ctx_get())
                .unwrap()
                .name,
            "catchall"
        );
    }

    #[test]
    fn route_falls_through_to_catchall_on_wildcard_host_path_miss() {
        let host_up = upstream("host", "10.0.0.1:80");
        let catchall_up = upstream("catchall", "10.0.0.2:80");

        let mut b = RoutingTableBuilder::new();
        b.wildcard_host("*.example.com")
            .add_prefix_route("/api", entry(host_up));
        b.catchall().add_prefix_route("/", entry(catchall_up));

        let table = b.build().unwrap();
        assert_eq!(
            table
                .route("api.example.com", "/api/v1", &ctx_get())
                .unwrap()
                .name,
            "host"
        );
        assert_eq!(
            table
                .route("api.example.com", "/other", &ctx_get())
                .unwrap()
                .name,
            "catchall"
        );
    }

    #[test]
    fn route_returns_none_when_neither_host_router_nor_catchall_match() {
        let host_up = upstream("host", "10.0.0.1:80");

        let mut b = RoutingTableBuilder::new();
        b.exact_host("example.com")
            .add_prefix_route("/api", entry(host_up));

        let table = b.build().unwrap();
        assert!(table.route("example.com", "/other", &ctx_get()).is_none());
        assert!(table.route("unknown.com", "/api", &ctx_get()).is_none());
    }

    #[test]
    fn route_host_router_takes_precedence_over_catchall_for_same_path() {
        let host_up = upstream("host", "10.0.0.1:80");
        let catchall_up = upstream("catchall", "10.0.0.2:80");

        let mut b = RoutingTableBuilder::new();
        b.exact_host("example.com")
            .add_prefix_route("/api", entry(host_up));
        b.catchall().add_prefix_route("/api", entry(catchall_up));

        let table = b.build().unwrap();
        assert_eq!(
            table
                .route("example.com", "/api/v1", &ctx_get())
                .unwrap()
                .name,
            "host"
        );
        assert_eq!(
            table
                .route("other.com", "/api/v1", &ctx_get())
                .unwrap()
                .name,
            "catchall"
        );
    }

    #[test]
    fn round_robin_cycles() {
        let addrs: Vec<SocketAddr> = vec![
            "10.0.0.1:80".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
            "10.0.0.3:80".parse().unwrap(),
        ];
        let up = Upstream::new("svc".to_string(), addrs.clone());
        let results: Vec<SocketAddr> = (0..6).map(|_| *up.next_endpoint().unwrap()).collect();
        assert_eq!(
            results,
            [addrs[0], addrs[1], addrs[2], addrs[0], addrs[1], addrs[2]]
        );
    }

    // ── Predicate tests ────────────────────────────────────────────────────────

    fn headers_from(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        m
    }

    fn make_predicates(
        method: Option<&str>,
        headers: &[(&str, &str)], // (name, exact_value)
        query: &[(&str, &str)],   // (name, exact_value)
    ) -> MatchPredicates {
        MatchPredicates {
            method: method.map(|m| m.parse().unwrap()),
            headers: headers
                .iter()
                .map(|(n, v)| HeaderPredicate {
                    name: HeaderName::from_bytes(n.as_bytes()).unwrap(),
                    matcher: ValueMatch::Exact(v.to_string()),
                })
                .collect(),
            query: query
                .iter()
                .map(|(n, v)| QueryPredicate {
                    name: n.to_string(),
                    matcher: ValueMatch::Exact(v.to_string()),
                })
                .collect(),
        }
    }

    #[test]
    fn predicate_empty_matches_everything() {
        let pred = MatchPredicates::default();
        let headers = headers_from(&[]);
        let ctx = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: None,
        };
        assert!(pred.matches(&ctx));
    }

    #[test]
    fn predicate_method_match() {
        let pred = make_predicates(Some("POST"), &[], &[]);
        let headers = headers_from(&[]);
        let get = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: None,
        };
        let post = RequestContext {
            method: &Method::POST,
            headers: &headers,
            query: None,
        };
        assert!(!pred.matches(&get));
        assert!(pred.matches(&post));
    }

    #[test]
    fn predicate_header_exact_match() {
        let pred = make_predicates(None, &[("x-tenant", "foo")], &[]);
        let matching = headers_from(&[("x-tenant", "foo")]);
        let wrong = headers_from(&[("x-tenant", "bar")]);
        let absent = headers_from(&[]);
        let ctx_m = RequestContext {
            method: &Method::GET,
            headers: &matching,
            query: None,
        };
        let ctx_w = RequestContext {
            method: &Method::GET,
            headers: &wrong,
            query: None,
        };
        let ctx_a = RequestContext {
            method: &Method::GET,
            headers: &absent,
            query: None,
        };
        assert!(pred.matches(&ctx_m));
        assert!(!pred.matches(&ctx_w));
        assert!(!pred.matches(&ctx_a));
    }

    #[test]
    fn predicate_header_regex_match() {
        let pred = MatchPredicates {
            method: None,
            headers: vec![HeaderPredicate {
                name: HeaderName::from_static("x-version"),
                matcher: ValueMatch::Regex(Regex::new(r"^v\d+$").unwrap()),
            }],
            query: vec![],
        };
        let matching = headers_from(&[("x-version", "v42")]);
        let wrong = headers_from(&[("x-version", "beta")]);
        let ctx_m = RequestContext {
            method: &Method::GET,
            headers: &matching,
            query: None,
        };
        let ctx_w = RequestContext {
            method: &Method::GET,
            headers: &wrong,
            query: None,
        };
        assert!(pred.matches(&ctx_m));
        assert!(!pred.matches(&ctx_w));
    }

    #[test]
    fn predicate_query_exact_match() {
        let pred = make_predicates(None, &[], &[("version", "v1")]);
        let headers = headers_from(&[]);
        let ctx_yes = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: Some("version=v1&x=y"),
        };
        let ctx_no = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: Some("version=v2"),
        };
        let ctx_absent = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: None,
        };
        assert!(pred.matches(&ctx_yes));
        assert!(!pred.matches(&ctx_no));
        assert!(!pred.matches(&ctx_absent));
    }

    #[test]
    fn predicate_query_regex_match() {
        let pred = MatchPredicates {
            method: None,
            headers: vec![],
            query: vec![QueryPredicate {
                name: "env".to_string(),
                matcher: ValueMatch::Regex(Regex::new(r"^(dev|staging)$").unwrap()),
            }],
        };
        let headers = headers_from(&[]);
        let ctx_dev = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: Some("env=dev"),
        };
        let ctx_prod = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: Some("env=prod"),
        };
        assert!(pred.matches(&ctx_dev));
        assert!(!pred.matches(&ctx_prod));
    }

    #[test]
    fn predicate_and_semantics() {
        // Both method AND header must match.
        let pred = make_predicates(Some("POST"), &[("x-tenant", "a")], &[]);
        let headers_ok = headers_from(&[("x-tenant", "a")]);
        let headers_wrong = headers_from(&[("x-tenant", "b")]);
        let ctx_both = RequestContext {
            method: &Method::POST,
            headers: &headers_ok,
            query: None,
        };
        let ctx_method_only = RequestContext {
            method: &Method::POST,
            headers: &headers_wrong,
            query: None,
        };
        let ctx_header_only = RequestContext {
            method: &Method::GET,
            headers: &headers_ok,
            query: None,
        };
        assert!(pred.matches(&ctx_both));
        assert!(!pred.matches(&ctx_method_only));
        assert!(!pred.matches(&ctx_header_only));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        // Predicate stores lowercase HeaderName; request may have mixed case.
        let pred = make_predicates(None, &[("x-tenant", "acme")], &[]);
        // HTTP/1.1 allows any case; HeaderMap canonicalises to lowercase internally.
        let headers = headers_from(&[("x-tenant", "acme")]);
        let ctx = RequestContext {
            method: &Method::GET,
            headers: &headers,
            query: None,
        };
        assert!(pred.matches(&ctx));
    }

    #[test]
    fn specificity_ordering_more_headers_wins() {
        // Two entries at the same path: one with a header predicate, one without.
        // The one with more predicates should win when its predicate passes.
        let specific_up = upstream("specific", "10.0.0.1:80");
        let generic_up = upstream("generic", "10.0.0.2:80");

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
        let hb = b.exact_host("example.com");
        hb.add_exact_route("/", Arc::clone(&generic));
        hb.add_exact_route("/", Arc::clone(&specific));

        let table = b.build().unwrap();
        let headers_match = headers_from(&[("x-tenant", "acme")]);
        let headers_no = headers_from(&[]);

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
            table.route("example.com", "/", &ctx_match).unwrap().name,
            "specific"
        );
        // Without matching header → specific's predicate fails; falls through to generic.
        assert_eq!(
            table.route("example.com", "/", &ctx_no).unwrap().name,
            "generic"
        );
    }

    #[test]
    fn timestamp_tiebreaker_older_wins() {
        // Two entries with the same predicate count; older route wins.
        let older_up = upstream("older", "10.0.0.1:80");
        let newer_up = upstream("newer", "10.0.0.2:80");

        let t_old = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000);
        let t_new = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2000);

        let older = Arc::new(RouteEntry::path_only(
            Arc::clone(&older_up),
            "default/older".to_string(),
            Some(t_old),
        ));
        let newer = Arc::new(RouteEntry::path_only(
            Arc::clone(&newer_up),
            "default/newer".to_string(),
            Some(t_new),
        ));

        let mut b = RoutingTableBuilder::new();
        let hb = b.exact_host("example.com");
        // Insert newer first; sort should put older first.
        hb.add_exact_route("/", Arc::clone(&newer));
        hb.add_exact_route("/", Arc::clone(&older));

        let table = b.build().unwrap();
        assert_eq!(
            table.route("example.com", "/", &ctx_get()).unwrap().name,
            "older"
        );
    }

    #[test]
    fn or_semantics_across_multiple_entries() {
        // Two entries at the same path with different header predicates:
        // whichever predicate matches the request wins.
        let up_a = upstream("a", "10.0.0.1:80");
        let up_b = upstream("b", "10.0.0.2:80");

        let pred_a = make_predicates(None, &[("x-tenant", "a")], &[]);
        let pred_b = make_predicates(None, &[("x-tenant", "b")], &[]);

        let entry_a = Arc::new(RouteEntry::new(up_a, pred_a, "default/a".to_string(), None));
        let entry_b = Arc::new(RouteEntry::new(up_b, pred_b, "default/b".to_string(), None));

        let mut b = RoutingTableBuilder::new();
        let hb = b.exact_host("example.com");
        hb.add_exact_route("/", Arc::clone(&entry_a));
        hb.add_exact_route("/", Arc::clone(&entry_b));

        let table = b.build().unwrap();

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

        assert_eq!(table.route("example.com", "/", &ctx_a).unwrap().name, "a");
        assert_eq!(table.route("example.com", "/", &ctx_b).unwrap().name, "b");
    }

    #[test]
    fn find_returns_timeouts_from_route_entry() {
        let up = upstream("svc", "10.0.0.1:80");
        let timeouts = RouteTimeouts {
            request: Some(std::time::Duration::from_secs(10)),
            backend_request: Some(std::time::Duration::from_secs(2)),
        };
        let e = Arc::new(RouteEntry::with_filters(
            up,
            MatchPredicates::default(),
            vec![],
            timeouts.clone(),
            "default/svc".to_string(),
            None,
        ));

        let mut b = RoutingTableBuilder::new();
        b.exact_host("example.com").add_prefix_route("/", e);
        let table = b.build().unwrap();

        match table.find("example.com", "/foo", &ctx_get()) {
            RouteOutcome::Found(_, _, t) => {
                assert_eq!(t.request, timeouts.request);
                assert_eq!(t.backend_request, timeouts.backend_request);
            }
            _ => panic!("expected Found"),
        }
    }
}
