//! Per-host path router: exact, prefix, and regex path matching with predicate filtering.

use super::auth::IngressAuthConfig;
use super::backend::BackendGroup;
use super::circuit_breaker::CircuitBreakerConfig;
use super::compression::CompressionConfig;
use super::entry::{
    ForwardedForConfig, RouteConflict, RouteEntry, RouteInfo, RouteKind, RouteTimeouts,
};
use super::filters::FilterAction;
use super::path_normalize::NormalizeLevel;
use super::predicate::{MatchPredicates, RequestContext, ValueMatch};
use super::rate_limit::RateLimitConfig;
use matchit::Router;
use regex::{RegexSet, RegexSetBuilder};
use std::cmp::Reverse;
use std::sync::Arc;
use std::time::SystemTime;

/// Resolved per-rule match payload returned by [`HostRouter::route`] and carried
/// by [`RouteOutcome::Found`](super::table::RouteOutcome::Found).
///
/// Every field is either `Copy`, an `Arc` (clone = refcount bump), or a small
/// `RouteTimeouts`, so building one on the hot path allocates nothing.
/// `error_status` is `Some` only when the matched rule has an invalid/missing
/// backend ref; [`PortRoutingTable::find`](super::port::PortRoutingTable) peels
/// it off into [`RouteOutcome::Error`](super::table::RouteOutcome::Error), so it
/// is always `None` once a `RouteMatch` is wrapped in `Found`.
pub struct RouteMatch {
    /// Backend group to forward matching requests to.
    pub backend_group: Arc<BackendGroup>,
    /// Filter actions applied to the request/response for this rule.
    pub filters: Arc<[FilterAction]>,
    /// Per-rule timeout overrides.
    pub timeouts: RouteTimeouts,
    /// Registered path pattern of the matched rule (for the access-log `pattern` mode).
    pub path_pattern: Arc<str>,
    /// Canonical metric/log identifier for the matched rule.
    pub metric_route_id: Arc<str>,
    /// Per-route request body size limit in bytes (`None` = unlimited).
    pub max_body_size: Option<u64>,
    /// Per-route source-IP allow-list (`None` = admit all source IPs).
    pub allow_source_range: Option<Arc<[ipnet::IpNet]>>,
    /// Per-route source-IP block list (`None` = block nothing; deny checked before allow).
    pub deny_source_range: Option<Arc<[ipnet::IpNet]>>,
    /// Per-class access-log enabled override (`None` = inherit proxy-wide flag).
    ///
    /// Populated from `RouteEntry::access_log_enabled`. `Some(false)` suppresses
    /// the `coxswain_proxy::access` log line for this matched route while leaving
    /// metrics unaffected. Only set for Ingress routes whose
    /// `CoxswainIngressClassParameters.spec.accessLog` is `false`.
    pub access_log_enabled: Option<bool>,
    /// Per-route rate-limiting configuration (`None` = no rate limiting).
    pub rate_limit: Option<Arc<RateLimitConfig>>,
    /// The additive authentication chain for this route (empty = no auth).
    ///
    /// Cloned from [`RouteEntry::auth`]; the proxy enforces every check in order
    /// in `request_filter` before forwarding to upstream, and the first hard-deny
    /// wins (#23).
    pub auth: Arc<[Arc<IngressAuthConfig>]>,
    /// Per-route response-compression configuration (`None` = no compression).
    ///
    /// Populated from `RouteEntry::compression`; `Some` only for Ingress routes
    /// that opt in via `ingress.coxswain-labs.dev/compression-gzip: "true"` or
    /// `compression-brotli: "true"`. The proxy reads this in
    /// `upstream_response_filter` to negotiate and stream compressed responses.
    pub compression: Option<Arc<CompressionConfig>>,
    /// Trusted-proxy forwarded-IP configuration (`None` = use L4 peer as client IP).
    ///
    /// Populated from `RouteEntry::forwarded_for`; `Some` only for Ingress routes
    /// that set `ingress.coxswain-labs.dev/trust-forwarded-for: "true"`. The
    /// proxy reads this in `request_filter` to extract the real client IP from the
    /// configured header and stores it in `ProxyCtx::client_ip` for use by all
    /// IP-based features (allow/deny-source-range, rate limiting, access logs).
    pub forwarded_for: Option<Arc<ForwardedForConfig>>,
    /// Per-route circuit-breaker configuration (`None` = disabled).
    ///
    /// Populated from `RouteEntry::circuit_breaker`; `Some` only for Ingress routes
    /// that configure `ingress.coxswain-labs.dev/circuit-breaker-threshold`. The
    /// proxy gates each request through the per-endpoint
    /// `CircuitBreakerRegistry` in `upstream_peer` and records the outcome in `logging`.
    pub circuit_breaker: Option<Arc<CircuitBreakerConfig>>,

    /// Normalized form of the request path, when it differs from the raw path.
    ///
    /// Set by `PortRoutingTable::find` after applying the host's
    /// [`NormalizeLevel`] to the request path before the routing lookup.
    /// `None` when normalization was a no-op (the path was already canonical or
    /// the level is `None`) — the raw request path is used verbatim.  When
    /// `Some`, the proxy adopts this as `ResolvedRoute::original_path` so the
    /// normalized path is both matched and forwarded upstream.
    pub normalized_path: Option<Arc<str>>,

    /// When `Some`, the proxy returns this status immediately without contacting
    /// upstream (invalid/missing/forbidden backend ref). See the struct docs.
    pub error_status: Option<u16>,
}

impl RouteMatch {
    /// Build a `RouteMatch` from the matched entry, cloning the shared (`Arc`) and
    /// `Copy` fields — a refcount bump per `Arc`, no heap allocation.
    fn from_entry(entry: &RouteEntry) -> Self {
        Self {
            backend_group: Arc::clone(&entry.backend_group),
            filters: Arc::clone(&entry.filters),
            timeouts: entry.timeouts.clone(),
            path_pattern: Arc::clone(&entry.path_pattern),
            metric_route_id: Arc::clone(&entry.metric_route_id),
            max_body_size: entry.max_body_size,
            allow_source_range: entry.allow_source_range.clone(),
            deny_source_range: entry.deny_source_range.clone(),
            access_log_enabled: entry.access_log_enabled,
            rate_limit: entry.rate_limit.clone(),
            auth: entry.auth.clone(),
            compression: entry.compression.clone(),
            forwarded_for: entry.forwarded_for.clone(),
            circuit_breaker: entry.circuit_breaker.clone(),
            normalized_path: None,

            error_status: entry.error_status,
        }
    }
}

/// Compile a path pattern as a regular expression, the safe-compile guard for
/// regex routes.
///
/// This is the single entry point callers use to validate an
/// `ImplementationSpecific`/`RegularExpression` path *before* inserting it, so an
/// uncompilable pattern can be skipped with a WARN rather than failing the whole
/// routing-table `build` (`HostRouterBuilder::build`, which would drop every route).
/// The returned [`regex::Regex`] is also what capture-group rewrites
/// ([`PathModifier::RegexReplace`](super::filters::PathModifier::RegexReplace)) match
/// against. The matcher itself compiles the same pattern into a
/// [`RegexSet`] at build time; both use the default `regex` parser, so a pattern that
/// compiles here is guaranteed to compile there.
///
/// # Errors
/// Returns [`regex::Error`] if `pattern` is not a valid regular expression or its
/// compiled program would exceed [`REGEX_SIZE_LIMIT`].
#[must_use = "the compiled Regex is the result; dropping it discards the compile work"]
pub fn compile_path_regex(pattern: &str) -> Result<regex::Regex, regex::Error> {
    compile_bounded(pattern)
}

/// Compiled-program size cap for every regex compiled from tenant-supplied input.
///
/// The `regex` crate defaults to a 10 MB compiled-program `size_limit`; a tenant
/// creating many route/CRD matchers could force ~10 MB of controller memory per
/// pattern — a reflector memory-exhaustion DoS. 64 KiB is ample for realistic
/// host/path/header/query patterns while bounding the per-pattern memory a hostile
/// CRD can demand.
pub const REGEX_SIZE_LIMIT: usize = 64 * 1024;

/// Compile a regular expression from (potentially tenant-supplied) input with a
/// bounded compiled-program size ([`REGEX_SIZE_LIMIT`]).
///
/// This is the single sanctioned entry point for compiling any pattern that
/// originates from an Ingress annotation, `HTTPRoute`/`GRPCRoute` match, or CRD
/// field. Bare `regex::Regex::new` on such input is banned by
/// `scripts/check-bounded-regex.sh` because the crate default (10 MB) is a
/// memory-exhaustion DoS vector — see [`REGEX_SIZE_LIMIT`].
///
/// # Errors
/// Returns [`regex::Error`] if `pattern` is invalid or its compiled program would
/// exceed [`REGEX_SIZE_LIMIT`].
#[must_use = "the compiled Regex is the result; dropping it discards the compile work"]
pub fn compile_bounded(pattern: &str) -> Result<regex::Regex, regex::Error> {
    regex::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
}

/// One entry in the cold wire side-table: `(path_pattern, kind, entry)`.
///
/// A type alias keeps the `HostRouter.wire_table` field from tripping
/// `clippy::type_complexity` while remaining self-documenting at use sites.
pub(crate) type WireTableEntry = (Box<str>, RouteKind, Arc<RouteEntry>);

/// Compiled path router for a single hostname, supporting exact, prefix, and regex patterns.
pub struct HostRouter {
    router: Router<Box<[Arc<RouteEntry>]>>,
    regex_routes: Vec<(RegexSet, Box<[Arc<RouteEntry>]>)>,
    has_query_predicates: bool,
    route_info: Vec<RouteInfo>,
    /// Path normalization level applied before every routing lookup and retained
    /// as the forwarded path.  Defaults to [`NormalizeLevel::Base`].
    normalize: NormalizeLevel,
    /// Cold side-table of every registered route entry, in insertion order.
    ///
    /// Retained so the discovery wire layer can enumerate `(path, kind, entry)` tuples
    /// for serialisation — the primary `matchit::Router` and `regex_routes` are sealed
    /// behind compiled automata and cannot be iterated.  Never read on the request hot
    /// path.  Prefix entries store the **normalised** prefix (trailing slash stripped),
    /// identical to what `add_prefix_route` passes to matchit.  Replaying
    /// `add_prefix_route` with the same normalised value is a fixpoint.
    wire_table: Box<[WireTableEntry]>,
}

impl HostRouter {
    /// All registered path rules, in insertion order, for introspection.
    pub fn routes(&self) -> &[RouteInfo] {
        &self.route_info
    }

    /// Path normalization level in effect for this host.
    ///
    /// Exposed for the discovery wire layer so `to_wire` can serialise the
    /// `set_path_normalize` setting and `from_wire` can replay it via
    /// [`HostRouterBuilder::set_path_normalize`].
    pub fn normalize(&self) -> NormalizeLevel {
        self.normalize
    }

    /// Iterate every registered route entry in insertion order.
    ///
    /// Each item is `(path_or_pattern, kind, entry)` where:
    /// - `Exact` — exact path string as registered.
    /// - `Prefix` — normalised prefix (trailing slash stripped, root `"/"` preserved).
    ///   Replaying `add_prefix_route` with this value is idempotent.
    /// - `Regex` — pattern string, recoverable via [`regex::Regex::as_str`].
    ///
    /// Used exclusively by the discovery wire layer (`to_wire`).  Never called on the
    /// request hot path.
    pub fn wire_entries(&self) -> impl Iterator<Item = (&str, RouteKind, &Arc<RouteEntry>)> {
        self.wire_table
            .iter()
            .map(|(path, kind, entry)| (path.as_ref(), *kind, entry))
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
                    return Some(RouteMatch::from_entry(entry));
                }
            }
        }
        // Regex fallback: each slot holds its own RegexSet for a single pattern group;
        // insertion order across patterns is preserved by Vec position.
        for (set, entries) in &self.regex_routes {
            if set.is_match(path) {
                for entry in entries.iter() {
                    if entry.predicates.matches(ctx) {
                        return Some(RouteMatch::from_entry(entry));
                    }
                }
            }
        }
        None
    }

    /// Whether any registered route on this host uses query-parameter predicates.
    ///
    /// The proxy uses this to skip query-string parsing when it's unnecessary.
    #[must_use]
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

/// Normalize a PathPrefix value by stripping a trailing slash (the root "/" is
/// preserved). Both Ingress and Gateway API define PathPrefix matching with a
/// trailing "/" ignored — "/foo" and "/foo/" are the same prefix — so the table
/// keys prefix groups on the normalized form.
fn normalize_prefix(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Canonical signature of a predicate set. Two routes on the same (host, path)
/// with equal signatures are not differentiated by predicates and therefore
/// shadow each other — only the highest-precedence one ever fires.
fn predicate_signature(p: &MatchPredicates) -> String {
    let value_sig = |v: &ValueMatch| match v {
        ValueMatch::Exact(s) => format!("e:{s}"),
        ValueMatch::Regex(r) => format!("r:{}", r.as_str()),
    };
    let mut headers: Vec<String> = p
        .headers
        .iter()
        .map(|h| format!("{}={}", h.name.as_str(), value_sig(&h.matcher)))
        .collect();
    headers.sort();
    let mut query: Vec<String> = p
        .query
        .iter()
        .map(|q| format!("{}={}", q.name, value_sig(&q.matcher)))
        .collect();
    query.sort();
    format!(
        "m={}|h={}|q={}",
        p.method.as_ref().map_or("", |m| m.as_str()),
        headers.join(","),
        query.join(",")
    )
}

/// Conflicts for routes in a single path group that are shadowed by an earlier
/// route with the same predicate signature — i.e. distinct routes claiming the
/// same (host, path) without anything to tell them apart (e.g. two Ingresses on
/// `demo.local/`). The group is specificity-sorted, so the first entry per
/// signature wins and later distinct routes are shadowed. One conflict per
/// distinct shadowed route; `host`/`port` are stamped by the caller. Routes that
/// differ by method/header/query get distinct signatures and legitimately
/// coexist (no conflict).
fn dup_conflicts(path: &str, kind: RouteKind, frozen: &[Arc<RouteEntry>]) -> Vec<RouteConflict> {
    use std::collections::{HashMap, HashSet};
    let mut winner: HashMap<String, &str> = HashMap::new();
    let mut emitted: HashSet<&str> = HashSet::new();
    let mut conflicts = Vec::new();
    for e in frozen {
        let sig = predicate_signature(&e.predicates);
        match winner.get(&sig) {
            None => {
                winner.insert(sig, e.route_id.as_str());
            }
            Some(&win) if win != e.route_id.as_str() && emitted.insert(e.route_id.as_str()) => {
                conflicts.push(RouteConflict {
                    port: 0,
                    host: String::new(),
                    path: path.to_string(),
                    kind,
                    rejected_group: e.backend_group.name().to_string(),
                    rejected_route_id: e.route_id.clone(),
                    winner_route_id: win.to_string(),
                });
            }
            Some(_) => {}
        }
    }
    conflicts
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
#[derive(Default)]
pub struct HostRouterBuilder {
    exact_routes: Vec<(String, Arc<RouteEntry>)>,
    prefix_routes: Vec<(String, Arc<RouteEntry>)>,
    regex_routes: Vec<(String, Arc<RouteEntry>)>,
    /// Explicit path normalization level set via `set_path_normalize`.
    /// `None` means "use the default" (`NormalizeLevel::Base`) at build time.
    normalize: Option<NormalizeLevel>,
}

impl HostRouterBuilder {
    /// Set the path normalization level for all routes on this host.
    ///
    /// The first explicit level set wins.  A subsequent call with a *different*
    /// level emits a `tracing::warn!` and is ignored — ensuring the more
    /// specific (first-registered) Ingress wins when multiple Ingresses share a
    /// host.  Calling with the same level as already set is a no-op.
    ///
    /// Absent any call, the host defaults to [`NormalizeLevel::Base`].
    pub fn set_path_normalize(&mut self, level: NormalizeLevel) -> &mut Self {
        match self.normalize {
            Some(existing) if existing == level => {
                // Same level — no-op, no warning needed.
            }
            Some(existing) => {
                tracing::warn!(
                    existing = ?existing,
                    requested = ?level,
                    "path-normalize level conflict on shared host: \
                     keeping first-registered level"
                );
            }
            None => {
                self.normalize = Some(level);
            }
        }
        self
    }

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
        // Cold side-table for the wire layer — accumulates (path, kind, entry) in
        // the same insertion order as `route_info`.
        let mut wire_table: Vec<(Box<str>, RouteKind, Arc<RouteEntry>)> = Vec::new();
        let mut conflicts: Vec<RouteConflict> = Vec::new();
        let mut has_query_predicates = false;

        // Track whether any entry uses query predicates.
        let check_query = |entries: &[(usize, Arc<RouteEntry>)]| {
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
                wire_table.push((
                    path.clone().into_boxed_str(),
                    RouteKind::Exact,
                    Arc::clone(e),
                ));
            }
            let frozen = sort_and_freeze(entries);
            conflicts.extend(dup_conflicts(&path, RouteKind::Exact, &frozen));
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

        // Prefix paths are normalized by stripping the trailing slash (the root
        // "/" is preserved): both Ingress and Gateway API define PathPrefix
        // matching with a trailing "/" ignored, so "/foo" and "/foo/" are the same
        // prefix. Grouping by the normalized path merges them; genuine duplicates
        // (distinct routes on the same prefix) are surfaced by `dup_conflicts`.
        // Normalization is build-time only — request matching is unchanged.
        let prefix_routes: Vec<(String, Arc<RouteEntry>)> = self
            .prefix_routes
            .into_iter()
            .map(|(p, e)| (normalize_prefix(&p), e))
            .collect();
        let prefix_groups = group_by_path(prefix_routes);
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
                // Store normalised prefix so replaying add_prefix_route is a fixpoint.
                wire_table.push((
                    path.clone().into_boxed_str(),
                    RouteKind::Prefix,
                    Arc::clone(e),
                ));
            }
            let frozen = sort_and_freeze(entries);
            conflicts.extend(dup_conflicts(&path, RouteKind::Prefix, &frozen));

            // Prefix semantics (path already normalized — no trailing slash except
            // the root):
            //   "/foo" matches /foo, /foo/, /foo/anything
            //   "/"    matches everything
            // matchit 0.9.2 does not route "/foo/" to "/foo/{*rest}", so insert
            // "/foo/" explicitly to bridge the gap. A genuine insert failure here
            // is unexpected (groups are keyed by normalized path) — log it.
            if path == "/" {
                if let Err(e) = router.insert("/", frozen.clone()) {
                    log_conflict(&frozen, "/", &e);
                }
                if let Err(e) = router.insert("/{*rest}", frozen.clone()) {
                    log_conflict(&frozen, "/{*rest}", &e);
                }
            } else {
                if let Err(e) = router.insert(path.clone(), frozen.clone()) {
                    log_conflict(&frozen, &path, &e);
                }
                let with_slash = format!("{path}/");
                if let Err(e) = router.insert(with_slash.clone(), frozen.clone()) {
                    log_conflict(&frozen, &with_slash, &e);
                }
                let wildcard = format!("{path}/{{*rest}}");
                if let Err(e) = router.insert(wildcard.clone(), frozen.clone()) {
                    log_conflict(&frozen, &wildcard, &e);
                }
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
                // Regex pattern string is preserved verbatim; from_wire calls
                // Regex::new(pattern) to recompile it.
                wire_table.push((
                    pattern.clone().into_boxed_str(),
                    RouteKind::Regex,
                    Arc::clone(e),
                ));
            }
            // RegexSet::new already validates the pattern; the second compile is
            // redundant. Bounded to REGEX_SIZE_LIMIT so a tenant pattern cannot force
            // an oversized compiled program at the matcher (parity with compile_bounded).
            let set = RegexSetBuilder::new([&pattern])
                .size_limit(REGEX_SIZE_LIMIT)
                .build()?;
            let frozen = sort_and_freeze(entries);
            compiled_regex_routes.push((set, frozen));
        }

        Ok((
            HostRouter {
                router,
                regex_routes: compiled_regex_routes,
                has_query_predicates,
                route_info,
                normalize: self.normalize.unwrap_or_default(),
                wire_table: wire_table.into_boxed_slice(),
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
pub(crate) fn wildcard_matches(host: &str, suffix: &str, kind: WildcardKind) -> bool {
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
    fn compile_bounded_accepts_ordinary_pattern() {
        let re = compile_bounded(r"^/api/v\d+/.*$").expect("valid pattern compiles");
        assert!(re.is_match("/api/v2/users"));
    }

    #[test]
    fn compile_bounded_rejects_oversized_program() {
        // A large bounded-repetition pattern compiles to a program far exceeding
        // REGEX_SIZE_LIMIT; the bounded builder must reject it rather than allocate.
        let hostile = format!(r"(?:a{{1000}}){{1000}}{}", "b".repeat(10));
        assert!(
            compile_bounded(&hostile).is_err(),
            "oversized pattern must be rejected by the size limit"
        );
    }

    #[test]
    fn compile_path_regex_is_bounded() {
        // compile_path_regex routes through compile_bounded, so it enforces the same cap.
        let hostile = format!(r"(?:a{{1000}}){{1000}}{}", "c".repeat(10));
        assert!(compile_path_regex(&hostile).is_err());
    }

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
    fn trailing_slash_prefix_matches_bare_path() {
        // Both specs ignore a trailing slash in a PathPrefix value: "/foo/" must
        // match a bare "/foo" request (as well as "/foo/" and "/foo/bar").
        let up = make_group("svc", "10.0.0.1:80");
        let mut b = RoutingTableBuilder::new();
        b.for_port(PORT)
            .exact_host("example.com")
            .add_prefix_route("/foo/", entry(up));

        let table = b.build().unwrap();
        assert!(
            table
                .route(PORT, "example.com", "/foo", &ctx_get())
                .is_some()
        );
        assert!(
            table
                .route(PORT, "example.com", "/foo/", &ctx_get())
                .is_some()
        );
        assert!(
            table
                .route(PORT, "example.com", "/foo/bar", &ctx_get())
                .is_some()
        );
        // A sibling that merely shares a prefix string must NOT match.
        assert!(
            table
                .route(PORT, "example.com", "/foobar", &ctx_get())
                .is_none()
        );
    }

    #[test]
    fn normalized_prefix_distinct_routes_conflict() {
        // "/foo" and "/foo/" normalize to the same prefix, so two distinct routes
        // claiming them collide — one is shadowed and recorded as a conflict at the
        // normalized path.
        let first = make_group("first", "10.0.0.1:80");
        let second = make_group("second", "10.0.0.2:80");

        let mut b = RoutingTableBuilder::new();
        let host = b.for_port(PORT).exact_host("example.com");
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
        assert_eq!(conflicts.len(), 1, "one conflict for the shadowed route");
        let c = &conflicts[0];
        assert_eq!(c.host, "example.com");
        assert_eq!(c.port, PORT);
        assert_eq!(c.path, "/foo", "conflict reported at the normalized prefix");
        assert!(matches!(c.kind, RouteKind::Prefix));
        // first-route wins the tie (route_id order); second-route is shadowed.
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
