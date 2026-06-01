use arc_swap::ArcSwap;
use matchit::Router;
use regex::{Regex, RegexSet};
use std::cmp::Reverse;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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

/// Snapshot of a single path rule, kept alongside the compiled router for inspection.
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
    router: Router<Arc<Upstream>>,
    regex_set: RegexSet,
    regex_routes: Vec<(Regex, Arc<Upstream>)>,
    route_info: Vec<RouteInfo>,
}

impl HostRouter {
    /// All registered path rules, in insertion order, for introspection.
    pub fn routes(&self) -> &[RouteInfo] {
        &self.route_info
    }

    /// Resolves `path` to an upstream. Checks matchit first, then the regex fallback.
    pub fn route(&self, path: &str) -> Option<Arc<Upstream>> {
        if let Ok(m) = self.router.at(path) {
            return Some(Arc::clone(m.value));
        }
        // RegexSet matches all patterns simultaneously; take only the first hit so
        // insertion order acts as priority (earlier-added patterns win).
        let idx = self.regex_set.matches(path).iter().next()?;
        self.regex_routes.get(idx).map(|(_, u)| Arc::clone(u))
    }
}

#[derive(Default)]
pub struct HostRouterBuilder {
    exact_routes: Vec<(String, Arc<Upstream>)>,
    prefix_routes: Vec<(String, Arc<Upstream>)>,
    regex_routes: Vec<(String, Arc<Upstream>)>,
}

impl HostRouterBuilder {
    pub fn add_exact_route(&mut self, path: &str, upstream: Arc<Upstream>) -> &mut Self {
        self.exact_routes.push((path.to_string(), upstream));
        self
    }

    pub fn add_prefix_route(&mut self, path: &str, upstream: Arc<Upstream>) -> &mut Self {
        self.prefix_routes.push((path.to_string(), upstream));
        self
    }

    pub fn add_regex_route(&mut self, pattern: &str, upstream: Arc<Upstream>) -> &mut Self {
        self.regex_routes.push((pattern.to_string(), upstream));
        self
    }

    pub(crate) fn build(self, host: &str) -> Result<(HostRouter, Vec<RouteConflict>), RouterError> {
        let mut router = Router::new();
        let mut route_info: Vec<RouteInfo> = Vec::new();
        let mut conflicts: Vec<RouteConflict> = Vec::new();

        for (path, upstream) in self.exact_routes {
            match router.insert(path.clone(), Arc::clone(&upstream)) {
                Ok(()) => route_info.push(RouteInfo {
                    path,
                    kind: RouteKind::Exact,
                    upstream,
                }),
                Err(_) => conflicts.push(RouteConflict {
                    host: host.to_string(),
                    path,
                    kind: RouteKind::Exact,
                    rejected_upstream: upstream.name.clone(),
                }),
            }
        }

        for (path, upstream) in self.prefix_routes {
            // Normalise: strip any trailing slash so "/api/" and "/api" are treated identically.
            let base = path.trim_end_matches('/');
            let (p1, p2) = if base.is_empty() {
                // Root prefix "/": matchit's {*rest} does not match an empty tail, so
                // insert "/" explicitly for the root path itself.
                ("/".to_string(), "/{*rest}".to_string())
            } else {
                // Two inserts: the bare path itself, and everything beneath it.
                (base.to_string(), format!("{base}/{{*rest}}"))
            };

            match router.insert(p1, Arc::clone(&upstream)) {
                Ok(()) => {
                    // Base inserted; the wildcard should succeed too — any failure here is an
                    // edge case (another rule claimed the exact wildcard path). Still mark active
                    // since the base path is routing.
                    let _ = router.insert(p2, Arc::clone(&upstream));
                    route_info.push(RouteInfo {
                        path,
                        kind: RouteKind::Prefix,
                        upstream,
                    });
                }
                Err(_) => {
                    // Base path already claimed by an earlier rule — skip the whole prefix.
                    conflicts.push(RouteConflict {
                        host: host.to_string(),
                        path,
                        kind: RouteKind::Prefix,
                        rejected_upstream: upstream.name.clone(),
                    });
                }
            }
        }

        let patterns: Vec<&str> = self.regex_routes.iter().map(|(p, _)| p.as_str()).collect();
        let regex_set = RegexSet::new(&patterns)?;
        let regex_routes = self
            .regex_routes
            .into_iter()
            .map(|(p, u)| {
                route_info.push(RouteInfo {
                    path: p.clone(),
                    kind: RouteKind::Regex,
                    upstream: Arc::clone(&u),
                });
                Ok((Regex::new(&p)?, u))
            })
            .collect::<Result<Vec<_>, regex::Error>>()?;

        Ok((
            HostRouter {
                router,
                regex_set,
                regex_routes,
                route_info,
            },
            conflicts,
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
    ///
    /// Conflicts (duplicate host+path claims) are resolved by first-writer wins; the losing rules
    /// are collected in [`RoutingTable::conflicts`] rather than failing the whole build.
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

/// Result of a two-level host+path routing lookup.
pub enum RouteOutcome {
    Found(Arc<Upstream>),
    /// No entry for this hostname (host is not registered at this proxy).
    NoHost,
    /// Host is registered but no path rule matched.
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
    /// Rules that were dropped because an earlier rule already claimed the same host+path slot.
    conflicts: Vec<RouteConflict>,
}

impl RoutingTable {
    pub fn route(&self, host: &str, path: &str) -> Option<Arc<Upstream>> {
        let host_router = if let Some(router) = self.exact_hosts.get(host) {
            Some(router)
        } else {
            self.wildcard_hosts
                .iter()
                .find(|(s, _)| wildcard_matches(host, s))
                .map(|(_, r)| r)
        };
        if let Some(router) = host_router
            && let Some(upstream) = router.route(path)
        {
            return Some(upstream);
        }
        self.catchall.as_ref()?.route(path)
    }

    /// Like [`route`] but distinguishes "host not registered" from "path not matched".
    pub fn find(&self, host: &str, path: &str) -> RouteOutcome {
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
        match router.route(path) {
            Some(u) => RouteOutcome::Found(u),
            None => RouteOutcome::NoPath,
        }
    }

    /// Rules dropped due to host+path conflicts, in the order they were encountered.
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

    #[test]
    fn exact_host_beats_wildcard() {
        let exact_up = upstream("exact", "10.0.0.1:80");
        let wildcard_up = upstream("wildcard", "10.0.0.2:80");

        let mut b = RoutingTableBuilder::new();
        b.exact_host("example.com").add_exact_route("/", exact_up);
        b.wildcard_host("*.com").add_exact_route("/", wildcard_up);

        let table = b.build().unwrap();
        assert_eq!(table.route("example.com", "/").unwrap().name, "exact");
        assert_eq!(table.route("other.com", "/").unwrap().name, "wildcard");
    }

    #[test]
    fn path_routing_within_host() {
        let api_up = upstream("api", "10.0.0.1:80");
        let health_up = upstream("health", "10.0.0.2:80");

        let mut b = RoutingTableBuilder::new();
        let host = b.exact_host("example.com");
        host.add_prefix_route("/api", api_up);
        host.add_exact_route("/health", health_up);

        let table = b.build().unwrap();
        assert_eq!(
            table.route("example.com", "/api/users").unwrap().name,
            "api"
        );
        assert_eq!(
            table.route("example.com", "/health").unwrap().name,
            "health"
        );
    }

    #[test]
    fn wildcard_host_matches() {
        let up = upstream("svc", "10.0.0.1:80");

        let mut b = RoutingTableBuilder::new();
        b.wildcard_host("*.test.com").add_exact_route("/", up);

        let table = b.build().unwrap();
        assert!(table.route("api.test.com", "/").is_some());
        assert!(table.route("test.com", "/").is_none());
    }

    #[test]
    fn route_falls_through_to_catchall_on_exact_host_path_miss() {
        let host_up = upstream("host", "10.0.0.1:80");
        let catchall_up = upstream("catchall", "10.0.0.2:80");

        let mut b = RoutingTableBuilder::new();
        b.exact_host("example.com")
            .add_prefix_route("/api", host_up);
        b.catchall().add_prefix_route("/", catchall_up);

        let table = b.build().unwrap();
        assert_eq!(table.route("example.com", "/api/v1").unwrap().name, "host");
        assert_eq!(
            table.route("example.com", "/other").unwrap().name,
            "catchall"
        );
    }

    #[test]
    fn route_falls_through_to_catchall_on_wildcard_host_path_miss() {
        let host_up = upstream("host", "10.0.0.1:80");
        let catchall_up = upstream("catchall", "10.0.0.2:80");

        let mut b = RoutingTableBuilder::new();
        b.wildcard_host("*.example.com")
            .add_prefix_route("/api", host_up);
        b.catchall().add_prefix_route("/", catchall_up);

        let table = b.build().unwrap();
        assert_eq!(
            table.route("api.example.com", "/api/v1").unwrap().name,
            "host"
        );
        assert_eq!(
            table.route("api.example.com", "/other").unwrap().name,
            "catchall"
        );
    }

    #[test]
    fn route_returns_none_when_neither_host_router_nor_catchall_match() {
        let host_up = upstream("host", "10.0.0.1:80");

        let mut b = RoutingTableBuilder::new();
        b.exact_host("example.com")
            .add_prefix_route("/api", host_up);

        let table = b.build().unwrap();
        assert!(table.route("example.com", "/other").is_none());
        assert!(table.route("unknown.com", "/api").is_none());
    }

    #[test]
    fn route_host_router_takes_precedence_over_catchall_for_same_path() {
        let host_up = upstream("host", "10.0.0.1:80");
        let catchall_up = upstream("catchall", "10.0.0.2:80");

        let mut b = RoutingTableBuilder::new();
        b.exact_host("example.com")
            .add_prefix_route("/api", host_up);
        b.catchall().add_prefix_route("/api", catchall_up);

        let table = b.build().unwrap();
        assert_eq!(table.route("example.com", "/api/v1").unwrap().name, "host");
        assert_eq!(
            table.route("other.com", "/api/v1").unwrap().name,
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
}
