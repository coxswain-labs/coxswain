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

    /// Returns a snapshot of the current routing table.
    pub fn load(&self) -> Arc<RoutingTable> {
        self.inner.load_full()
    }

    /// Atomically replaces the active routing table.
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
    /// Round-robin cursor. Incremented on every call to `next_endpoint`.
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

/// Compiled path-level router for a single virtual hostname.
pub struct HostRouter {
    router: Router<Arc<Upstream>>,
    regex_set: RegexSet,
    regex_routes: Vec<(Regex, Arc<Upstream>)>,
}

impl HostRouter {
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

/// Builder for a single hostname's path-level routing rules.
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

    pub(crate) fn build(self) -> Result<HostRouter, RouterError> {
        let mut router = Router::new();

        for (path, upstream) in self.exact_routes {
            router.insert(path, upstream)?;
        }

        for (path, upstream) in self.prefix_routes {
            // Normalise: strip any trailing slash so "/api/" and "/api" are treated identically.
            let base = path.trim_end_matches('/');
            if base.is_empty() {
                // Root prefix "/": matchit's {*rest} does not match an empty tail, so
                // insert "/" explicitly for the root path itself.
                router.insert("/".to_string(), upstream.clone())?;
                router.insert("/{*rest}".to_string(), upstream)?;
            } else {
                // Two inserts: the bare path itself, and everything beneath it.
                router.insert(base.to_string(), upstream.clone())?;
                router.insert(format!("{base}/{{*rest}}"), upstream)?;
            }
        }

        let patterns: Vec<&str> = self.regex_routes.iter().map(|(p, _)| p.as_str()).collect();
        let regex_set = RegexSet::new(&patterns)?;
        let regex_routes = self
            .regex_routes
            .into_iter()
            .map(|(p, u)| Ok((Regex::new(&p)?, u)))
            .collect::<Result<Vec<_>, regex::Error>>()?;

        Ok(HostRouter {
            router,
            regex_set,
            regex_routes,
        })
    }
}

/// Builder for the complete multi-hostname routing table.
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
        let exact_hosts = self
            .exact_hosts
            .into_iter()
            .map(|(h, b)| Ok((h, b.build()?)))
            .collect::<Result<HashMap<_, _>, RouterError>>()?;

        let mut wildcard_hosts: Vec<(String, HostRouter)> = self
            .wildcard_hosts
            .into_iter()
            .map(|(suffix, b)| Ok((suffix, b.build()?)))
            .collect::<Result<Vec<_>, RouterError>>()?;
        // Most specific (longest suffix) first — matches K8s Gateway API precedence.
        wildcard_hosts.sort_by_key(|e| Reverse(e.0.len()));

        let catchall = self.catchall.map(HostRouterBuilder::build).transpose()?;

        Ok(RoutingTable {
            exact_hosts,
            wildcard_hosts,
            catchall,
        })
    }
}

/// Immutable compiled routing structure.
///
/// Host resolution follows K8s Gateway API precedence:
/// exact match → wildcard (most specific first) → catch-all.
#[derive(Default)]
pub struct RoutingTable {
    exact_hosts: HashMap<String, HostRouter>,
    /// Sorted most-specific (longest suffix) first.
    wildcard_hosts: Vec<(String, HostRouter)>,
    catchall: Option<HostRouter>,
}

impl RoutingTable {
    /// Resolves `host` and `path` to an upstream.
    pub fn route(&self, host: &str, path: &str) -> Option<Arc<Upstream>> {
        if let Some(router) = self.exact_hosts.get(host) {
            return router.route(path);
        }
        for (suffix, router) in &self.wildcard_hosts {
            if wildcard_matches(host, suffix) {
                return router.route(path);
            }
        }
        self.catchall.as_ref()?.route(path)
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
