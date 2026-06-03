use crate::shared::Shared;
use std::collections::HashMap;
use std::sync::Arc;

mod builder;
mod entry;
mod host_router;
mod predicate;

pub use builder::RoutingTableBuilder;
pub use entry::{
    FilterAction, HeaderMod, PathModifier, RouteConflict, RouteEntry, RouteInfo, RouteKind,
    RouteTimeouts, Upstream,
};
pub use host_router::{HostRouter, HostRouterBuilder};
pub use predicate::{HeaderPredicate, MatchPredicates, QueryPredicate, RequestContext, ValueMatch};

#[cfg(test)]
mod tests;

#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("matchit insert failed: {0}")]
    MatchitInsert(#[from] matchit::InsertError),
    #[error("invalid regex pattern: {0}")]
    Regex(#[from] regex::Error),
}

/// A cheaply-cloneable handle to the active routing table.
pub type SharedRoutingTable = Shared<RoutingTable>;

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
    pub(crate) exact_hosts: HashMap<String, HostRouter>,
    /// Sorted most-specific (longest suffix) first.
    pub(crate) wildcard_hosts: Vec<(String, HostRouter)>,
    pub(crate) catchall: Option<HostRouter>,
    /// Rules that were dropped due to un-insertable matchit patterns.
    pub(crate) conflicts: Vec<RouteConflict>,
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
                .find(|(s, _)| host_router::wildcard_matches(host, s))
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
            .find(|(s, _)| host_router::wildcard_matches(host, s))
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
