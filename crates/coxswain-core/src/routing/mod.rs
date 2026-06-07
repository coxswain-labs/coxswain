//! Compiled routing table keyed by listener port, host pattern, and path rule.
//!
//! Build with [`RoutingTableBuilder`], then wrap in a [`SharedRoutingTable`] for
//! lock-free access across threads.

use crate::shared::Shared;
use std::collections::HashMap;
use std::sync::Arc;

mod builder;
mod entry;
mod host_router;
mod predicate;

pub use builder::{PortTableBuilder, RoutingTableBuilder};
pub use entry::{
    BackendGroup, BackendProtocol, FilterAction, HeaderMod, HeaderModError, PathModifier,
    RouteConflict, RouteEntry, RouteInfo, RouteKind, RouteTimeouts, UpstreamCa, UpstreamTls,
    parse_app_protocol,
};
pub use host_router::{HostRouter, HostRouterBuilder};
pub use predicate::{HeaderPredicate, MatchPredicates, QueryPredicate, RequestContext, ValueMatch};

#[cfg(test)]
mod tests;

/// Errors that can occur while building a routing table.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    /// A path pattern could not be inserted into the `matchit` router.
    #[error("matchit insert failed: {0}")]
    MatchitInsert(#[from] matchit::InsertError),
    /// A regex pattern string is syntactically invalid.
    #[error("invalid regex pattern: {0}")]
    Regex(#[from] regex::Error),
}

/// A cheaply-cloneable handle to the active routing table.
pub type SharedRoutingTable = Shared<RoutingTable>;

/// Result of a two-level host+path routing lookup.
#[non_exhaustive]
pub enum RouteOutcome {
    /// Route matched; tuple is `(backend_group, filters, timeouts)`.
    Found(Arc<BackendGroup>, Arc<[FilterAction]>, RouteTimeouts),
    /// Route matched but backend is invalid/missing/forbidden — return this status immediately.
    Error(u16),
    /// No entry for this hostname (host is not registered at this proxy).
    NoHost,
    /// Host is registered but no path rule matched (or path matched but predicates failed).
    NoPath,
}

/// Per-port routing bucket: the host+path+predicate logic for one listener port.
///
/// This is the content that `RoutingTable` used to hold directly at the top level.
pub(crate) struct PortRoutingTable {
    pub(crate) exact_hosts: HashMap<String, HostRouter>,
    /// Sorted most-specific (longest suffix) first.
    pub(crate) wildcard_hosts: Vec<(String, HostRouter)>,
    pub(crate) catchall: Option<HostRouter>,
}

impl PortRoutingTable {
    fn find(&self, host: &str, path: &str, ctx: &RequestContext<'_>) -> RouteOutcome {
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

    fn route(&self, host: &str, path: &str, ctx: &RequestContext<'_>) -> Option<Arc<BackendGroup>> {
        let router = if let Some(r) = self.exact_hosts.get(host) {
            Some(r)
        } else {
            self.wildcard_hosts
                .iter()
                .find(|(s, _)| host_router::wildcard_matches(host, s))
                .map(|(_, r)| r)
        };
        if let Some(r) = router
            && let Some((group, _, _, _)) = r.route(path, ctx)
        {
            return Some(group);
        }
        self.catchall
            .as_ref()?
            .route(path, ctx)
            .map(|(u, _, _, _)| u)
    }

    fn host_routes(&self) -> Vec<(String, &HostRouter)> {
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
}

/// Immutable compiled routing table keyed by listener port.
///
/// Each port maintains its own host+path+predicate routers; a request on port 8080
/// only matches routes attached to a listener declared on port 8080.
#[derive(Default)]
pub struct RoutingTable {
    pub(crate) by_port: HashMap<u16, PortRoutingTable>,
    /// Rules dropped due to un-insertable matchit patterns, across all ports.
    pub(crate) conflicts: Vec<RouteConflict>,
}

impl RoutingTable {
    /// Routes to a backend group by port, host, and path, discarding filter and timeout information.
    ///
    /// Convenience for tests and admin introspection. The proxy hot path should
    /// use [`Self::find`] to also receive the filter list and timeouts.
    pub fn route(
        &self,
        port: u16,
        host: &str,
        path: &str,
        ctx: &RequestContext<'_>,
    ) -> Option<Arc<BackendGroup>> {
        self.by_port.get(&port)?.route(host, path, ctx)
    }

    /// Like [`Self::route`] but distinguishes "host not registered" from "path not matched",
    /// and returns filters and timeouts alongside the backend group.
    pub fn find(
        &self,
        port: u16,
        host: &str,
        path: &str,
        ctx: &RequestContext<'_>,
    ) -> RouteOutcome {
        match self.by_port.get(&port) {
            Some(pt) => pt.find(host, path, ctx),
            None => RouteOutcome::NoHost,
        }
    }

    /// Rules dropped due to un-insertable matchit patterns, in the order they were encountered.
    pub fn conflicts(&self) -> &[RouteConflict] {
        &self.conflicts
    }

    /// All host entries with their compiled routers, across all ports.
    ///
    /// Each tuple is `(port, host_pattern, router)`. Host patterns: exact hostnames
    /// as-is, wildcard patterns with `*.` prefix restored, `"*"` for catch-all.
    pub fn host_routes(&self) -> Vec<(u16, String, &HostRouter)> {
        let mut result = Vec::new();
        for (port, pt) in &self.by_port {
            for (host, router) in pt.host_routes() {
                result.push((*port, host, router));
            }
        }
        result
    }

    /// All configured hostnames across all ports. Wildcard patterns include the `*.` prefix.
    pub fn host_names(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for pt in self.by_port.values() {
            for (host, _) in pt.host_routes() {
                names.push(host);
            }
        }
        names
    }

    /// Number of distinct host entries summed across all ports (exact + wildcard, excluding catch-all).
    pub fn host_count(&self) -> usize {
        self.by_port
            .values()
            .map(|pt| pt.exact_hosts.len() + pt.wildcard_hosts.len())
            .sum()
    }
}
