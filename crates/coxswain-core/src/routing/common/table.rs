//! Top-level routing-table container generic over a phantom `Kind` marker.
//!
//! The container is generic so that `RoutingTable<Ingress>` and
//! `RoutingTable<Gateway>` are distinct types at the compiler level even though
//! their in-memory layouts are identical. The
//! [`crate::routing::ingress`][crate::routing::ingress] and
//! [`crate::routing::gateway`][crate::routing::gateway] sub-modules instantiate
//! this generic via type aliases and supply the marker types.

use super::entry::{BackendGroup, FilterAction, RouteConflict, RouteTimeouts};
use super::host_router::HostRouter;
use super::port::{PortRoutingTable, PortTableBuilder};
use super::predicate::RequestContext;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;

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

/// Result of a two-level host+path routing lookup.
#[non_exhaustive]
pub enum RouteOutcome {
    /// Route matched; tuple is `(backend_group, filters, timeouts, path_pattern,
    /// metric_route_id, max_body_size)`.
    ///
    /// `path_pattern` is the matched rule's registered pattern (for the
    /// access-log `pattern` mode) and `metric_route_id` is the canonical
    /// rule identifier emitted as the `route` Prometheus label and the
    /// `route_id` access-log field. `max_body_size` is the per-route request
    /// body limit in bytes (`None` = unlimited), enforced by the proxy.
    Found(
        Arc<BackendGroup>,
        Arc<[FilterAction]>,
        RouteTimeouts,
        Arc<str>,
        Arc<str>,
        Option<u64>,
    ),
    /// Route matched but backend is invalid/missing/forbidden — return this status immediately.
    Error(u16),
    /// No entry for this hostname (host is not registered at this proxy).
    NoHost,
    /// Host is registered but no path rule matched (or path matched but predicates failed).
    NoPath,
}

/// Immutable compiled routing table keyed by listener port.
///
/// Generic over a phantom `Kind` marker so the type-checker treats
/// `RoutingTable<Ingress>` and `RoutingTable<Gateway>` as incompatible — a
/// proxy that expects one will not accidentally accept the other.
#[non_exhaustive]
pub struct RoutingTable<Kind> {
    pub(crate) by_port: HashMap<u16, PortRoutingTable>,
    /// Rules dropped due to un-insertable matchit patterns, across all ports.
    pub(crate) conflicts: Vec<RouteConflict>,
    _kind: PhantomData<fn() -> Kind>,
}

impl<Kind> Default for RoutingTable<Kind> {
    fn default() -> Self {
        Self {
            by_port: HashMap::new(),
            conflicts: Vec::new(),
            _kind: PhantomData,
        }
    }
}

impl<Kind> RoutingTable<Kind> {
    /// Routes to a backend group by port, host, and path, discarding filter and timeout information.
    ///
    /// Convenience for tests and admin introspection. The proxy hot path should
    /// use [`Self::find`] to also receive the filter list and timeouts.
    #[must_use]
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
    #[must_use]
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
    #[must_use]
    pub fn conflicts(&self) -> &[RouteConflict] {
        &self.conflicts
    }

    /// All host entries with their compiled routers, across all ports.
    ///
    /// Each tuple is `(port, host_pattern, router)`. Host patterns: exact hostnames
    /// as-is, wildcard patterns with `*.` prefix restored, `"*"` for catch-all.
    #[must_use]
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
    #[must_use]
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
    #[must_use]
    pub fn host_count(&self) -> usize {
        self.by_port
            .values()
            .map(|pt| pt.exact_hosts.len() + pt.wildcard_hosts.len())
            .sum()
    }
}

/// Builds an immutable [`RoutingTable`] keyed by listener port.
///
/// Use [`for_port`](Self::for_port) to obtain a [`PortTableBuilder`] for a
/// specific port, then call its host-level methods to register routes.
#[non_exhaustive]
pub struct RoutingTableBuilder<Kind> {
    by_port: HashMap<u16, PortTableBuilder>,
    _kind: PhantomData<fn() -> Kind>,
}

impl<Kind> Default for RoutingTableBuilder<Kind> {
    fn default() -> Self {
        Self {
            by_port: HashMap::new(),
            _kind: PhantomData,
        }
    }
}

impl<Kind> RoutingTableBuilder<Kind> {
    /// Construct an empty routing table builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the [`PortTableBuilder`] for `port`, creating it if absent.
    #[must_use]
    pub fn for_port(&mut self, port: u16) -> &mut PortTableBuilder {
        self.by_port.entry(port).or_default()
    }

    /// Compiles all registered routes into an immutable [`RoutingTable`].
    ///
    /// # Errors
    /// Returns [`RouterError::MatchitInsert`] if a path pattern was rejected by
    /// the `matchit` router, or [`RouterError::Regex`] if a regex pattern
    /// failed to compile.
    pub fn build(self) -> Result<RoutingTable<Kind>, RouterError> {
        let mut conflicts: Vec<RouteConflict> = Vec::new();
        let mut by_port: HashMap<u16, PortRoutingTable> = HashMap::new();

        for (port, pb) in self.by_port {
            let (table, cs) = pb.build(port)?;
            conflicts.extend(cs);
            by_port.insert(port, table);
        }

        Ok(RoutingTable {
            by_port,
            conflicts,
            _kind: PhantomData,
        })
    }
}
