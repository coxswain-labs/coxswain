use crate::routing::entry::RouteConflict;
use crate::routing::host_router::{HostRouter, HostRouterBuilder};
use std::cmp::Reverse;
use std::collections::HashMap;

use super::{PortRoutingTable, RouterError, RoutingTable};

/// Per-port route builder, mirroring the entry points of the old flat builder.
#[derive(Default)]
pub struct PortTableBuilder {
    exact_hosts: HashMap<String, HostRouterBuilder>,
    /// Keyed by suffix (e.g. `"example.com"` for the pattern `"*.example.com"`).
    wildcard_hosts: HashMap<String, HostRouterBuilder>,
    catchall: Option<HostRouterBuilder>,
}

impl PortTableBuilder {
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

    /// Dispatches to `exact_host`, `wildcard_host`, or `catchall` based on `host`.
    ///
    /// `None` → catchall, `Some("*.foo.com")` → wildcard, `Some("foo.com")` → exact.
    pub fn host_for(&mut self, host: Option<&str>) -> &mut HostRouterBuilder {
        match host {
            None => self.catchall(),
            Some(h) if h.starts_with("*.") => self.wildcard_host(h),
            Some(h) => self.exact_host(h),
        }
    }

    pub(super) fn build(
        self,
        port: u16,
    ) -> Result<(PortRoutingTable, Vec<RouteConflict>), RouterError> {
        let mut conflicts: Vec<RouteConflict> = Vec::new();

        let exact_hosts = self
            .exact_hosts
            .into_iter()
            .map(|(h, b)| {
                let (router, cs) = b.build()?;
                conflicts.extend(cs.into_iter().map(|c| RouteConflict { port, ..c }));
                Ok((h, router))
            })
            .collect::<Result<HashMap<_, _>, RouterError>>()?;

        let mut wildcard_hosts: Vec<(String, HostRouter)> = self
            .wildcard_hosts
            .into_iter()
            .map(|(suffix, b)| {
                let (router, cs) = b.build()?;
                conflicts.extend(cs.into_iter().map(|c| RouteConflict { port, ..c }));
                Ok((suffix, router))
            })
            .collect::<Result<Vec<_>, RouterError>>()?;
        wildcard_hosts.sort_by_key(|e| Reverse(e.0.len()));

        let catchall = match self.catchall {
            Some(b) => {
                let (router, cs) = b.build()?;
                conflicts.extend(cs.into_iter().map(|c| RouteConflict { port, ..c }));
                Some(router)
            }
            None => None,
        };

        Ok((
            PortRoutingTable {
                exact_hosts,
                wildcard_hosts,
                catchall,
            },
            conflicts,
        ))
    }
}

/// Builds an immutable [`RoutingTable`] keyed by listener port.
///
/// Use [`for_port`](Self::for_port) to obtain a [`PortTableBuilder`] for a
/// specific port, then call its host-level methods to register routes.
#[derive(Default)]
pub struct RoutingTableBuilder {
    by_port: HashMap<u16, PortTableBuilder>,
}

impl RoutingTableBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the [`PortTableBuilder`] for `port`, creating it if absent.
    pub fn for_port(&mut self, port: u16) -> &mut PortTableBuilder {
        self.by_port.entry(port).or_default()
    }

    /// Compiles all registered routes into an immutable [`RoutingTable`].
    pub fn build(self) -> Result<RoutingTable, RouterError> {
        let mut conflicts: Vec<RouteConflict> = Vec::new();
        let mut by_port: HashMap<u16, PortRoutingTable> = HashMap::new();

        for (port, pb) in self.by_port {
            let (table, cs) = pb.build(port)?;
            conflicts.extend(cs);
            by_port.insert(port, table);
        }

        Ok(RoutingTable { by_port, conflicts })
    }
}
