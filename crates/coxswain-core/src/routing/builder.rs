use crate::routing::entry::RouteConflict;
use crate::routing::host_router::{HostRouter, HostRouterBuilder};
use std::cmp::Reverse;
use std::collections::HashMap;

use super::{RouterError, RoutingTable};

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
                let (router, cs) = b.build()?;
                conflicts.extend(cs);
                Ok((h, router))
            })
            .collect::<Result<HashMap<_, _>, RouterError>>()?;

        let mut wildcard_hosts: Vec<(String, HostRouter)> = self
            .wildcard_hosts
            .into_iter()
            .map(|(suffix, b)| {
                let (router, cs) = b.build()?;
                conflicts.extend(cs);
                Ok((suffix, router))
            })
            .collect::<Result<Vec<_>, RouterError>>()?;
        // Most specific (longest suffix) first — matches K8s Gateway API precedence.
        wildcard_hosts.sort_by_key(|e| Reverse(e.0.len()));

        let catchall = match self.catchall {
            Some(b) => {
                let (router, cs) = b.build()?;
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
