//! Per-port routing bucket and its associated builder.
//!
//! A [`PortRoutingTable`] is the immutable host+path+predicate router for one
//! listener port. A [`PortTableBuilder`] accumulates host entries and freezes
//! them into the compiled `PortRoutingTable` at table-build time.

use super::entry::RouteConflict;
use super::host_router::{HostRouter, HostRouterBuilder, WildcardKind, wildcard_matches};
use super::predicate::RequestContext;
use super::table::{RouteOutcome, RouterError};
use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;

use super::entry::BackendGroup;

/// Per-port routing bucket: the host+path+predicate logic for one listener port.
///
/// Shared between Ingress and Gateway-API top-level routing tables — the per-rule
/// matching machinery is identical; only the top-level container distinguishes
/// the two specs at the type level.
pub(crate) struct PortRoutingTable {
    pub(crate) exact_hosts: HashMap<String, HostRouter>,
    /// Sorted most-specific (longest suffix) first; `SingleLabel` before `MultiLabel` on ties.
    pub(crate) wildcard_hosts: Vec<(String, WildcardKind, HostRouter)>,
    pub(crate) catchall: Option<HostRouter>,
}

impl PortRoutingTable {
    pub(super) fn find(&self, host: &str, path: &str, ctx: &RequestContext<'_>) -> RouteOutcome {
        let router = if let Some(r) = self.exact_hosts.get(host) {
            r
        } else if let Some((_, _, r)) = self
            .wildcard_hosts
            .iter()
            .find(|(s, k, _)| wildcard_matches(host, s, *k))
        {
            r
        } else if let Some(r) = self.catchall.as_ref() {
            r
        } else {
            return RouteOutcome::NoHost;
        };
        match router.route(path, ctx) {
            Some((_, _, _, _, _, Some(status))) => RouteOutcome::Error(status),
            Some((u, f, t, p, m, None)) => RouteOutcome::Found(u, f, t, p, m),
            None => RouteOutcome::NoPath,
        }
    }

    pub(super) fn route(
        &self,
        host: &str,
        path: &str,
        ctx: &RequestContext<'_>,
    ) -> Option<Arc<BackendGroup>> {
        let router = if let Some(r) = self.exact_hosts.get(host) {
            Some(r)
        } else {
            self.wildcard_hosts
                .iter()
                .find(|(s, k, _)| wildcard_matches(host, s, *k))
                .map(|(_, _, r)| r)
        };
        if let Some(r) = router
            && let Some((group, _, _, _, _, _)) = r.route(path, ctx)
        {
            return Some(group);
        }
        self.catchall
            .as_ref()?
            .route(path, ctx)
            .map(|(u, _, _, _, _, _)| u)
    }

    pub(super) fn host_routes(&self) -> Vec<(String, &HostRouter)> {
        let mut result: Vec<(String, &HostRouter)> = Vec::new();
        for (host, router) in &self.exact_hosts {
            result.push((host.clone(), router));
        }
        for (suffix, _kind, router) in &self.wildcard_hosts {
            result.push((format!("*.{suffix}"), router));
        }
        if let Some(router) = &self.catchall {
            result.push(("*".to_string(), router));
        }
        result
    }
}

/// Per-port route builder.
///
/// Use [`exact_host`](Self::exact_host), [`wildcard_host`](Self::wildcard_host),
/// or [`catchall`](Self::catchall) (or the dispatch helper
/// [`host_for`](Self::host_for)) to obtain a [`HostRouterBuilder`] for the
/// hostname class you want, then call its `add_*_route` methods to register
/// path rules.
#[non_exhaustive]
#[derive(Default)]
pub struct PortTableBuilder {
    exact_hosts: HashMap<String, HostRouterBuilder>,
    /// Keyed by `(suffix, WildcardKind)` so the same suffix can be registered
    /// with Ingress (single-label) and Gateway API (multi-label) semantics independently.
    wildcard_hosts: HashMap<(String, WildcardKind), HostRouterBuilder>,
    catchall: Option<HostRouterBuilder>,
}

impl PortTableBuilder {
    /// Returns the `HostRouterBuilder` for an exact hostname match.
    pub fn exact_host(&mut self, hostname: &str) -> &mut HostRouterBuilder {
        self.exact_hosts.entry(hostname.to_string()).or_default()
    }

    /// Returns the `HostRouterBuilder` for a wildcard hostname pattern with the given semantics.
    ///
    /// `pattern` must be in `*.example.com` form; the `*.` prefix is stripped internally.
    /// The same suffix registered with different `WildcardKind` values produces separate entries.
    pub fn wildcard_host(&mut self, pattern: &str, kind: WildcardKind) -> &mut HostRouterBuilder {
        let suffix = pattern.trim_start_matches("*.");
        self.wildcard_hosts
            .entry((suffix.to_string(), kind))
            .or_default()
    }

    /// Returns the `HostRouterBuilder` for the catch-all domain (`*`).
    pub fn catchall(&mut self) -> &mut HostRouterBuilder {
        self.catchall.get_or_insert_with(HostRouterBuilder::default)
    }

    /// Dispatches to `exact_host`, `wildcard_host`, or `catchall` based on `host`.
    ///
    /// `None` → catchall, `Some("*.foo.com")` → wildcard with `kind`, `Some("foo.com")` → exact.
    /// `kind` is only used for wildcard patterns; it is ignored for exact and catchall entries.
    pub fn host_for(&mut self, host: Option<&str>, kind: WildcardKind) -> &mut HostRouterBuilder {
        match host {
            None => self.catchall(),
            Some(h) if h.starts_with("*.") => self.wildcard_host(h, kind),
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

        let mut wildcard_hosts: Vec<(String, WildcardKind, HostRouter)> = self
            .wildcard_hosts
            .into_iter()
            .map(|((suffix, kind), b)| {
                let (router, cs) = b.build()?;
                conflicts.extend(cs.into_iter().map(|c| RouteConflict { port, ..c }));
                Ok((suffix, kind, router))
            })
            .collect::<Result<Vec<_>, RouterError>>()?;
        // Longest suffix first for specificity. Among equal-length suffixes, SingleLabel sorts
        // before MultiLabel so the more-restrictive Ingress entry wins on ties.
        wildcard_hosts.sort_by_key(|(s, k, _)| {
            (
                Reverse(s.len()),
                matches!(k, WildcardKind::MultiLabel) as u8,
            )
        });

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
