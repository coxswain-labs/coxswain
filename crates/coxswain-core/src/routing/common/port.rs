//! Per-port routing bucket and its associated builder.
//!
//! A [`PortRoutingTable`] is the immutable host+path+predicate router for one
//! listener port. A [`PortTableBuilder`] accumulates host entries and freezes
//! them into the compiled `PortRoutingTable` at table-build time.

use super::entry::RouteConflict;
use super::host_router::{HostRouter, HostRouterBuilder, WildcardKind, wildcard_matches};
use super::predicate::RequestContext;
use super::table::{RouteOutcome, RouterError};
use std::borrow::Cow;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;

use super::backend::BackendGroup;

/// How a host selector is represented in the wire view of a routing table.
///
/// Mirrors the three host-bucket kinds in [`PortTableBuilder`] so the discovery
/// wire layer can round-trip hostname class through `to_wire` / `from_wire`
/// without losing the wildcard kind.
#[non_exhaustive]
pub enum HostPattern<'a> {
    /// An exact hostname, e.g. `"api.example.com"`.
    Exact(&'a str),
    /// A wildcard pattern, e.g. `"*.example.com"` (suffix stored without `*.` prefix),
    /// along with the label-matching semantics.
    Wildcard(&'a str, WildcardKind),
    /// The catch-all `"*"` host bucket.
    Catchall,
}

/// Per-port routing bucket: the host+path+predicate logic for one listener port.
///
/// Shared between Ingress and Gateway-API top-level routing tables — the per-rule
/// matching machinery is identical; only the top-level container distinguishes
/// the two specs at the type level.
#[non_exhaustive]
pub struct PortRoutingTable {
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

        // Apply path normalization once, after the single host resolution.
        // `Borrowed` on the common (already-canonical) path costs one linear
        // scan and zero allocation; `Owned` allocates exactly one `String` only
        // when the path actually changes.
        let normalized: Cow<str> = router.normalize().apply(path);

        match router.route(&normalized, ctx) {
            Some(mut m) => {
                // Surface the normalized path so the proxy can forward it
                // upstream without re-computing normalization.  Set only when
                // the path actually changed (`Owned`); `None` means "use the
                // raw path" and avoids an `Arc` allocation on the common case.
                if let Cow::Owned(s) = normalized {
                    m.normalized_path = Some(Arc::from(s));
                }
                match m.error_status {
                    Some(status) => RouteOutcome::Error(status),
                    None => RouteOutcome::Found(m),
                }
            }
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
            && let Some(m) = r.route(path, ctx)
        {
            return Some(m.backend_group);
        }
        self.catchall
            .as_ref()?
            .route(path, ctx)
            .map(|m| m.backend_group)
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

    /// Iterate every host bucket with its [`HostPattern`] discriminator, in
    /// canonical order: exact hosts (unspecified), wildcard hosts (sorted
    /// longest-suffix first), catchall last.
    ///
    /// Used by the discovery wire layer to enumerate the full routing table for
    /// serialisation (`to_wire`).  The `from_wire` counterpart replays the same
    /// ordering via [`PortTableBuilder::host_for`].
    pub fn host_views(&self) -> impl Iterator<Item = (HostPattern<'_>, &HostRouter)> {
        let exact = self
            .exact_hosts
            .iter()
            .map(|(h, r)| (HostPattern::Exact(h.as_str()), r));
        let wildcard = self
            .wildcard_hosts
            .iter()
            .map(|(suffix, kind, r)| (HostPattern::Wildcard(suffix.as_str(), *kind), r));
        let catchall = self.catchall.iter().map(|r| (HostPattern::Catchall, r));
        exact.chain(wildcard).chain(catchall)
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
                conflicts.extend(cs.into_iter().map(|c| RouteConflict {
                    port,
                    host: h.clone(),
                    ..c
                }));
                Ok((h, router))
            })
            .collect::<Result<HashMap<_, _>, RouterError>>()?;

        let mut wildcard_hosts: Vec<(String, WildcardKind, HostRouter)> = self
            .wildcard_hosts
            .into_iter()
            .map(|((suffix, kind), b)| {
                let (router, cs) = b.build()?;
                let host = format!("*.{suffix}");
                conflicts.extend(cs.into_iter().map(|c| RouteConflict {
                    port,
                    host: host.clone(),
                    ..c
                }));
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
                conflicts.extend(cs.into_iter().map(|c| RouteConflict {
                    port,
                    host: "*".to_string(),
                    ..c
                }));
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
