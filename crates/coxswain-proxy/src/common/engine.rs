//! Lock-free routing engine wrapping a typed `Shared<RoutingTable<Kind>>`.
//!
//! `RoutingEngine<Kind>` is generic over the spec marker so the proxy that
//! serves Ingress traffic and the proxy that serves Gateway-API traffic each
//! hold a statically-typed engine and cannot accidentally exchange snapshots.

use coxswain_core::routing::{BackendGroup, RequestContext, RouteOutcome, RoutingTable};
use coxswain_core::shared::Shared;
use std::sync::Arc;

/// Lock-free routing engine for the request hot path.
///
/// Reads its snapshot with a single atomic load via the wrapped
/// [`Shared`][coxswain_core::shared::Shared] handle. The `Kind` marker
/// preserves the Ingress-vs-Gateway distinction at the type level.
pub struct RoutingEngine<Kind> {
    table: Shared<RoutingTable<Kind>>,
}

impl<Kind> RoutingEngine<Kind> {
    /// Wrap a typed shared routing-table handle in a routing engine.
    #[must_use]
    pub fn new(table: Shared<RoutingTable<Kind>>) -> Self {
        Self { table }
    }

    /// Returns the matching backend group, discarding filter/timeout context.
    ///
    /// Convenience for tests and admin introspection. The proxy hot path uses
    /// [`Self::find`] instead so it can also retrieve filters and timeouts.
    #[must_use]
    pub fn route(
        &self,
        port: u16,
        host: &str,
        path: &str,
        ctx: &RequestContext<'_>,
    ) -> Option<Arc<BackendGroup>> {
        self.table.load().route(port, host, path, ctx)
    }

    /// Resolves a request to a route outcome.
    ///
    /// Distinguishes "host not registered" (`RouteOutcome::NoHost`) from "host
    /// registered but path or predicate did not match" (`RouteOutcome::NoPath`).
    #[must_use]
    pub fn find(
        &self,
        port: u16,
        host: &str,
        path: &str,
        ctx: &RequestContext<'_>,
    ) -> RouteOutcome {
        self.table.load().find(port, host, path, ctx)
    }
}
