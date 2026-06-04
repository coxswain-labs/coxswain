use coxswain_core::routing::{RequestContext, RouteOutcome, SharedRoutingTable, Upstream};
use std::sync::Arc;

/// Lock-free routing engine for the request hot path.
pub struct RoutingEngine {
    table: SharedRoutingTable,
}

impl RoutingEngine {
    pub fn new(table: SharedRoutingTable) -> Self {
        Self { table }
    }

    /// Like [`find`] but returns only the upstream, without host/path distinction.
    pub fn route(
        &self,
        port: u16,
        host: &str,
        path: &str,
        ctx: &RequestContext<'_>,
    ) -> Option<Arc<Upstream>> {
        self.table.load().route(port, host, path, ctx)
    }

    /// Distinguishes "host not registered" from "path/predicate not matched".
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
