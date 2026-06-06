mod proxy;

use super::redirect::RedirectOrigin;
use super::*;
use coxswain_core::routing::{BackendGroup, RouteEntry, RoutingTableBuilder, SharedRoutingTable};
use std::net::SocketAddr;
use std::sync::Arc;

pub(super) fn make_group(name: &str, addr: &str) -> Arc<BackendGroup> {
    Arc::new(BackendGroup::new(
        name.to_string(),
        vec![addr.parse::<SocketAddr>().unwrap()],
    ))
}

pub(super) fn entry(g: Arc<BackendGroup>) -> Arc<RouteEntry> {
    Arc::new(RouteEntry::path_only(g, "default/svc".to_string(), None))
}

pub(super) fn engine_with_table(shared: SharedRoutingTable) -> RoutingEngine {
    RoutingEngine::new(shared)
}

pub(super) const PORT: u16 = 80;

pub(super) fn origin(
    scheme: &'static str,
    host: &'static str,
    port: u16,
    path: &'static str,
    query: Option<&'static str>,
) -> RedirectOrigin<'static> {
    RedirectOrigin {
        scheme,
        host,
        port,
        path,
        query,
    }
}
