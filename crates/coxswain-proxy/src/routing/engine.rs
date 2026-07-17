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
#[non_exhaustive]
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
        self.table.guard().route(port, host, path, ctx)
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
        self.table.guard().find(port, host, path, ctx)
    }
}

#[cfg(test)]
mod tests {
    use crate::filters::redirect::{RedirectOrigin, build_redirect_location};
    use crate::routing::engine::RoutingEngine;
    use coxswain_core::routing::{
        BackendGroup, FilterAction, GatewayRoutingTableBuilder, HeaderMod, PathModifier,
        RequestContext, RouteEntry, RouteOutcome, SharedGatewayRoutingTable,
    };
    use std::net::SocketAddr;
    use std::sync::Arc;

    const PORT: u16 = 80;

    fn make_group(name: &str, addr: &str) -> Arc<BackendGroup> {
        Arc::new(BackendGroup::new(
            name.to_string(),
            vec![addr.parse::<SocketAddr>().unwrap()],
        ))
    }

    fn entry(g: Arc<BackendGroup>) -> Arc<RouteEntry> {
        Arc::new(RouteEntry::path_only(g, "default/svc".to_string(), None))
    }

    fn engine_with_table(
        shared: SharedGatewayRoutingTable,
    ) -> RoutingEngine<coxswain_core::routing::Gateway> {
        RoutingEngine::new(shared)
    }

    fn origin(
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

    #[test]
    fn route_resolves_matched_host_and_path() {
        let upstream = make_group("default/backend", "10.0.0.1:8080");
        let mut builder = GatewayRoutingTableBuilder::new();
        builder
            .for_port(PORT)
            .exact_host("example.com")
            .add_prefix_route("/", entry(upstream));
        let shared = SharedGatewayRoutingTable::new();
        shared.store(Arc::new(builder.build().unwrap()));

        let engine = engine_with_table(shared);
        let ctx = RequestContext::default();
        let result = engine.route(PORT, "example.com", "/api/users", &ctx);
        assert!(result.is_some());
        assert_eq!(result.unwrap().name(), "default/backend");
    }

    #[test]
    fn route_returns_none_for_unknown_host() {
        let upstream = make_group("default/backend", "10.0.0.1:8080");
        let mut builder = GatewayRoutingTableBuilder::new();
        builder
            .for_port(PORT)
            .exact_host("example.com")
            .add_prefix_route("/", entry(upstream));
        let shared = SharedGatewayRoutingTable::new();
        shared.store(Arc::new(builder.build().unwrap()));

        let engine = engine_with_table(shared);
        let ctx = RequestContext::default();
        assert!(engine.route(PORT, "other.com", "/", &ctx).is_none());
    }

    #[test]
    fn route_returns_none_on_empty_table() {
        let engine = engine_with_table(SharedGatewayRoutingTable::new());
        let ctx = RequestContext::default();
        assert!(engine.route(PORT, "example.com", "/", &ctx).is_none());
    }

    #[test]
    fn upstream_with_no_endpoints_returns_none_from_next_endpoint() {
        let upstream = Arc::new(BackendGroup::new("default/empty".to_string(), vec![]));
        let mut builder = GatewayRoutingTableBuilder::new();
        builder
            .for_port(PORT)
            .exact_host("example.com")
            .add_exact_route("/", entry(upstream));
        let shared = SharedGatewayRoutingTable::new();
        shared.store(Arc::new(builder.build().unwrap()));

        let engine = engine_with_table(shared);
        let ctx = RequestContext::default();
        let resolved = engine.route(PORT, "example.com", "/", &ctx);
        assert!(resolved.is_some(), "route should resolve");
        assert!(
            resolved.unwrap().next_endpoint().is_none(),
            "empty upstream yields no endpoint"
        );
    }

    #[test]
    fn redirect_location_no_overrides_returns_original() {
        let loc = build_redirect_location(
            None,
            None,
            None,
            None,
            &origin("http", "example.com", 80, "/foo", None),
        );
        assert_eq!(loc, "http://example.com/foo");
    }

    #[test]
    fn redirect_location_no_overrides_preserves_non_default_port() {
        let loc = build_redirect_location(
            None,
            None,
            None,
            None,
            &origin("http", "example.com", 8080, "/foo", None),
        );
        assert_eq!(loc, "http://example.com:8080/foo");
    }

    #[test]
    fn redirect_location_scheme_override() {
        let loc = build_redirect_location(
            Some("https"),
            None,
            None,
            None,
            &origin("http", "example.com", 80, "/foo", None),
        );
        assert_eq!(loc, "https://example.com/foo");
    }

    #[test]
    fn redirect_location_hostname_override() {
        let loc = build_redirect_location(
            None,
            Some("new.example.com"),
            None,
            None,
            &origin("http", "old.example.com", 80, "/bar", None),
        );
        assert_eq!(loc, "http://new.example.com/bar");
    }

    #[test]
    fn redirect_location_preserves_query() {
        let loc = build_redirect_location(
            None,
            None,
            None,
            None,
            &origin("http", "example.com", 80, "/x", Some("k=v")),
        );
        assert_eq!(loc, "http://example.com/x?k=v");
    }

    #[test]
    fn redirect_location_non_default_port_included() {
        let loc = build_redirect_location(
            None,
            None,
            Some(8080),
            None,
            &origin("http", "example.com", 80, "/", None),
        );
        assert_eq!(loc, "http://example.com:8080/");
    }

    #[test]
    fn redirect_location_default_http_port_omitted() {
        let loc = build_redirect_location(
            Some("http"),
            None,
            Some(80),
            None,
            &origin("http", "example.com", 80, "/", None),
        );
        assert_eq!(loc, "http://example.com/");
    }

    #[test]
    fn redirect_location_replace_full_path() {
        let pm = PathModifier::ReplaceFullPath("/new".to_string());
        let loc = build_redirect_location(
            None,
            None,
            None,
            Some(&pm),
            &origin("http", "example.com", 80, "/old/path", None),
        );
        assert_eq!(loc, "http://example.com/new");
    }

    #[test]
    fn redirect_location_replace_prefix() {
        let pm = PathModifier::ReplacePrefixMatch {
            prefix: "/api".to_string(),
            replacement: "/v2".to_string(),
        };
        let loc = build_redirect_location(
            None,
            None,
            None,
            Some(&pm),
            &origin("http", "example.com", 80, "/api/users", None),
        );
        assert_eq!(loc, "http://example.com/v2/users");
    }

    #[test]
    fn find_returns_filters_alongside_upstream() {
        let upstream = make_group("default/backend", "10.0.0.1:8080");
        let filters = vec![FilterAction::RequestHeaderModifier(
            HeaderMod::parse(&[], &[("x-env", "test")], &[]).unwrap(),
        )];
        let entry = Arc::new(RouteEntry::with_filters(
            upstream,
            Default::default(),
            filters,
            Default::default(),
            "default/svc".to_string(),
            None,
        ));
        let mut builder = GatewayRoutingTableBuilder::new();
        builder
            .for_port(PORT)
            .exact_host("example.com")
            .add_prefix_route("/", entry);
        let shared = SharedGatewayRoutingTable::new();
        shared.store(Arc::new(builder.build().unwrap()));

        let engine = engine_with_table(shared);
        let ctx = RequestContext::default();
        match engine.find(PORT, "example.com", "/test", &ctx) {
            RouteOutcome::Found(m) => {
                let filters = m.filters;
                assert_eq!(filters.len(), 1);
                assert!(matches!(
                    &filters[0],
                    FilterAction::RequestHeaderModifier(_)
                ));
            }
            _ => panic!("expected Found"),
        }
    }
}
