use super::*;
use std::time::SystemTime;

#[test]
fn exact_host_beats_wildcard() {
    let exact_up = make_group("exact", "10.0.0.1:80");
    let wildcard_up = make_group("wildcard", "10.0.0.2:80");

    let mut b = RoutingTableBuilder::new();
    b.for_port(PORT)
        .exact_host("example.com")
        .add_exact_route("/", entry(exact_up));
    b.for_port(PORT)
        .wildcard_host("*.com", WildcardKind::MultiLabel)
        .add_exact_route("/", entry(wildcard_up));

    let table = b.build().unwrap();
    assert_eq!(
        table
            .route(PORT, "example.com", "/", &ctx_get())
            .unwrap()
            .name(),
        "exact"
    );
    assert_eq!(
        table
            .route(PORT, "other.com", "/", &ctx_get())
            .unwrap()
            .name(),
        "wildcard"
    );
}

#[test]
fn path_routing_within_host() {
    let api_up = make_group("api", "10.0.0.1:80");
    let health_up = make_group("health", "10.0.0.2:80");

    let mut b = RoutingTableBuilder::new();
    let host = b.for_port(PORT).exact_host("example.com");
    host.add_prefix_route("/api", entry(api_up));
    host.add_exact_route("/health", entry(health_up));

    let table = b.build().unwrap();
    assert_eq!(
        table
            .route(PORT, "example.com", "/api/users", &ctx_get())
            .unwrap()
            .name(),
        "api"
    );
    assert_eq!(
        table
            .route(PORT, "example.com", "/health", &ctx_get())
            .unwrap()
            .name(),
        "health"
    );
}

#[test]
fn route_falls_through_to_catchall_on_exact_host_path_miss() {
    let host_up = make_group("host", "10.0.0.1:80");
    let catchall_up = make_group("catchall", "10.0.0.2:80");

    let mut b = RoutingTableBuilder::new();
    b.for_port(PORT)
        .exact_host("example.com")
        .add_prefix_route("/api", entry(host_up));
    b.for_port(PORT)
        .catchall()
        .add_prefix_route("/", entry(catchall_up));

    let table = b.build().unwrap();
    assert_eq!(
        table
            .route(PORT, "example.com", "/api/v1", &ctx_get())
            .unwrap()
            .name(),
        "host"
    );
    assert_eq!(
        table
            .route(PORT, "example.com", "/other", &ctx_get())
            .unwrap()
            .name(),
        "catchall"
    );
}

#[test]
fn route_falls_through_to_catchall_on_wildcard_host_path_miss() {
    let host_up = make_group("host", "10.0.0.1:80");
    let catchall_up = make_group("catchall", "10.0.0.2:80");

    let mut b = RoutingTableBuilder::new();
    b.for_port(PORT)
        .wildcard_host("*.example.com", WildcardKind::MultiLabel)
        .add_prefix_route("/api", entry(host_up));
    b.for_port(PORT)
        .catchall()
        .add_prefix_route("/", entry(catchall_up));

    let table = b.build().unwrap();
    assert_eq!(
        table
            .route(PORT, "api.example.com", "/api/v1", &ctx_get())
            .unwrap()
            .name(),
        "host"
    );
    assert_eq!(
        table
            .route(PORT, "api.example.com", "/other", &ctx_get())
            .unwrap()
            .name(),
        "catchall"
    );
}

#[test]
fn route_returns_none_when_neither_host_router_nor_catchall_match() {
    let host_up = make_group("host", "10.0.0.1:80");

    let mut b = RoutingTableBuilder::new();
    b.for_port(PORT)
        .exact_host("example.com")
        .add_prefix_route("/api", entry(host_up));

    let table = b.build().unwrap();
    assert!(
        table
            .route(PORT, "example.com", "/other", &ctx_get())
            .is_none()
    );
    assert!(
        table
            .route(PORT, "unknown.com", "/api", &ctx_get())
            .is_none()
    );
}

#[test]
fn route_host_router_takes_precedence_over_catchall_for_same_path() {
    let host_up = make_group("host", "10.0.0.1:80");
    let catchall_up = make_group("catchall", "10.0.0.2:80");

    let mut b = RoutingTableBuilder::new();
    b.for_port(PORT)
        .exact_host("example.com")
        .add_prefix_route("/api", entry(host_up));
    b.for_port(PORT)
        .catchall()
        .add_prefix_route("/api", entry(catchall_up));

    let table = b.build().unwrap();
    assert_eq!(
        table
            .route(PORT, "example.com", "/api/v1", &ctx_get())
            .unwrap()
            .name(),
        "host"
    );
    assert_eq!(
        table
            .route(PORT, "other.com", "/api/v1", &ctx_get())
            .unwrap()
            .name(),
        "catchall"
    );
}

#[test]
fn routes_on_different_ports_are_isolated() {
    let up80 = make_group("svc-80", "10.0.0.1:80");
    let up8080 = make_group("svc-8080", "10.0.0.2:8080");

    let mut b = RoutingTableBuilder::new();
    b.for_port(80)
        .exact_host("example.com")
        .add_prefix_route("/", entry(up80));
    b.for_port(8080)
        .exact_host("example.com")
        .add_prefix_route("/", entry(up8080));

    let table = b.build().unwrap();
    assert_eq!(
        table
            .route(80, "example.com", "/", &ctx_get())
            .unwrap()
            .name(),
        "svc-80"
    );
    assert_eq!(
        table
            .route(8080, "example.com", "/", &ctx_get())
            .unwrap()
            .name(),
        "svc-8080"
    );
    // A route scoped to 8080 must not be reachable on 80.
    assert!(table.route(80, "example.com", "/api", &ctx_get()).is_some()); // prefix / catches it
    // A port with no registered routes returns NoHost.
    assert!(table.route(9090, "example.com", "/", &ctx_get()).is_none());
}

#[test]
fn find_returns_timeouts_from_route_entry() {
    use std::sync::Arc;
    let up = make_group("svc", "10.0.0.1:80");
    let timeouts = RouteTimeouts {
        request: Some(std::time::Duration::from_secs(10)),
        backend_request: Some(std::time::Duration::from_secs(2)),
    };
    let e = Arc::new(RouteEntry::with_filters(
        up,
        MatchPredicates::default(),
        vec![],
        timeouts.clone(),
        "default/svc".to_string(),
        None,
    ));

    let mut b = RoutingTableBuilder::new();
    b.for_port(PORT)
        .exact_host("example.com")
        .add_prefix_route("/", e);
    let table = b.build().unwrap();

    match table.find(PORT, "example.com", "/foo", &ctx_get()) {
        RouteOutcome::Found(_, _, t) => {
            assert_eq!(t.request, timeouts.request);
            assert_eq!(t.backend_request, timeouts.backend_request);
        }
        _ => panic!("expected Found"),
    }
}

#[test]
fn timestamp_tiebreaker_older_wins() {
    // Two entries with the same predicate count; older route wins.
    use std::sync::Arc;
    let older_up = make_group("older", "10.0.0.1:80");
    let newer_up = make_group("newer", "10.0.0.2:80");

    let t_old = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000);
    let t_new = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2000);

    let older = Arc::new(RouteEntry::path_only(
        Arc::clone(&older_up),
        "default/older".to_string(),
        Some(t_old),
    ));
    let newer = Arc::new(RouteEntry::path_only(
        Arc::clone(&newer_up),
        "default/newer".to_string(),
        Some(t_new),
    ));

    let mut b = RoutingTableBuilder::new();
    let hb = b.for_port(PORT).exact_host("example.com");
    // Insert newer first; sort should put older first.
    hb.add_exact_route("/", Arc::clone(&newer));
    hb.add_exact_route("/", Arc::clone(&older));

    let table = b.build().unwrap();
    assert_eq!(
        table
            .route(PORT, "example.com", "/", &ctx_get())
            .unwrap()
            .name(),
        "older"
    );
}
