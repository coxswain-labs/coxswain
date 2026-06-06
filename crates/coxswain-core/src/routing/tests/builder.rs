use super::*;

#[test]
fn empty_builder_produces_empty_table() {
    let table = RoutingTableBuilder::new().build().unwrap();
    assert_eq!(table.host_count(), 0);
    assert!(table.conflicts().is_empty());
}

#[test]
fn single_exact_route_is_routable() {
    let g = make_group("svc", "10.0.0.1:80");
    let mut b = RoutingTableBuilder::new();
    b.for_port(PORT)
        .exact_host("a.example.com")
        .add_prefix_route("/api", entry(g));
    let table = b.build().unwrap();
    assert!(
        table
            .route(PORT, "a.example.com", "/api", &ctx_get())
            .is_some()
    );
    assert!(
        table
            .route(PORT, "a.example.com", "/other", &ctx_get())
            .is_none()
    );
    assert!(
        table
            .route(PORT, "b.example.com", "/api", &ctx_get())
            .is_none()
    );
}

#[test]
fn catchall_host_serves_all_hostnames() {
    let g = make_group("svc", "10.0.0.1:80");
    let mut b = RoutingTableBuilder::new();
    b.for_port(PORT).catchall().add_prefix_route("/", entry(g));
    let table = b.build().unwrap();
    assert!(
        table
            .route(PORT, "any.example.com", "/", &ctx_get())
            .is_some()
    );
    assert!(table.route(PORT, "other.io", "/", &ctx_get()).is_some());
}

#[test]
fn wildcard_host_routes_matching_subdomains() {
    let g = make_group("svc", "10.0.0.1:80");
    let mut b = RoutingTableBuilder::new();
    b.for_port(PORT)
        .wildcard_host("*.example.com")
        .add_prefix_route("/", entry(g));
    let table = b.build().unwrap();
    assert!(
        table
            .route(PORT, "foo.example.com", "/", &ctx_get())
            .is_some()
    );
    assert!(
        table
            .route(PORT, "bar.example.com", "/", &ctx_get())
            .is_some()
    );
    assert!(table.route(PORT, "example.com", "/", &ctx_get()).is_none());
    assert!(table.route(PORT, "other.io", "/", &ctx_get()).is_none());
}

#[test]
fn ports_are_isolated() {
    let g80 = make_group("svc80", "10.0.0.1:80");
    let g8080 = make_group("svc8080", "10.0.0.2:8080");
    let mut b = RoutingTableBuilder::new();
    b.for_port(80)
        .exact_host("a.com")
        .add_prefix_route("/", entry(g80));
    b.for_port(8080)
        .exact_host("b.com")
        .add_prefix_route("/", entry(g8080));
    let table = b.build().unwrap();
    assert!(table.route(80, "a.com", "/", &ctx_get()).is_some());
    assert!(table.route(80, "b.com", "/", &ctx_get()).is_none());
    assert!(table.route(8080, "b.com", "/", &ctx_get()).is_some());
    assert!(table.route(8080, "a.com", "/", &ctx_get()).is_none());
}

#[test]
fn host_for_dispatches_exact_wildcard_and_catchall() {
    let g = make_group("svc", "10.0.0.1:80");
    let mut b = RoutingTableBuilder::new();
    let pb = b.for_port(PORT);
    pb.host_for(Some("exact.com"))
        .add_prefix_route("/e", entry(g.clone()));
    pb.host_for(Some("*.wild.com"))
        .add_prefix_route("/w", entry(g.clone()));
    pb.host_for(None).add_prefix_route("/c", entry(g.clone()));
    let table = b.build().unwrap();
    assert!(table.route(PORT, "exact.com", "/e", &ctx_get()).is_some());
    assert!(
        table
            .route(PORT, "sub.wild.com", "/w", &ctx_get())
            .is_some()
    );
    assert!(
        table
            .route(PORT, "anything.else", "/c", &ctx_get())
            .is_some()
    );
}
