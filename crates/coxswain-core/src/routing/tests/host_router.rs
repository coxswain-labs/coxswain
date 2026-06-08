use super::*;
use std::sync::Arc;

#[test]
fn wildcard_host_multi_label_matches() {
    let up = make_group("svc", "10.0.0.1:80");

    let mut b = RoutingTableBuilder::new();
    b.for_port(PORT)
        .wildcard_host("*.test.com", WildcardKind::MultiLabel)
        .add_exact_route("/", entry(up));

    let table = b.build().unwrap();
    // Single-label subdomain always matches.
    assert!(table.route(PORT, "api.test.com", "/", &ctx_get()).is_some());
    // Bare suffix does not match (prefix must be non-empty).
    assert!(table.route(PORT, "test.com", "/", &ctx_get()).is_none());
    // Gateway API spec: `*` matches any number of subdomain labels.
    assert!(
        table
            .route(PORT, "nested.api.test.com", "/", &ctx_get())
            .is_some()
    );
}

#[test]
fn wildcard_host_single_label_matches() {
    let up = make_group("svc", "10.0.0.1:80");

    let mut b = RoutingTableBuilder::new();
    b.for_port(PORT)
        .wildcard_host("*.test.com", WildcardKind::SingleLabel)
        .add_exact_route("/", entry(up));

    let table = b.build().unwrap();
    // Single-label subdomain matches.
    assert!(table.route(PORT, "api.test.com", "/", &ctx_get()).is_some());
    // Bare suffix does not match.
    assert!(table.route(PORT, "test.com", "/", &ctx_get()).is_none());
    // Ingress spec: multi-label subdomain must NOT match.
    assert!(
        table
            .route(PORT, "nested.api.test.com", "/", &ctx_get())
            .is_none()
    );
}

#[test]
#[tracing_test::traced_test]
fn prefix_insert_collision_emits_debug_log() {
    let first = make_group("first", "10.0.0.1:80");
    let second = make_group("second", "10.0.0.2:80");

    let mut b = RoutingTableBuilder::new();
    let host = b.for_port(PORT).exact_host("example.com");
    // /foo expands to: /foo, /foo/, /foo/{*rest}
    // /foo/ expands to: /foo/, /foo/{*rest}
    // The second group's inserts collide with the first.
    host.add_prefix_route("/foo", entry(first));
    host.add_prefix_route("/foo/", entry(second));

    let _table = b.build().unwrap();

    assert!(logs_contain(
        "host router prefix insert shadowed by earlier rule"
    ));
    assert!(logs_contain("default/svc"));
}

#[test]
fn specificity_ordering_more_headers_wins() {
    // Two entries at the same path: one with a header predicate, one without.
    // The one with more predicates should win when its predicate passes.
    let specific_up = make_group("specific", "10.0.0.1:80");
    let generic_up = make_group("generic", "10.0.0.2:80");

    let pred = make_predicates(None, &[("x-tenant", "acme")], &[]);
    let specific = Arc::new(RouteEntry::new(
        Arc::clone(&specific_up),
        pred,
        "default/specific".to_string(),
        None,
    ));
    let generic = Arc::new(RouteEntry::path_only(
        Arc::clone(&generic_up),
        "default/generic".to_string(),
        None,
    ));

    let mut b = RoutingTableBuilder::new();
    // Insert generic first, specific second — specificity sort should reorder.
    let hb = b.for_port(PORT).exact_host("example.com");
    hb.add_exact_route("/", Arc::clone(&generic));
    hb.add_exact_route("/", Arc::clone(&specific));

    let table = b.build().unwrap();
    use super::headers_from;
    let headers_match = headers_from(&[("x-tenant", "acme")]);
    let headers_no = headers_from(&[]);

    use http::Method;
    let ctx_match = RequestContext {
        method: &Method::GET,
        headers: &headers_match,
        query: None,
    };
    let ctx_no = RequestContext {
        method: &Method::GET,
        headers: &headers_no,
        query: None,
    };

    // With matching header → specific wins (sorted first due to header count).
    assert_eq!(
        table
            .route(PORT, "example.com", "/", &ctx_match)
            .unwrap()
            .name(),
        "specific"
    );
    // Without matching header → specific's predicate fails; falls through to generic.
    assert_eq!(
        table
            .route(PORT, "example.com", "/", &ctx_no)
            .unwrap()
            .name(),
        "generic"
    );
}

#[test]
fn or_semantics_across_multiple_entries() {
    // Two entries at the same path with different header predicates:
    // whichever predicate matches the request wins.
    let up_a = make_group("a", "10.0.0.1:80");
    let up_b = make_group("b", "10.0.0.2:80");

    let pred_a = make_predicates(None, &[("x-tenant", "a")], &[]);
    let pred_b = make_predicates(None, &[("x-tenant", "b")], &[]);

    let entry_a = Arc::new(RouteEntry::new(up_a, pred_a, "default/a".to_string(), None));
    let entry_b = Arc::new(RouteEntry::new(up_b, pred_b, "default/b".to_string(), None));

    let mut b = RoutingTableBuilder::new();
    let hb = b.for_port(PORT).exact_host("example.com");
    hb.add_exact_route("/", Arc::clone(&entry_a));
    hb.add_exact_route("/", Arc::clone(&entry_b));

    let table = b.build().unwrap();

    use super::headers_from;
    use http::Method;
    let hdrs_a = headers_from(&[("x-tenant", "a")]);
    let hdrs_b = headers_from(&[("x-tenant", "b")]);
    let ctx_a = RequestContext {
        method: &Method::GET,
        headers: &hdrs_a,
        query: None,
    };
    let ctx_b = RequestContext {
        method: &Method::GET,
        headers: &hdrs_b,
        query: None,
    };

    assert_eq!(
        table
            .route(PORT, "example.com", "/", &ctx_a)
            .unwrap()
            .name(),
        "a"
    );
    assert_eq!(
        table
            .route(PORT, "example.com", "/", &ctx_b)
            .unwrap()
            .name(),
        "b"
    );
}
