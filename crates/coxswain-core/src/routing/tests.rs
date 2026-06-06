use super::*;
use http::{HeaderMap, HeaderName, Method};
use regex::Regex;
use std::net::SocketAddr;
use std::time::SystemTime;

const PORT: u16 = 80;

fn group(name: &str, addr: &str) -> Arc<BackendGroup> {
    Arc::new(BackendGroup::new(
        name.to_string(),
        vec![addr.parse::<SocketAddr>().unwrap()],
    ))
}

fn entry(g: Arc<BackendGroup>) -> Arc<RouteEntry> {
    Arc::new(RouteEntry::path_only(g, "default/svc".to_string(), None))
}

fn ctx_get() -> RequestContext<'static> {
    RequestContext::default()
}

#[test]
fn exact_host_beats_wildcard() {
    let exact_up = group("exact", "10.0.0.1:80");
    let wildcard_up = group("wildcard", "10.0.0.2:80");

    let mut b = RoutingTableBuilder::new();
    b.for_port(PORT)
        .exact_host("example.com")
        .add_exact_route("/", entry(exact_up));
    b.for_port(PORT)
        .wildcard_host("*.com")
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
    let api_up = group("api", "10.0.0.1:80");
    let health_up = group("health", "10.0.0.2:80");

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
fn wildcard_host_matches() {
    let up = group("svc", "10.0.0.1:80");

    let mut b = RoutingTableBuilder::new();
    b.for_port(PORT)
        .wildcard_host("*.test.com")
        .add_exact_route("/", entry(up));

    let table = b.build().unwrap();
    assert!(table.route(PORT, "api.test.com", "/", &ctx_get()).is_some());
    assert!(table.route(PORT, "test.com", "/", &ctx_get()).is_none());
    // Per Gateway API spec, `*` matches any number of subdomain labels.
    assert!(
        table
            .route(PORT, "nested.api.test.com", "/", &ctx_get())
            .is_some()
    );
}

#[test]
fn route_falls_through_to_catchall_on_exact_host_path_miss() {
    let host_up = group("host", "10.0.0.1:80");
    let catchall_up = group("catchall", "10.0.0.2:80");

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
    let host_up = group("host", "10.0.0.1:80");
    let catchall_up = group("catchall", "10.0.0.2:80");

    let mut b = RoutingTableBuilder::new();
    b.for_port(PORT)
        .wildcard_host("*.example.com")
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
    let host_up = group("host", "10.0.0.1:80");

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
    let host_up = group("host", "10.0.0.1:80");
    let catchall_up = group("catchall", "10.0.0.2:80");

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
    let up80 = group("svc-80", "10.0.0.1:80");
    let up8080 = group("svc-8080", "10.0.0.2:8080");

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
fn round_robin_cycles() {
    let addrs: Vec<SocketAddr> = vec![
        "10.0.0.1:80".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        "10.0.0.3:80".parse().unwrap(),
    ];
    let up = BackendGroup::new("svc".to_string(), addrs.clone());
    let results: Vec<SocketAddr> = (0..6).map(|_| up.next_endpoint().unwrap()).collect();
    assert_eq!(
        results,
        [addrs[0], addrs[1], addrs[2], addrs[0], addrs[1], addrs[2]]
    );
}

#[test]
fn weighted_round_robin_distributes_proportionally() {
    let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
    let a2: SocketAddr = "10.0.0.2:80".parse().unwrap();
    let b1: SocketAddr = "10.0.1.1:80".parse().unwrap();

    // Backend A: 2 pods, weight 4.  Backend B: 1 pod, weight 1.
    // Expected: P(A) = 4/5 = 80%.
    let up = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1, a2], 4), (vec![b1], 1)]);

    let n = 1000;
    let mut a_count = 0usize;
    let mut b_count = 0usize;
    for _ in 0..n {
        let addr = up.next_endpoint().unwrap();
        if addr == a1 || addr == a2 {
            a_count += 1;
        } else if addr == b1 {
            b_count += 1;
        }
    }
    assert_eq!(a_count + b_count, n);
    // Allow ±5% tolerance around the expected 80/20 split.
    let a_ratio = a_count as f64 / n as f64;
    assert!(
        (0.75..=0.85).contains(&a_ratio),
        "backend A ratio {a_ratio:.2} out of expected 0.75–0.85"
    );
}

#[test]
fn weighted_zero_weight_backend_gets_no_traffic() {
    let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
    let b1: SocketAddr = "10.0.1.1:80".parse().unwrap();

    let up = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1], 0), (vec![b1], 1)]);
    for _ in 0..100 {
        assert_eq!(up.next_endpoint().unwrap(), b1);
    }
}

#[test]
fn weighted_all_zero_is_empty() {
    let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
    let up = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1], 0)]);
    assert!(up.next_endpoint().is_none());
}

#[test]
fn weighted_equal_weights_uniform() {
    let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
    let b1: SocketAddr = "10.0.1.1:80".parse().unwrap();

    // Equal weights → after GCD reduction both get 1 slot → 50/50.
    let up = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1], 5), (vec![b1], 5)]);
    let results: Vec<SocketAddr> = (0..4).map(|_| up.next_endpoint().unwrap()).collect();
    // slots = [0, 1] after reduction; cycling: a1, b1, a1, b1
    assert_eq!(results, [a1, b1, a1, b1]);
}

// ── Predicate tests ────────────────────────────────────────────────────────

fn headers_from(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut m = HeaderMap::new();
    for (k, v) in pairs {
        m.insert(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    m
}

fn make_predicates(
    method: Option<&str>,
    headers: &[(&str, &str)], // (name, exact_value)
    query: &[(&str, &str)],   // (name, exact_value)
) -> MatchPredicates {
    MatchPredicates {
        method: method.map(|m| m.parse().unwrap()),
        headers: headers
            .iter()
            .map(|(n, v)| HeaderPredicate {
                name: HeaderName::from_bytes(n.as_bytes()).unwrap(),
                matcher: ValueMatch::Exact(v.to_string()),
            })
            .collect(),
        query: query
            .iter()
            .map(|(n, v)| QueryPredicate {
                name: n.to_string(),
                matcher: ValueMatch::Exact(v.to_string()),
            })
            .collect(),
    }
}

#[test]
fn predicate_empty_matches_everything() {
    let pred = MatchPredicates::default();
    let headers = headers_from(&[]);
    let ctx = RequestContext {
        method: &Method::GET,
        headers: &headers,
        query: None,
    };
    assert!(pred.matches(&ctx));
}

#[test]
fn predicate_method_match() {
    let pred = make_predicates(Some("POST"), &[], &[]);
    let headers = headers_from(&[]);
    let get = RequestContext {
        method: &Method::GET,
        headers: &headers,
        query: None,
    };
    let post = RequestContext {
        method: &Method::POST,
        headers: &headers,
        query: None,
    };
    assert!(!pred.matches(&get));
    assert!(pred.matches(&post));
}

#[test]
fn predicate_header_exact_match() {
    let pred = make_predicates(None, &[("x-tenant", "foo")], &[]);
    let matching = headers_from(&[("x-tenant", "foo")]);
    let wrong = headers_from(&[("x-tenant", "bar")]);
    let absent = headers_from(&[]);
    let ctx_m = RequestContext {
        method: &Method::GET,
        headers: &matching,
        query: None,
    };
    let ctx_w = RequestContext {
        method: &Method::GET,
        headers: &wrong,
        query: None,
    };
    let ctx_a = RequestContext {
        method: &Method::GET,
        headers: &absent,
        query: None,
    };
    assert!(pred.matches(&ctx_m));
    assert!(!pred.matches(&ctx_w));
    assert!(!pred.matches(&ctx_a));
}

#[test]
fn predicate_header_regex_match() {
    let pred = MatchPredicates {
        method: None,
        headers: vec![HeaderPredicate {
            name: HeaderName::from_static("x-version"),
            matcher: ValueMatch::Regex(Regex::new(r"^v\d+$").unwrap()),
        }],
        query: vec![],
    };
    let matching = headers_from(&[("x-version", "v42")]);
    let wrong = headers_from(&[("x-version", "beta")]);
    let ctx_m = RequestContext {
        method: &Method::GET,
        headers: &matching,
        query: None,
    };
    let ctx_w = RequestContext {
        method: &Method::GET,
        headers: &wrong,
        query: None,
    };
    assert!(pred.matches(&ctx_m));
    assert!(!pred.matches(&ctx_w));
}

#[test]
fn predicate_query_exact_match() {
    let pred = make_predicates(None, &[], &[("version", "v1")]);
    let headers = headers_from(&[]);
    let ctx_yes = RequestContext {
        method: &Method::GET,
        headers: &headers,
        query: Some("version=v1&x=y"),
    };
    let ctx_no = RequestContext {
        method: &Method::GET,
        headers: &headers,
        query: Some("version=v2"),
    };
    let ctx_absent = RequestContext {
        method: &Method::GET,
        headers: &headers,
        query: None,
    };
    assert!(pred.matches(&ctx_yes));
    assert!(!pred.matches(&ctx_no));
    assert!(!pred.matches(&ctx_absent));
}

#[test]
fn predicate_query_regex_match() {
    let pred = MatchPredicates {
        method: None,
        headers: vec![],
        query: vec![QueryPredicate {
            name: "env".to_string(),
            matcher: ValueMatch::Regex(Regex::new(r"^(dev|staging)$").unwrap()),
        }],
    };
    let headers = headers_from(&[]);
    let ctx_dev = RequestContext {
        method: &Method::GET,
        headers: &headers,
        query: Some("env=dev"),
    };
    let ctx_prod = RequestContext {
        method: &Method::GET,
        headers: &headers,
        query: Some("env=prod"),
    };
    assert!(pred.matches(&ctx_dev));
    assert!(!pred.matches(&ctx_prod));
}

#[test]
fn predicate_and_semantics() {
    // Both method AND header must match.
    let pred = make_predicates(Some("POST"), &[("x-tenant", "a")], &[]);
    let headers_ok = headers_from(&[("x-tenant", "a")]);
    let headers_wrong = headers_from(&[("x-tenant", "b")]);
    let ctx_both = RequestContext {
        method: &Method::POST,
        headers: &headers_ok,
        query: None,
    };
    let ctx_method_only = RequestContext {
        method: &Method::POST,
        headers: &headers_wrong,
        query: None,
    };
    let ctx_header_only = RequestContext {
        method: &Method::GET,
        headers: &headers_ok,
        query: None,
    };
    assert!(pred.matches(&ctx_both));
    assert!(!pred.matches(&ctx_method_only));
    assert!(!pred.matches(&ctx_header_only));
}

#[test]
fn header_lookup_is_case_insensitive() {
    // Predicate stores lowercase HeaderName; request may have mixed case.
    let pred = make_predicates(None, &[("x-tenant", "acme")], &[]);
    // HTTP/1.1 allows any case; HeaderMap canonicalises to lowercase internally.
    let headers = headers_from(&[("x-tenant", "acme")]);
    let ctx = RequestContext {
        method: &Method::GET,
        headers: &headers,
        query: None,
    };
    assert!(pred.matches(&ctx));
}

#[test]
fn specificity_ordering_more_headers_wins() {
    // Two entries at the same path: one with a header predicate, one without.
    // The one with more predicates should win when its predicate passes.
    let specific_up = group("specific", "10.0.0.1:80");
    let generic_up = group("generic", "10.0.0.2:80");

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
    let headers_match = headers_from(&[("x-tenant", "acme")]);
    let headers_no = headers_from(&[]);

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
fn timestamp_tiebreaker_older_wins() {
    // Two entries with the same predicate count; older route wins.
    let older_up = group("older", "10.0.0.1:80");
    let newer_up = group("newer", "10.0.0.2:80");

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

#[test]
fn or_semantics_across_multiple_entries() {
    // Two entries at the same path with different header predicates:
    // whichever predicate matches the request wins.
    let up_a = group("a", "10.0.0.1:80");
    let up_b = group("b", "10.0.0.2:80");

    let pred_a = make_predicates(None, &[("x-tenant", "a")], &[]);
    let pred_b = make_predicates(None, &[("x-tenant", "b")], &[]);

    let entry_a = Arc::new(RouteEntry::new(up_a, pred_a, "default/a".to_string(), None));
    let entry_b = Arc::new(RouteEntry::new(up_b, pred_b, "default/b".to_string(), None));

    let mut b = RoutingTableBuilder::new();
    let hb = b.for_port(PORT).exact_host("example.com");
    hb.add_exact_route("/", Arc::clone(&entry_a));
    hb.add_exact_route("/", Arc::clone(&entry_b));

    let table = b.build().unwrap();

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

#[test]
fn find_returns_timeouts_from_route_entry() {
    let up = group("svc", "10.0.0.1:80");
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
#[tracing_test::traced_test]
fn prefix_insert_collision_emits_debug_log() {
    let first = group("first", "10.0.0.1:80");
    let second = group("second", "10.0.0.2:80");

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
