use super::*;

// ── Original path-matching tests (unchanged behaviour) ────────────────────

#[test]
fn reconcile_exact_path() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route(
        "default",
        &["example.com"],
        Some(vec![path_match(
            "/api",
            HttpRouteRulesMatchesPathType::Exact,
        )]),
        "svc",
    );
    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listener_info(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let empty_hdrs = HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

    assert!(table.route(80, "example.com", "/api", &ctx).is_some());
    assert!(table.route(80, "example.com", "/api/users", &ctx).is_none());
}

#[test]
fn reconcile_prefix_path() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route(
        "default",
        &["example.com"],
        Some(vec![path_match(
            "/api",
            HttpRouteRulesMatchesPathType::PathPrefix,
        )]),
        "svc",
    );
    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listener_info(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let empty_hdrs = HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

    assert!(table.route(80, "example.com", "/api", &ctx).is_some());
    assert!(table.route(80, "example.com", "/api/users", &ctx).is_some());
}

#[test]
fn reconcile_regex_path() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route(
        "default",
        &["example.com"],
        Some(vec![path_match(
            r"/item/\d+",
            HttpRouteRulesMatchesPathType::RegularExpression,
        )]),
        "svc",
    );
    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listener_info(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let empty_hdrs = HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

    assert!(table.route(80, "example.com", "/item/42", &ctx).is_some());
    assert!(table.route(80, "example.com", "/item/abc", &ctx).is_none());
}

#[test]
fn reconcile_no_matches_defaults_to_root_prefix() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route("default", &["example.com"], None, "svc");
    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listener_info(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let empty_hdrs = HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

    assert!(table.route(80, "example.com", "/anything", &ctx).is_some());
}

#[test]
fn reconcile_skips_route_without_owned_parent() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route("default", &["example.com"], None, "svc");
    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &owned(&[("other", "gw")]),
        &grants,
        &no_listener_info(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let empty_hdrs = HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

    assert!(table.route(80, "example.com", "/", &ctx).is_none());
}

// ── New predicate tests ────────────────────────────────────────────────────

#[test]
fn reconcile_header_exact_routes_to_correct_backend() {
    let store = slice_store(vec![
        make_slice("default", "svc-a", "10.0.0.1"),
        make_slice("default", "svc-b", "10.0.0.2"),
    ]);

    // Two rules: same path, different header → different backends.
    let route = HttpRoute {
        metadata: ObjectMeta {
            name: Some("route".to_string()),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        spec: HttpRouteSpec {
            parent_refs: default_parents(),
            hostnames: Some(vec!["example.com".to_string()]),
            rules: Some(vec![
                HttpRouteRules {
                    matches: Some(vec![header_exact_match("/", "x-tenant", "a")]),
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc-a".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
                HttpRouteRules {
                    matches: Some(vec![header_exact_match("/", "x-tenant", "b")]),
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc-b".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
            ]),
        },
        ..Default::default()
    };

    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listener_info(),
        &mut builder,
    );
    let table = builder.build().unwrap();

    let hdrs_a = headers_from(&[("x-tenant", "a")]);
    let hdrs_b = headers_from(&[("x-tenant", "b")]);
    let ctx_a = ctx_with(&Method::GET, &hdrs_a, None);
    let ctx_b = ctx_with(&Method::GET, &hdrs_b, None);

    assert_eq!(
        table.route(80, "example.com", "/", &ctx_a).unwrap().name(),
        "default/svc-a"
    );
    assert_eq!(
        table.route(80, "example.com", "/", &ctx_b).unwrap().name(),
        "default/svc-b"
    );
}

#[test]
fn reconcile_header_regex_routes_to_correct_backend() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route(
        "default",
        &["example.com"],
        Some(vec![header_regex_match("/", "x-version", r"^v\d+$")]),
        "svc",
    );
    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listener_info(),
        &mut builder,
    );
    let table = builder.build().unwrap();

    let hdrs_ok = headers_from(&[("x-version", "v42")]);
    let hdrs_bad = headers_from(&[("x-version", "beta")]);
    let ctx_ok = ctx_with(&Method::GET, &hdrs_ok, None);
    let ctx_bad = ctx_with(&Method::GET, &hdrs_bad, None);

    assert!(table.route(80, "example.com", "/", &ctx_ok).is_some());
    assert!(table.route(80, "example.com", "/", &ctx_bad).is_none());
}

#[test]
fn reconcile_method_routes_to_correct_backend() {
    let store = slice_store(vec![
        make_slice("default", "svc-get", "10.0.0.1"),
        make_slice("default", "svc-post", "10.0.0.2"),
    ]);

    let route = HttpRoute {
        metadata: ObjectMeta {
            name: Some("route".to_string()),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        spec: HttpRouteSpec {
            parent_refs: default_parents(),
            hostnames: Some(vec!["example.com".to_string()]),
            rules: Some(vec![
                HttpRouteRules {
                    matches: Some(vec![method_match("/", HttpRouteRulesMatchesMethod::Get)]),
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc-get".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
                HttpRouteRules {
                    matches: Some(vec![method_match("/", HttpRouteRulesMatchesMethod::Post)]),
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc-post".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
            ]),
        },
        ..Default::default()
    };

    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listener_info(),
        &mut builder,
    );
    let table = builder.build().unwrap();

    let h = HeaderMap::new();
    let ctx_get = ctx_with(&Method::GET, &h, None);
    let ctx_post = ctx_with(&Method::POST, &h, None);

    assert_eq!(
        table
            .route(80, "example.com", "/", &ctx_get)
            .unwrap()
            .name(),
        "default/svc-get"
    );
    assert_eq!(
        table
            .route(80, "example.com", "/", &ctx_post)
            .unwrap()
            .name(),
        "default/svc-post"
    );
}

#[test]
fn reconcile_query_param_routes_to_correct_backend() {
    let store = slice_store(vec![
        make_slice("default", "svc-v1", "10.0.0.1"),
        make_slice("default", "svc-v2", "10.0.0.2"),
    ]);

    let route = HttpRoute {
        metadata: ObjectMeta {
            name: Some("route".to_string()),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        spec: HttpRouteSpec {
            parent_refs: default_parents(),
            hostnames: Some(vec!["example.com".to_string()]),
            rules: Some(vec![
                HttpRouteRules {
                    matches: Some(vec![query_exact_match("/", "version", "v1")]),
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc-v1".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
                HttpRouteRules {
                    matches: Some(vec![query_exact_match("/", "version", "v2")]),
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc-v2".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
            ]),
        },
        ..Default::default()
    };

    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listener_info(),
        &mut builder,
    );
    let table = builder.build().unwrap();

    let h = HeaderMap::new();
    let ctx_v1 = ctx_with(&Method::GET, &h, Some("version=v1"));
    let ctx_v2 = ctx_with(&Method::GET, &h, Some("version=v2"));

    assert_eq!(
        table.route(80, "example.com", "/", &ctx_v1).unwrap().name(),
        "default/svc-v1"
    );
    assert_eq!(
        table.route(80, "example.com", "/", &ctx_v2).unwrap().name(),
        "default/svc-v2"
    );
}

#[test]
fn reconcile_invalid_regex_skips_match_entry() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route(
        "default",
        &["example.com"],
        Some(vec![
            // invalid regex
            HttpRouteRulesMatches {
                headers: Some(vec![HttpRouteRulesMatchesHeaders {
                    name: "x-bad".to_string(),
                    value: "[invalid".to_string(),
                    r#type: Some(HttpRouteRulesMatchesHeadersType::RegularExpression),
                }]),
                ..Default::default()
            },
            // valid path-only fallback
            path_match("/", HttpRouteRulesMatchesPathType::PathPrefix),
        ]),
        "svc",
    );
    let mut builder = RoutingTableBuilder::new();
    let grants = HashSet::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &grants,
        &no_listener_info(),
        &mut builder,
    );
    let table = builder.build().unwrap();

    let empty_hdrs = HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);
    assert!(table.route(80, "example.com", "/", &ctx).is_some());
}

#[test]
fn reconcile_header_name_dedup_keeps_first() {
    let m = HttpRouteRulesMatches {
        headers: Some(vec![
            HttpRouteRulesMatchesHeaders {
                name: "X-Tenant".to_string(),
                value: "first".to_string(),
                r#type: Some(HttpRouteRulesMatchesHeadersType::Exact),
            },
            HttpRouteRulesMatchesHeaders {
                name: "x-tenant".to_string(), // same header, different case
                value: "second".to_string(),
                r#type: Some(HttpRouteRulesMatchesHeadersType::Exact),
            },
        ]),
        ..Default::default()
    };
    let predicates = super::super::filters::build_predicates(&m).unwrap();
    assert_eq!(predicates.headers.len(), 1);
    match &predicates.headers[0].matcher {
        coxswain_core::routing::ValueMatch::Exact(v) => assert_eq!(v, "first"),
        _ => panic!("expected exact matcher"),
    }
}

// ── Weighted backendRefs (issue #17) ─────────────────────────────────────────

fn weighted_route(ns: &str, refs: &[(&str, Option<i32>)]) -> HttpRoute {
    HttpRoute {
        metadata: ObjectMeta {
            name: Some("route".to_string()),
            namespace: Some(ns.to_string()),
            ..Default::default()
        },
        spec: HttpRouteSpec {
            parent_refs: default_parents(),
            hostnames: Some(vec!["example.com".to_string()]),
            rules: Some(vec![HttpRouteRules {
                backend_refs: Some(
                    refs.iter()
                        .map(|(svc, w)| HttpRouteRulesBackendRefs {
                            name: svc.to_string(),
                            port: Some(80),
                            weight: *w,
                            ..Default::default()
                        })
                        .collect(),
                ),
                ..Default::default()
            }]),
        },
        ..Default::default()
    }
}

#[test]
fn weighted_backends_80_20_split() {
    let a_ip = "10.0.0.1";
    let b_ip = "10.0.1.1";
    let store = slice_store(vec![
        make_slice("default", "svc-a", a_ip),
        make_slice("default", "svc-b", b_ip),
    ]);
    let route = weighted_route("default", &[("svc-a", Some(4)), ("svc-b", Some(1))]);
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &HashSet::new(),
        &no_listener_info(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let upstream = table.route(80, "example.com", "/", &ctx_get()).unwrap();

    let a: std::net::SocketAddr = format!("{a_ip}:80").parse().unwrap();
    let n = 1000usize;
    let mut a_count = 0usize;
    for _ in 0..n {
        let addr = upstream.next_endpoint().unwrap();
        if addr == a {
            a_count += 1;
        }
    }
    let ratio = a_count as f64 / n as f64;
    assert!(
        (0.75..=0.85).contains(&ratio),
        "backend-A ratio {ratio:.3} expected 0.75–0.85"
    );
}

#[test]
fn zero_weight_backend_gets_no_traffic() {
    let a_ip = "10.0.0.1";
    let b_ip = "10.0.1.1";
    let store = slice_store(vec![
        make_slice("default", "svc-a", a_ip),
        make_slice("default", "svc-b", b_ip),
    ]);
    let route = weighted_route("default", &[("svc-a", Some(0)), ("svc-b", Some(1))]);
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &HashSet::new(),
        &no_listener_info(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let upstream = table.route(80, "example.com", "/", &ctx_get()).unwrap();

    let b: std::net::SocketAddr = format!("{b_ip}:80").parse().unwrap();
    for _ in 0..100 {
        assert_eq!(
            upstream.next_endpoint().unwrap(),
            b,
            "weight-0 backend should receive no traffic"
        );
    }
}

#[test]
fn all_zero_weights_installs_error_route() {
    let store = slice_store(vec![
        make_slice("default", "svc-a", "10.0.0.1"),
        make_slice("default", "svc-b", "10.0.1.1"),
    ]);
    let route = weighted_route("default", &[("svc-a", Some(0)), ("svc-b", Some(0))]);
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &HashSet::new(),
        &no_listener_info(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    // All weights zero → empty upstream → error_status = Some(500) → RouteOutcome::Error
    let outcome = table.find(80, "example.com", "/", &ctx_get());
    assert!(
        matches!(outcome, coxswain_core::routing::RouteOutcome::Error(500)),
        "all-zero-weight rule must resolve to Error(500)"
    );
}

#[test]
fn absent_weight_defaults_to_1() {
    let a_ip = "10.0.0.1";
    let b_ip = "10.0.1.1";
    let store = slice_store(vec![
        make_slice("default", "svc-a", a_ip),
        make_slice("default", "svc-b", b_ip),
    ]);
    // weight field is None — should default to 1 each → roughly equal split
    let route = weighted_route("default", &[("svc-a", None), ("svc-b", None)]);
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &HashSet::new(),
        &no_listener_info(),
        &mut builder,
    );
    let table = builder.build().unwrap();
    let upstream = table.route(80, "example.com", "/", &ctx_get()).unwrap();

    let a: std::net::SocketAddr = format!("{a_ip}:80").parse().unwrap();
    let b: std::net::SocketAddr = format!("{b_ip}:80").parse().unwrap();
    let results: Vec<_> = (0..4).map(|_| upstream.next_endpoint().unwrap()).collect();
    // With equal weights, slots = [0, 1]; cycling: a, b, a, b
    assert_eq!(results, [a, b, a, b]);
}
