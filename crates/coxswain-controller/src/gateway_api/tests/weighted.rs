use super::*;

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
