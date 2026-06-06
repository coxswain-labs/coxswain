use super::*;

// ── Listener isolation tests ──────────────────────────────────────────────────

#[test]
fn listener_isolation_empty_listener_route_not_accessible_via_more_specific_listener() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route_with_hostnames_and_parent(
        "default",
        &["bar.com", "*.example.com"],
        "gw",
        Some("empty-listener"),
    );
    let listener_info = make_listener_info(
        "default",
        "gw",
        &[
            ("empty-listener", "", 80),
            ("specific-listener", "*.example.com", 80),
        ],
    );
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &default_owned(),
        &HashSet::new(),
        &listener_info,
        &mut builder,
    );
    let table = builder.build().unwrap();
    assert!(
        table.route(80, "bar.com", "/", &ctx_get()).is_some(),
        "bar.com should be routable"
    );
    assert!(
        table
            .route(80, "bar.example.com", "/", &ctx_get())
            .is_none(),
        "bar.example.com should not leak from the empty-hostname listener"
    );
}

// ── parentRef.port tests ──────────────────────────────────────────────────────

#[test]
fn parent_ref_port_filters_to_matching_listener() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route_with_parent_port("default", &["h.example.com"], "gw", Some(80));
    let listener_info = make_listener_info(
        "default",
        "gw",
        &[("a", "h.example.com", 80), ("b", "h.example.com", 8080)],
    );
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &owned(&[("default", "gw")]),
        &HashSet::new(),
        &listener_info,
        &mut builder,
    );
    let table = builder.build().unwrap();
    assert!(
        table.route(80, "h.example.com", "/", &ctx_get()).is_some(),
        "route must be installed for port 80"
    );
    assert!(
        table
            .route(8080, "h.example.com", "/", &ctx_get())
            .is_none(),
        "route must not be installed for port 8080"
    );
}

#[test]
fn parent_ref_port_unset_attaches_to_all_listeners() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route_with_parent_port("default", &["h.example.com"], "gw", None);
    let listener_info = make_listener_info(
        "default",
        "gw",
        &[("a", "h.example.com", 80), ("b", "h.example.com", 8080)],
    );
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &owned(&[("default", "gw")]),
        &HashSet::new(),
        &listener_info,
        &mut builder,
    );
    let table = builder.build().unwrap();
    assert!(
        table.route(80, "h.example.com", "/", &ctx_get()).is_some(),
        "route must be installed for port 80"
    );
    assert!(
        table
            .route(8080, "h.example.com", "/", &ctx_get())
            .is_some(),
        "route must be installed for port 8080"
    );
}

#[test]
fn parent_ref_port_no_match_drops_route() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let route = make_route_with_parent_port("default", &["h.example.com"], "gw", Some(9999));
    let listener_info = make_listener_info(
        "default",
        "gw",
        &[("a", "h.example.com", 80), ("b", "h.example.com", 8080)],
    );
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route,
        &store,
        &empty_svc_store(),
        &owned(&[("default", "gw")]),
        &HashSet::new(),
        &listener_info,
        &mut builder,
    );
    let table = builder.build().unwrap();
    assert!(
        table.route(80, "h.example.com", "/", &ctx_get()).is_none(),
        "route must not be installed for port 80"
    );
    assert!(
        table
            .route(8080, "h.example.com", "/", &ctx_get())
            .is_none(),
        "route must not be installed for port 8080"
    );
    assert!(
        table
            .route(9999, "h.example.com", "/", &ctx_get())
            .is_none(),
        "route must not be installed for port 9999"
    );
}

#[test]
fn parent_ref_port_with_section_name_combined() {
    // parentRef with both sectionName and port: only attaches when both match.
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
    let listener_info = make_listener_info(
        "default",
        "gw",
        &[("a", "h.example.com", 80), ("b", "h.example.com", 8080)],
    );
    let owned_gw = owned(&[("default", "gw")]);

    let make_route_sn_port = |section_name: Option<&str>, port: Option<i32>| {
        use gateway_api::apis::standard::httproutes::HttpRouteSpec;
        HttpRoute {
            metadata: kube::api::ObjectMeta {
                name: Some("test-route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: Some(vec![HttpRouteParentRefs {
                    name: "gw".to_string(),
                    namespace: Some("default".to_string()),
                    section_name: section_name.map(str::to_string),
                    port,
                    ..Default::default()
                }]),
                hostnames: Some(vec!["h.example.com".to_string()]),
                rules: Some(vec![make_simple_rule("svc")]),
            },
            status: None,
        }
    };

    // sectionName="a" + port=80: listener "a" is on port 80 → should attach.
    let route_match = make_route_sn_port(Some("a"), Some(80));
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route_match,
        &store,
        &empty_svc_store(),
        &owned_gw,
        &HashSet::new(),
        &listener_info,
        &mut builder,
    );
    let table = builder.build().unwrap();
    assert!(
        table.route(80, "h.example.com", "/", &ctx_get()).is_some(),
        "sectionName=a + port=80 must attach"
    );

    // sectionName="a" + port=8080: listener "a" is on port 80, not 8080 → must not attach.
    let route_mismatch = make_route_sn_port(Some("a"), Some(8080));
    let mut builder = RoutingTableBuilder::new();
    GatewayApiReconciler::reconcile(
        &route_mismatch,
        &store,
        &empty_svc_store(),
        &owned_gw,
        &HashSet::new(),
        &listener_info,
        &mut builder,
    );
    let table = builder.build().unwrap();
    assert!(
        table.route(80, "h.example.com", "/", &ctx_get()).is_none(),
        "sectionName=a + port=8080 must not attach"
    );
    assert!(
        table
            .route(8080, "h.example.com", "/", &ctx_get())
            .is_none(),
        "sectionName=a + port=8080 must not appear under 8080 either"
    );
}
