use super::*;

// ── Timeout tests ────────────────────────────────────────────────────────────

use coxswain_core::routing::RouteOutcome;
use gateway_api::apis::standard::httproutes::HttpRouteRulesTimeouts;
use std::time::Duration;

fn find_timeouts(
    table: &coxswain_core::routing::RoutingTable,
    host: &str,
    path: &str,
) -> coxswain_core::routing::RouteTimeouts {
    let empty_hdrs = http::HeaderMap::new();
    let ctx = ctx_with(&Method::GET, &empty_hdrs, None);
    match table.find(80, host, path, &ctx) {
        RouteOutcome::Found(_, _, t) => t,
        _ => panic!("expected Found"),
    }
}

#[test]
fn parse_gateway_duration_parses_common_values() {
    assert_eq!(
        super::super::timeouts::parse_gateway_duration("10s"),
        Some(Duration::from_secs(10))
    );
    assert_eq!(
        super::super::timeouts::parse_gateway_duration("500ms"),
        Some(Duration::from_millis(500))
    );
    assert_eq!(
        super::super::timeouts::parse_gateway_duration("1m"),
        Some(Duration::from_secs(60))
    );
    assert_eq!(
        super::super::timeouts::parse_gateway_duration("2h45m"),
        Some(Duration::from_secs(2 * 3600 + 45 * 60))
    );
}

#[test]
fn parse_gateway_duration_zero_returns_none() {
    assert_eq!(super::super::timeouts::parse_gateway_duration("0s"), None);
    assert_eq!(super::super::timeouts::parse_gateway_duration("0"), None);
    assert_eq!(super::super::timeouts::parse_gateway_duration(""), None);
}

#[test]
fn parse_gateway_duration_invalid_returns_none() {
    assert_eq!(super::super::timeouts::parse_gateway_duration("10x"), None);
    assert_eq!(super::super::timeouts::parse_gateway_duration("abc"), None);
}

#[test]
fn reconcile_timeouts_stored_and_round_trip() {
    let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);

    let route = HttpRoute {
        metadata: ObjectMeta {
            name: Some("route".to_string()),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        spec: gateway_api::apis::standard::httproutes::HttpRouteSpec {
            parent_refs: default_parents(),
            hostnames: Some(vec!["example.com".to_string()]),
            rules: Some(vec![
                gateway_api::apis::standard::httproutes::HttpRouteRules {
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc".to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    timeouts: Some(HttpRouteRulesTimeouts {
                        request: Some("10s".to_string()),
                        backend_request: Some("2s".to_string()),
                    }),
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
        crate::gateway_api::RouteResolution {
            listener_info: &no_listener_info(),
            policy_index: &HashMap::new(),
        },
        &mut builder,
    );
    let table = builder.build().unwrap();
    let t = find_timeouts(&table, "example.com", "/");
    assert_eq!(t.request, Some(Duration::from_secs(10)));
    assert_eq!(t.backend_request, Some(Duration::from_secs(2)));
}

#[test]
fn reconcile_timeouts_missing_field_falls_back_to_none() {
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
        crate::gateway_api::RouteResolution {
            listener_info: &no_listener_info(),
            policy_index: &HashMap::new(),
        },
        &mut builder,
    );
    let table = builder.build().unwrap();
    let t = find_timeouts(&table, "example.com", "/");
    assert!(t.request.is_none());
    assert!(t.backend_request.is_none());
}
