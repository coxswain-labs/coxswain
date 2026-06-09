#![allow(missing_docs)]
use coxswain_core::routing::{
    BackendGroup, GatewayRoutingTableBuilder, IngressRoutingTableBuilder, RouteEntry,
    SharedGatewayRoutingTable, SharedIngressRoutingTable,
};
use coxswain_proxy::{GatewayEngine, IngressEngine, RoutingEngine};
use criterion::{Criterion, criterion_group, criterion_main};
use std::net::SocketAddr;
use std::sync::Arc;

fn make_group(name: &str, addr: &str) -> Arc<BackendGroup> {
    Arc::new(BackendGroup::new(
        name.to_string(),
        vec![
            addr.parse::<SocketAddr>()
                .unwrap_or_else(|e| panic!("{addr}: {e}")),
        ],
    ))
}

fn build_ingress_engine() -> IngressEngine {
    let mut b = IngressRoutingTableBuilder::new();
    let host = b.for_port(80).exact_host("example.com");
    for i in 0..10 {
        host.add_prefix_route(
            &format!("/api/v{i}"),
            Arc::new(RouteEntry::path_only(
                make_group(&format!("svc-{i}"), "10.0.0.1:80"),
                format!("default/svc-{i}"),
                None,
            )),
        );
    }
    let shared = SharedIngressRoutingTable::default();
    shared.store(Arc::new(b.build().unwrap_or_else(|e| panic!("{e}"))));
    RoutingEngine::new(shared)
}

fn build_gateway_engine() -> GatewayEngine {
    let mut b = GatewayRoutingTableBuilder::new();
    let host = b.for_port(80).exact_host("example.com");
    for i in 0..10 {
        host.add_prefix_route(
            &format!("/api/v{i}"),
            Arc::new(RouteEntry::path_only(
                make_group(&format!("svc-{i}"), "10.0.0.1:80"),
                format!("default/svc-{i}"),
                None,
            )),
        );
    }
    let shared = SharedGatewayRoutingTable::default();
    shared.store(Arc::new(b.build().unwrap_or_else(|e| panic!("{e}"))));
    RoutingEngine::new(shared)
}

fn bench_routing_engine_find(c: &mut Criterion) {
    use coxswain_core::routing::RequestContext;
    use http::{HeaderMap, Method};

    let method = Method::GET;
    let headers = HeaderMap::new();
    let ctx = RequestContext {
        method: &method,
        headers: &headers,
        query: None,
    };

    // The two engines are structurally identical today; the benches keep the
    // historical `engine_find_hit` / `engine_find_no_host` names so deltas
    // remain comparable to the pre-split baseline, with explicit per-spec
    // smoke benches for both typed paths.
    let gateway = build_gateway_engine();
    let ingress = build_ingress_engine();

    c.bench_function("engine_find_hit", |b| {
        b.iter(|| gateway.find(80, "example.com", "/api/v3/items", &ctx))
    });
    c.bench_function("engine_find_no_host", |b| {
        b.iter(|| gateway.find(80, "unknown.com", "/api/v3", &ctx))
    });
    c.bench_function("proxy_path_ingress", |b| {
        b.iter(|| ingress.find(80, "example.com", "/api/v3/items", &ctx))
    });
    c.bench_function("proxy_path_gateway", |b| {
        b.iter(|| gateway.find(80, "example.com", "/api/v3/items", &ctx))
    });
}

criterion_group!(benches, bench_routing_engine_find);
criterion_main!(benches);
