#![allow(missing_docs)]
use coxswain_core::routing::{BackendGroup, RouteEntry, RoutingTableBuilder, SharedRoutingTable};
use coxswain_proxy::RoutingEngine;
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

fn build_engine() -> RoutingEngine {
    let mut b = RoutingTableBuilder::new();
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
    let shared = SharedRoutingTable::default();
    shared.store(Arc::new(b.build().unwrap_or_else(|e| panic!("{e}"))));
    RoutingEngine::new(shared)
}

fn bench_routing_engine_find(c: &mut Criterion) {
    use coxswain_core::routing::RequestContext;
    use http::{HeaderMap, Method};

    let engine = build_engine();
    let method = Method::GET;
    let headers = HeaderMap::new();
    let ctx = RequestContext {
        method: &method,
        headers: &headers,
        query: None,
    };

    c.bench_function("engine_find_hit", |b| {
        b.iter(|| engine.find(80, "example.com", "/api/v3/items", &ctx))
    });

    c.bench_function("engine_find_no_host", |b| {
        b.iter(|| engine.find(80, "unknown.com", "/api/v3", &ctx))
    });
}

criterion_group!(benches, bench_routing_engine_find);
criterion_main!(benches);
