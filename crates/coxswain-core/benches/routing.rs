#![allow(missing_docs)]
use coxswain_core::routing::{
    BackendGroup, GatewayRoutingTableBuilder, RequestContext, RouteEntry, SharedGatewayRoutingTable,
};
use criterion::{Criterion, criterion_group, criterion_main};
use http::{HeaderMap, Method};
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

fn make_entry(g: Arc<BackendGroup>) -> Arc<RouteEntry> {
    Arc::new(RouteEntry::path_only(g, "default/svc".to_string(), None))
}

fn build_table() -> SharedGatewayRoutingTable {
    let mut b = GatewayRoutingTableBuilder::new();
    let host = b.for_port(80).exact_host("example.com");
    for i in 0..20 {
        host.add_prefix_route(
            &format!("/api/v{i}"),
            make_entry(make_group(&format!("svc-{i}"), "10.0.0.1:80")),
        );
    }
    let shared = SharedGatewayRoutingTable::default();
    shared.store(Arc::new(b.build().unwrap_or_else(|e| panic!("{e}"))));
    shared
}

fn bench_route_lookup(c: &mut Criterion) {
    let shared = build_table();
    let method = Method::GET;
    let headers = HeaderMap::new();
    let ctx = RequestContext {
        method: &method,
        headers: &headers,
        query: None,
    };
    c.bench_function("route_lookup_hit", |b| {
        b.iter(|| {
            let table = shared.load();
            table.route(80, "example.com", "/api/v5/users", &ctx)
        })
    });
    c.bench_function("route_lookup_miss_path", |b| {
        b.iter(|| {
            let table = shared.load();
            table.route(80, "example.com", "/unknown", &ctx)
        })
    });
    c.bench_function("route_lookup_miss_host", |b| {
        b.iter(|| {
            let table = shared.load();
            table.route(80, "other.com", "/api/v5", &ctx)
        })
    });
}

criterion_group!(benches, bench_route_lookup);
criterion_main!(benches);
