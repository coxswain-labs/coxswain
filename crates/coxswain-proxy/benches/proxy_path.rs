#![allow(missing_docs)]
use coxswain_core::routing::{
    BackendGroup, GatewayRoutingTableBuilder, IngressRoutingTableBuilder, RouteEntry,
    SharedGatewayRoutingTable, SharedIngressRoutingTable,
};
use coxswain_proxy::{GatewayEngine, GrpcAuthChannelCache, IngressEngine, RoutingEngine};
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

/// Steady-state cost of `GrpcAuthChannelCache::get_or_connect` on a warm entry
/// (#544): DashMap get + `Channel` clone + `AtomicBool` store — no connect, no
/// allocation of an `Endpoint`. This is the per-request cost the pool adds on
/// the gRPC ext_authz hot path, replacing the pre-pooling per-request
/// TCP+HTTP/2 dial this bench's baseline (git history) used to pay.
fn bench_grpc_channel_cache_hit(c: &mut Criterion) {
    // `connect_lazy` touches the tokio runtime handle during construction, so
    // the warm-up fill runs inside one; the measured hit path itself is sync.
    let rt = tokio::runtime::Runtime::new().unwrap_or_else(|e| panic!("runtime: {e}"));
    let cache = GrpcAuthChannelCache::new();
    let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap_or_else(|e| panic!("{e}"));
    rt.block_on(async {
        cache
            .get_or_connect(addr)
            .unwrap_or_else(|e| panic!("warm-up connect: {e}"));
    });

    c.bench_function("grpc_channel_cache_hit", |b| {
        b.iter(|| cache.get_or_connect(addr))
    });
}

criterion_group!(
    benches,
    bench_routing_engine_find,
    bench_grpc_channel_cache_hit
);
criterion_main!(benches);
