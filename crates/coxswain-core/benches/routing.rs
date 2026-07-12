#![allow(missing_docs)]
use coxswain_core::routing::{
    BackendGroup, GatewayRoutingTableBuilder, RequestContext, RouteEntry, SharedGatewayRoutingTable,
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
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

/// Populate a fresh, unbuilt [`GatewayRoutingTableBuilder`] with `total_routes`
/// spread across `total_routes / 10` hosts (10 routes/host, minimum one host) —
/// a many-hosts-few-routes-each shape closer to a real Ingress/HTTPRoute
/// population than one giant host, without needing a distribution model this
/// bench has no data to justify.
fn build_populated(total_routes: usize) -> GatewayRoutingTableBuilder {
    let hosts = (total_routes / 10).max(1);
    let per_host = total_routes / hosts;
    let mut b = GatewayRoutingTableBuilder::new();
    for h in 0..hosts {
        let host = b.for_port(80).exact_host(&format!("host-{h}.example.com"));
        for i in 0..per_host {
            host.add_prefix_route(
                &format!("/api/v{i}"),
                make_entry(make_group(&format!("svc-{h}-{i}"), "10.0.0.1:80")),
            );
        }
    }
    b
}

/// #513 baseline: routing-table **build** cost (not lookup) as a function of
/// total route count — the reflector `rebuild()` cost this bench models is
/// "recompile the whole table from scratch on every debounced rebuild"; #511's
/// partitioned rebuild targets exactly this curve (unaffected `(port,host)`
/// partitions should stop paying it).
///
/// `iter_batched` is required because `GatewayRoutingTableBuilder::build`
/// consumes `self` — population must happen fresh, untimed, per iteration.
fn bench_table_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("table_build");
    for &routes in &[100usize, 1000usize] {
        group.bench_function(format!("routes{routes}"), |b| {
            b.iter_batched(
                || build_populated(routes),
                |builder| builder.build().unwrap_or_else(|e| panic!("{e}")),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// #511 comparison: rebuilding a `total_routes`-route table when only ONE
/// host actually changed. Two strategies, same host/route shape as
/// [`bench_table_build`]:
///
/// - `full`: the pre-#511 world — `build_populated` repopulates every host's
///   `HostRouterBuilder` from scratch and `.build()` compiles all of them
///   (matchit + `RegexSet` for every host), identical to `table_build`.
/// - `partitioned`: only the one dirty host gets a fresh `HostRouterBuilder`;
///   every other host's already-compiled `Arc<HostRouter>` (from a
///   once-built baseline table) is spliced in directly via
///   `PortTableBuilder::insert_compiled_exact_host`, skipping
///   `HostRouterBuilder::build()` (and its `matchit`/`RegexSet` compilation)
///   for all of them. `.build()` on this mixed builder is the #511 partitioned
///   rebuild's actual final-assembly step (`route_builder::build_gateway_routes`).
///
/// At `routes100` (10 hosts) the win is modest; at `routes1000` (100 hosts)
/// `partitioned` should scale ~O(1) in the dirty-host count instead of
/// O(hosts) — see the module doc for the `--save-baseline`/`--baseline`
/// before/after workflow.
fn bench_partitioned_rebuild(c: &mut Criterion) {
    let mut group = c.benchmark_group("partitioned_rebuild");
    for &routes in &[100usize, 1000usize] {
        let hosts = (routes / 10).max(1);
        // Baseline: every host compiled once, up front — models the
        // previously-published table `route_builder` reuses `Arc<HostRouter>`
        // from.
        let baseline = build_populated(routes)
            .build()
            .unwrap_or_else(|e| panic!("{e}"));

        group.bench_function(format!("full_routes{routes}"), |b| {
            b.iter_batched(
                || build_populated(routes),
                |builder| builder.build().unwrap_or_else(|e| panic!("{e}")),
                BatchSize::SmallInput,
            );
        });

        group.bench_function(format!("partitioned_routes{routes}"), |b| {
            b.iter_batched(
                || {
                    let per_host = routes / hosts;
                    let mut builder = GatewayRoutingTableBuilder::new();
                    // Host 0 is dirty: freshly populated, same shape as
                    // `build_populated`'s per-host loop.
                    let dirty_host = builder.for_port(80).exact_host("host-0.example.com");
                    for i in 0..per_host {
                        dirty_host.add_prefix_route(
                            &format!("/api/v{i}"),
                            make_entry(make_group(&format!("svc-0-{i}"), "10.0.0.1:80")),
                        );
                    }
                    // Every other host reuses its already-compiled Arc from
                    // the baseline table — no HostRouterBuilder::build() at
                    // all for these (hosts - 1) hosts.
                    for h in 1..hosts {
                        let name = format!("host-{h}.example.com");
                        let router = baseline
                            .get_compiled(
                                80,
                                Some(&name),
                                coxswain_core::routing::WildcardKind::MultiLabel,
                            )
                            .unwrap_or_else(|| panic!("host {name} missing from baseline table"));
                        builder
                            .for_port(80)
                            .insert_compiled_exact_host(name, router);
                    }
                    builder
                },
                |builder| builder.build().unwrap_or_else(|e| panic!("{e}")),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_route_lookup,
    bench_table_build,
    bench_partitioned_rebuild
);
criterion_main!(benches);
