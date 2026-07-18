#![allow(missing_docs)]
//! #621 relay-apply micro-benchmark: quantifies the namespace-relay demux apply
//! path — per-key digest retention (a delta re-hashes only its own upserts, not
//! the whole namespace world) and the trusted per-Gateway reconstruction (the
//! synthetic full is applied without the redundant F6 self-check re-hash).
//!
//! Fixture: a namespace of `G` dedicated Gateways, each with `H` exact-host
//! routes in its Gateway routing table. The `Scope::Namespace` full is the union
//! of every Gateway's qualified resources; a one-Gateway delta rewrites a single
//! route on `gw-0` only.
//!
//! Cases per `G` (H fixed), each timing exactly one [`RelayHarness::apply`]:
//!
//! - **`full_cold_g{G}`** — the whole namespace full applied to a cold demux:
//!   every Gateway reconstructed, the entire world hashed. The baseline the delta
//!   is read against.
//! - **`one_gateway_delta_g{G}`** — a delta touching only `gw-0`, applied to a
//!   warm demux. Post-#621 it re-hashes only `gw-0`'s resources (retained digests
//!   for the other `G-1` Gateways are carried by refcount) and reconstructs
//!   `gw-0` via the trusted apply (no double hash). This should stay far flatter
//!   in `G` than `full_cold`, whose cost is the whole namespace.
//!
//! Run: `cargo bench -p coxswain-discovery --bench relay_apply`.
//! Follow the "do not commit numbers" convention — post before/after as a #603
//! comment.

use std::sync::Arc;

use coxswain_core::dedicated_registry::{
    DedicatedRegistryData, DedicatedRoutingRegistry, DedicatedRoutingSnapshot,
};
use coxswain_core::listener_status::GatewayListenerStatusHandle;
use coxswain_core::ownership::ObjectKey;
use coxswain_core::publish_index::GatewayPublishIndexHandle;
use coxswain_core::routing::{
    BackendGroup, GatewayRoutingTableBuilder, RouteEntry, SharedGatewayRoutingTable,
    SharedIngressRoutingTable, SharedTcpRouteTable, SharedTlsPassthroughTable, SharedUdpRouteTable,
};
use coxswain_core::tls::{
    ClientCertStore, PortTlsStore, SharedClientCertStore, SharedPortTlsStore,
};
use coxswain_discovery::bench_internals::RelayHarness;
use coxswain_discovery::proto::v1 as p;
use coxswain_discovery::{MaterializedView, Scope, SnapshotSource, materialize};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

const NS: &str = "prod";
/// Exact-host routes per Gateway.
const H: usize = 50;
/// Gateway counts swept (namespace fan-out width).
const GATEWAYS: [usize; 2] = [10, 50];

/// One dedicated Gateway's snapshot: `H` exact-host routes on port 443. When
/// `bump` is set, the first host's `route_id` differs, so exactly that Gateway's
/// world changes hash (the delta's single moved Gateway).
fn gateway_snapshot(name: &str, bump: bool) -> DedicatedRoutingSnapshot {
    let mut builder = GatewayRoutingTableBuilder::new();
    let port_builder = builder.for_port(443);
    for hi in 0..H {
        let host = format!("h{hi}.{name}.example.com");
        let route_id = if bump && hi == 0 {
            format!("{name}-h{hi}-v2")
        } else {
            format!("{name}-h{hi}-v1")
        };
        let bg = Arc::new(BackendGroup::new(
            format!("{NS}/{name}-{hi}"),
            vec![
                "10.0.0.1:80"
                    .parse()
                    .unwrap_or_else(|e| panic!("addr: {e}")),
            ],
        ));
        let entry = Arc::new(RouteEntry::path_only(bg, route_id, None));
        port_builder.exact_host(&host).add_prefix_route("/", entry);
    }
    DedicatedRoutingSnapshot {
        gateway: Arc::new(
            builder
                .build()
                .unwrap_or_else(|e| panic!("build gateway: {e}")),
        ),
        tls: Arc::new(PortTlsStore::default()),
        client_certs: Arc::new(ClientCertStore::default()),
        listener_status: std::collections::HashMap::new(),
        expected_proxy_sa: format!("{name}-coxswain"),
    }
}

/// A snapshot source over `g` dedicated Gateways in [`NS`]; `bump_gw0` moves one
/// route on `gw-0` so a before/after pair differs in exactly that Gateway.
fn dedicated_source(g: usize, bump_gw0: bool) -> SnapshotSource {
    let dedicated = DedicatedRoutingRegistry::new();
    let mut map = std::collections::HashMap::new();
    for gi in 0..g {
        let name = format!("gw-{gi}");
        let snap = gateway_snapshot(&name, bump_gw0 && gi == 0);
        map.insert(ObjectKey::new(NS.to_owned(), name), Arc::new(snap));
    }
    dedicated.store(Arc::new(DedicatedRegistryData::from_map(map)));
    SnapshotSource {
        ingress: SharedIngressRoutingTable::new(),
        gateway: SharedGatewayRoutingTable::new(),
        tls: SharedPortTlsStore::new(),
        client_certs: SharedClientCertStore::new(),
        listener_status: GatewayListenerStatusHandle::new(),
        dedicated,
        passthrough_routes: SharedTlsPassthroughTable::new(),
        terminate_routes: SharedTlsPassthroughTable::new(),
        tcp_routes: SharedTcpRouteTable::new(),
        udp_routes: SharedUdpRouteTable::new(),
        publish: GatewayPublishIndexHandle::new(),
    }
}

fn ns_scope() -> Scope {
    Scope::Namespace {
        namespace: NS.to_owned(),
    }
}

/// The `Scope::Namespace` full a controller sends as the first message.
fn full_snapshot(view: &MaterializedView) -> p::Snapshot {
    p::Snapshot {
        version: view.version.clone(),
        nonce: Vec::new(),
        full: true,
        resources: view
            .resources
            .values()
            .map(|entry| (*entry.resource).clone())
            .collect(),
        removed_resources: Vec::new(),
        publish_seq: view.seq,
    }
}

/// The delta carrying `base` → `target`: upserts are keys whose per-resource hash
/// moved (only `gw-0`'s here), tombstones are keys `target` dropped.
fn build_delta(base: &MaterializedView, target: &MaterializedView) -> p::Snapshot {
    let resources: Vec<p::Resource> = target
        .resources
        .iter()
        .filter(|(k, e)| base.resource_hashes.get(*k) != Some(&e.hash))
        .map(|(_, e)| (*e.resource).clone())
        .collect();
    let removed_resources: Vec<String> = base
        .resource_hashes
        .keys()
        .filter(|k| !target.resources.contains_key(*k))
        .cloned()
        .collect();
    p::Snapshot {
        version: target.version.clone(),
        nonce: Vec::new(),
        full: false,
        resources,
        removed_resources,
        publish_seq: target.seq,
    }
}

fn bench_relay_apply(c: &mut Criterion) {
    for &g in &GATEWAYS {
        let base_view = materialize(&dedicated_source(g, false), &ns_scope());
        let target_view = materialize(&dedicated_source(g, true), &ns_scope());
        let full = full_snapshot(&base_view);
        let delta = build_delta(&base_view, &target_view);

        // Sanity: the delta must move exactly gw-0 (a non-empty, sub-total upsert).
        assert!(
            !delta.resources.is_empty() && delta.resources.len() < full.resources.len(),
            "the one-Gateway delta must touch some but not all resources"
        );

        c.bench_function(&format!("full_cold_g{g}"), |b| {
            b.iter_batched_ref(
                RelayHarness::new,
                |harness| {
                    harness
                        .apply(&full)
                        .unwrap_or_else(|e| panic!("full: {e:?}"));
                },
                BatchSize::SmallInput,
            );
        });

        c.bench_function(&format!("one_gateway_delta_g{g}"), |b| {
            b.iter_batched_ref(
                || {
                    let mut harness = RelayHarness::new();
                    harness
                        .apply(&full)
                        .unwrap_or_else(|e| panic!("warm full: {e:?}"));
                    harness
                },
                |harness| {
                    harness
                        .apply(&delta)
                        .unwrap_or_else(|e| panic!("delta: {e:?}"));
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, bench_relay_apply);
criterion_main!(benches);
