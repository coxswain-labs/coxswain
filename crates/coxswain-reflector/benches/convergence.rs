#![allow(missing_docs)]
//! #513 convergence-scaling benchmark: `endpoints::resolve()` cost as a
//! function of cluster size (routes/services) and per-service endpoint count.
//!
//! `resolve()` (`coxswain_reflector::endpoints::resolve`, exposed
//! `#[doc(hidden)] pub` for exactly this bench — see its doc comment) does a
//! full linear scan of the `EndpointSlice` store on every call, filtered
//! in-loop by namespace + the `kubernetes.io/service-name` label. A rebuild
//! calls it once per backend reference, so the aggregate cost across R routes
//! against a store holding S services is O(R x S) for the background scan
//! alone, plus O(R x E) for the endpoints actually enumerated inside each
//! call's matched slice (E = endpoints on the target service). This bench
//! demonstrates that scaling directly — the curve #511's `(ns, svc, port)`
//! endpoint-resolution cache exists to flatten.
//!
//! Run: `cargo bench -p coxswain-reflector --bench convergence`.
//! Baseline for a later comparison: append `-- --save-baseline <name>`, then
//! after a change re-run with `-- --baseline <name>` (criterion persists
//! results under `target/criterion/`, gitignored — no numbers land in git).

use coxswain_reflector::endpoints::resolve;
use criterion::{Criterion, criterion_group, criterion_main};
use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointSlice};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;
use kube::runtime::{reflector, watcher};
use std::collections::BTreeMap;

const NAMESPACE: &str = "bench-ns";
const SERVICE_PORT: i32 = 80;

/// One `Service` with a single numeric-target-port entry, matching
/// `SERVICE_PORT` on both sides (keeps `resolve()`'s target-port resolution
/// branch trivial — the bench targets the `EndpointSlice` scan, not the
/// Service-port lookup).
fn make_service(name: &str) -> Service {
    Service {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(NAMESPACE.to_string()),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            ports: Some(vec![ServicePort {
                port: SERVICE_PORT,
                target_port: Some(IntOrString::Int(SERVICE_PORT)),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// One `EndpointSlice` for `svc` carrying `n` distinct ready endpoints — models
/// a single service scaled to `n` pods, all in one slice (well under the
/// real K8s 100-endpoints-per-slice cap for every `n` this bench sweeps).
fn make_slice(svc: &str, n: usize) -> EndpointSlice {
    let mut labels = BTreeMap::new();
    labels.insert("kubernetes.io/service-name".to_string(), svc.to_string());
    let endpoints = (0..n)
        .map(|i| {
            let i = u32::try_from(i).unwrap_or(u32::MAX);
            Endpoint {
                addresses: vec![format!(
                    "10.{}.{}.{}",
                    (i >> 16) & 0xff,
                    (i >> 8) & 0xff,
                    i & 0xff
                )],
                conditions: Some(EndpointConditions {
                    ready: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }
        })
        .collect();
    EndpointSlice {
        metadata: ObjectMeta {
            name: Some(format!("{svc}-slice")),
            namespace: Some(NAMESPACE.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        address_type: "IPv4".to_string(),
        endpoints: Some(endpoints),
        ports: None,
    }
}

/// Build `services` distinct `(Service, EndpointSlice)` pairs — `services-1`
/// pods each — plus the target service on which `endpoints_per_service`
/// varies. Named `svc-0` .. `svc-{services-1}`; the resolve-scaling bench
/// looks up each in turn, so every call pays the full background-scan cost of
/// the OTHER `services-1` slices before (possibly) reaching its match.
fn build_stores(
    services: usize,
    endpoints_per_service: usize,
) -> (reflector::Store<EndpointSlice>, reflector::Store<Service>) {
    let mut slice_writer = reflector::store::Writer::<EndpointSlice>::default();
    let mut svc_writer = reflector::store::Writer::<Service>::default();
    for i in 0..services {
        let name = format!("svc-{i}");
        slice_writer.apply_watcher_event(&watcher::Event::Apply(make_slice(
            &name,
            endpoints_per_service,
        )));
        svc_writer.apply_watcher_event(&watcher::Event::Apply(make_service(&name)));
    }
    (slice_writer.as_reader(), svc_writer.as_reader())
}

/// Simulates one rebuild's worth of endpoint resolution: `routes` backend
/// references, round-robining over the `services` distinct Services in the
/// store — i.e. R backend refs against a cluster holding R total services (a
/// simple 1:1 routes-to-services topology; #511's fix targets exactly this
/// full-store-rescan cost, independent of topology shape).
fn bench_resolve_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("endpoints_resolve");
    for &routes in &[100usize, 1000usize] {
        for &endpoints_per_service in &[5usize, 50usize, 500usize] {
            let (slices, services) = build_stores(routes, endpoints_per_service);
            let bench_id = format!("routes{routes}_eps{endpoints_per_service}");
            group.bench_function(bench_id, |b| {
                b.iter(|| {
                    let mut total_addrs = 0usize;
                    for i in 0..routes {
                        let name = format!("svc-{i}");
                        let resolved = resolve(NAMESPACE, &name, SERVICE_PORT, &slices, &services);
                        total_addrs += resolved.addrs.len();
                    }
                    std::hint::black_box(total_addrs);
                });
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_resolve_scaling);
criterion_main!(benches);
