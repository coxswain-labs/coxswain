#![allow(missing_docs)]
//! #383 client-side partitioned-apply benchmark: quantifies the win of
//! recompiling only the route partitions a change touches versus rebuilding the
//! whole routing world.
//!
//! Fixture: a populated client resource cache of `P` listener ports × `H` hosts
//! per port × `R` routes per host, whose keyed backends reference `S` distinct
//! services (host `n` → service `n % S`). Constants: `P` = 2, `R` = 5,
//! `S` = 20; `H` is swept over {50, 250}. Total route partitions = `P × H`;
//! `P × H / S` of them reference any one service.
//!
//! Three cases per `H`, each timing exactly one [`Harness::apply`] over a
//! prepared (untimed) cache — `criterion`'s `iter_batched_ref` builds the warm
//! cache in the setup closure so only the apply is measured:
//!
//! - **(a) `endpoint_delta_h{H}`** — an endpoint-only delta moving ONE of the
//!   `S` services' addresses against a warm cache. Only the `P × H / S`
//!   partitions referencing that service recompile; every other partition's
//!   compiled `Arc<HostRouter>` is spliced from the live table. This is the
//!   post-#383 rolling-deploy cost.
//! - **(b) `full_cold_h{H}`** — the whole snapshot applied to a cold (empty)
//!   cache: every partition dirty, nothing to reuse. This is the pre-#383
//!   equivalent — a full recompile of the routing world.
//! - **(c) `identical_full_warm_h{H}`** — the same full re-applied to a warm
//!   cache: it still pays the whole `stage_full` (wire-decode + per-resource
//!   hashing of the entire world) and only THEN short-circuits at phase B on the
//!   digest compare, skipping compilation. This is the cost of a redundant full
//!   resync, not a floor beneath (a).
//!
//! How to read it: the **(a)-vs-(b)** gap at each `H` is the acceptance-criterion
//! evidence — "unaffected HostRouters are not rebuilt". Neither (a) nor (c) is
//! flat: (a) recompiles the `P × H / S` partitions referencing the moved service
//! and `stage_delta` clones the O(H) committed cache, so (a) grows with `H` — but
//! far more slowly than (b), which recompiles all `P × H` partitions; the gap IS
//! the reuse payoff. (c) grows with `H` too (it hashes the whole world), and at
//! small `H` can even measure *slower* than (a), whose delta wire payload is a
//! single endpoint. The bench also prints the one-shot recompiled/reused counts
//! per `H` to stderr (not timed) so the reuse ratio is visible without a profiler.
//!
//! Run: `cargo bench -p coxswain-discovery --bench delta_apply`.
//! Baselines persist under `target/criterion/` (gitignored): add
//! `-- --save-baseline <name>`, then `-- --baseline <name>` after a change.

use coxswain_discovery::bench_internals::{Harness, snapshot_version};
use coxswain_discovery::proto::v1 as p;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

const NS: &str = "ns";
/// Fixed backend (service target) port every keyed reference resolves against.
const EP_PORT: u32 = 9090;
/// Routes per host.
const R: usize = 5;
/// Distinct backend services the hosts fan out over.
const S: usize = 20;
/// Listener bind ports; hosts are laid out `H` per port.
const PORTS: [u32; 2] = [80, 443];

/// A keyed backend group referencing `svc{svc_idx}` in namespace `ns` on
/// [`EP_PORT`] — no literal addresses, so the endpoint pool must resolve it.
fn keyed_bg(svc_idx: usize) -> p::BackendGroup {
    p::BackendGroup {
        name: format!("bg-svc{svc_idx}"),
        weighted: vec![p::WeightedBackend {
            addrs: Vec::new(),
            weight: 1,
            endpoint_ref: Some(p::EndpointRef {
                namespace: NS.to_owned(),
                service: format!("svc{svc_idx}"),
                port: EP_PORT,
            }),
        }],
        load_balance: Some(p::LoadBalance {
            algorithm: Some(p::load_balance::Algorithm::RoundRobin(true)),
        }),
        ..Default::default()
    }
}

/// One Ingress route-host resource: exact host `h{host_idx}.example.com` on
/// `listen_port`, carrying `R` distinct prefix routes all keyed to `svc_idx`.
fn host_resource(listen_port: u32, host_idx: usize, svc_idx: usize) -> p::Resource {
    let routes = (0..R)
        .map(|r| p::RouteEntry {
            kind: p::RouteKind::Prefix as i32,
            path: format!("/r{r}"),
            route_id: format!("ns/h{host_idx}-r{r}"),
            backend_group: Some(keyed_bg(svc_idx)),
            ..Default::default()
        })
        .collect();
    p::Resource {
        payload: Some(p::resource::Payload::RouteHost(p::RouteHostResource {
            table: p::RouteTableKind::Ingress as i32,
            port: listen_port,
            host: Some(p::HostEntry {
                pattern: Some(p::host_entry::Pattern::Exact(format!(
                    "h{host_idx}.example.com"
                ))),
                routes,
                ..Default::default()
            }),
        })),
        ..Default::default()
    }
}

/// One endpoint resource for `svc{svc_idx}` resolving to a single address whose
/// last octet is `octet` — bumping `octet` is what makes a delta genuinely dirty.
fn endpoint(svc_idx: usize, octet: u8) -> p::Resource {
    let svc = u8::try_from(svc_idx).unwrap_or(u8::MAX);
    p::Resource {
        payload: Some(p::resource::Payload::Endpoints(p::EndpointResource {
            namespace: NS.to_owned(),
            service: format!("svc{svc_idx}"),
            port: EP_PORT,
            app_protocol: 0,
            service_exists: true,
            addrs: vec![format!("10.1.{svc}.{octet}:9090")],
        })),
        ..Default::default()
    }
}

/// The full resource world for `hosts_per_port` hosts on each of [`PORTS`], plus
/// one endpoint per service. `svc0_octet` selects the address of `svc0`'s
/// endpoint so the same builder produces both the baseline (octet 1) and the
/// post-delta world (octet 2).
fn world(hosts_per_port: usize, svc0_octet: u8) -> Vec<p::Resource> {
    let mut resources = Vec::new();
    for (port_idx, &port) in PORTS.iter().enumerate() {
        for h in 0..hosts_per_port {
            let global = port_idx * hosts_per_port + h;
            resources.push(host_resource(port, global, global % S));
        }
    }
    for s in 0..S {
        let octet = if s == 0 { svc0_octet } else { 1 };
        resources.push(endpoint(s, octet));
    }
    resources
}

/// A full snapshot over `resources`, version-stamped like a real server.
fn full_snapshot(resources: Vec<p::Resource>) -> p::Snapshot {
    p::Snapshot {
        version: snapshot_version(&resources),
        nonce: vec![0],
        full: true,
        resources,
        removed_resources: Vec::new(),
        publish_seq: 0,
    }
}

/// An endpoint-only delta upserting `svc0`'s moved endpoint; the version is the
/// hash of the whole declared `post_apply` world (F6).
fn endpoint_delta(post_apply: &[p::Resource]) -> p::Snapshot {
    p::Snapshot {
        version: snapshot_version(post_apply),
        nonce: vec![0],
        full: false,
        resources: vec![endpoint(0, 2)],
        removed_resources: Vec::new(),
        publish_seq: 0,
    }
}

/// Apply-or-panic. The bench runs known-good fixtures, so a `WireError` here is a
/// bug in the fixture, never a runtime condition — panicking (which benches may
/// do) keeps the call sites free of `.expect()`, which the workspace lints deny
/// even in `harness = false` benches. Returns `(recompiled, reused)`.
fn apply(h: &mut Harness, msg: &p::Snapshot, expect_full: bool) -> (u64, u64) {
    match h.apply(msg, expect_full) {
        Ok(counts) => counts,
        Err(e) => panic!("bench fixture failed to apply: {e:?}"),
    }
}

/// Build every message once (untimed): the baseline full, its identical twin,
/// the post-delta world, and the endpoint-only delta.
fn bench_apply(c: &mut Criterion) {
    let mut group = c.benchmark_group("client_delta_apply");
    for &hosts_per_port in &[50usize, 250usize] {
        let baseline = world(hosts_per_port, 1);
        let post = world(hosts_per_port, 2);
        let full_msg = full_snapshot(baseline);
        let delta_msg = endpoint_delta(&post);

        // One-shot reuse accounting (printed, never timed) — the acceptance
        // evidence that unaffected partitions are not rebuilt.
        let mut warm = Harness::new();
        apply(&mut warm, &full_msg, true);
        let (rec_a, reuse_a) = apply(&mut warm, &delta_msg, false);
        let (rec_b, reuse_b) = apply(&mut Harness::new(), &full_msg, true);
        let partitions = PORTS.len() * hosts_per_port;
        // Exactly the `P × H / S` partitions referencing the moved service (svc0)
        // recompile; `S` divides `P × H` for both swept `H`, so this is exact.
        let affected = partitions / S;
        eprintln!(
            "H={hosts_per_port} (partitions={partitions}): (a) endpoint-delta recompiled={rec_a} reused={reuse_a} | (b) cold-full recompiled={rec_b} reused={reuse_b}",
        );
        // Assert the splice accounting so a reuse regression fails the bench loudly
        // rather than silently regressing the timing it is meant to prove.
        assert_eq!(
            rec_a, affected as u64,
            "H={hosts_per_port}: endpoint delta must recompile exactly the P×H/S partitions referencing the moved service",
        );
        assert_eq!(
            reuse_a,
            (partitions - affected) as u64,
            "H={hosts_per_port}: every partition NOT referencing the moved service must be spliced, not recompiled",
        );
        assert_eq!(
            rec_b, partitions as u64,
            "H={hosts_per_port}: a cold full recompiles every partition",
        );
        assert_eq!(reuse_b, 0, "H={hosts_per_port}: a cold full reuses nothing",);

        // (a) endpoint-only delta against a warm cache — partitioned recompile.
        group.bench_function(format!("endpoint_delta_h{hosts_per_port}"), |b| {
            b.iter_batched_ref(
                || {
                    let mut h = Harness::new();
                    apply(&mut h, &full_msg, true);
                    h
                },
                |h| {
                    std::hint::black_box(apply(h, std::hint::black_box(&delta_msg), false));
                },
                BatchSize::SmallInput,
            );
        });

        // (b) full snapshot against a cold cache — every partition dirty.
        group.bench_function(format!("full_cold_h{hosts_per_port}"), |b| {
            b.iter_batched_ref(
                Harness::new,
                |h| {
                    std::hint::black_box(apply(h, std::hint::black_box(&full_msg), true));
                },
                BatchSize::SmallInput,
            );
        });

        // (c) identical full against a warm cache — digest-equal no-op path.
        group.bench_function(format!("identical_full_warm_h{hosts_per_port}"), |b| {
            b.iter_batched_ref(
                || {
                    let mut h = Harness::new();
                    apply(&mut h, &full_msg, true);
                    h
                },
                |h| {
                    std::hint::black_box(apply(h, std::hint::black_box(&full_msg), true));
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_apply);
criterion_main!(benches);
