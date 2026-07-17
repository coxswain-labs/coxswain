//! Hot-path allocation budget gate (#620).
//!
//! Replaces CLAUDE.md's old, arbitrary "3 allocations/request" prose with a
//! *measured* floor pinned in code. A counting global allocator (armed only
//! around the measured region, per thread) counts heap allocations while the
//! request hot path runs, and each case asserts an exact count. A regression
//! that reintroduces a per-request allocation flips a pinned number and fails
//! CI — which the prose budget never did.
//!
//! Scope: the parts of the hot path reachable WITHOUT a pingora `Session` —
//! `RoutingEngine::find` (the lock-free routing lookup) and the pure
//! `CorsOrigin::matches` filter predicate. The `Session`-coupled internals of
//! `request_filter` (cors_origin capture, client-cert PEM handling) and the
//! `resolve_outcome` error path (async, `&mut Session`) are NOT reachable here
//! and stay review-only — this gate does not claim to cover them.
//!
//! A counting global allocator is inherently `unsafe` (it implements
//! `GlobalAlloc`); the workspace `unsafe_code = "deny"` is relaxed here because
//! this is a test binary, not shipped code.
#![allow(missing_docs)]
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::Arc;

use coxswain_core::routing::{
    BackendGroup, CorsOrigin, GatewayRoutingTableBuilder, RequestContext, RouteEntry,
    SharedGatewayRoutingTable,
};
use coxswain_proxy::{GatewayEngine, RoutingEngine};
use http::{HeaderMap, Method};

// ---- counting global allocator -------------------------------------------

thread_local! {
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

struct CountingAllocator;

// SAFETY: forwards every operation to the system allocator unchanged; the only
// added work is a thread-local counter bump on `alloc` while armed, which never
// touches the returned pointer.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.with(Cell::get) {
            ALLOCS.with(|c| c.set(c.get() + 1));
        }
        // SAFETY: identical contract to the delegated call.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: identical contract to the delegated call.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Runs `f` with the counter armed on the current thread and returns the number
/// of heap allocations it made. Counters are thread-local, so parallel test
/// threads don't interfere.
fn allocations<R>(f: impl FnOnce() -> R) -> u64 {
    ALLOCS.with(|c| c.set(0));
    ARMED.with(|a| a.set(true));
    let r = f();
    ARMED.with(|a| a.set(false));
    // Keep the result alive past the disarm so its construction is counted but
    // its drop (which may free) is not mistaken for the measured work.
    std::hint::black_box(&r);
    ALLOCS.with(Cell::get)
}

// ---- fixtures -------------------------------------------------------------

fn make_group(name: &str, addr: &str) -> Arc<BackendGroup> {
    Arc::new(BackendGroup::new(
        name.to_string(),
        vec![
            addr.parse::<SocketAddr>()
                .unwrap_or_else(|e| panic!("{addr}: {e}")),
        ],
    ))
}

fn engine() -> GatewayEngine {
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

// ---- gates ----------------------------------------------------------------

#[test]
fn routing_lookup_allocation_budget() {
    let eng = engine();
    let method = Method::GET;
    let headers = HeaderMap::new();
    let ctx_plain = RequestContext {
        method: &method,
        headers: &headers,
        query: None,
    };
    let ctx_query = RequestContext {
        method: &method,
        headers: &headers,
        query: Some("a=1&b=2"),
    };

    // Warm up: force any one-time lazy statics before the armed measurement.
    let _ = eng.find(80, "example.com", "/api/v3/items", &ctx_plain);
    let _ = eng.find(80, "nope.example.com", "/x", &ctx_plain);

    // A matched lookup returns `Found` holding `Arc` clones (refcount bumps, not
    // heap allocations) — the lock-free find path allocates nothing.
    let hit = allocations(|| eng.find(80, "example.com", "/api/v3/items", &ctx_plain));
    assert_eq!(hit, 0, "routing hit allocated {hit} times (expected 0)");

    // A present query string is a borrow in `RequestContext` — no extra alloc.
    let hit_q = allocations(|| eng.find(80, "example.com", "/api/v3/items", &ctx_query));
    assert_eq!(
        hit_q, 0,
        "routing hit +query allocated {hit_q} (expected 0)"
    );

    // Host not registered → `NoHost`, an enum variant. No allocation on the miss.
    let no_host = allocations(|| eng.find(80, "unknown.example.com", "/api/v3", &ctx_plain));
    assert_eq!(no_host, 0, "NoHost miss allocated {no_host} (expected 0)");

    // Host registered, path unmatched → `NoPath`. Still allocation-free.
    let no_path = allocations(|| eng.find(80, "example.com", "/does/not/exist", &ctx_plain));
    assert_eq!(no_path, 0, "NoPath miss allocated {no_path} (expected 0)");
}

#[test]
fn cors_exact_match_allocation_budget() {
    let exact = CorsOrigin::Exact("https://app.example.com".to_string());

    // Warm up.
    let _ = exact.matches("https://app.example.com");

    // Exact match compares via `eq_ignore_ascii_case` — no owned lowercase copy.
    let hit = allocations(|| exact.matches("https://APP.example.com"));
    assert_eq!(hit, 0, "CORS exact hit allocated {hit} (expected 0)");

    let miss = allocations(|| exact.matches("https://evil.example.com"));
    assert_eq!(miss, 0, "CORS exact miss allocated {miss} (expected 0)");
}
