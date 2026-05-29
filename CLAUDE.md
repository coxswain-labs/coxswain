# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

**Coxswain** is a pure-Rust Kubernetes Ingress & Gateway API controller backed by [Pingora](https://github.com/cloudflare/pingora) as the proxy engine. It watches Kubernetes `Ingress` and `Gateway API` resources and dynamically routes traffic without a full reload. Multiple replicas can run simultaneously using Kubernetes Lease-based leader election: all replicas maintain a hot data-plane routing table, but only the active leader writes status back to the API server.

## Commands

```bash
# Build all crates
cargo build

# Build release
cargo build --release

# Run all tests
cargo test

# Run tests for a single crate
cargo test -p coxswain-core

# Run a single test by name
cargo test -p coxswain-core test_name

# Check (no codegen, fast)
cargo check

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt

# Run the binary (local dev)
cargo run --bin coxswain -- --log-format console
```

## Architecture

The workspace has five crates with a strict dependency order:

```
coxswain-bin
  ├── coxswain-controller
  │     └── coxswain-core
  ├── coxswain-proxy
  │     └── coxswain-core
  └── coxswain-admin
        └── coxswain-core
```

### `coxswain-core`
Shared types and the routing table. `RoutingTable` maps hostnames to per-host `matchit` radix-tree routers, each routing URL paths to a `RouteTarget` (a list of backend `BackendPod`s with IP, port, and weight). Uses `arc-swap` for lock-free atomic swaps so the controller and proxy can share state without locks or channels.

### `coxswain-controller`
Kubernetes controller that reconciles `Ingress`, `HTTPRoute`, and `GatewayClass` resources. Uses `kube` (v3) for watch streams and `k8s-openapi`/`gateway-api` for typed API objects.

Key files:
- `watcher.rs` — main event loop; runs three concurrent watch streams (`Ingress`, `HTTPRoute`, `GatewayClass`) inside a `tokio::select!` loop backed by a Pingora `BackgroundService`. Handles leader election and all status writes.
- `ingress.rs` — `IngressTranslator`: translates `Ingress` watch events into `RoutingTable` mutations.
- `gateway_api.rs` — `GatewayApiTranslator`: translates `HTTPRoute` watch events into `RoutingTable` mutations.

**Leader election** uses `kube-leader-election` (Kubernetes `Lease` objects, 15s TTL, renewed every 5s). All replicas update the local `ArcSwap<RoutingTable>` unconditionally; only the leader patches resource status back to the API server (`GatewayClass` Accepted, `HTTPRoute` Accepted + Programmed). Status writes are idempotent — the controller checks whether the condition is already `True` before issuing a patch to avoid feedback loops.

**kube 3.x watcher event variants:**
- `Event::InitApply(obj)` — existing objects from the initial LIST phase (startup)
- `Event::Apply(obj)` — subsequent watch-stream updates (creates/updates after sync)
- `Event::Delete(obj)` — deletions
- `Event::InitDone` — signals end of initial list; used to flip the `synced` flag

Both `InitApply` and `Apply` must be handled identically for routing table updates.

### `coxswain-proxy`
Pingora-based reverse proxy. Reads routing decisions from `coxswain-core` and forwards requests upstream. Also hosts the health endpoints.

Key files:
- `engine.rs` — `CoxswainProxy`: implements `ProxyHttp`; calls `RoutingTable::match_route` on every request and selects the first backend.
- `filter.rs` — `TrafficFilter`: injects the `X-Proxy-Engine: Coxswain-Pingora` header on upstream requests.
- `health.rs` — `HealthService`: serves `/healthz` (always 200) and `/readyz` (200 once the initial sync completes, 503 before).

### `coxswain-admin`
Diagnostics and observability endpoints, served on a separate port.

- `GET /metrics` — Prometheus text format (via the `prometheus` crate).
- `GET /routes` — JSON list of active hostnames in the routing table.
- `GET /status` — JSON with `version`, `synced`, `leader`, and `host_count`.

### `coxswain-bin`
Entry point only — parses CLI args, wires all services together, and starts the Pingora runtime.

## Key design pattern

The controller and proxy communicate through an `Arc<ArcSwap<RoutingTable>>` defined in `coxswain-core`. The controller swaps in a new table on every reconcile event; the proxy does a cheap `load()` on every request. There are no channels or locks on the hot path.

Three `Arc<AtomicBool>` flags are shared across services:
- `synced` — flips to `true` when the initial LIST phase completes; gates `/readyz`.
- `leader` — mirrors the current Lease election outcome; exposed on `/status`.

## Ports (default)

| Port   | Service  | Endpoints                          |
|--------|----------|------------------------------------|
| `8080` | proxy    | HTTP data plane                    |
| `8081` | health   | `/healthz`, `/readyz`              |
| `8082` | admin    | `/metrics`, `/routes`, `/status`   |

## Deploy manifests

Located in `deploy/manifests/`:
- `namespace.yaml` — `coxswain-system` namespace
- `rbac.yaml` — `ClusterRole` for watching/patching Gateway API and Ingress resources, plus a namespaced `Role` in `coxswain-system` for `coordination.k8s.io/leases` (leader election)
- `gateway-class.yaml` — `GatewayClass` with `controllerName: coxswain-labs.dev/gateway-controller`
- `deployment.yaml` — in-cluster `Deployment` with Downward API env vars (`POD_NAME`, `POD_NAMESPACE`)
