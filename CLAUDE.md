# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## GitHub Issue Workflow

When the user says "start working on issue N":
1. Run `gh issue view N --repo coxswain-labs/coxswain` to read the full issue description and grill the user, if necessary.
2. Sync local `main` with the remote before branching: `git checkout main && git pull --ff-only origin main`. Then create and check out a branch named `issue-N` from that updated `main`.
3. In `ROADMAP.md`, change the corresponding checklist item from `- [ ]` to `- [x] ~~...~~` (tick the checkbox and wrap the description in strikethrough). Commit this change on the new branch with `Refs #N`.
4. Read all relevant source files before writing any code.
5. Implement the issue per its acceptance criteria.
6. Add or update e2e tests in `crates/coxswain-e2e/` that cover the new behaviour. Every issue that changes routing, status conditions, or proxy behaviour must have at least one new scenario in `tests/gateway_api.rs` or `tests/ingress.rs`. Run `cargo test -p coxswain-e2e --test <file> -- --test-threads=1` locally before pushing.

When working on a GitHub issue, always include a reference in every commit message:
- Use `Refs #N` for partial work on an issue.
- Use `Fixes #N` for the final commit that completes it (GitHub closes the issue automatically on push).

When the user says "close the issue" or "an issue is done":
1. Run `gh issue close N --repo coxswain-labs/coxswain`.
2. Ensure the `ROADMAP.md` item is `- [x] ~~...~~` (tick + strikethrough). This should already be done from step 3 above; if not, do it now and commit with `Fixes #N`.
3. Merge the PR with `gh pr merge --squash --delete-branch`.

## GitHub Milestones and Labels

GitHub milestones use plain version numbers only (`v0.1`, `post-v0.1`; future milestones created on demand as scope is committed). Never use special characters like em dashes, colons, or `&` in milestone titles — they break GitHub's issue filter URL parser.

The two active labels are `milestone: v0.1` and `milestone: post-v0.1`. Apply the matching label to every issue alongside its milestone assignment.

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

The workspace has six crates under `crates/` with a strict dependency order:

```
coxswain-bin
  ├── coxswain-controller
  │     └── coxswain-core
  ├── coxswain-proxy
  │     └── coxswain-core
  ├── coxswain-health
  │     └── coxswain-core
  └── coxswain-admin
        └── coxswain-core
```

### `coxswain-core`
Shared types and the routing table. `RoutingTable` maps hostnames to per-host `matchit` radix-tree routers, each routing URL paths to an `Upstream` (a named group of pod `SocketAddr`s with lock-free round-robin selection).

`SharedRoutingTable` is an opaque newtype wrapping `Arc<ArcSwap<RoutingTable>>`. It exposes `load() -> Arc<RoutingTable>` and `store(Arc<RoutingTable>)`. The controller stores a new table on every reconcile; the proxy loads on every request. No locks or channels on the hot path. `arc-swap` is an implementation detail confined to this crate.

### `coxswain-controller`
Kubernetes controller split into two independent Pingora `BackgroundService`s.

**`controller.rs` — `Controller`**
Status writer and leader elector. Runs two raw watch streams (`HTTPRoute`, `GatewayClass`) in a `tokio::select!` loop. Responsibilities:
- Renews the `kube-leader-election` Lease every 5 s (15 s TTL); updates the `leader` flag.
- On `HTTPRoute InitDone`: flips the `synced` flag, unblocking `/readyz`.
- On `HTTPRoute Apply`/`InitApply`: if leader, patches "Programmed" status back to the API server.
- On `GatewayClass Apply`/`InitApply`: if leader, patches "Accepted" status.
- On shutdown: steps down from the Lease gracefully.

**`reconciler.rs` — `ReconcilerService`**
Routing table builder. Spawns four tasks in a `JoinSet`:
- Three reflector tasks — one each for `HTTPRoute`, `Ingress`, and `EndpointSlice`. Each task populates an in-memory store via `kube::runtime::reflector` and signals a shared `Notify` on every event.
- One debounce+rebuild task — waits for the first `Notify`, then races further signals against a 500 ms timer (trailing-edge debounce). When the timer expires uninterrupted, calls `rebuild()`, which snapshots all three stores and constructs a fresh `RoutingTable` from scratch. On success, atomically publishes it via `SharedRoutingTable::store()`.

**`endpoints.rs`**
`pub(crate) fn resolve(ns, svc, port, slices) -> Vec<SocketAddr>` — scans the local `EndpointSlice` store for ready pod addresses. Shared by both reconcilers; never queries the API server.

**`gateway_api.rs` — `GatewayApiReconciler`**
`reconcile(route, slices, builder)` — translates one `HTTPRoute` into `RoutingTableBuilder` entries. Resolves pod addresses via `endpoints::resolve`. Handles exact/prefix/regex path types and exact/wildcard/catch-all host patterns.

**`ingress.rs` — `IngressReconciler`**
`reconcile(ingress, slices, builder)` — translates one `Ingress` into `RoutingTableBuilder` entries. Same endpoint resolution and host-pattern logic.

**Leader election** uses `kube-leader-election` (Kubernetes `Lease` objects, 15 s TTL, renewed every 5 s). Only the active leader patches resource status; standby replicas skip writes to avoid feedback loops. Status writes are idempotent — the controller checks whether a condition is already `True` before patching.

**kube 3.x watcher event variants (relevant to `controller.rs`):**
- `Event::InitApply(obj)` — existing objects from the initial LIST phase
- `Event::Apply(obj)` — subsequent watch-stream updates (creates/updates)
- `Event::Delete(obj)` — deletions (routing table deletions handled automatically by the reflector stores in `ReconcilerService`)
- `Event::InitDone` — end of initial list; used to flip `synced`

### `coxswain-proxy`
Pingora-based reverse proxy. Reads routing decisions from `coxswain-core` and forwards requests upstream.

Key files:
- `engine.rs` — `RoutingEngine` wraps `SharedRoutingTable` for reads on the hot path. `CoxswainProxy` implements `ProxyHttp`, calling `engine.route(host, path)` on every request.
- `filter.rs` — `TrafficFilter`: injects the `X-Proxy-Engine: Coxswain-Pingora` header on upstream requests.

### `coxswain-health`
Health endpoints served on a dedicated port, keeping liveness/readiness concerns out of the proxy hot path. `HealthService` implements Pingora's `Service` trait and handles:
- `GET /healthz` — always 200; confirms the process is alive.
- `GET /readyz` — 200 once `synced` flips true (initial LIST completed); 503 before.

### `coxswain-admin`
Diagnostics and observability endpoints, served on a separate port.

- `GET /metrics` — Prometheus text format (via the `prometheus` crate).
- `GET /routes` — JSON list of active hostnames in the routing table.
- `GET /status` — JSON with `version`, `synced`, `leader`, and `host_count`.

### `coxswain-bin`
Entry point only — parses CLI args, wires all services together, and starts the Pingora runtime.

`SharedRoutingTable::new()` is created first in `main()` and cloned into `RoutingEngine`, `ReconcilerService`, and `AdminService`. The `Controller` and `ReconcilerService` are registered as Pingora `BackgroundService`s alongside the proxy, health, and admin services.

## Key design pattern

`SharedRoutingTable` is the single shared state between the controller and proxy. `ReconcilerService` stores a new table after every debounced rebuild; the proxy loads atomically on every request with no locks.

Three `Arc<AtomicBool>` flags are shared across services:
- `synced` — flips to `true` when `HTTPRoute` initial sync completes; gates `/readyz`.
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
