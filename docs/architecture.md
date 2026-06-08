# Architecture

## Crate structure

Coxswain is a Cargo workspace with seven crates under `crates/`. Dependency order is strict — lower crates cannot import upper ones:

```
coxswain-bin
  ├── coxswain-controller
  │     └── coxswain-core
  ├── coxswain-proxy
  │     └── coxswain-core
  ├── coxswain-health
  ├── coxswain-admin
  │     └── coxswain-core
  └── (coxswain-e2e — black-box tests, not a runtime dep)
```

### Per-crate responsibilities

**`coxswain-core`** — Shared types consumed by all other crates:
- `Shared<T>` — an `ArcSwap`-backed atomic snapshot primitive; readers get a consistent view without locking.
- `RoutingTable` — the in-memory routing table: hostname → ordered rules → upstream set.
- `TlsStore` — maps hostnames to `rustls` `CertifiedKey` structs; hot-reload on Secret change.
- Ownership and `ReferenceGrant` helpers.

**`coxswain-controller`** — Kubernetes integration:
- Reflectors (one per watched resource type: `Ingress`, `Gateway`, `HTTPRoute`, `Secret`, `Service`, `Endpoints`, `ReferenceGrant`).
- A debounced reconciler that runs when any reflector fires and rebuilds the routing/TLS tables.
- A status writer gated on Lease-based leader election (`kube-leader-election`).

**`coxswain-proxy`** — Pingora-based reverse proxy:
- Lock-free routing lookup via `Shared<RoutingTable>`.
- Request/response filter application.
- In-process SNI TLS termination.
- Optional HAProxy PROXY-protocol acceptor.

**`coxswain-health`** — `/healthz` (always 200) and `/readyz` (gated on `HealthRegistry::is_ready`). Every registered subsystem must reach `Ready` or `Degraded`.

**`coxswain-admin`** — `/metrics` (Prometheus), `/routes` (routing table dump), `/status` (per-subsystem health detail).

**`coxswain-bin`** — Entry point: CLI parsing (`clap`), shared-state wiring, Pingora runtime bootstrap.

**`coxswain-e2e`** — Black-box integration tests against a live cluster. Not a runtime dependency; excluded from `default-members` to keep `cargo test` fast.

## Routing table design

The routing table is the central data structure of the hot path. Its invariants:

- **Immutable snapshots.** The reconciler produces a complete new `RoutingTable` from scratch on every reconcile. There is no incremental mutation. Once built, a table is never modified.
- **Lock-free reads.** `Shared<RoutingTable>` wraps `ArcSwap`. Every read (one per proxy request) is an atomic pointer load — no mutex, no channel, no allocation.
- **Atomic swap.** When the reconciler finishes, it calls `Shared::store(new_table)`. Readers already mid-lookup see the old table to completion; new readers see the new table. No request ever blocks on a table swap.

### Lookup path (per request)

```
request arrives
  → load Shared<RoutingTable> snapshot (atomic, ~2ns)
  → extract host header
  → lookup host in HashMap<Arc<str>, HostEntry>
  → iterate rules (ordered by specificity: Exact > Prefix, longer > shorter)
  → find first matching rule
  → round-robin pick from upstream set
  → upstream_peer() returns the selected address
```

The only allocations on the hot path are the three captures at `request_filter` entry: host (`Arc<str>`), path (`Option<String>`), query (`Option<String>`). The lookup itself allocates nothing.

## Leader election

All replicas reconcile watch events and maintain their own routing table independently. Leader election controls only the status-writer loop:

```
All replicas:  watch K8s events → reconcile → update local routing table → serve traffic
Only leader:   watch K8s events → reconcile → write status to Ingress/Gateway/HTTPRoute
```

The leader is determined by a Kubernetes `Lease` object in the `coxswain-system` namespace. The Lease TTL is 15 seconds by default; a replica with an expired lease loses leadership and stops writing status. The new leader is elected within one TTL window.

This design means:
- **No split-brain on the data plane.** All replicas independently serve the same traffic.
- **Possible temporary stale status during leader transition.** Status conditions may lag by up to one TTL during a failover — this is visible to users and known.

## Reconciler

The reconciler is debounced: it coalesces rapid watch events into a single reconcile pass. The flow:

```
watch event (any resource type)
  → debounce timer reset (100ms default)
  → timer fires
  → reconciler runs:
      1. snapshot all reflector caches
      2. resolve ownership (IngressClass, GatewayClass claims)
      3. resolve ReferenceGrants for cross-namespace refs
      4. build new RoutingTable
      5. build new TlsStore (for changed Secrets)
      6. Shared::store(new_routing_table)
      7. Shared::store(new_tls_store)
      8. notify_waiters() (for status writer and health check)
```

A periodic resync tick (default: 5 minutes) fires the reconciler even if no watch events arrive, providing a backstop against missed events.

## TLS hot-reload

The TLS store watches `kubernetes.io/tls` Secrets. When a Secret is created, updated, or deleted:

1. The reconciler rebuilds the `TlsStore` from the new Secret set.
2. `Shared::store(new_tls_store)` atomically swaps the store.
3. New TLS connections use the new store immediately; connections already in progress complete with the old store.

No restart is required. Cert-manager's automatic renewal triggers a Secret update, which triggers this path.

## Code quality rules

The following rules were established through the v0.1 refactor pass and apply to all contributions:

- **No `#[allow(...)]`** on lints — fix the root cause or alias upstream-imposed names at crate boundaries.
- **No `.unwrap()` / `.expect()` in non-test code** — recoverable errors propagate with `?`; invariants use `unwrap_or_else(|e| panic!("invariant: {e}"))`.
- **`#[non_exhaustive]`** on every public struct and enum not intentionally open for downstream construction.
- **`#[must_use]`** on every `pub fn` returning a value the caller is expected to consume.
- **`pub(crate)` / `pub(super)` by default** — bare `pub` only for items re-exported at the crate root.
- See [CLAUDE.md](https://github.com/coxswain-labs/coxswain/blob/main/CLAUDE.md) in the repository for the full rule set.
