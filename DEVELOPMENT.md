# Development Guide

## Quick reference

```bash
cargo build                                    # build
cargo test --workspace --exclude coxswain-e2e  # unit tests (no cluster)
cargo clippy --workspace --all-targets --exclude coxswain-e2e -- -D warnings  # lint (CI gate)
cargo fmt                                      # format
cargo run --bin coxswain -- serve controller --log-format console  # terminal 1
cargo run --bin coxswain -- serve proxy --shared --log-format console \
  --ingress-http-port 80 --ingress-https-port 443              # terminal 2
```

Coxswain ships as three pod roles: `serve controller` (writer + operator UI), `serve proxy` (read-only data plane), and `serve relay` (discovery fan-out cache). Local development normally needs just the first two — run `serve controller` and `serve proxy --shared` in separate terminals against the same cluster.

For the release procedure, see `RELEASE.md`. For contributing conventions (docs site, etc.), see `CONTRIBUTING.md`.

---

## Prerequisites

- [Rust](https://rustup.rs/) stable toolchain.
- [cargo-nextest](https://nextest.rs/installation): `cargo install cargo-nextest` (or `cargo binstall cargo-nextest`). Required for e2e runs.
- A local Kubernetes cluster with `kubectl` configured (`~/.kube/config`). Any of OrbStack, Docker Desktop, minikube, kind, or k3d works.

---

## Running the controller locally

Run the binary directly on your machine. It discovers the cluster via `~/.kube/config`.

### 1. Install the Gateway API CRDs

```bash
kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/$(scripts/gateway-api-versions.sh --latest)/standard-install.yaml"
```

`.gateway-api-versions.json` is the single source of truth for Gateway API versions. Each entry pairs a CRD release tag with its upstream conformance report directory (not a mechanical transform: upstream keeps per-patch directories through v1.4.x but unified minor directories from v1.5), and exactly one entry is marked `"latest": true`:

```json
[
  { "gatewayApiVersion": "v1.4.1", "reportDir": "v1.4.1", "latest": false },
  { "gatewayApiVersion": "v1.6.1", "reportDir": "v1.6",   "latest": true  }
]
```

The `latest` entry is what `coxswain-e2e`'s bootstrap installs, what `kubeconform` validates against, and what `gateway-api-types` is generated from. The rest are versions conformance reports are published for; the controller detects at runtime which kinds and schema fields the installed CRDs actually serve — see `docs/src/reference/capability-matrix.md`.

Read it via `scripts/gateway-api-versions.sh` (`--latest`, `--versions`, `--list`, `--report-dir vX.Y.Z`). That script is the only JSON parser in the shell/CI surface, so no consumer needs `jq` and none can disagree about the schema. `scripts/check-gateway-api-versions.sh` validates it.

This replaced a `.gateway-api-version` pin plus a separate plural manifest. A `"latest": true` flag makes "the pin is not in the manifest" unrepresentable rather than merely gated.

#### Regenerating `gateway-api-types`

`crates/gateway-api-types` (Gateway API Rust bindings) is generated wholesale — never hand-edited — by the `xtask` crate, a repo-root sibling of `crates/` (the classic `cargo xtask` layout; not part of the runtime dependency graph, same non-runtime category as `coxswain-e2e`). To bump the Gateway API version:

1. Requires the [`kopium`](https://github.com/kube-rs/kopium) CLI (`cargo install kopium`) and an authenticated `gh` CLI (used for GitHub API tree listings that drive CRD-kind and condition-constant discovery).
2. Edit `.gateway-api-versions.json` at the repo root: add the new version's entry and move `"latest": true` onto it.
3. Run the generator:
   ```bash
   cargo run -p xtask -- gateway-api-types
   ```
   (Pass an explicit tag as a trailing argument, e.g. `-- gateway-api-types v1.6.0`, to test an unreleased tag without touching `.gateway-api-versions.json`.)
4. Review the regenerated diff under `crates/gateway-api-types/src/` like any other committed-generated artifact (same trust model as `charts/coxswain/crds/*.yaml`), then `cargo test --workspace --exclude coxswain-e2e` to catch any CRD schema changes existing fixtures need to account for (new required fields show up as `E0063` compile errors at every affected struct literal).

### 2. Apply the cluster manifests

Apply the base (CRDs, RBAC, GatewayClass, IngressClass, admission policy, Services), then scale the in-cluster controller to zero so your local binary is the only controller:

```bash
kubectl apply -k deploy/manifests
kubectl -n coxswain-system scale deployment/coxswain-controller --replicas=0
```

Or use the Helm chart, but keep the in-cluster data plane out of the way so your local binary is the only instance. The shared proxy pool is controller-owned (provisioned off `proxy.shared.*`, not Helm-rendered), so disable it via values rather than scaling its Deployment — a running controller would otherwise reconcile the replica count back:

```bash
helm install coxswain charts/coxswain --namespace coxswain-system --create-namespace \
  --set proxy.shared.enabled=false
kubectl -n coxswain-system scale deployment/coxswain-controller --replicas=0
```

`deploy/` is split into three subdirectories:

- `deploy/manifests/` — production Kubernetes manifests. `coxswain.yaml` is **generated from the Helm chart** by `scripts/render-manifests.sh` (the chart is the single source of truth; `scripts/check-manifests-synced.sh` gates drift), and the CRDs live in `crds/`. Never hand-edit `coxswain.yaml`.
- `deploy/dev/` — local dev fixtures (echo backends, sample HTTPRoute and Ingress objects, cross-namespace scenarios).
- `deploy/examples/` — user-facing example configurations shipped as documentation (e.g. cert-manager TLS setup).

> **Namespace-scoped install.** Pass `--watch-namespace=<ns>` (or `COXSWAIN_WATCH_NAMESPACE=<ns>`) to restrict the controller's reflectors to a single namespace. Replace the cluster-scoped `ClusterRole`/`ClusterRoleBinding` with a namespaced `Role`/`RoleBinding` when running scoped — `deploy/manifests/controller-rbac-namespaced.yaml` is a worked example. The shared-proxy SA has no RBAC to adjust.

### 3. Run the binary

Run the two roles in separate terminals:

```bash
# Terminal 1 — controller (status writer + operator UI)
cargo run --bin coxswain -- serve controller --log-format console

# Terminal 2 — shared-proxy (read-only data plane)
cargo run --bin coxswain -- serve proxy --shared --log-format console \
  --ingress-http-port 80 --ingress-https-port 443
```

`--log-format console` produces human-readable output instead of JSON. `--ingress-http-port` and `--ingress-https-port` are required on the proxy to bind listeners; omitting both starts no listeners.

To run a dedicated-mode proxy (per-Gateway data plane) locally, see [docs/src/guides/dedicated-mode.md](docs/src/guides/dedicated-mode.md).

### Ports

| Port   | Purpose                                          |
|--------|--------------------------------------------------|
| `80`   | HTTP proxy (data plane)                          |
| `443`  | HTTPS proxy (data plane, SNI TLS)                |
| `8081` | Health endpoints (`/healthz`, `/readyz`)         |
| `8082` | Admin endpoints (`/metrics`, `/api/v1/health`; operator UI + the `/api/v1/*` routing/fleet API on the controller) |

The bind address for all listeners defaults to `0.0.0.0`. Pass `--proxy-bind-address 127.0.0.1` to restrict to localhost.

### 4. Verify

```bash
# Health
curl -s http://localhost:8081/healthz      # ok
curl -s http://localhost:8081/readyz       # ok (after every subsystem check is Ready)

# Admin diagnostics
curl -s http://localhost:8082/api/v1/health          # {"version":"...","kubernetes_version":"...","leader":...,"subsystems":{...}}
curl -s http://localhost:8082/api/v1/routing/summary # per-category route + problem counts (controller role)
curl -s http://localhost:8082/metrics                # Prometheus text

# Kubernetes
kubectl get gatewayclass                   # should show "coxswain" accepted
```

The full controller admin API (the `/api/v1/{fleet,routing}/*` surface, summaries, problems, health) is described in `api/openapi.yaml` — an internal aid kept in sync with the dispatch.

`/readyz` returns 200 iff every registered subsystem check is `Ready` or `Degraded` (`Pending` and `Failed` flip it to 503). `/api/v1/health`'s `subsystems` exposes the full per-subsystem detail. If the Gateway API CRDs (or RBAC for any watched resource) are missing, the corresponding reflector errors out instead of emitting `InitDone`, its check stays `Pending`, and `/readyz` stays 503 — the pod is not actually ready until its dependencies are installed.

---

## Manual smoke tests

`deploy/dev/` contains lightweight test fixtures for exercising both routing paths without any application code.

### Apply backends and routes

```bash
kubectl apply -f deploy/dev/echo-backends.yaml   # echo-a, echo-b, echo-c
kubectl apply -f deploy/dev/httproute.yaml       # Gateway API routes
kubectl apply -f deploy/dev/ingress.yaml         # classic Ingress routes
```

### Test Gateway API routes

The `deploy/dev/httproute.yaml` fixture binds the Gateway listener to port `8000`:

```bash
# echo.local — path-based routing
curl -H "Host: echo.local" http://localhost:8000/a       # hello from echo-a
curl -H "Host: echo.local" http://localhost:8000/b       # hello from echo-b
curl -H "Host: echo.local" http://localhost:8000/        # hello from echo-a (catchall)

# split.local — pooled upstream; round-robins across both services
curl -H "Host: split.local" http://localhost:8000/       # alternates echo-a and echo-b

# *.wildcard.local — any subdomain matches
curl -H "Host: foo.wildcard.local" http://localhost:8000/   # hello from echo-c
```

### Test classic Ingress routes

```bash
curl -H "Host: ingress.local" http://localhost/a    # hello from echo-a
curl -H "Host: ingress.local" http://localhost/b    # hello from echo-b
curl -H "Host: ingress2.local" http://localhost/c   # hello from echo-c
```

### Test cross-namespace routes (ReferenceGrant)

Cross-namespace backend refs require a `ReferenceGrant` in the target namespace:

```bash
kubectl apply -f deploy/dev/cross-namespace.yaml
curl -H "Host: cross-ns.local" http://localhost:8000/    # hello from echo-d

kubectl delete referencegrant allow-httproute-from-default -n echo-tenant
curl -H "Host: cross-ns.local" http://localhost:8000/    # 503 Service Unavailable
```

### Observe the routing table

The proxy no longer exposes a route-dump endpoint — observe the live table through the controller's aggregated admin API (or the operator UI at `http://localhost:8082/`):

```bash
curl -s http://localhost:8082/api/v1/routing/summary    | jq .   # per-category counts
curl -s http://localhost:8082/api/v1/routing/httproutes | jq .   # active HTTPRoutes
curl -s http://localhost:8082/api/v1/routing/ingresses  | jq .   # active Ingresses
```

---

## Operator UI

The operator web UI lives in `ui/` (Vite + Preact, built to a single self-contained `dist/index.html`). That file is embedded into `coxswain-admin` via `include_str!` and served at `GET /` on the **controller admin port** (controller role only — proxy pods return 404). `dist/` is gitignored: the Docker `ui-builder` stage rebuilds it, so it is never committed.

### Fast iteration (no cluster)

```bash
cd ui
npm install        # first time only
npm run dev        # http://localhost:5173
```

`npm run dev` serves the UI with hot-reload and a mock `/api/v1/*` backend, so you can work on every screen and edge case without a controller, cluster, or container. Fixtures — and how to regenerate or capture them — are documented in `ui/mock/README.md` (`node mock/generate.mjs` writes the synthetic state matrix; `mock/capture.sh` snapshots a live controller). When you add a UI state, extend the mock so it stays reachable in dev.

### Seeing it as the binary serves it

The dev server uses Vite; the binary serves the *embedded* build, which only changes on a rebuild:

```bash
cd ui && npm run build      # regenerates dist/index.html
# then restart `serve controller`
```

### Testing against a cluster

The full `Dockerfile` builds the UI in its `ui-builder` stage, so a normal image build picks up `ui/src` changes — no separate UI build needed:

```bash
docker build -t coxswain:ui .                                   # builds UI + binary
kubectl -n coxswain-system rollout restart deploy/coxswain-controller deploy/coxswain-shared-proxy
kubectl -n coxswain-system port-forward svc/coxswain-controller 8082:8082
# open http://localhost:8082/
```

`rollout restart` only re-pulls the image — it does **not** apply chart changes. If your change also touches RBAC or any other rendered resource (e.g. a new `pods/log` grant under `charts/coxswain/templates/`), apply the chart first, then restart for the new binary:

```bash
helm upgrade coxswain charts/coxswain -n coxswain-system --reuse-values --set image.tag=ui
kubectl -n coxswain-system rollout restart deploy/coxswain-controller deploy/coxswain-shared-proxy
```

`deploy/dev/operator-ui-demo.yaml` seeds a representative workload (healthy + dead + conflicting routes across namespaces) so the UI has realistic signals during a live test.

---

## E2E tests

All Rust e2e suites require a live cluster. The harness builds a Docker image, installs the Helm chart, and runs tests against the deployed pods. Reset the cluster before each run.

Each suite runs as **two passes** — a parallel pass (`e2e`), then a serial pass (`e2e-serial`) — both filtered by `binary(<suite>)`. Run them in that order:

```bash
# Suites are by behavior plane (see each tests/*.rs header). For each suite:
cargo nextest run --profile e2e        -p coxswain-e2e -E 'binary(routing)' --no-tests=pass
cargo nextest run --profile e2e-serial -p coxswain-e2e -E 'binary(routing)' --no-tests=pass
# …and likewise for: tls, traffic_policy, status_conditions, provisioning,
# resilience, observability, discovery.
```

`.config/nextest.toml` defines two profiles whose `default-filter`s split the work, so the command is identical per suite — only the profile changes:

- **`e2e`** — up to 4 tests concurrently against the one shared proxy; everything *except* the global-config mutators and the resilience suite.
- **`e2e-serial`** — one at a time. The global-config mutators (`default_backend`, `proxy_protocol_*`, `access_log_*`, `status_load_balancer_ip`) each reconfigure the shared proxy/controller via `helm upgrade`, which rolls the Deployment and is proxy-wide — so they must own the shared control plane while they run (a cap-1 group is *not* enough, since it doesn't stop overlap with ungrouped tests). The resilience suite (restarts/migrates the controller) runs here too.

`--no-tests=pass` makes the empty side of the split a no-op (e.g. `traffic_policy` has no mutators; `resilience` runs entirely in the serial pass). Bootstrap runs once per `cargo nextest` invocation via the `e2e-setup` setup script (idempotent — a fast no-op on the second pass).

> **On macOS the harness uses the production multi-stage `Dockerfile`.** macOS produces Mach-O binaries that won't run in Linux containers, so the COPY-only `Dockerfile.ci` (the fast Linux-CI path) is bypassed. First build is ~5–10 min for BoringSSL; cached afterwards. CI Linux runners keep the fast `Dockerfile.ci` path.

### Conformance

The Gateway API conformance suite needs the production image and a Helm install with Ingress entry points disabled (so every conformance Gateway listener binds cleanly). The setup is wrapped in a script that takes a `--reset` flag for cluster-agnostic operation:

```bash
bash scripts/setup-conformance.sh --reset 'orb delete -f k8s && orb start k8s'

cd conformance && go test -v -timeout 60m -run TestConformance -args \
  --organization=coxswain-labs --project=coxswain \
  --url=https://github.com/coxswain-labs/coxswain \
  --version="$(git describe --tags --always)" \
  --contact=https://github.com/coxswain-labs/coxswain/issues \
  --report-output=reports/local-report.yaml
```

Examples for other clusters:
- kind: `--reset 'kind delete cluster --name kind && kind create cluster --name kind'`
- minikube: `--reset 'minikube delete && minikube start'`

`main_test.go` is the entrypoint. The claimed profiles and features are derived from the cluster's installed CRDs rather than hard-coded: `capabilities.go` reads the Gateway API CRD definitions (kind presence plus two schema-field probes) and `features.go` holds the `gatedFeatures` table naming what each declaration requires. Profiles are built from strings rather than `suite.Gateway*ConformanceProfileName` constants because the TCP/UDP constants do not exist in the Gateway API v1.4 Go module, and this file must compile against it. Reports are written to `reports/` (`local-report.yaml` is gitignored). Verify compilation without a cluster via `cd conformance && go vet ./...`.

### Tips

- Verbose output: `RUST_LOG=coxswain_e2e=debug,warn` (nextest captures output per test; add `--no-capture` to stream live).
- Cleanup after an interrupted run: `kubectl delete ns -l coxswain-e2e=true && helm uninstall coxswain -n coxswain-system`.
- `cargo test` alone does not run e2e — the crate is excluded from `default-members`.
- Set `COXSWAIN_E2E_SKIP_BUILD=1` to skip the `docker build` step when the `coxswain:e2e` image is already current.

---

## Convergence benchmarks

Control-plane convergence — `watch event → notify → debounce fire → rebuild() → snapshot build → discovery push → proxy apply` — has per-stage Prometheus histograms (`coxswain_{proxy,controller}_reconcile_debounce_seconds`, `coxswain_{proxy,controller}_routing_table_rebuild_duration_seconds`, `coxswain_discovery_snapshot_build_seconds`, `coxswain_discovery_ack_latency_seconds`, `coxswain_discovery_snapshot_apply_seconds`) and two benchmark layers (#513). **Neither layer's numbers are committed to this repo** — they're environment-dependent (OrbStack vs CI kind, machine noise) and a committed snapshot goes stale and misleads the moment hardware or cluster state changes.

### Layer 1 — synthetic scaling curves (criterion)

Deterministic, no cluster needed. Demonstrates cost as a function of cluster size, independent of any one machine's absolute numbers:

```bash
# endpoints::resolve() cost vs. route count x endpoints/service (O(routes x endpoints), #511's target)
cargo bench -p coxswain-reflector --bench convergence

# routing-table build cost vs. total route count (#511's partitioned-rebuild target)
cargo bench -p coxswain-core --bench routing
```

Criterion persists every run's results under `target/criterion/` (gitignored) and auto-diffs each new run against the prior one — this, not a hand-copied table, is the mechanism a later change (#511, #512) uses to prove a win:

```bash
# before the change
cargo bench -p coxswain-reflector --bench convergence -- --save-baseline pre-511
# after the change
cargo bench -p coxswain-reflector --bench convergence -- --baseline pre-511
```

### Layer 2 — real full-rebuild operating point (live cluster)

The synthetic benches model `resolve()` and table-build in isolation; this layer scrapes the stage histograms off a REAL controller + proxy after a real workload — the actual private `rebuild()` end-to-end, doubling as validation that the instrumentation is wired correctly.

```bash
# 1. Drive a real workload against the cluster (conformance is the canonical
#    driver — the largest realistic Gateway API route set this repo exercises).
bash scripts/setup-conformance.sh --reset 'orb delete -f k8s && orb start k8s'
cd conformance && go test -v -timeout 60m -run TestConformance -args ... && cd ..

# 2. Capture the stage histograms.
bash scripts/capture-convergence-baseline.sh
```

Post the script's output as a comment on the relevant GitHub issue (e.g. #513, or the issue making the claim) — that comment, timestamped and environment-noted, is what #511/#512/#383 cite as the baseline reference. Do not paste the numbers into this file or any other tracked doc.

---

## Relay fan-out load test

A relay replica is a fan-out cache — one upstream stream in, broadcast to N downstream subscribers — so its real capacity is bounded by egress/serialization cost and failover blast radius, not compute. `--relay-target-proxies-per-replica` (the relay autoscaler's capacity ratio) is set from a measured knee in that cost, not a guess (#603). **The measured number is not committed to this repo** — it's environment-dependent (machine cores, OrbStack vs CI, background load) — so re-run the harness and post the output as a #603 comment rather than trusting a stale snapshot.

Not a `criterion` micro-bench: a relay's cost is I/O on change, not a hot function, so the harness drives real gRPC connections against a real child OS process instead.

```bash
# Release build for accurate CPU/mem numbers — debug-mode overhead skews both.
cargo build --release -p coxswain-discovery --bench relay_fanout

# Full default sweep (N = 10,50,100,250,500,1000 x churn = 0,1,10 changes/sec,
# 10s per cell) — takes several minutes.
./target/release/deps/relay_fanout-* --world-size 500

# Narrower sweep for a quick check.
./target/release/deps/relay_fanout-* --subscribers 100,500 --churn-rates 0,10 --duration-secs 5
```

Each row is one (subscriber count, churn rate) cell: p50/p99 change-to-delivery latency, the relay child process's average CPU/mem (sampled via `sysinfo`, isolated from the driver's own usage), and aggregate egress bytes/sec (`Σ Message::encoded_len()` over every delivered snapshot — no server-side instrumentation needed). Idle-mode latency prints `-`: there's no churn event to time, only connection-hold steady-state cost.

Pick the default from where cost stays comfortably safe under the worst-case (highest churn) row — not at the edge of the observed range, since a relay's capacity ratio is deliberately conservative relative to failover blast radius (a dead replica's subscribers all reconnect to a survivor at once). Wire the result into `crates/coxswain-bin/src/args.rs`'s `relay_target_proxies_per_replica` default (+ doc comment), `charts/coxswain/values.yaml`'s `relay.targetProxiesPerReplica`, and the CRD doc string in `crates/coxswain-core/src/crd/relay_policy.rs` (regenerate both CRD YAMLs per that file's `committed_manifest_crd_matches_generator` test failure message — never hand-edit them).

Re-tune once v0.6 delta/EDS snapshot updates land — the harness only exercises full-snapshot push today, and the knee moves a lot under deltas.

---

## Troubleshooting

### macOS: BoringSSL build setup

`coxswain-proxy` uses Pingora with the `boringssl` feature, which compiles BoringSSL from source via `boring-sys`. This requires `cmake` and `go`:

```bash
brew install cmake go
```

#### macOS 26+ libclang issue

On macOS 26 (Tahoe) the system `libclang` in CommandLineTools ships with the macOS 26 SDK. A change in that SDK's `cdefs.h` causes `bindgen 0.72` to panic. The fix is to install Xcode 16.x alongside the macOS 26 beta toolchain and point `bindgen` at Xcode 16's `libclang` and macOS 15 SDK:

```bash
xcodes install 16.3
cp .cargo/config.toml.example .cargo/config.toml
```

Edit `.cargo/config.toml` if your Xcode path or SDK version differs. After that, `cargo build` and `cargo check` work without extra environment variables. The config file is gitignored — the paths are machine-local.

### Gateway convergence stalls (#570 regression signatures)

Two historical failure signatures, both fixed in #570 — if either reappears, start from the named metric rather than the logs (container log rotation drops the WARN samples long before a run finishes):

- **Tests/conformance steps clustering at 30–60 s** — the operator reconcile loop is burning error-retry cycles. Check `coxswain_controller_reconcile_errors_total{controller="operator", reason=…}`: transient reasons (`namespace_terminating`, `conflict`, `transport`) retry on a per-Gateway exponential backoff (0.5 s → 15 s cap), so a healthy run shows only a handful per reason; persistent reasons (`forbidden`, `invalid`) poll flat at 15 s and mean RBAC or a rejected rendered spec — fix the config, don't wait it out.
- **A Gateway spinning forever with conditions stuck below `metadata.generation`** — the shared writer's convergence gate is holding `Programmed` deferred. Check `coxswain_controller_gateways_held_pending`: it must return to zero within seconds of any spec change. Terminally-invalid configurations (malformed cert Secret, unsupported `parametersRef`, every listener unserviceable) must never hold — they settle `Programmed=False/Invalid` at the current generation; if one holds instead, the settled-negative escape in `reconcile_gateway_inner` (controller) / `programmed_outcome` (operator) regressed. `coxswain_controller_vip_reconcile_total{result="degraded"}` climbing alongside points at the VIP loop starving `awaiting_own_vip` instead.
