# Development Guide

## Quick reference

```bash
cargo build                                    # build
cargo test --workspace --exclude coxswain-e2e  # unit tests (no cluster)
cargo clippy -- -D warnings                    # lint
cargo fmt                                      # format
cargo run --bin coxswain -- serve controller --log-format console  # terminal 1
cargo run --bin coxswain -- serve proxy --shared --log-format console \
  --ingress-http-port 80 --ingress-https-port 443              # terminal 2
```

Coxswain ships as two cooperating pods: `serve controller` (writer + operator UI) and `serve proxy --shared` (read-only data plane). Run them in separate terminals against the same cluster.

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
kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/$(cat .gateway-api-version)/standard-install.yaml"
```

`.gateway-api-version` is the **single** version knob for the whole repo — the same file also pins the CRD version installed by `coxswain-e2e`'s bootstrap harness and drives regeneration of the `gateway-api-types` crate (see below). Bumping it does not require any other file to change in lockstep.

#### Regenerating `gateway-api-types`

`crates/gateway-api-types` (Gateway API Rust bindings) is generated wholesale — never hand-edited — by the `xtask` crate, a repo-root sibling of `crates/` (the classic `cargo xtask` layout; not part of the runtime dependency graph, same non-runtime category as `coxswain-e2e`). To bump the Gateway API version:

1. Requires the [`kopium`](https://github.com/kube-rs/kopium) CLI (`cargo install kopium`) and an authenticated `gh` CLI (used for GitHub API tree listings that drive CRD-kind and condition-constant discovery).
2. Edit `.gateway-api-version` at the repo root.
3. Run the generator:
   ```bash
   cargo run -p xtask -- gateway-api-types
   ```
   (Pass an explicit tag as a trailing argument, e.g. `-- gateway-api-types v1.6.0`, to test an unreleased tag without touching `.gateway-api-version`.)
4. Review the regenerated diff under `crates/gateway-api-types/src/` like any other committed-generated artifact (same trust model as `charts/coxswain/crds/*.yaml`), then `cargo test --workspace --exclude coxswain-e2e` to catch any CRD schema changes existing fixtures need to account for (new required fields show up as `E0063` compile errors at every affected struct literal).

### 2. Apply the cluster manifests

Apply everything except the Deployments — the binary runs on your machine:

```bash
kubectl apply -f deploy/manifests/namespace.yaml
kubectl apply -f deploy/manifests/controller-rbac.yaml
kubectl apply -f deploy/manifests/shared-proxy-rbac.yaml
kubectl apply -f deploy/manifests/gateway-class.yaml
```

Or use the Helm chart and scale the in-cluster pods to zero so the local binary is the only instance:

```bash
helm install coxswain charts/coxswain --namespace coxswain-system --create-namespace
kubectl -n coxswain-system scale deployment/coxswain-controller --replicas=0
kubectl -n coxswain-system scale deployment/coxswain-shared-proxy --replicas=0
```

`deploy/` is split into three subdirectories:

- `deploy/manifests/` — production Kubernetes manifests (namespace, RBAC, GatewayClass, IngressClass, PodDisruptionBudget, Deployment).
- `deploy/dev/` — local dev fixtures (echo backends, sample HTTPRoute and Ingress objects, cross-namespace scenarios).
- `deploy/examples/` — user-facing example configurations shipped as documentation (e.g. cert-manager TLS setup).

> **Namespace-scoped install.** Pass `--watch-namespace=<ns>` (or `COXSWAIN_WATCH_NAMESPACE=<ns>`) to restrict the controller's reflectors to a single namespace. Replace the cluster-scoped `ClusterRole`/`ClusterRoleBinding` in `controller-rbac.yaml` with a namespaced `Role`/`RoleBinding` when running scoped. The shared-proxy SA has no RBAC to adjust.

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
| `8082` | Admin endpoints (`/metrics`, `/api/v1/routes`, `/api/v1/health`, operator UI + `/api/v1/*`) |

The bind address for all listeners defaults to `0.0.0.0`. Pass `--proxy-bind-address 127.0.0.1` to restrict to localhost.

### 4. Verify

```bash
# Health
curl -s http://localhost:8081/healthz      # ok
curl -s http://localhost:8081/readyz       # ok (after every subsystem check is Ready)

# Admin diagnostics
curl -s http://localhost:8082/api/v1/health  # {"version":"...","kubernetes_version":"...","leader":...,"subsystems":{...}}
curl -s http://localhost:8082/api/v1/routes  # {"ingress":{"hosts":[]},"gateway":{"hosts":[]}} (proxy role only)
curl -s http://localhost:8082/metrics        # Prometheus text

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

```bash
curl -s http://localhost:8082/api/v1/routes | jq .    # lists all active hostnames
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

`main_test.go` is the entrypoint; `opts.SupportedFeatures` lists the feature flags this release claims to pass. Reports are written to `reports/` (`local-report.yaml` is gitignored). Verify compilation without a cluster via `cd conformance && go vet ./...`.

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
