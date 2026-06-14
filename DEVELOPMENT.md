# Development Guide

## Quick reference

```bash
cargo build                                    # build
cargo test --workspace --exclude coxswain-e2e  # unit tests (no cluster)
cargo clippy -- -D warnings                    # lint
cargo fmt                                      # format
cargo run --bin coxswain -- serve dev --log-format console  # run locally (all-in-one)
```

The `dev` role runs both the status writer and the proxy data plane in one process — convenient for local development. In production Coxswain ships as two cooperating pods: `serve controller` (writer) and `serve proxy --shared` (read-only data plane). The Helm chart and `deploy/manifests/` render both Deployments by default.

For the release procedure, see `RELEASE.md`. For contributing conventions (docs site, etc.), see `CONTRIBUTING.md`.

---

## Prerequisites

- [Rust](https://rustup.rs/) stable toolchain.
- A local Kubernetes cluster with `kubectl` configured (`~/.kube/config`). Any of OrbStack, Docker Desktop, minikube, kind, or k3d works.

---

## Running the controller locally

Run the binary directly on your machine. It discovers the cluster via `~/.kube/config`.

### 1. Install the Gateway API CRDs

```bash
kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/$(cat .gateway-api-version)/standard-install.yaml"
```

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

> **Namespace-scoped install.** Pass `--watch-namespace=<ns>` (or `COXSWAIN_WATCH_NAMESPACE=<ns>`) to either pod to scope its reflectors to a single namespace. Replace the cluster-scoped `ClusterRole`/`ClusterRoleBinding` in `controller-rbac.yaml` / `shared-proxy-rbac.yaml` with a namespaced `Role`/`RoleBinding` when running scoped.

### 3. Run the binary

```bash
cargo run --bin coxswain -- serve dev \
  --log-format console \
  --ingress-http-port 80 \
  --ingress-https-port 443
```

`serve dev` is the hidden all-in-one role for local development: same process as production but wiring both the status writer and the proxy data plane. `--log-format console` produces human-readable output instead of JSON. `--ingress-http-port` and `--ingress-https-port` are required to bind proxy listeners; omitting both starts no listeners.

To exercise the production split locally, run two terminals:

```bash
# Terminal 1 — controller (writer)
cargo run --bin coxswain -- serve controller --log-format console

# Terminal 2 — shared-proxy (read-only data plane)
cargo run --bin coxswain -- serve proxy --shared --log-format console \
  --ingress-http-port 80 --ingress-https-port 443
```

To run a dedicated-mode proxy (per-Gateway data plane) locally, see [docs/src/guides/dedicated-mode.md](docs/src/guides/dedicated-mode.md).

### Ports

| Port   | Purpose                                          |
|--------|--------------------------------------------------|
| `80`   | HTTP proxy (data plane)                          |
| `443`  | HTTPS proxy (data plane, SNI TLS)                |
| `8081` | Health endpoints (`/healthz`, `/readyz`)         |
| `8082` | Admin endpoints (`/metrics`, `/routes`, `/status`) |

The bind address for all listeners defaults to `0.0.0.0`. Pass `--proxy-bind-address 127.0.0.1` to restrict to localhost.

### 4. Verify

```bash
# Health
curl -s http://localhost:8081/healthz      # ok
curl -s http://localhost:8081/readyz       # ok (after every subsystem check is Ready)

# Admin diagnostics
curl -s http://localhost:8082/status       # {"version":"...","synced":true,...}
curl -s http://localhost:8082/routes       # {"hosts":[]}
curl -s http://localhost:8082/metrics      # Prometheus text

# Kubernetes
kubectl get gatewayclass                   # should show "coxswain" accepted
```

`/readyz` returns 200 iff every registered subsystem check is `Ready` or `Degraded` (`Pending` and `Failed` flip it to 503). `/status.subsystems` exposes the full per-subsystem detail. If the Gateway API CRDs (or RBAC for any watched resource) are missing, the corresponding reflector errors out instead of emitting `InitDone`, its check stays `Pending`, and `/readyz` stays 503 — the pod is not actually ready until its dependencies are installed.

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
curl -s http://localhost:8082/routes | jq .    # lists all active hostnames
```

---

## Operator UI

The operator web UI lives in `ui/` (Vite + Preact, built to a single self-contained `dist/index.html`). That file is embedded into `coxswain-admin` via `include_str!` and served at `GET /` on the **controller admin port** (controller and `dev` roles only — proxy pods return 404). `dist/` is gitignored: the Docker `ui-builder` stage rebuilds it, so it is never committed.

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
# then restart `serve controller` / `serve dev`
```

### Testing against a cluster

The full `Dockerfile` builds the UI in its `ui-builder` stage, so a normal image build picks up `ui/src` changes — no separate UI build needed:

```bash
docker build -t coxswain:ui .                                   # builds UI + binary
kubectl -n coxswain-system rollout restart deploy/coxswain-controller deploy/coxswain-shared-proxy
kubectl -n coxswain-system port-forward svc/coxswain-controller 8082:8082
# open http://localhost:8082/
```

`deploy/dev/operator-ui-demo.yaml` seeds a representative workload (healthy + dead + conflicting routes across namespaces) so the UI has realistic signals during a live test.

---

## E2E tests

All Rust e2e suites require a live cluster. The harness builds a Docker image, installs the Helm chart, and runs tests against the deployed pods. Reset the cluster before each run.

```bash
cargo build --release --bin coxswain   # compile once; re-run only when source changes
cargo test -p coxswain-e2e --test ingress           -- --test-threads=1
cargo test -p coxswain-e2e --test gateway_api       -- --test-threads=1
cargo test -p coxswain-e2e --test dedicated_proxy   -- --test-threads=1
cargo test -p coxswain-e2e --test proxy_hot_reconfig -- --test-threads=1
cargo test -p coxswain-e2e --test observability     -- --test-threads=1
```

The bootstrap fails fast with a clear message if `target/release/coxswain` is missing.

> **On macOS the harness uses the production multi-stage `Dockerfile`.** macOS produces Mach-O binaries that won't run in Linux containers, so the COPY-only `Dockerfile.ci` (the fast Linux-CI path) is bypassed. First build is ~5–10 min for BoringSSL; cached afterwards. CI Linux runners keep the fast `Dockerfile.ci` path.

### Conformance

The Gateway API conformance suite needs the production image and a Helm install with Ingress entry points disabled (so every conformance Gateway listener binds cleanly). The setup is wrapped in a script that takes a `--reset` flag for cluster-agnostic operation:

```bash
bash scripts/setup-conformance.sh --reset 'orb delete -f k8s && orb start k8s'

cd conformance && go test -v -timeout 60m -run TestConformance -args \
  --organization=coxswain-labs --project=coxswain \
  --url=https://github.com/coxswain-labs/coxswain \
  --version="$(git describe --tags --always)" \
  --report-output=reports/local-report.yaml
```

Examples for other clusters:
- kind: `--reset 'kind delete cluster --name kind && kind create cluster --name kind'`
- minikube: `--reset 'minikube delete && minikube start'`

`main_test.go` is the entrypoint; `opts.SupportedFeatures` lists the feature flags this release claims to pass. Reports are written to `reports/` (`local-report.yaml` is gitignored). Verify compilation without a cluster via `cd conformance && go vet ./...`.

### Tips

- Verbose output: `RUST_LOG=coxswain_e2e=debug,warn` + `--nocapture`.
- Cleanup after an interrupted run: `kubectl delete ns -l coxswain-e2e=true && helm uninstall coxswain -n coxswain-system`.
- `cargo test` alone does not run e2e — the crate is excluded from `default-members`.
- Set `COXSWAIN_E2E_SKIP_BUILD=1` to skip the `docker build` step when the `coxswain:e2e` image is already current.

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
