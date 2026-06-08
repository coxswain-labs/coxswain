# Development Guide

## Quick reference

```bash
cargo build                                    # build
cargo test --workspace --exclude coxswain-e2e  # unit tests (no cluster)
cargo check && cargo clippy -- -D warnings     # check + lint
cargo fmt                                      # format
cargo run --bin coxswain -- serve --log-format console  # run locally
```

For the release procedure, see `RELEASE.md`.

---

## Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- A local Kubernetes cluster with `kubectl` configured (`~/.kube/config`)

Any of the following should work:
- [OrbStack](https://orbstack.dev/)
- [Docker Desktop](https://docs.docker.com/desktop/kubernetes/)
- [minikube](https://minikube.sigs.k8s.io/)
- [kind](https://kind.sigs.k8s.io/)
- [k3d](https://k3d.io/)
- etc.

---

## Running the controller locally

When developing locally, run the binary directly on your machine. It discovers the cluster via `~/.kube/config` and talks to Kubernetes without needing to be inside a pod.

### 1. Install the Gateway API CRDs

The Gateway API CRDs are not bundled with Kubernetes and must be installed once per cluster:

```bash
kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/$(cat .gateway-api-version)/standard-install.yaml"
```

### 2. Apply the cluster manifests

Apply everything except the Deployment — the binary runs on your machine instead:

```bash
kubectl apply -f deploy/manifests/namespace.yaml
kubectl apply -f deploy/manifests/rbac.yaml
kubectl apply -f deploy/manifests/gateway-class.yaml
```

Alternatively, use the Helm chart (installs all resources including the Deployment; then stop Helm managing the pod and run the binary locally instead):

```bash
helm install coxswain charts/coxswain --namespace coxswain-system --create-namespace
# Scale the in-cluster pod to 0 if you want the local binary to be the only instance:
kubectl -n coxswain-system scale deployment/coxswain --replicas=0
```

`deploy/` is split into three subdirectories:

- **`deploy/manifests/`** — production Kubernetes manifests (namespace, RBAC, GatewayClass, IngressClass, PodDisruptionBudget, Deployment).
- **`deploy/dev/`** — local dev fixtures for manual testing (echo backends, sample HTTPRoute and Ingress objects, cross-namespace scenarios). Not applied to production.
- **`deploy/examples/`** — user-facing example configurations shipped as documentation (e.g. cert-manager TLS setup).

> The RBAC grants are scoped to the `coxswain-controller` ServiceAccount inside the cluster. When running locally, your kubeconfig identity is used instead, which typically has cluster-admin on local distributions.

> **Namespace-scoped install**: `deploy/manifests/rbac.yaml` contains a commented-out example showing how to replace the default ClusterRole with a namespaced Role + a residual ClusterRole (for GatewayClass/IngressClass only). Use this when running Coxswain with `COXSWAIN_CONTROLLER_WATCH_NAMESPACE=<ns>` to minimise RBAC surface.

### 3. Run the binary

```bash
cargo run --bin coxswain -- serve \
  --log-format console \
  --proxy-http-port 80 \
  --proxy-https-port 443
```

`--log-format console` produces human-readable output instead of JSON. `--proxy-http-port` and `--proxy-https-port` are required to bind proxy listeners; omitting both logs a warning and starts no listeners.

| Port   | Purpose                                          |
|--------|--------------------------------------------------|
| `80`   | HTTP proxy (data plane)                          |
| `443`  | HTTPS proxy (data plane, SNI TLS)                |
| `8081` | Health endpoints (`/healthz`, `/readyz`)          |
| `8082` | Admin endpoints (`/metrics`, `/routes`, `/status`) |

The bind address for all listeners defaults to `0.0.0.0`. Pass `--proxy-bind-address 127.0.0.1` to restrict to localhost.

### 4. Verify

```bash
# Health
curl -s http://localhost:8081/healthz      # ok
curl -s http://localhost:8081/readyz       # ok (after every subsystem check is Ready)

# Admin diagnostics
curl -s http://localhost:8082/status       # {"version":"...","synced":true,"leader":false,"host_count":0,"subsystems":{...}}
curl -s http://localhost:8082/routes       # {"hosts":[]}
curl -s http://localhost:8082/metrics      # Prometheus text

# Kubernetes
kubectl get gatewayclass                   # should show "coxswain" accepted
```

`/readyz` returns 200 iff every registered subsystem check is `Ready` or `Degraded` (`Pending` and `Failed` flip it to 503). `/status.subsystems` exposes the full per-subsystem detail. The `controller` subsystem flips each per-reflector check (`httproute`, `ingress`, `gateway`, …) to `Ready` on the reflector's first `InitDone`, then `routing_table_built` on the first successful rebuild. The `proxy` subsystem flips `routing_table_loaded` on the same event. The top-level `synced` field is retained as a derived alias for `is_ready()` so dashboards predating the per-subsystem model keep working.

> **CRD prerequisites and `/readyz`.** If the Gateway API CRDs (or RBAC for any watched resource) are missing, the corresponding reflector errors out instead of emitting `InitDone`, so its check stays `Pending` and `/readyz` stays 503. This is intentional: the pod is not actually ready until its dependencies are installed. Inspect `/status` to see which check is `Pending`.

---

## Manual smoke tests

The `deploy/dev/` directory contains lightweight test fixtures for exercising both routing paths without any application code.

### Apply backends and routes

```bash
# Three echo servers (echo-a, echo-b, echo-c) — apply once
kubectl apply -f deploy/dev/echo-backends.yaml

# Gateway API routes (requires Gateway API CRDs from step 1)
kubectl apply -f deploy/dev/httproute.yaml

# Classic Ingress routes
kubectl apply -f deploy/dev/ingress.yaml
```

### Test Gateway API routes

```bash
# echo.local — path-based routing, single backend per rule
curl -H "Host: echo.local" http://localhost/a          # hello from echo-a
curl -H "Host: echo.local" http://localhost/b          # hello from echo-b
curl -H "Host: echo.local" http://localhost/           # hello from echo-a (catchall)

# split.local — both echo-a and echo-b are pooled into one upstream;
# coxswain round-robins across all ready pod addresses from both services
curl -H "Host: split.local" http://localhost/          # hello from echo-a
curl -H "Host: split.local" http://localhost/          # hello from echo-b

# *.wildcard.local — any subdomain matches
curl -H "Host: foo.wildcard.local" http://localhost/   # hello from echo-c
curl -H "Host: bar.wildcard.local" http://localhost/   # hello from echo-c
```

### Test classic Ingress routes

```bash
# ingress.local
curl -H "Host: ingress.local" http://localhost/a       # hello from echo-a
curl -H "Host: ingress.local" http://localhost/b       # hello from echo-b

# ingress2.local — second Ingress resource
curl -H "Host: ingress2.local" http://localhost/c      # hello from echo-c
curl -H "Host: ingress2.local" http://localhost/       # hello from echo-a (catchall)
```

### Test cross-namespace routes (ReferenceGrant)

Cross-namespace backend refs require a `ReferenceGrant` in the target namespace. The `cross-namespace.yaml` fixture creates an `echo-tenant` namespace with a backend, a `ReferenceGrant` permitting access from `default`, and an HTTPRoute in `default` referencing it.

```bash
kubectl apply -f deploy/dev/cross-namespace.yaml
```

```bash
# Route resolves when the grant is present
curl -H "Host: cross-ns.local" http://localhost/   # hello from echo-d
```

Delete the grant to confirm enforcement:

```bash
kubectl delete referencegrant allow-httproute-from-default -n echo-tenant
curl -H "Host: cross-ns.local" http://localhost/   # 503 Service Unavailable

# Restore
kubectl apply -f deploy/dev/cross-namespace.yaml
```

### Observe the routing table

```bash
curl -s http://localhost:8082/routes | jq .    # lists all active hostnames
```

---

## E2E tests

All three suites require a live cluster. Reset your cluster (delete and recreate it) per your distro's documentation, then prepare it as described in the **Running coxswain locally** section above.

### ingress

The harness spawns coxswain automatically on ephemeral ports. Build the binary first:

```bash
cargo build --bin coxswain
cargo test -p coxswain-e2e --test ingress -- --test-threads=1
```

### gateway_api

```bash
cargo build --bin coxswain
cargo test -p coxswain-e2e --test gateway_api -- --test-threads=1
```

### conformance

The Gateway API conformance suite (`conformance/`) connects to a coxswain instance you start manually on fixed ports. Start coxswain in a separate terminal first:

```bash
# Terminal 1 — keep running
cargo run --bin coxswain -- serve \
  --proxy-http-port 80 \
  --proxy-https-port 443 \
  --health-port 8081 \
  --admin-port 8082 \
  --status-address 127.0.0.1 \
  --log-format console \
  --pod-name coxswain-conformance \
  --pod-namespace coxswain-system
```

Then run the suite:

```bash
# Terminal 2
cd conformance && go test -v -timeout 60m -run TestConformance \
  -args \
  --organization=coxswain-labs \
  --project=coxswain \
  --url=https://github.com/coxswain-labs/coxswain \
  --version=$(git describe --tags --always) \
  --report-output=reports/local-report.yaml
```

Verify the conformance file compiles (no cluster needed):

```bash
cd conformance && go vet ./...
```

`main_test.go` is the entrypoint; `opts.SupportedFeatures` lists the feature flags this release claims to pass. Reports are written to `reports/` (`local-report.yaml` is gitignored from CI artifacts).

### Tips

- **Verbose output** (ingress/gateway_api): prepend `RUST_LOG=coxswain_e2e=debug,warn` and pass `--nocapture`.
- **Manual cleanup** after an interrupted run: `kubectl delete ns -l coxswain-e2e=true`.
- The harness bootstraps the cluster on first ingress/gateway_api run (installs Gateway API CRDs, applies `deploy/manifests/`); subsequent runs skip bootstrap in ~100 ms.
- `cargo test` alone does **not** run e2e — the crate is excluded from `default-members` to keep the unit-test loop fast.
- CI runs all three suites on every PR (see `.github/workflows/e2e.yml`).
- Set `COXSWAIN_BIN=/path/to/binary` to point the ingress/gateway_api harness at a specific binary instead of `target/debug/coxswain`.

---

## Documentation site

The docs site source lives in `docs/` with `mkdocs.yml` at the repo root. It is built with [mkdocs-material](https://squidfunk.github.io/mkdocs-material/) and versioned with [mike](https://github.com/jimporter/mike).

### Preview locally

```bash
uv venv .venv
uv pip install -r requirements-docs.txt
source .venv/bin/activate
mkdocs serve          # live-reload at http://localhost:8000
mike serve            # serves the versioned site (requires a prior mike deploy)
```

`.venv/` is gitignored. The `--system` flag used in CI does not work on Homebrew-managed Python.

### How versioning works

- **Push to `main`** → publishes under the `dev` alias (always the latest unreleased docs).
- **Push a tag `vX.Y.Z`** → publishes under the `X.Y` key and updates the `stable` alias.
- Patches overwrite their minor version key (`0.1.1` → `0.1`, same as `0.1.0`).
- The site root redirects to `stable`.

Publishing happens automatically via `.github/workflows/docs.yml`. The workflow pushes into the `coxswain/` subdirectory of the `coxswain-labs/coxswain-labs.github.io` org-level Pages repo using a cross-repo PAT.

### CI secrets

All PAT secrets are managed through a single script:

```bash
./scripts/refresh-pat.sh [labeler|docs]
```

Run without arguments to select interactively. The script prints the required PAT permissions before opening the GitHub token creation page.

#### `GH_LABELER_PAT` — PR labeler

The labeler workflow (`.github/workflows/label.yml`) uses a fine-grained PAT instead of `GITHUB_TOKEN` so that label events fired by the labeler can propagate to any downstream workflows. (`GITHUB_TOKEN`-generated events are deliberately blocked from triggering downstream workflows.) Label rules live in `.github/labeler.yml`.

**Initial setup or renewal:** `./scripts/refresh-pat.sh labeler`

PAT settings:
- Resource owner: `coxswain-labs`
- Repository access: `coxswain-labs/coxswain` only
- Permission: Pull requests → Read and write

#### `GH_DOCS_PAT` — docs publish

The docs workflow (`.github/workflows/docs.yml`) needs write access to the org-level Pages repo to push the built site.

**Initial setup or renewal:** `./scripts/refresh-pat.sh docs`

PAT settings:
- Resource owner: `coxswain-labs`
- Repository access: `coxswain-labs/coxswain-labs.github.io` only
- Permission: Contents → Read and write

GitHub sends an email before tokens expire. When you get it, run the script above to rotate it.

---

## Troubleshooting

### macOS: BoringSSL build setup

Coxswain's proxy crate uses Pingora with the `boringssl` feature, which compiles BoringSSL from source via `boring-sys`. This requires `cmake` and `go` (for the BoringSSL build) and the correct `libclang` (for the `bindgen`-generated FFI bindings).

#### First-time build requirements

```bash
brew install cmake go
```

#### macOS 26+ libclang issue

On macOS 26 (Tahoe) the system `libclang` in CommandLineTools ships with the macOS 26 SDK. A change in that SDK's `cdefs.h` causes `bindgen 0.72` to panic:

```
assertion `left == right` failed: "arm64-apple-darwin" "aarch64-apple-darwin"
  left: 4
 right: 8
```

**Fix:** install Xcode 16.x alongside the macOS 26 beta toolchain, then tell `bindgen` to use Xcode 16's `libclang` and the macOS 15 SDK it ships with.

```bash
xcodes install 16.3          # or download from https://xcodereleases.com/
```

Then copy the provided Cargo config template to your local (gitignored) override:

```bash
cp .cargo/config.toml.example .cargo/config.toml
```

Edit `.cargo/config.toml` if your Xcode path or SDK version differs from the defaults in the template. After that, `cargo build` and `cargo check` work without any extra environment variables.

This file is gitignored — the paths are machine-local.
