# Development Guide

## Quick reference

```bash
cargo build                                    # build
cargo test --workspace --exclude coxswain-e2e  # unit tests (no cluster)
cargo check && cargo clippy -- -D warnings     # check + lint
cargo fmt                                      # format
cargo run --bin coxswain -- serve dev --log-format console  # run locally (all-in-one)
```

The `dev` role runs both the status writer and the proxy data plane in one process — convenient for local development. In production, Coxswain ships as two cooperating pods: `serve controller` (writer) and `serve proxy --shared` (read-only data plane). The Helm chart and `deploy/manifests/` render both Deployments by default.

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

Apply everything except the Deployments — the binary runs on your machine instead:

```bash
kubectl apply -f deploy/manifests/namespace.yaml
kubectl apply -f deploy/manifests/controller-rbac.yaml
kubectl apply -f deploy/manifests/shared-proxy-rbac.yaml
kubectl apply -f deploy/manifests/gateway-class.yaml
```

Alternatively, use the Helm chart (installs all resources including both Deployments; then scale the in-cluster pods to 0 so the local binary is the only instance):

```bash
helm install coxswain charts/coxswain --namespace coxswain-system --create-namespace
kubectl -n coxswain-system scale deployment/coxswain-controller --replicas=0
kubectl -n coxswain-system scale deployment/coxswain-shared-proxy --replicas=0
```

`deploy/` is split into three subdirectories:

- **`deploy/manifests/`** — production Kubernetes manifests (namespace, RBAC, GatewayClass, IngressClass, PodDisruptionBudget, Deployment).
- **`deploy/dev/`** — local dev fixtures for manual testing (echo backends, sample HTTPRoute and Ingress objects, cross-namespace scenarios). Not applied to production.
- **`deploy/examples/`** — user-facing example configurations shipped as documentation (e.g. cert-manager TLS setup).

> Two ServiceAccounts are installed: `coxswain-controller` (cluster-wide reads + `*/status` writes) and `coxswain-shared-proxy` (cluster-wide reads, zero writes). When running locally, your kubeconfig identity is used instead, which typically has cluster-admin on local distributions.

> **Namespace-scoped install**: pass `--watch-namespace=<ns>` (or `COXSWAIN_WATCH_NAMESPACE=<ns>`) to either pod to scope its reflectors to a single namespace. The controller-rbac and shared-proxy-rbac files are cluster-scoped by default; replace the ClusterRole/ClusterRoleBinding with a namespaced Role/RoleBinding when running scoped.

### 3. Run the binary

```bash
cargo run --bin coxswain -- serve dev \
  --log-format console \
  --ingress-http-port 80 \
  --ingress-https-port 443
```

`serve dev` is the hidden all-in-one role for local development: same process as production but wiring both the status writer and the proxy data plane. `--log-format console` produces human-readable output instead of JSON. `--ingress-http-port` and `--ingress-https-port` are required to bind proxy listeners; omitting both logs a warning and starts no listeners.

To exercise the production split locally, run two terminals:

```bash
# Terminal 1 — controller (writer)
cargo run --bin coxswain -- serve controller --log-format console

# Terminal 2 — shared-proxy (read-only data plane)
cargo run --bin coxswain -- serve proxy --shared --log-format console \
  --ingress-http-port 80 --ingress-https-port 443
```

### Run a dedicated-mode proxy locally

`serve proxy --dedicated` is the per-Gateway data plane mode (issue #206). It runs the same image, watches the same K8s resources, but filters the routing-table build to one named Gateway — exactly the shape the controller will provision automatically once Step 9 of the architecture plan lands.

Before reaching for this, apply the dev Gateway fixture so there's something to attach to:

```bash
kubectl apply -f deploy/dev/echo-backends.yaml
kubectl apply -f deploy/dev/httproute.yaml   # creates the `coxswain-test` Gateway
```

Then start the dedicated proxy in its own terminal alongside the controller:

```bash
# Terminal 3 — dedicated proxy for one Gateway
cargo run --bin coxswain -- serve proxy --dedicated \
  --gateway-name coxswain-test \
  --gateway-namespace default \
  --log-format console
```

Verify only that Gateway's routes are loaded:

```bash
curl -s http://localhost:8082/routes | jq .
```

The output lists exactly the hosts the target Gateway's HTTPRoutes serve; Ingress routes and routes attached to other Gateways do not appear.

#### Opt-in flags for cross-namespace route attachment

By default, dedicated mode treats listeners with `allowedRoutes.namespaces.from: All` or `from: Selector` as needing operator consent to broader RBAC scope. Today the watches are still cluster-wide (Step 7 keeps the shared-proxy RBAC profile); the opt-in flags govern a startup warning only. Once Step 10 lands, listeners using a non-`Same` `from` without the matching opt-in will be marked `Accepted=false`.

| Flag | Gates listeners with |
|---|---|
| `--allow-cluster-wide-route-read` | `allowedRoutes.namespaces.from: All` |
| `--allow-cluster-wide-namespace-read` | `allowedRoutes.namespaces.from: Selector` |

Both default to false. Set them only on Gateways that genuinely accept cross-namespace route attachment:

```bash
cargo run --bin coxswain -- serve proxy --dedicated \
  --gateway-name coxswain-test \
  --gateway-namespace default \
  --allow-cluster-wide-route-read \
  --log-format console
```

#### Known limitations (deferred)

- **Watch scope is per-namespace only on `from: Same` listeners (#209).** The dedicated proxy now spawns per-namespace reflectors driven by the controller-rendered `--proxy-watch-namespaces` arg list, which mirrors the per-namespace `RoleBinding`s the controller has provisioned for the proxy ServiceAccount. `from: All` and `from: Selector` route attachment, plus the CRD-level opt-in flags `spec.proxy.allowClusterWideRouteRead` / `allowClusterWideNamespaceRead` and the `Accepted=false` listener-refusal status, are punted to a follow-up issue tracked in the v0.2 milestone.
- **`ControllerReconciler` is a type alias for `SharedProxyReconciler`.** The narrower controller-only output set (skipping routing-table builds, skipping TLS store) is deferred to a follow-up; the controller pod runs the full shared-proxy reconciler today. The type-level distinction exists so the future split is a purely internal refactor.

### Observe dedicated-mode provisioning

`serve controller` (and `serve dev`) runs a provisioning operator that watches every `Gateway` and provisions a dedicated-proxy `Deployment` / `Service` / `ServiceAccount` for any Gateway whose `parametersRef` (or whose `GatewayClass`'s `parametersRef`) points at a `CoxswainGatewayParameters` object. As of #208 the operator applies these resources to the cluster via server-side-apply under field manager `"coxswain-controller"`, owner-referenced to the parent Gateway so deletion cascades.

Apply the dev fixture set and verify the resources land:

```bash
kubectl apply -f deploy/dev/dedicated-gateway/
# Three resources land in tenant-a, named <gateway-name>-coxswain:
kubectl get deploy,svc,sa -n tenant-a \
  -l gateway.networking.k8s.io/gateway-name=tenant-a-gw
```

Field-manager assertion (Step 9 acceptance criterion):

```bash
kubectl get deployment tenant-a-gw-coxswain -n tenant-a -o json | \
  jq '.metadata.managedFields[].manager'
# "coxswain-controller"
```

Garbage collection on Gateway deletion (owner-ref cascade):

```bash
kubectl delete gateway tenant-a-gw -n tenant-a
# All three resources disappear within ~30s.
```

If `parametersRef` targets a missing `CoxswainGatewayParameters` object, the operator publishes an `Accepted=False, reason=InvalidParameters` condition on the Gateway via the shared override channel; the status writer picks it up on the next Gateway reconcile.

As of #209 the controller also reconciles a `RoleBinding` in every namespace the Gateway's HTTPRoutes route a backend into (gated by `ReferenceGrant` for cross-namespace refs). Each binding ties the provisioned `ServiceAccount` to the static `coxswain-gateway-proxy-reader` `ClusterRole` (shipped by the Helm chart and `deploy/manifests/dedicated-proxy-clusterrole.yaml`). The dedicated proxy pod uses the controller-rendered `--proxy-watch-namespaces` arg to spawn per-namespace reflectors that match the binding set — so a multi-tenant install gets least-privilege RBAC by construction. The Gateway carries a `gateway.coxswain-labs.dev/dedicated-cleanup` finalizer so cross-namespace bindings are removed before K8s finalizes the Gateway deletion.

#### Known limitations (deferred)

- **Opt-in RBAC flags are not on the CRD yet (#229).** The two flags exist as CLI args for manual `serve proxy --dedicated` (Step 7) but `spec.proxy.allowClusterWideRouteRead` / `spec.proxy.allowClusterWideNamespaceRead` are not yet on `CoxswainGatewayParameters`. They land in #229 alongside the cluster-wide-mode ClusterRoles and the `Accepted=false` listener-refusal status promotion.
- **Shared pool still serves dedicated-mode Gateways.** Step 11 (#210) excludes dedicated Gateways from the shared-proxy's routing table; until then, traffic served by the shared pool *and* the dedicated pod overlap.

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

Gateway listeners declare their own ports independently of the Ingress entry
points. The `deploy/dev/httproute.yaml` fixture binds the Gateway listener to
port `8000` (see that file's header for why); test against that port.

```bash
# echo.local — path-based routing, single backend per rule
curl -H "Host: echo.local" http://localhost:8000/a          # hello from echo-a
curl -H "Host: echo.local" http://localhost:8000/b          # hello from echo-b
curl -H "Host: echo.local" http://localhost:8000/           # hello from echo-a (catchall)

# split.local — both echo-a and echo-b are pooled into one upstream;
# coxswain round-robins across all ready pod addresses from both services
curl -H "Host: split.local" http://localhost:8000/          # hello from echo-a
curl -H "Host: split.local" http://localhost:8000/          # hello from echo-b

# *.wildcard.local — any subdomain matches
curl -H "Host: foo.wildcard.local" http://localhost:8000/   # hello from echo-c
curl -H "Host: bar.wildcard.local" http://localhost:8000/   # hello from echo-c
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
# Route resolves when the grant is present (Gateway listener on port 8000)
curl -H "Host: cross-ns.local" http://localhost:8000/   # hello from echo-d
```

Delete the grant to confirm enforcement:

```bash
kubectl delete referencegrant allow-httproute-from-default -n echo-tenant
curl -H "Host: cross-ns.local" http://localhost:8000/   # 503 Service Unavailable

# Restore
kubectl apply -f deploy/dev/cross-namespace.yaml
```

### Observe the routing table

```bash
curl -s http://localhost:8082/routes | jq .    # lists all active hostnames
```

---

## E2E tests

All four suites require a live cluster. Reset your cluster (delete and recreate it) before each run — the harness bootstraps everything from scratch.

The harness wraps the locally compiled binary in a minimal `Dockerfile.e2e` image (~5 s build), loads it into the cluster, installs the Helm chart, and runs tests against the deployed pods. First-time setup is fast because there is no BoringSSL compilation — the full `Dockerfile` is only used for production releases.

### ingress / gateway_api / dedicated_proxy / proxy_hot_reconfig / observability

```bash
cargo build --release --bin coxswain   # compile once; re-run only when source changes
cargo test -p coxswain-e2e --test ingress           -- --test-threads=1
cargo test -p coxswain-e2e --test gateway_api        -- --test-threads=1
cargo test -p coxswain-e2e --test dedicated_proxy    -- --test-threads=1
cargo test -p coxswain-e2e --test proxy_hot_reconfig -- --test-threads=1
cargo test -p coxswain-e2e --test observability      -- --test-threads=1
```

The `observability` suite covers readiness/status (formerly `health.rs`), the Prometheus surface from #20, and the access-log contract from #21.

The bootstrap detects a missing `target/debug/coxswain` and fails fast with a clear message if you forget the build step.

`proxy_hot_reconfig` covers:
- Zero-drop Gateway listener add/remove (#231): 2 000 requests through a live listener while a port is added or removed mid-flight; asserts zero non-2xx and zero connection errors.
- Dedicated-mode crash-loop (#210): a Gateway promoted into dedicated mode with an unreachable image keeps being served by the shared pool indefinitely.

### conformance

The Gateway API conformance suite runs against coxswain deployed via Helm. The harness installs the chart, discovers the LoadBalancer IP, and passes it as `--status-address` so `Gateway.status.addresses` is populated correctly.

```bash
# Build the image first (same image the harness would build automatically).
docker build -t coxswain:e2e .

# Install coxswain; discover the LB IP; run the suite.
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

- **Verbose output**: prepend `RUST_LOG=coxswain_e2e=debug,warn` and pass `--nocapture`.
- **Manual cleanup** after an interrupted run: `kubectl delete ns -l coxswain-e2e=true && helm uninstall coxswain -n coxswain-system`.
- The bootstrap is idempotent: if the Helm release is already installed and the image is unchanged, `bootstrap()` returns in < 1 s.
- `cargo test` alone does **not** run e2e — the crate is excluded from `default-members` to keep the unit-test loop fast.
- Set `COXSWAIN_E2E_SKIP_BUILD=1` to skip the `docker build` step when you know the `coxswain:e2e` image is already up to date in the local Docker daemon.
- CI builds and caches the Docker image in the `build` job, then each matrix job downloads the image tar, loads it, and runs with `COXSWAIN_E2E_SKIP_BUILD=1`.

---

## Documentation site

The docs site is self-contained under `docs/`: pages live in `docs/src/`, the mkdocs config is `docs/mkdocs.yml`, Python deps are `docs/requirements.txt`, and the page hooks (currently just the `PACKAGE_VERSION` substitution) live under `docs/hooks/`. It is built with [mkdocs-material](https://squidfunk.github.io/mkdocs-material/) and versioned with [mike](https://github.com/jimporter/mike).

### Preview locally

```bash
cd docs
uv venv .venv
uv pip install -r requirements.txt
source .venv/bin/activate
mkdocs serve          # live-reload at http://localhost:8000
mike serve            # serves the versioned site (requires a prior mike deploy)
```

`.venv/` is gitignored. The `--system` flag used in CI does not work on Homebrew-managed Python.

The `PACKAGE_VERSION` env var drives a page hook that rewrites the `X.Y.Z`
placeholders found in install and verification pages. Substitution only fires
when `PACKAGE_VERSION` parses as a SemVer (e.g. `0.1.2`); on the `main` default
(or any non-SemVer value) the placeholders are left literal, because several of
the substituted commands (`helm --version`, GitHub release-asset URLs, signed
chart tags) only have valid values for tagged releases. Set a SemVer to preview
what a tagged release will render:

```bash
PACKAGE_VERSION=0.1.2 mkdocs serve
```

### How versioning works

- **Push to `main`** → publishes under the `dev` alias (always the latest unreleased docs).
- **Push a tag `vX.Y.Z`** → publishes under the `X.Y` key and updates the `stable` alias.
- Patches overwrite their minor version key (`0.1.1` → `0.1`, same as `0.1.0`).
- The site root redirects to `stable`.

Publishing happens automatically as the `publish-docs` job at the tail of `.github/workflows/release.yml`. It runs after `publish-image`, `trivy-scan`, `publish-chart`, and `publish-kustomize`, so a failed release step skips the docs promotion and leaves the site unchanged. The job pushes into the `coxswain/` subdirectory of the `coxswain-labs/coxswain-labs.github.io` org-level Pages repo using a cross-repo PAT. PR-time validation (`mkdocs build --strict`) lives alongside the Docker and Helm checks in `.github/workflows/distribution.yml` as the `docs-build` job.

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

The `publish-docs` job in `.github/workflows/release.yml` needs write access to the org-level Pages repo to push the built site.

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
