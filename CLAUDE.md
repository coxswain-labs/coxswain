# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## GitHub Issue Workflow

When the user says "start working on issue N":
1. Enter plan mode
2. Run `gh issue view N --repo coxswain-labs/coxswain` to read the full issue description and grill the user, if necessary.
3. Read all relevant source files and plan the implementation. Branch creation is deferred to step 3 — do NOT create the branch while in plan mode, as tool access may be restricted.
4. Once plan mode exits and implementation begins: ensure you're working on the latest code and create the branch: `git checkout main && git pull --ff-only origin main && git checkout -b issue-N`.
5. Implement the issue per its acceptance criteria.
6. Add or update e2e tests in `crates/coxswain-e2e/` that cover the new behaviour. Every issue that changes routing, status conditions, or proxy behaviour must have at least one new scenario in `tests/gateway_api.rs` or `tests/ingress.rs`. 
7. ALWAYS run `cargo test --workspace --exclude coxswain-e2e` (unit tests) before pushing. E2e tests (`cargo test -p coxswain-e2e --test <file> -- --test-threads=1`) require a live cluster and are run by CI — do not attempt them locally unless a cluster is available.
8. If the issue implements a Gateway API conformance feature (check the issue body for a **Feature flags** line), add the corresponding `features.SupportXxx` constant(s) to `opts.SupportedFeatures` in `conformance/main_test.go`. Include a comment referencing the issue number. Run `go vet ./...` in `conformance/` to confirm the constant names are valid. Also add the bare feature name(s) to `SUPPORTED_FEATURES` in `crates/coxswain-controller/src/controller/gateway_class_status.rs` (keep sorted). Run `bash scripts/check-supported-features.sh` to confirm both lists match. See `docs/gateway-api-support.md` for the full feature promotion policy and instructions for bumping the Gateway API version.
9. In `ROADMAP.md`, change the corresponding checklist item from `- ⬜` to `- ✅ ~~...~~` (swap the emoji and wrap the description in strikethrough). Only commit this change on the new branch with `Refs #N` at the end, when the issue is fully implemented.

When the user says "close the issue" or "an issue is done":
1. Run `gh issue close N --repo coxswain-labs/coxswain`.
2. Ensure the `ROADMAP.md` item is `- ✅ ~~...~~` (emoji + strikethrough). This should already be done from step 4 above; if not, do it now and commit with `Fixes #N`.
3. Merge the PR with `gh pr merge --squash --delete-branch`.
4. Return to `main` and pull the merged changes: `git checkout main && git pull --ff-only origin main`.

When working on a GitHub issue, always include a reference in every commit message:
- Use `Refs #N` for partial work on an issue.
- Use `Fixes #N` for the final commit that completes it (GitHub closes the issue automatically on push).

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

# Run all unit tests (excludes coxswain-e2e which requires a live cluster)
cargo test --workspace --exclude coxswain-e2e

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
cargo run --bin coxswain -- serve --log-format console

# Start coxswain for conformance testing (ports 80/443, status-address = localhost)
# Must be running before the go test command below.
cargo run --bin coxswain -- serve \
  --proxy-http-port 80 \
  --proxy-https-port 443 \
  --health-port 8081 \
  --admin-port 8082 \
  --status-address 127.0.0.1 \
  --log-format console \
  --pod-name coxswain-conformance \
  --pod-namespace coxswain-system

# Verify conformance test file compiles (no live cluster needed)
cd conformance && go vet ./...

# Run the Gateway API conformance suite (requires a live cluster with coxswain running)
# Must reset the local k8s cluster before running this command.
cd conformance && go test -v -timeout 60m -run TestConformance \
  -args \
  --organization=coxswain-labs \
  --project=coxswain \
  --url=https://github.com/coxswain-labs/coxswain \
  --version=$(git describe --tags --always) \
  --report-output=reports/local-report.yaml

# Reset the local k8s cluster (Orb) before running the conformance or e2e test above.
# After this ensure to prepare the cluster as explained in as explained in DEVELOPMENT.md 
orb delete -f k8s && orb start k8s
```

## Architecture

The workspace has seven crates under `crates/` with a strict dependency order:

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

Per-crate responsibilities (see each crate's `src/lib.rs` for the up-to-date module layout):

- **`coxswain-core`** — shared routing-table types, atomic `Shared<T>` snapshot primitive, TLS store, ownership and reference-grant helpers.
- **`coxswain-controller`** — Kubernetes reflectors and a debounced reconciler that rebuilds the routing and TLS tables; separate status writer with `kube-leader-election`-based leader election.
- **`coxswain-proxy`** — Pingora-based reverse proxy: lock-free routing lookup, request/response filter application, in-process SNI TLS termination, optional HAProxy PROXY-protocol acceptor.
- **`coxswain-health`** — `/healthz` (always 200) and `/readyz` (gated on `synced`).
- **`coxswain-admin`** — `/metrics` (Prometheus), `/routes`, `/status`.
- **`coxswain-bin`** — entry point: CLI parsing, shared-state wiring, Pingora runtime bootstrap.
- **`coxswain-e2e`** — black-box integration tests against a live cluster (kind/Orb); not a runtime dependency.

## Ports (default)

| Port   | Service  | Endpoints                          |
|--------|----------|------------------------------------|
| `80`   | proxy    | HTTP data plane                    |
| `443`  | proxy    | HTTPS data plane (SNI TLS)         |
| `8081` | health   | `/healthz`, `/readyz`              |
| `8082` | admin    | `/metrics`, `/routes`, `/status`   |

## Deploy manifests

`deploy/` is split into three subdirectories:

**`deploy/manifests/`** — production Kubernetes manifests applied to a real cluster:
- `namespace.yaml` — `coxswain-system` namespace
- `rbac.yaml` — `ClusterRole` for watching/patching Gateway API and Ingress resources, plus a namespaced `Role` in `coxswain-system` for `coordination.k8s.io/leases` (leader election)
- `gateway-class.yaml` — `GatewayClass` with `controllerName: coxswain-labs.dev/gateway-controller`
- `deployment.yaml` — in-cluster `Deployment` with Downward API env vars (`POD_NAME`, `POD_NAMESPACE`)

**`deploy/dev/`** — local dev fixtures used during development and manual testing (echo backends, sample HTTPRoute and Ingress objects, cross-namespace scenarios). Not applied to production.

**`deploy/examples/`** — user-facing example configurations shipped as documentation (e.g. cert-manager TLS setup for both Gateway API and Ingress).

## Docs

`docs/` contains user-facing markdown guides (e.g. `tls-cert-manager.md`). Add a doc here whenever a feature requires non-obvious user configuration.

## Conformance

`conformance/` is a Go module that runs the Gateway API conformance test suite against a live cluster:
- `main_test.go` — test entrypoint; `opts.SupportedFeatures` lists the feature flags this release claims to pass
- `reports/` — YAML conformance reports generated by `--report-output`; `local-report.yaml` is the latest local run (gitignored from CI artifacts)
