# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

**Coxswain** is a pure-Rust Kubernetes Ingress & Gateway API controller backed by [Pingora](https://github.com/cloudflare/pingora) as the proxy engine. It watches Kubernetes `Ingress` and `Gateway API` resources and dynamically routes traffic without a full reload. Multiple replicas can run simultaneously using Kubernetes Lease-based leader election: all replicas maintain a hot data-plane routing table, but only the active leader writes status back to the API server.

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

## Commands

```bash
# Build
cargo build
cargo build --release

# Unit tests (no cluster needed)
cargo test --workspace --exclude coxswain-e2e
cargo test -p coxswain-core               # single crate
cargo test -p coxswain-core test_name     # single test

# Check / lint / format
cargo check
cargo clippy -- -D warnings
cargo fmt

# Run (local dev)
cargo run --bin coxswain -- serve --log-format console
```

For cluster-bound tests (e2e, conformance) see `DEVELOPMENT.md`.

## GitHub Issue Workflow

When the user says "start working on issue N":
1. Enter plan mode
2. Run `gh issue view N --repo coxswain-labs/coxswain` to read the full issue description and grill the user, if necessary.
3. Read all relevant source files and plan the implementation. Branch creation is deferred to step 3 — do NOT create the branch while in plan mode, as tool access may be restricted.
4. Once plan mode exits and implementation begins: ensure you're working on the latest code and create the branch: `git checkout main && git pull --ff-only origin main && git checkout -b issue-N`.
5. Implement the issue per its acceptance criteria.
6. Add or update e2e tests in `crates/coxswain-e2e/` that cover the new behaviour. Every issue that changes routing, status conditions, or proxy behaviour must have at least one new scenario in `tests/gateway_api.rs` or `tests/ingress.rs`.
7. ALWAYS run `cargo test --workspace --exclude coxswain-e2e` (unit tests) before pushing. E2e tests require a live cluster and must run sequentially — see `DEVELOPMENT.md`. Do not attempt locally unless a cluster is available; CI runs them.
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

## See also

- **`DEVELOPMENT.md`** — local cluster setup, default ports, deploy manifests, e2e tests, conformance tests, release procedure.
- **`docs/`** — user-facing guides (e.g. cert-manager TLS configuration, Gateway API feature support policy).
- **`ROADMAP.md`** — issue/milestone status; tick boxes here when closing an issue.
