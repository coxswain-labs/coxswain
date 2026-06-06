# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

**Always read the following files at the start of every session:**
- `DEVELOPMENT.md` — cluster setup, ports, deploy manifests, e2e and conformance test procedures, release process.
- `ROADMAP.md` — current issue/milestone status; needed to tick items and understand what's in scope.
- Any file in `docs/` that is relevant to the task at hand.

## Project Overview

**Coxswain** is a pure-Rust Kubernetes Ingress & Gateway API controller backed by [Pingora](https://github.com/cloudflare/pingora) as the proxy engine. 
It watches Kubernetes `Ingress` and `Gateway API` resources and dynamically routes traffic without a full reload. 
Multiple replicas can run simultaneously using Kubernetes Lease-based leader election: all replicas maintain a hot data-plane routing table, but only the active leader writes status back to the API server.

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

## GitHub Issue Workflow

### Starting work on issue N

1. Invoke `/rust-skills` to load Rust coding guidelines into context.
2. Ensure you're on the latest code: `git checkout main && git pull --ff-only origin main`. **Stop and tell the user if this fails — do not continue.**
3. Enter plan mode.
4. Run `gh issue view N --repo coxswain-labs/coxswain`. Read the full description, cross-check any code references against the current implementation, and grill the user on anything unclear.
5. Read all relevant source files and plan the implementation.
6. Once plan mode exits, create the branch: `git checkout -b issue-N`.
7. Implement the issue per its acceptance criteria, including:
   - **E2E tests**: add or update scenarios in `crates/coxswain-e2e/tests/gateway_api.rs` and/or `tests/ingress.rs` for any change to routing, status conditions, or proxy behaviour.
   - **Conformance** (only if the issue body has a **Feature flags** line): add the corresponding `features.SupportXxx` constant(s) to `opts.SupportedFeatures` in `conformance/main_test.go` (with a comment referencing `#N`), run `go vet ./...` to validate, add the bare feature name(s) to `SUPPORTED_FEATURES` in `crates/coxswain-controller/src/controller/gateway_class_status.rs` (keep sorted), and run `bash scripts/check-supported-features.sh`. See `docs/gateway-api-support.md` for the full promotion policy.
   - **Roadmap**: once the issue is fully implemented (not before), change the corresponding `ROADMAP.md` item from `- ⬜` to `- ✅ ~~...~~`.
8. At the end of each implementation or refinement cycle:
   - Run `cargo fmt` then `cargo test --workspace --exclude coxswain-e2e` and report results.
   - **Ask the user** what to do next. Options:
     - **Refine** — continue implementation.
     - **Run e2e** `gateway_api` and/or `ingress` — requires a live cluster (~5 min each; see `DEVELOPMENT.md` for cluster reset and prep).
     - **Run conformance** — expensive: requires cluster reset, cluster prep, and coxswain running in a separate terminal (~30–60 min; see `DEVELOPMENT.md`).
     - **Commit only** — stages and commits, requires user presence.
     - **Commit and push** — commits and pushes, requires user presence.

### Closing an issue

1. Run `gh issue close N --repo coxswain-labs/coxswain`.
2. Confirm the `ROADMAP.md` item is `- ✅ ~~...~~`; if not, fix and commit with `Fixes #N`.
3. Merge with `gh pr merge --squash --delete-branch`.
4. Ask the user to confirm before pulling — then run `git checkout main && git pull --ff-only origin main` (requires user presence).

### Commit message convention

Title format: `type(scope): description` — e.g. `feat(controller): add HTTPRoute timeout support`.

Common types: `feat`, `fix`, `refactor`, `perf`, `chore`, `docs`, `ci`, `test`. Scope is the affected crate(s) without the `coxswain-` prefix (e.g. `controller`, `proxy,core`).

Every commit on an issue branch must reference the issue in the footer:
- `Refs #N` — partial work.
- `Fixes #N` — final commit (GitHub closes the issue automatically on push).

## Issue and project management

### Milestones

Plain version numbers only (`v0.1`, `post-v0.1`; create new milestones on demand as scope is committed). Never use special characters like em dashes, colons, or `&` in milestone titles — they break GitHub's issue filter URL parser.

### Labels

Every issue gets one label from each relevant group. At minimum: one `milestone:`, one `type:`, and at least one `area:` or `api:`.

**Milestone** — always apply one alongside the milestone assignment:
- `milestone: v0.1` — first usable release
- `milestone: post-v0.1` — future work, grouped by priority

**Priority** — how urgent within its milestone:
- `priority: must-have` — v1.0 blocker; do not ship without it
- `priority: should-have` — post-v1.0, high priority
- `priority: nice-to-have` — future / community-driven

**Type** — what kind of work:
- `type: feature` — new capability
- `type: bug` — something broken
- `type: conformance` — Gateway API spec compliance
- `type: chore` — tooling, CI, maintenance
- `type: spec-deviation` — known intentional deviation from a spec, documented with rationale
- `type: experimental` — touches alpha/experimental Gateway API channel

**Area** — which subsystem:
- `area: controller` — reconciler, leader election, status writes
- `area: proxy` — Pingora data plane, protocol handling
- `area: routing` — routing table, path/host matching
- `area: tls` — TLS termination, cert management, SNI
- `area: observability` — metrics, logging, tracing
- `area: security` — auth, rate limiting, policy
- `area: distribution` — Helm, OCI image, CI/CD
- `area: docs` — documentation site and guides

**API surface** — use when the issue is specific to one API:
- `api: gateway` — HTTPRoute, Gateway, GatewayClass, policies
- `api: ingress` — classic Kubernetes Ingress

**Process** — applied by CI or humans during triage:
- `process: good first issue` — good for newcomers
- `process: help wanted` — extra attention needed
