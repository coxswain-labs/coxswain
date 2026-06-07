# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

**Always read the following files at the start of every session:**
- `DEVELOPMENT.md` — cluster setup, ports, deploy manifests, e2e and conformance test procedures, release process.
- Any file in `docs/` that is relevant to the task at hand.

The live roadmap is the [GitHub Project](https://github.com/orgs/coxswain-labs/projects/2). Use `gh project view 2 --owner coxswain-labs` and `gh issue list --milestone v0.1 --state all` to see what's in scope and what's done.

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
- **`coxswain-health`** — `/healthz` (always 200) and `/readyz` (gated on `HealthRegistry::is_ready`: every registered subsystem must be `Ready` or `Degraded`).
- **`coxswain-admin`** — `/metrics` (Prometheus), `/routes`, `/status` (full per-subsystem check detail).
- **`coxswain-bin`** — entry point: CLI parsing, shared-state wiring, Pingora runtime bootstrap.
- **`coxswain-e2e`** — black-box integration tests against a live cluster (kind/Orb); not a runtime dependency.

## Code Quality

These rules were established through the v0.1 refactor pass (issues #136–#147). They are deliberate decisions — do not silently undo them.

### Lints

`[workspace.lints]` in `Cargo.toml` is the single source of truth for lint configuration. **Never add `#[allow(...)]` or `#[expect(...)]` to silence a lint** — both are per-site escape hatches that this rule prohibits, regardless of attribute spelling. Fix the root cause instead.

- If a lint fires on *our* code: rename, refactor, or restructure to satisfy it.
- If a lint fires on an *upstream-imposed* name (e.g. `HTTPRoute` from codegen tripping `upper_case_acronyms`): re-export with a project-canonical alias at the crate boundary (`gw_types.rs`) and use that alias everywhere internally. This is a one-time fix; a per-site annotation locks in an inconsistency forever.
- Workspace-wide opt-outs in `[workspace.lints]` are acceptable only when an entire lint *group* is too broad for the project. The current example is `clippy::pedantic = "allow"`. Per-site annotations are never acceptable.

The current workspace shape (do not drift without a deliberate decision):

```toml
[workspace.lints.rust]
unsafe_code  = "deny"
missing_docs = "warn"

[workspace.lints.clippy]
correctness     = { level = "deny",  priority = -1 }
suspicious      = { level = "warn",  priority = -1 }
style           = { level = "warn",  priority = -1 }
complexity      = { level = "warn",  priority = -1 }
perf            = { level = "warn",  priority = -1 }
pedantic        = { level = "allow", priority = -1 }
type_complexity = "deny"
unwrap_used     = "warn"
expect_used     = "warn"
```

The one legitimate use of `#![allow(missing_docs)]` is at the top of bench files and `coxswain-e2e/tests/*`, where `criterion_group!` and similar macros expand to `pub fn` items that are not user-controllable.

`clippy.toml` sets `allow-unwrap-in-tests = true` / `allow-expect-in-tests = true`. These apply **only** to code inside `#[test]` functions and `#[cfg(test)]` modules — not to non-test code that tests happen to call (e.g. `coxswain-e2e/src/`). Harness and fixture code is non-test code that runs under test, not test code itself.

### Panics and unwrap

Never use `.unwrap()` or `.expect("message")` in non-test code.

- **Recoverable errors** → propagate with `?` or return a typed `Err`.
- **Invariants** (violated only by a bug in this module) → `unwrap_or_else(|e| panic!("invariant: {e}"))`. Prefer this form over `.expect("msg")` because it interpolates the actual error alongside the invariant claim, making any violation self-diagnosing. The message must state *what must be true*, not *what the code is doing*.

The same rule applies to `unreachable!()` and `todo!()` — they are panics; include a message stating the invariant that makes the branch impossible. `debug_assert!` is permitted for invariants too expensive to check in release builds.

Code in `crates/*/benches/` and `crates/coxswain-e2e/` may use plain context-style messages (`"{addr}: {e}"`) because fixture and setup failures don't have the "violated only by a bug" framing.

### Function signatures

Functions with more than 7 parameters trigger `clippy::too_many_arguments`. Do not suppress and do not raise the threshold in `clippy.toml` — refactor into a parameter-grouping struct instead. Name the struct after its semantic role (`ReflectorStores<'a>`, `SharedOutputs<'a>`), not after the function it serves. The struct lives in the same module as the function and takes the narrowest visibility that compiles (typically `pub(crate)` or `pub(super)`).

### Documentation

Every `.rs` file must open with a `//!` module header (a short paragraph: what the module owns, not what every function in it does). Every `pub` item that introduces a new name must carry a `///` doc comment; trivial re-exports (`pub use foo::Bar;`) are exempt.

- Fallible `pub` functions that return `Result` must include a `# Errors` section listing the variants.
- `pub` functions that can panic under documented conditions must include `# Panics`.
- `unsafe` functions must include `# Safety` (currently a non-issue because `unsafe_code = "deny"`, but apply this if that ever changes).

Doc comments explain **why** and **what the invariants are** — the names already say *what*. One precise sentence beats a paragraph of padding.

> **Backfill note:** Only ~6 fallible `pub` functions currently carry `# Errors` sections. New code is held to the rule immediately; existing under-coverage is a known gap to backfill incrementally.

### Visibility

Default to `pub(crate)` for items reachable within the workspace, `pub(super)` for items that only need to cross a module boundary. Use bare `pub` only for items re-exported at the crate root (`lib.rs`) that are consumed by another crate in the workspace. See `rust-skills` rules `proj-pub-crate-internal` and `proj-pub-super-parent`.

### Hot path

The proxy request path (`Proxy::request_filter`, `upstream_peer`, `filter::FilterSet::apply_request_filters`, `filter::FilterSet::apply_response_filters`) is performance-critical:

- At `request_filter` entry, capture immutable request data (host, path, query) once as `Arc<str>` / `Option<String>` — at most 3 allocations per request. Later Pingora hooks clone these arcs cheaply without re-borrowing `session.req_header()`.
- Beyond that fixed capture set, the routing lookup and upstream-selection paths must not allocate. (Exception: TLS connections allocate one `String` for the SNI hostname in `upstream_peer` — documented and deliberate.)
- Use `Shared<T>` (the `ArcSwap`-backed wrapper in `coxswain-core`) for lock-free routing/TLS snapshot reads.
- Never hold a `Mutex` or `RwLock` guard across an `.await` point.

### Error types

Every crate-defined error type uses `#[derive(thiserror::Error)]` with a `#[error("...")]` message on each variant. Error enums are `#[non_exhaustive]`. Library crates (`coxswain-core`, `coxswain-controller`, `coxswain-proxy`, `coxswain-health`, `coxswain-admin`) never use `anyhow` — only `coxswain-bin` may use it at the binary boundary.

### API stability annotations

Every public struct and enum is `#[non_exhaustive]` unless it is intentionally open for downstream construction. Every `pub fn` that returns a value the caller is expected to consume carries `#[must_use]`. This sweep was issue #140 — do not omit these attributes on new public items.

### Test layout

Per-source-file unit tests live in a `#[cfg(test)] mod tests;` submodule in the same file (small bodies) or in a sibling `<module>_tests.rs` file (large bodies). Cross-cutting tests for a crate live under `crates/<crate>/src/tests/`. Integration tests against the binary live in `crates/coxswain-e2e/tests/`. Established by issues #143 and #144 — do not collapse back into one test block per file.

### Per-crate Cargo manifest

Every `crates/*/Cargo.toml` must declare `[lints] workspace = true`. Without it, a new crate silently escapes every workspace lint, defeating the single-source-of-truth rule above.

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
   - Closing the issue (via `Fixes #N` in the commit footer, or `gh issue close N` later) automatically flips its `Status` to `Done` in the GitHub Project — no manual roadmap edit.
8. At the end of each implementation or refinement cycle:
   - Run `cargo fmt` then `cargo test --workspace --exclude coxswain-e2e` and report results.
   - **Use `AskUserQuestion` with two simultaneous questions** to ask what to do next. Never commit, push, or close without the user explicitly selecting it here. The `AskUserQuestion` tool allows a maximum of 4 options per question, so split across two questions sent in one call:
     - Q1 (header "Next step"): **Refine implementation** / **Run e2e tests** / **Commit and push** / **Merge PR and close issue**
     - Q2 (header "E2E suite", only relevant when Q1 = "Run e2e tests"): **ingress** / **gateway_api** / **conformance** / **N/A**
   - Act on the combination: if Q1 = "Run e2e tests", use Q2 to pick the suite. If Q1 = "Merge PR and close issue", follow the closing procedure below. If Q1 = "Refine" or "Commit and push", ignore Q2.
   - Keep presenting these questions after each action until the user selects **Merge PR and close issue** and the PR is merged.

### Closing an issue

1. Run `gh issue close N --repo coxswain-labs/coxswain` (the merge auto-closes if the commit footer is `Fixes #N`; this step is for paranoia).
2. Merge with `gh pr merge --squash --delete-branch`.
3. Ask the user to confirm before pulling — then run `git checkout main && git pull --ff-only origin main` (requires user presence).

### Commit message convention

Title format: `type(scope): description` — e.g. `feat(controller): add HTTPRoute timeout support`.

Common types: `feat`, `fix`, `refactor`, `perf`, `chore`, `docs`, `ci`, `test`. Scope is the affected crate(s) without the `coxswain-` prefix (e.g. `controller`, `proxy,core`).

Every commit on an issue branch must reference the issue in the footer:
- `Refs #N` — partial work.
- `Fixes #N` — final commit (GitHub closes the issue automatically on push).

## Issue and project management

The single source of truth for scope and status is the [Coxswain Roadmap Project](https://github.com/orgs/coxswain-labs/projects/2). New issues are auto-added at `Status: Todo`. Triage populates the Project's `Track` (single-select; cross-cutting workstream) and, for milestoned items, `Order` (numeric; intended execution sequence within the milestone).

### Milestones

Plain version numbers only (`v0.1`, `v0.2`; create new milestones on demand as scope is committed). Use the GitHub-native milestone field (`gh issue edit N --milestone vX.Y`) — there is no longer a mirror `milestone:` label. Never use special characters like em dashes, colons, or `&` in milestone titles — they break GitHub's issue filter URL parser. Issues not yet committed to a release carry no milestone assignment and the `status: backlog` label instead.

### Labels

Every issue gets one label from each relevant group. At minimum: one `type:` and at least one `area:` or `api:`. Use `status: backlog` for issues that are triaged but deliberately uncommitted to a milestone.

**Status** — applies only when the issue is not committed to any milestone:
- `status: backlog` — parked; promotion to a v0.N milestone happens when scope solidifies

**Priority** — how urgent within its milestone (or, for backlog items, relative ordering when triage promotes to a milestone):
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
