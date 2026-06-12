# CLAUDE.md

Source-of-truth guidance for Claude Code in this repository.

**Always read at the start of every session:**
- `DEVELOPMENT.md` — local setup, e2e + conformance procedures, troubleshooting.
- Any `docs/src/` file relevant to the task at hand.

Roadmap: [Coxswain Roadmap Project](https://github.com/orgs/coxswain-labs/projects/2). `gh project view 2 --owner coxswain-labs` and `gh issue list --milestone v0.X --state all` enumerate scope.

## Project Overview

**Coxswain** is a pure-Rust Kubernetes Ingress & Gateway API controller backed by [Pingora](https://github.com/cloudflare/pingora). It watches `Ingress` and `Gateway API` resources and dynamically routes traffic without a full reload.

Coxswain ships as two cooperating pod roles:
- `serve controller` — leader-elected status writer; cluster-wide reads + `*/status` writes.
- `serve proxy --shared` — read-only data plane; the ServiceAccount holds zero write verbs.

The hidden `serve dev` runs both pipelines in one process for local development. Production deployments always pick a role explicitly; bare `coxswain serve` errors with clap help. The Dockerfile has no `CMD`.

## Architecture

Eight crates with a strict dependency order:

```
coxswain-bin
  ├── coxswain-controller
  │     ├── coxswain-core
  │     └── coxswain-reflector
  ├── coxswain-proxy
  │     ├── coxswain-core
  │     └── coxswain-reflector
  ├── coxswain-reflector
  │     └── coxswain-core
  ├── coxswain-health
  ├── coxswain-admin
  │     └── coxswain-core
  └── (coxswain-e2e — black-box tests, not a runtime dep)
```

`coxswain-proxy` and `coxswain-controller` never depend on each other. The read-only-proxy invariant is enforced at RBAC (proxy SA holds zero write verbs) AND at the crate graph (the proxy never imports the controller). Per-crate responsibilities live in each crate's `src/lib.rs` `//!` header.

## Code Quality

**Rule additions go to CI first.** If a new project rule can be expressed as a clippy lint, a `scripts/check-*.sh` grep, or a `deny.toml` policy, encode it there and link from this doc. Don't restate CI-enforced rules in prose. Add prose here only when the rule is a behavioural policy that can't be checked mechanically.

### Enforced rules

| Rule | Enforced by |
|---|---|
| No `.unwrap()` / `.expect()` in non-test code | `unwrap_used = "deny"`, `expect_used = "deny"` (clippy) |
| Every public type carries `#[non_exhaustive]` or a `// intentionally open:` rationale | `scripts/check-public-types-stability.sh` |
| `//!` header on every non-test, non-bench `.rs` | `scripts/check-module-headers.sh` |
| Library crates never use `anyhow` | `scripts/check-no-anyhow-libs.sh` |
| `[lints] workspace = true` in every `crates/*/Cargo.toml` | `scripts/check-workspace-lints-decl.sh` |
| No per-site `#[allow]` / `#[expect]` in non-test source | `scripts/check-no-per-site-allow.sh` |
| Gateway API SupportedFeatures Rust↔Go parity | `scripts/check-supported-features.sh` |

`[workspace.lints]` in `Cargo.toml` is the source of truth for lint configuration. Workspace-wide opt-outs in `[workspace.lints]` are acceptable when an entire lint *group* is too broad for the project (current: `clippy::pedantic = "allow"`). For upstream-imposed names that trip a lint (e.g. `HTTPRoute` from codegen tripping `upper_case_acronyms`): re-export with a project-canonical alias at the crate boundary (`gw_types.rs`) and use the alias everywhere internally — a one-time fix; per-site annotations lock the inconsistency in forever.

### Policies the CI gates don't cover

- **Panics.** Invariant violations (only reachable via a bug in this module) use `unwrap_or_else(|e| panic!("invariant: {e}"))` — the message states *what must be true*, not what the code is doing. Recoverable errors use `?` or return a typed `Err`. Same rule applies to `unreachable!()`, `todo!()`, and `assert!`-family macros. `debug_assert!` is fine for invariants too expensive in release builds. Bench files and `crates/coxswain-e2e/` may use plain context-style messages (`"{addr}: {e}"`) — setup failures don't fit the "violated only by a bug" framing.

- **>7-arg functions.** Refactor into a parameter-grouping struct named after the semantic role (`ReflectorStores<'a>`, `DedicatedRebuildTarget<'a>`), with the narrowest visibility that compiles. Never bump `clippy.toml`'s threshold.

- **Documentation.** Every `///` on a `pub` item explains *why* and what the invariants are — names already say *what*. Fallible `pub fn`s returning `Result` carry a `# Errors` section; documented-panic `pub fn`s carry `# Panics`; `unsafe` carries `# Safety`. Current `# Errors` / `# Panics` coverage has known gaps tracked in v0.2.

- **Visibility.** Default to `pub(crate)` for items reachable within the workspace; `pub(super)` for items only crossing one module boundary; bare `pub` only for items re-exported at the crate root for cross-crate consumption.

- **Error types.** Every crate-defined error type uses `#[derive(thiserror::Error)]` with `#[error("…")]` on each variant, and `#[non_exhaustive]`. Library crates emit typed errors via `thiserror`; only `coxswain-bin` may use `anyhow` at the binary boundary.

- **Test layout.** Per-source-file unit tests live INLINE as `#[cfg(test)] mod tests { use super::*; ... }` at the bottom of the source file (rust-skills `test-cfg-test-module`). Cross-cutting tests (those that span multiple source files + shared helpers) live under `crates/<crate>/src/[<submodule>/]tests/`. Inline test blocks reach shared helpers via `use crate::<path>::tests::*;`; helpers are declared `pub(super)` so wildcard imports work. Integration tests against the binary live in `crates/coxswain-e2e/tests/`.

### Hot path

Proxy request path (`Proxy::request_filter`, `upstream_peer`, `filter::FilterSet::apply_request_filters`, `filter::FilterSet::apply_response_filters`) is performance-critical:

- Capture immutable request data at `request_filter` entry: `host` and `path` as `Arc<str>`, `query` as `Option<String>` — 3 allocations per request, max.
- Routing lookup, upstream selection, metric emission, and access-log path allocate nothing beyond the capture set. Render `u16` labels (port, status) via `itoa::Buffer` — never `.to_string()`.
- TLS connections allocate one SNI hostname `String` per outbound connection (Pingora's `HttpPeer` requires owned). Per connection, not per request; cleartext upstreams skip it.
- Access-log `SocketAddr::to_string()` allocates exactly once per request, only when `--access-log=on`. Operators silencing the log skip it.
- Use `Shared<T>` (the `ArcSwap`-backed wrapper in `coxswain-core`) for lock-free routing/TLS snapshot reads.
- Never hold a `Mutex` or `RwLock` guard across `.await`.

## GitHub issue workflow

1. Invoke `/rust-skills` to load Rust coding guidelines.
2. `git checkout main && git pull --ff-only origin main`. Stop if it fails.
3. Enter plan mode. Read `gh issue view N`, cross-check code references, grill the user on anything unclear, design the implementation.
4. After plan approval: `git checkout -b issue-N`, implement per acceptance criteria. For Gateway API features with a **Feature flags** line in the issue body: add the `features.SupportXxx` constant(s) to `opts.SupportedFeatures` in `conformance/main_test.go` AND the bare feature name(s) to `SUPPORTED_FEATURES` in `crates/coxswain-controller/src/controller/gateway_class_status.rs` (sorted). The `check-supported-features.sh` gate enforces parity. For routing, status-condition, or proxy-behaviour changes: add/update scenarios in `crates/coxswain-e2e/tests/{ingress,gateway_api,dedicated_proxy,observability}.rs`.
5. After each work cycle: `cargo fmt && cargo test --workspace --exclude coxswain-e2e`. Then ask the user what's next via `AskUserQuestion` (two questions in one call):
   - **Q1 (header "Next step")**: Refine implementation / Run e2e tests / Commit and push / Merge PR and close issue.
   - **Q2 (header "E2E suite")**: ingress / gateway_api / conformance / N/A. Consulted only when Q1 = "Run e2e tests".

Always include the issue reference in commit footers: `Refs #N` (intermediate work) or `Fixes #N` (final commit). Closing via `Fixes #N` auto-flips the Project's `Status` to `Done`; never manually close + flip.

When a PR is approved for merge: `gh pr merge --squash --delete-branch`. Then ask the user before `git checkout main && git pull --ff-only origin main`.

### Commit message convention

Title format: `type(scope): description`. Common types: `feat`, `fix`, `refactor`, `perf`, `chore`, `docs`, `ci`, `test`. Scope is the affected crate(s) without the `coxswain-` prefix (e.g. `controller`, `proxy,core`).

## Issue / project management

Source of truth for scope and status: the [Coxswain Roadmap Project](https://github.com/orgs/coxswain-labs/projects/2). New issues land at `Status: Todo`. Triage populates Track (single-select; cross-cutting workstream) and, for milestoned items, Order (numeric; intended execution sequence within the milestone).

Milestones are plain version numbers (`v0.1`, `v0.2`, …); use `gh issue edit N --milestone vX.Y`. Never use special characters (em dashes, colons, `&`) — they break GitHub's filter URL parser.

Labels: discover the live taxonomy with `gh label list --repo coxswain-labs/coxswain`. Every issue carries at least one `type:` and one `area:` or `api:`. `status: backlog` only on issues with no milestone; `priority:` is per-milestone; `type:` and `area:`/`api:` are required everywhere.
