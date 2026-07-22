# CLAUDE.md

Source-of-truth guidance for Claude Code in this repository.

**Always read at the start of every session:**
- `DEVELOPMENT.md` — local setup, e2e + conformance procedures, troubleshooting.
- Any `docs/src/` file relevant to the task at hand.

Roadmap: [Coxswain Roadmap Project](https://github.com/orgs/coxswain-labs/projects/2). `gh project view 2 --owner coxswain-labs` and `gh issue list --milestone v0.X --state all` enumerate scope.

## Agent rules

- **Always be concise and to the point**
- **Do not over-explain, keep the prose short unless asked to explain**
- **Do not over-emphasize**
- **Do not be sycophantic**

## Project Overview

**Coxswain** is a pure-Rust Kubernetes Ingress & Gateway API controller backed by [Pingora](https://github.com/cloudflare/pingora). It watches `Ingress` and `Gateway API` resources and dynamically routes traffic without a full reload.

Coxswain ships as three cooperating pod roles:
- `serve controller` — leader-elected status writer; cluster-wide reads + `*/status` writes.
- `serve proxy --shared` / `--dedicated` — read-only HTTP/TCP/UDP data plane; the ServiceAccount holds zero write verbs.
- `serve relay --shared` / `--namespace=NS` — Kube-free discovery fan-out node; relays delta snapshots from the controller to proxy replicas without watching the cluster itself.

Production deployments always pick a role explicitly; bare `coxswain serve` errors with clap help. The Dockerfile has no `CMD`. For local development run each role you need in a separate terminal — most commonly `serve controller` and `serve proxy --shared`.

## Architecture

Ten crates. Dependency edges (measured from each crate's `[dependencies]`):

```
coxswain-bin        → core, reflector, admin, controller, discovery, health, proxy
coxswain-controller → core, discovery, reflector
coxswain-proxy      → core
coxswain-reflector  → core, gateway-api-types
coxswain-admin      → core, gateway-api-types
coxswain-health     → core
coxswain-discovery  → core
coxswain-core       → (none)
gateway-api-types   → (none)
(coxswain-e2e       — black-box tests, not a runtime dep)
```

`coxswain-proxy` and `coxswain-controller` never depend on each other, and `proxy` depends on `core` only — not `reflector`, not `discovery`. The read-only-proxy invariant is enforced at RBAC (proxy SA holds zero write verbs) AND at the crate graph (the proxy never imports the controller or the reflector). Per-crate responsibilities live in each crate's `src/lib.rs` `//!` header.

## Operator UI

`ui/` is the operator web UI (Vite + Preact). Full dev loop (dev server, mock backend, build/embed chain) in DEVELOPMENT.md "Operator UI". Guardrails:

- Never commit `ui/dist/` — it is gitignored and rebuilt by the Docker `ui-builder` stage.
- When you add a UI state, extend `ui/mock/generate.mjs` so it stays reachable in dev (see `ui/mock/README.md`).
- The binary serves the *embedded* build, which only updates on `npm run build`. During a UI review pass, batch the user's comments and rebuild once at the end — not after each comment.

## Code Quality

**A rule goes to the weakest mechanism that can actually decide it, and that mechanism must be provably able to fail.** In order: the compiler (a clippy lint or `clippy.toml` entry — it parses Rust, so it has no regex blind spots, and it runs in the authoring loop for free) → a `scripts/check-*.sh` gate *with a `scripts/tests/<gate>/{good,bad}` fixture pair* → a dimension in `.claude/agents/code-review.md` for rules needing judgment → prose here, last resort. Use `/add-rule` to walk the decision.

Two things this project learned the hard way, both non-obvious:

- **A gate with no negative test is not a check.** Four gates here passed unconditionally for their whole life (dead path filters, definition-only matching, a bare-`pub`-only regex) and nothing revealed it, because a broken gate and a working gate both print `OK`. `scripts/tests/run.sh` makes "this gate fires" executable; a rule may only be listed as enforced above once its fixture exists.
- **`forbid` is unusable here.** It overrules `#[allow]` injected by dependency macros, and `#[tokio::test]` emits `allow(clippy::expect_used)` while clap's `derive(Parser)` emits `allow(clippy::style)`. Use `deny`.

Gates run at authoring time via `scripts/gates.sh`, wired as a `PostToolUse` hook in `.claude/settings.json` — CI alone is too late to shape code as it is written. Don't restate mechanically-enforced rules in prose.

### Enforced rules

| Rule | Enforced by |
|---|---|
| No `.unwrap()` / `.expect()` in non-test code | `unwrap_used = "deny"`, `expect_used = "deny"` (clippy) |
| Library crates never use `anyhow` | `scripts/check-no-anyhow-libs.sh` |
| `[lints] workspace = true` in every `crates/*/Cargo.toml` | `scripts/check-workspace-lints-decl.sh` |
| No per-site `#[allow]` / `#[expect]` in non-test source | `scripts/check-no-per-site-allow.sh` |
| Builder methods returning `Self` carry `#[must_use]` | `clippy::return_self_not_must_use` |
| An unused `Result` is an error | `unused_must_use` (std — `Result` is already `#[must_use]`; annotating the fn is redundant) |
| No unused crate dependencies | `cargo-machete` (CI step) |
| Gateway API SupportedFeatures Rust↔Go parity | `scripts/check-supported-features.sh` |
| No bare sleeps in e2e test bodies; waits poll a real post-condition | `scripts/check-no-e2e-sleeps.sh` |
| Exactly one canonical e2e `poll_until`; no shadow pollers | `scripts/check-e2e-single-poller.sh` |
| Every `ingress.coxswain-labs.dev/*` annotation has a parse test + e2e effect test | `scripts/check-annotation-coverage.sh` |
| Every new `ingress.coxswain-labs.dev/*` annotation maps to a Gateway API field/GEP **or** a first-class Istio/Envoy concept | code review gate — pure nginx-isms (no GW-API, no Istio typed field, no Envoy native filter) require explicit written justification before merging |
| `coxswain-e2e/tests/*.rs` files belong to an approved behaviour plane | `scripts/check-e2e-plane-layout.sh` |
| Every e2e fixture image is `@sha256:`-pinned | `scripts/check-e2e-images-pinned.sh` |
| Every e2e global-config mutator (`ControllerOptions`) is serialized in the `e2e-serial` pass; no stale `test(=…)` filter names | `scripts/check-e2e-mutators-serialized.sh` |
| No `std::sync::{Mutex,RwLock}`; use `parking_lot` | `clippy::disallowed_types` (`clippy.toml`) |
| Every reflector `ReflectorEffects::new(…, "check", …)` name is registered on the controller health subsystem | `scripts/check-reflector-health-checks.sh` |
| Tenant-supplied regexes compile via `compile_bounded` (size-limited), never bare `Regex::new` in core/reflector | `scripts/check-bounded-regex.sh` |
| An `MSG_PEEK` retry loop waits via `edge::peek::PeekBackoff`, never `readable()` | `scripts/check-no-peek-readable.sh` |
| No `panic!`/`unreachable!`/`todo!` in a `_ =>`/bound catch-all arm in the data-plane crates (`coxswain-proxy`, `coxswain-discovery`); degrade instead | `scripts/check-no-wildcard-panic.sh` |
| Shipped CRD manifests (coxswain's own + the pinned upstream Gateway API CRDs) pass `kubeconform -strict` | `scripts/check-crd-kubeconform.sh` |
| `cargo doc` is warning-free (no broken or private intra-doc links) | `.github/workflows/ci.yml` `doc` job (`RUSTDOCFLAGS=-D warnings`) |
| Every `scripts/check-*.sh` gate rejects a known-bad fixture and accepts a known-good one | `scripts/tests/run.sh` (CI job `gate-self-tests`) |

`[workspace.lints]` in `Cargo.toml` is the source of truth for lint configuration. Workspace-wide opt-outs in `[workspace.lints]` are acceptable when an entire lint *group* is too broad for the project (current: `clippy::pedantic = "allow"`). For upstream-imposed names that trip a lint (e.g. `HTTPRoute` from codegen tripping `upper_case_acronyms`): re-export with a project-canonical alias at the crate boundary (`gw_types.rs`) and use the alias everywhere internally — a one-time fix; per-site annotations lock the inconsistency in forever.

### Policies the CI gates don't cover

- **Panics.** A `panic!` is permitted *only* for invariants reachable solely by a logic bug in this module — not by any runtime input, operator config, cert rotation, network event, or lock contention. Apply the reachability test before writing `unwrap_or_else(|e| panic!("invariant: {e}"))`: "can config / peer bytes / cert rotation / contention reach this?" If yes, it is **not** an invariant — return a typed `Err` (or, better, eliminate it structurally: parse-at-construction so the value carries its own proof, or pick a primitive that can't fail — e.g. `parking_lot` locks can't poison). The message states *what must be true*, not what the code is doing. The **data plane** (`coxswain-proxy`, `coxswain-discovery` client/runtime paths) has a stricter bar: **zero crash sites reachable by anything but a logic bug** — a crash there drops live traffic or halts routing convergence, so failures degrade to the last-good snapshot and let the reconnect/backoff supervisor retry. Same rule applies to `unreachable!()`, `todo!()`, and `assert!`-family macros. `debug_assert!` is fine for invariants too expensive in release builds. Bench files and `crates/coxswain-e2e/` may use plain context-style messages (`"{addr}: {e}"`) — setup failures don't fit the "violated only by a bug" framing.

- **>7-arg functions.** Refactor into a parameter-grouping struct named after the semantic role (`ReflectorStores<'a>`, `DedicatedRebuildTarget<'a>`), with the narrowest visibility that compiles. Never bump `clippy.toml`'s threshold.

- **Documentation.** Every `///` on a `pub` item explains *why* and what the invariants are — names already say *what*. Fallible `pub fn`s returning `Result` carry a `# Errors` section; documented-panic `pub fn`s carry `# Panics`; `unsafe` carries `# Safety`. Current `# Errors` / `# Panics` coverage has known gaps tracked in v0.2.

- **Visibility.** Default to `pub(crate)` for items reachable within the workspace; `pub(super)` for items only crossing one module boundary; bare `pub` only for items re-exported at the crate root for cross-crate consumption.

- **Error types.** Every crate-defined error type uses `#[derive(thiserror::Error)]` with `#[error("…")]` on each variant. Library crates emit typed errors via `thiserror`; only `coxswain-bin` may use `anyhow` at the binary boundary.

- **No `#[non_exhaustive]`.** Nothing outside this workspace consumes these crates, so it buys no semver headroom — and it costs exhaustiveness checking, which is the point of matching on an enum at all. It forces a `_ =>` arm in every cross-crate `match`, so adding a `coxswain-core` variant silently falls through at runtime instead of failing the build at each site that must handle it. That convention manufactured 17 dead wildcard arms and a whole issue's worth of crash-site cleanup. Add a variant and let the compiler enumerate the work.

- **Full e2e coverage.** Every user-visible feature ships with e2e for **both the happy path and the sad/error path** — a merge without both is incomplete, not a follow-up. When a feature applies to more than one route type (e.g. a protocol-agnostic `ExtensionRef` filter or `CoxswainBackendPolicy` behaviour that works on `HTTPRoute` **and** `GRPCRoute`), **each supported route type gets its own happy + sad e2e** — HTTPRoute coverage does not substitute for GRPCRoute coverage even when the enforcement code is shared, because the reconcile wiring and status/acceptance path differ per route type. If a route type is *deliberately* excluded (e.g. `PathRewriteRegex` is nonsensical for gRPC), state why in the feature's docs and the reconciler skips it. `IpAccessControl` / `RateLimit` (#479, #25) are the reference: HTTP allow/deny/precedence tests **and** gRPC allow/deny + rate-limit tests. Unit tests and shared-code reuse do **not** discharge this — they complement it.

- **Test layout.** Per-source-file unit tests live INLINE as `#[cfg(test)] mod tests { use super::*; ... }` at the bottom of the source file (rust-skills `test-cfg-test-module`). Cross-cutting tests (those that span multiple source files + shared helpers) live under `crates/<crate>/src/[<submodule>/]tests/`. Inline test blocks reach shared helpers via `use crate::<path>::tests::*;`; helpers are declared `pub(super)` so wildcard imports work. Integration tests against the binary live in `crates/coxswain-e2e/tests/`; the behavioural rules for writing them (black-box, atomic-on-shared-fixture, mutate-only-what-you-own, assert backend identity + the negative, zero flakes, self-diagnosing failures, behaviour+outcome naming) are the **e2e crate charter** in `crates/coxswain-e2e/src/lib.rs`.

### Hot path

Coxswain has four per-event data planes; each is performance-critical at its own event rate, and every rule below (no per-event allocation beyond a capture set, no lock/`.await` held across the event, degrade-don't-panic) applies to all four — an unnamed plane is an unaudited plane:

| Plane | Rate | Code |
|---|---|---|
| HTTP request | per **request** | `crates/coxswain-proxy/src/hooks.rs`, `filters/`, `routing/` |
| UDP datagram | per **datagram** — highest event rate in the product | `crates/coxswain-proxy/src/edge/udp.rs` |
| TCP / TLS passthrough / terminate | per **connection** | `crates/coxswain-proxy/src/edge/{tcp,passthrough,terminate}.rs` |
| Relay / discovery fan-out | per **message × per subscriber** | `crates/coxswain-discovery/src/server.rs` |

The relay is a data plane, not a control-plane convenience — the codebase already calls it "the delta-fan-out path" (`operator/render_shared_proxy.rs`, `render_relay.rs`) and `crates/coxswain-discovery/benches/relay_fanout.rs` (#603) load-tests it.

HTTP request path guardrails (`Proxy::request_filter`, `upstream_peer`, `FilterSet` request/response filters):

- Capture immutable request data once at `request_filter` entry; routing lookup, upstream selection, metric emission, and access-log path allocate nothing beyond that capture set.
- Use `Shared<T>` (the `ArcSwap`-backed wrapper in `coxswain-core`) for lock-free routing/TLS snapshot reads. Never hold a `Mutex` or `RwLock` guard across `.await`.
- The exact per-request allocation budget (what each capture, filter, and TLS path costs) lives in the `crates/coxswain-proxy/src/hooks.rs` `//!` header, not in prose here; #620 will pin it with a counting-allocator gate. Do not assert an allocation count in this doc.

### Proxy module structure

`crates/coxswain-proxy/src/hooks.rs` is a **thin orchestrator** — it sequences the Pingora hook calls and delegates to focused modules (`edge/`, `policy/`, `filters/`, `routing/`). Do not inline feature logic there; each module's `//!` header states its responsibility.

When adding a new upstream TLS feature (e.g. a new peer option driven by a `BackendTLSPolicy` field), extend `apply_upstream_tls` in `edge/upstream_ca.rs` — not `upstream_peer` in `hooks.rs`.

## GitHub issue workflow

1. Invoke `/rust-skills` to load Rust coding guidelines.
2. `git checkout main && git pull --ff-only origin main`. Stop if it fails.
3. Enter plan mode. Read `gh issue view N`, cross-check code references, grill the user on anything unclear, design the implementation.
4. After plan approval: `git checkout -b issue-N`, implement per acceptance criteria. For Gateway API features with a **Feature flags** line in the issue body: add the SupportedFeatures entries in both the Rust and Go lists (gate: `check-supported-features.sh` — it names both files). For routing, status-condition, or proxy-behaviour changes: add/update scenarios in the by-plane suite `crates/coxswain-e2e/tests/{routing,tls,security,traffic_policy,status_conditions,provisioning,resilience,observability,discovery}.rs` (a test belongs to the plane of its *primary assertion target* — see each file's header).
5. Iterate per chunk with a **scoped, cheap** check — `cargo fmt && cargo check -p <changed-crate>` (`--workspace` only for cross-crate edits). Run the full gate **once, at the end** (not per chunk): `cargo clippy --workspace --all-targets --exclude coxswain-e2e -- -D warnings` then `cargo test --workspace --exclude coxswain-e2e`. `clippy` subsumes `check`, and the subcommands don't share build artifacts, so a standalone `check` before `clippy` — or running the full clippy/test per chunk — is a wasted multi-minute rebuild each time.
6. **Before every `git push`**, run the doc gate: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude coxswain-e2e --no-deps`. The CI `doc` job is `-D warnings` and fails the PR otherwise; it is *not* caught by fmt/clippy/test. The recurring failure is `rustdoc::private_intra_doc_links` — a `///`/`//!` doc on a **`pub`** item using `[`X`]` to link a `pub(crate)`/private item. **Authoring rule:** an `[`X`]` intra-doc link may only target a **`pub`** item (in this crate or a dependency); for a `pub(crate)`/private/local-fn target, use a plain code span `` `X` `` instead.

Always include the issue reference in commit footers: `Refs #N` (intermediate work) or `Fixes #N` (final commit). Closing via `Fixes #N` auto-flips the Project's `Status` to `Done`; never manually close + flip.

When a PR is approved for merge: squash-merge it (via the GitHub MCP merge tool). The repo auto-deletes the head branch on merge, so no `--delete-branch` flag or manual remote deletion is needed — only the local branch lingers. Then ask the user before `git checkout main && git pull --ff-only origin main`, and drop the merged local branch with `git branch -d issue-N`.

### Commit message convention

Title format: `type(scope): description`. Common types: `feat`, `fix`, `refactor`, `perf`, `chore`, `docs`, `ci`, `test`. Scope is the affected crate(s) without the `coxswain-` prefix (e.g. `controller`, `proxy,core`).

## Issue / project management

Source of truth for scope and status: the [Coxswain Roadmap Project](https://github.com/orgs/coxswain-labs/projects/2). New issues land at `Status: Todo`. Triage populates Track (single-select; cross-cutting workstream) and, for milestoned items, Order (numeric; intended execution sequence within the milestone).

Milestones are plain version numbers (`v0.1`, `v0.2`, …); use `gh issue edit N --milestone vX.Y`. Never use special characters (em dashes, colons, `&`) — they break GitHub's filter URL parser.

Labels: discover the live taxonomy with `gh label list --repo coxswain-labs/coxswain`. Every issue carries at least one `type:` and one `area:` or `api:`. `status: backlog` only on issues with no milestone; `priority:` is per-milestone; `type:` and `area:`/`api:` are required everywhere.

<!-- CODEGRAPH_START -->
## CodeGraph

In repositories indexed by CodeGraph (a `.codegraph/` directory exists at the repo root), reach for it BEFORE grep/find or reading files when you need to understand or locate code:

- **MCP tool** (when available): `codegraph_explore` answers most code questions in one call — the relevant symbols' verbatim source plus the call paths between them, including dynamic-dispatch hops grep can't follow. Name a file or symbol in the query to read its current line-numbered source. If it's listed but deferred, load it by name via tool search.
- **Shell** (always works): `codegraph explore "<symbol names or question>"` prints the same output.

If there is no `.codegraph/` directory, skip CodeGraph entirely — indexing is the user's decision.
<!-- CODEGRAPH_END -->
