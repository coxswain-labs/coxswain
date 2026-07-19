---
name: start-issue
description: Start implementing a GitHub issue end-to-end in the coxswain project. Invoke this skill whenever the user says "start issue N", "work on issue #N", "implement #N", "pick up issue N", "tackle issue N", "begin work on issue N", or any variant of starting implementation work on a numbered GitHub issue. Covers the full lifecycle — branch setup, planning, implementation, quality gates, PR — with mandatory e2e coverage and engineering excellence. Always invoke this skill at the start of issue work, even if the request seems simple.
---

# Start Issue

## Communication style

Be short and direct. No meta-commentary, no restating what you just did. Ask one question at a time. Use prose for open design forks; `AskUserQuestion` only for crisp either/or choices.

## 1 — Load Rust guidelines

Invoke `/rust-skills` before anything else.

## 2 — Sync to latest main

```bash
git checkout main && git pull --ff-only origin main
```

Stop and report if this fails.

## 3 — Read the issue

Use `mcp__plugin_github_github__get_issue` (fall back to `gh issue view N`). Parse:

- Title, description, acceptance criteria
- **Feature flags** line → signals Gateway API `SupportedFeatures` additions required
- Labels: `area:`, `api:`, `type:`

Cross-reference every file, type, module, and annotation mentioned against the actual codebase. Read the source — do not rely on memory.

## 4 — Enter planning mode

Enter plan mode via `EnterPlanMode`.

### Read before designing

- Proxy/routing changes → `crates/coxswain-proxy/src/`
- Controller/status changes → `crates/coxswain-controller/src/`
- Shared types → `crates/coxswain-core/src/`
- Reflector logic → `crates/coxswain-reflector/src/`

### Clarify what's unclear

If any part of the issue is ambiguous, present your current understanding first, then the specific gap. Ask one question at a time, wait for an answer before continuing.

### Design the implementation

Apply crate-boundary discipline throughout:

- `coxswain-proxy` and `coxswain-controller` never depend on each other
- New types default to `pub(crate)`; `pub` only at crate-root re-exports
- Library crates use `thiserror`; `anyhow` is forbidden in library crates
- No `.unwrap()` / `.expect()` outside test code
- No `#[non_exhaustive]` — nothing outside this workspace consumes these crates, and it costs cross-crate exhaustiveness checking
- Every new `pub` item gets a `///` doc comment explaining invariants; fallible fns get `# Errors`

For issues with a **Feature flags** line, the plan must include:
- Adding `features.SupportXxx` to `opts.SupportedFeatures` in `conformance/main_test.go`
- Adding the bare feature name to `SUPPORTED_FEATURES` in `crates/coxswain-controller/src/controller/gateway_class_status.rs` (sorted)

For new `ingress.coxswain-labs.dev/*` annotations, include a parse test and an e2e effect test per annotation.

If the issue touches user-visible behaviour, include updating the relevant `docs/src/` page(s).

### Plan structure

**1. Affected crates** — which crates change and why
**2. New types / traits** — visibility, invariants, error variants
**3. Data flow** — how the change moves through reflector → controller/proxy → Kubernetes
**4. Commit sequence** — ordered commits with `type(scope): description` titles; `Refs #N` on intermediate commits, `Fixes #N` on the final
**5. E2e scenarios** — for each: plane, file, test name, happy path, sad path

### E2e scenarios

Every issue requires e2e coverage for both happy paths and sad/error paths.

Test names follow the **behaviour/outcome** pattern: `what_happens_when_condition`.

For each scenario list:
- **Plane**: `routing`, `tls`, `traffic_policy`, `status_conditions`, `provisioning`, `resilience`, `observability`, `discovery` — use the plane of the primary assertion target
- **File**: `crates/coxswain-e2e/tests/<plane>.rs`
- **Name**: `behaviour_when_condition` (snake_case)
- **Happy path**: what the test sets up and asserts succeeds
- **Sad path**: what misconfiguration or error condition the companion test covers

Wait for user approval before writing any code.

## 5 — Implement

```bash
git checkout -b issue-N
```

Implement per the approved plan.

Gates run automatically on every Edit/Write via the `PostToolUse` hook in `.claude/settings.json`, which dispatches through `scripts/gates.sh`. If one fires, fix the cause before continuing — do not proceed with a failing gate. To run them manually for a path: `bash scripts/gates.sh <path>`.

After each meaningful chunk, dispatch the `code-review` agent (`.claude/agents/code-review.md`) over the chunk's diff. It covers what no gate can decide: panic reachability, per-event allocation on the four data planes, tenant-controlled input, doc quality, architectural-vs-work-saving.

Iterate per chunk with a **scoped, cheap** check — do not run the full clippy+test suite after every chunk:

```bash
cargo fmt
cargo check -p <changed-crate>        # --workspace only for cross-crate edits
```

Run the full gate **once, at the end** (before the commit checkpoint), each command a single time:

```bash
cargo clippy --workspace --all-targets --exclude coxswain-e2e -- -D warnings
cargo test --workspace --exclude coxswain-e2e
```

`clippy` subsumes `check`, and the subcommands don't share build artifacts — so a standalone `check` before `clippy`, or per-chunk full runs, are wasted multi-minute rebuilds.

Every clippy warning is a blocker. Fix the root cause — never silence with `#[allow(...)]`. For upstream-imposed names that trip a lint, re-export with a project-canonical alias at the crate boundary.

If the change touches `scripts/check-*.sh`, run `bash scripts/tests/run.sh`: every gate must reject its `bad/` fixture and accept its `good/` one. A new gate needs a new fixture pair — a gate with no negative test is indistinguishable from one that cannot fail. Use `/add-rule` when adding a rule rather than reaching for a script by default.

### E2e tests

Add/update scenarios in `crates/coxswain-e2e/tests/<plane>.rs` per the approved plan. Each test must be:

- **Black-box** — no access to internal state
- **Atomic on shared fixture** — mutate only resources you own
- **Self-diagnosing** — assertion messages must tell you what failed without reading source
- **Behaviour/outcome named** — `what_happens_when_condition`
- **No bare sleeps** — all waits use `poll_until` on a real observable post-condition

## 6 — Commit checkpoint

At every logical checkpoint, run `/compact` first, then ask:

> Ready to commit? Options: **Refine** / **Run e2e** / **Run conformance** / **Commit only** / **Commit and push**

Never commit autonomously. Run `cargo fmt` immediately before `git add` on every commit cycle.

Commit format: `type(scope): description`
Common types: `feat`, `fix`, `refactor`, `perf`, `chore`, `test`, `docs`
Scope: affected crate(s) without `coxswain-` prefix, e.g. `proxy`, `controller,core`

Intermediate commits: `Refs #N` footer
Final commit: `Fixes #N` footer

## 7 — Push and PR

Push when instructed:

```bash
git push -u origin issue-N
```

Open a PR via `mcp__plugin_github_github__create_pull_request` (fall back to `gh pr create`). PR body must include:
- What changed and the engineering rationale
- Which e2e scenarios were added and which planes they cover
- `Fixes #N`

Do not merge without explicit user confirmation. On approval: squash-merge and delete the branch via the GitHub MCP plugin (fall back to `gh pr merge --squash --delete-branch`). Ask before checking out main and pulling.
