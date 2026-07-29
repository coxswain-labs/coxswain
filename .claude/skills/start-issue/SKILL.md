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
cargo sweep --installed && cargo sweep --time 7
```

Stop and report if the git step fails; a `cargo sweep` failure is non-blocking.

The sweep is cargo's missing garbage collector, run once per issue. `--installed` drops artifacts built by toolchains no longer installed (a rustc upgrade orphans an entire generation); `--time 7` drops anything untouched for a week — typically the previous issue branches' artifacts. Without it `target/` only grows: it reached 660 GB before this cadence existed.

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
- **Plane**: `routing`, `tls`, `traffic_policy`, `status_conditions`, `provisioning`, `resilience`, `observability`, `discovery`, `security` — use the plane of the primary assertion target
- **File**: `crates/coxswain-e2e/tests/<plane>.rs`
- **Name**: `behaviour_when_condition` (snake_case)
- **Happy path**: what the test sets up and asserts succeeds
- **Sad path**: what misconfiguration or error condition the companion test covers
- **Attack framing, when applicable**: if the sad path defends against an adversary reaching an asset across a trust boundary — not merely a misconfiguration a well-meaning tenant might hit — name it for the attack and the asset, not the feature (`foreign_namespace_cannot_claim_hostname_tls`, not `ingress_tls_cert_selection`), per `.claude/skills/security-audit/SKILL.md`'s Phase 6. Check whether the issue closes a row in `.claude/security/surface.yaml` (grep the issue number under `findings:`); if so, the plan's commit sequence should update that row alongside the fix, not leave it stale.

Wait for user approval before writing any code.

## 5 — Implement

```bash
git checkout -b issue-N
```

Implement per the approved plan.

Gates run automatically on every Edit/Write via the `PostToolUse` hook in `.claude/settings.json`, which dispatches through `scripts/gates.sh`. If one fires, fix the cause before continuing — do not proceed with a failing gate. To run them manually for a path: `bash scripts/gates.sh <path>`.

After each meaningful chunk, dispatch the `code-review` agent (`.claude/agents/code-review.md`) as **TIER 1**, with `model: "sonnet"`. Pass it the explicit list of files that chunk touched — you just edited them, so name them; there are no intermediate commits to diff against. The agent reviews only those files and only the dimensions its routing table maps to them.

Never widen a TIER 1 dispatch to `git diff main`. That diff grows monotonically across the issue, so a per-chunk exhaustive review re-reviews every earlier chunk — the cost that made this two-tier split necessary.

The exhaustive TIER 2 review runs once, in step 7. Between them they cover what no gate can decide: panic reachability, per-event allocation on the four data planes, tenant-controlled input, doc quality, architectural-vs-work-saving.

Use **one** cargo invocation form for the whole issue — per chunk and as the final gate alike:

```bash
cargo fmt
cargo clippy --workspace --all-targets --exclude coxswain-e2e -- -D warnings
```

Never substitute `cargo check`, never swap `-p <crate>` for `--workspace`, never drop `--all-targets`. Cargo gives each invocation form its own artifact family — `check` and `clippy` use different rustc drivers, and `-p` and `--workspace` resolve dependency features differently, so neither pair shares a single compiled dependency. Alternating forms doesn't save a build, it adds a cold one and leaves those artifacts in `target/` forever (cargo never garbage-collects). One form means one warm cache: the issue's first run pays, each run after it rebuilds only the changed crate and its dependents.

Run the test suite **once, at the end** (before the commit checkpoint):

```bash
cargo test --workspace --exclude coxswain-e2e
```

It is a separate artifact family (`--cfg test`) that cannot be folded into the clippy one — which is exactly why it runs once rather than per chunk.

Every clippy warning is a blocker. Fix the root cause — never silence with `#[allow(...)]`. For upstream-imposed names that trip a lint, re-export with a project-canonical alias at the crate boundary.

If the change touches `scripts/check-*.sh`, run `bash scripts/tests/run.sh`: every gate must reject its `bad/` fixture and accept its `good/` one. A new gate needs a new fixture pair — a gate with no negative test is indistinguishable from one that cannot fail. Use `/add-rule` when adding a rule rather than reaching for a script by default.

### E2e tests

Add/update scenarios in `crates/coxswain-e2e/tests/<plane>.rs` per the approved plan. Each test must be:

- **Black-box** — no access to internal state
- **Atomic on shared fixture** — mutate only resources you own
- **Self-diagnosing** — assertion messages must tell you what failed without reading source
- **Behaviour/outcome named** — `what_happens_when_condition`
- **No bare sleeps** — all waits use `poll_until` on a real observable post-condition
- **Verified red before green** — for every sad/error-path scenario, run it against the pre-fix code and confirm it actually fails, before implementing the fix that makes it pass. A sad-path test never observed to fail is not evidence the control works: #692 shipped a passing ReferenceGrant-revocation e2e while revocation did not land, because the test's grant shape happened not to exercise the cancelling code path. Mechanically: write the test, run it once on the pre-fix branch state (or against a stash of the old code) to see it fail for the *right* reason, then implement the fix and re-run.

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

Before pushing, dispatch the `code-review` agent as **TIER 2** (its default model, opus) scoped to `git diff main`. This is the exhaustive pass — every dimension, looped until dry — and it runs exactly once per issue. Address blockers before the push.

Then run the doc gate, which fmt/clippy/test do not cover:

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude coxswain-e2e --no-deps
```

Push when instructed:

```bash
git push -u origin issue-N
```

Open a PR via `mcp__plugin_github_github__create_pull_request` (fall back to `gh pr create`). PR body must include:
- What changed and the engineering rationale
- Which e2e scenarios were added and which planes they cover
- `Fixes #N`

Do not merge without explicit user confirmation. On approval: squash-merge and delete the branch via the GitHub MCP plugin (fall back to `gh pr merge --squash --delete-branch`). Ask before checking out main and pulling.
