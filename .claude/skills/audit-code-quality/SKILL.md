---
name: audit-code-quality
description: In-depth code-quality audit of the entire workspace leveraging /rust-skills. Produces a remediation plan (does not refactor directly); the user reviews findings and approves which workstreams to execute. Use when the user wants a thorough review after a wave of feature work — for example "audit the workspace", "check for drift", "review code quality", "have we drifted on conventions". Dispatches up to 3 Explore agents in parallel, verifies each BLOCKER claim against source, cross-checks findings against existing GitHub issues, and writes a remediation plan with commit sequencing.
---

In-depth code-quality audit of the workspace. Produces a remediation plan in plan mode; the user approves which workstreams to execute and the implementation lands as a multi-commit PR. The skill itself never refactors.

## Rules (meta)

1. **Never propose fixes that contradict CLAUDE.md or pinned memories.** If the audit reveals a real conflict, surface it as a finding and ask the user how to resolve before proposing a fix.
2. **One scoping question per `AskUserQuestion` call** (per memory `feedback_grill_one_at_a_time`). Batching design decisions into a single multi-question prompt prevents proper discussion of each.
3. **One issue per workstream** for multi-workstream refactors (per memory `feedback_refactor_branch_strategy`). Single bundled PRs are the exception, not the default; reach for the bundle only when the workstreams are tightly coupled.
4. **Audit ≠ refactor.** This skill writes a plan. Memory saves, code edits, commits, and any other state changes happen after `ExitPlanMode` is approved.
5. **When the audit proposes a NEW project rule, also propose its CI mechanism.** Mirror the `/add-rule` decision tree: clippy lint, `scripts/check-*.sh` grep, `deny.toml` policy, or doc-only-because-X. Prose rules without an enforcement plan grow into drift.

## Phase 1 — Orient

1. Invoke `/rust-skills` so the audit criteria are loaded.
2. Read `CLAUDE.md` and scan pinned memories for codebase-specific rules (filename prefix `feedback_` or `project_`).
3. Snapshot the workspace state:
   - `git log --oneline -30` — what landed recently is the highest-priority area to audit (the freshest code is the likeliest to have drifted).
   - File sizes: `find crates -name "*.rs" -not -path "*/tests/*" | xargs wc -l | sort -rn | head -20` — large recently-touched files are audit-priority targets.
   - **Enumerate the current CI-enforced rules**. List every `scripts/check-*.sh` and every `deny`-level lint in `[workspace.lints.clippy]` of `Cargo.toml`. These rules are mechanically enforced — agents must NOT re-flag findings in their scope. The audit's signal-to-noise depends on this exclusion list being accurate.
4. Enter plan mode.

## Phase 2 — Dispatch parallel Explore agents

Dispatch THREE Explore agents in a single message (three parallel tool calls). Partition by **role in the architecture**, not by crate name (crate sizes and recency shift over time):

- **Agent 1 — the newest / largest product-behaviour crate.** Identify it from the snapshot in Phase 1 (largest size + most recent `git log` touches). This crate carries the most fresh decisions and the highest drift risk.
- **Agent 2 — runtime-critical hot paths.** The request path through the proxy + the routing-table builder + lock-free snapshot primitives. Whatever the crate names happen to be at audit time, these subsystems are performance-load-bearing and warrant their own pass.
- **Agent 3 — cross-cutting concerns.** Workspace `Cargo.toml`, lint setup, naming consistency across crates, doc coverage, the entry-point binary, the e2e harness. This is the agent most likely to return an over-clean result — see Phase 3.

Each agent's prompt MUST include:

- "Judge against rust-skills rules at `.claude/skills/rust-skills/rules/`. Quote rule names when citing findings (e.g. `anti-lock-across-await`, `mem-box-large-variant`)."
- The category list relevant to the agent's role:
  - (a) idiomatic Rust failures: `.unwrap()`/`.expect()` outside tests, clones over borrows, `&String`/`&Vec<T>` params, `format!()` in hot paths, locks across `.await`, stringly-typed APIs, large unboxed enum variants.
  - (b) naming consistency: acronym casing (rust-skills `name-acronym-word`), `as_`/`to_`/`into_` prefix conventions, rename leftovers.
  - (c) module organization: file size, conceptual coherence, flat-vs-subdirectory mix.
  - (d) documentation gaps: missing `//!`, missing `///`, missing `#[must_use]`, missing `#[non_exhaustive]`, missing `# Errors`, missing `# Panics`.
  - (e) AI-slop / over-engineering / dead code / "for future use" hooks.
  - (f) error handling consistency.
  - For runtime/hot-path agents also: (g) async correctness (locks across await, bounded channels, cancellation tokens) and (h) hot-path performance (allocations in request path, format!() vs itoa::Buffer).
- **"Do NOT re-flag rules already enforced by CI"** followed by the list from Phase 1. A finding the existing CI mechanically catches is noise; the audit's job is to surface what CI doesn't.
- "Pay SPECIAL attention to the newest code. Compare it line-by-line against equivalent older code in the same crate. Flag any new pattern where an established one existed."
- "Report each finding as: `file:line`, one-sentence issue, severity (`BLOCKER`/`MAJOR`/`MINOR`/`NIT`), one-sentence concrete fix, rust-skill rule name where applicable."
- "End with a Top 10 priorities to fix first list, ordered by impact-per-effort."

## Phase 3 — Verify

For EACH `BLOCKER` claim:
- Read the actual `file:line` with the `Read` tool. Primary sources are authoritative.
- If the claim doesn't match source state, demote the severity or drop the finding entirely. Agents sometimes hallucinate or over-state.

**Yellow flag on over-clean reports.** If an agent returns "everything is fine" or claims a category has zero findings, audit a sample yourself: pick three representative files in the agent's scope and Read them. Agents that miss work are worse than agents that over-claim — at least over-claims show up in verification. (In a recent audit, one agent reported `#[non_exhaustive]` coverage as "perfect compliance" while actual coverage was 13/107. Never trust silence.)

Cross-check findings against the project's GitHub issues, by label rather than free-text search:

```
gh issue list --state open --repo coxswain-labs/coxswain \
  --label "area:<X>" --label "type:chore" --limit 50
```

For each finding that overlaps with an open issue, decide: drop (already tracked), reference (note the issue in the plan), or fold (absorb into this PR). Free-text `--search` is a fallback but tends to match noisy.

Accumulate a list of non-obvious design decisions worth recording as project memories. **Do NOT write them now** — plan mode blocks file edits outside the plan file. Note them in the plan's "Memories to save post-approval" section instead.

## Phase 4 — Confirm scope with the user

Ask the user one `AskUserQuestion` at a time. Required sequence:

1. **Scope breadth.** Which finding buckets are IN: critical-only (BLOCKER + MAJOR), critical + workspace-wide mechanical sweeps (e.g. `#[non_exhaustive]` coverage), all + invasive perf work, all + CI shift-left tooling. Recommend based on the severity profile of the findings.
2. **Sequencing.** Multi-issue / multi-workstream PRs (per `feedback_refactor_branch_strategy`) vs single bundled PR. Default to multi when the workstreams are loosely coupled; single bundle only when they're tightly coupled and reviewers benefit from seeing them together. Echo the recommendation with the trade-off explicit.
3. **CI shift-left for NEW rules.** For each prose rule the audit proposes, ask: clippy lint, `scripts/check-*.sh` grep, `deny.toml` policy, or doc-only-because-X. This is the `/add-rule` decision tree — invoke it once per proposed rule.
4. **Known-deferred handling.** For each finding that overlaps an OPEN issue: drop (already tracked), reference (link in this PR's plan as out-of-scope), or fold (absorb into this PR's commits).

Each answer becomes a durable line in the plan's "Scope decisions" section so reviewers see the reasoning, not just the choices.

## Phase 5 — Write the plan

Write to the plan file (the only writable file in plan mode). Required sections, in order:

- **Context.** What was audited, headline assessment, what's NOT a finding (already CI-enforced + already tracked in open issues).
- **Scope decisions (user-confirmed).** Echo the Phase 4 answers verbatim with the recommendations they overrode (so the choice is auditable).
- **Workstreams.** One section per concern area. Each lists: concrete file paths, rust-skill rule names, BLOCKER/MAJOR counts, the fix shape (mechanical sweep / per-call refactor / new CI gate / etc.).
- **Pre-implementation tasks.** Issues to open in the relevant milestone BEFORE the first commit, so commit footers resolve to real `Refs #N` / `Fixes #N` numbers. Typical pattern: one umbrella issue for the PR + one issue per major workstream + follow-up issues for out-of-scope items the audit surfaced.
- **Commit sequencing.** Branch setup (`git checkout -b chore/<topic>`), per-commit subject + scope, per-commit gate (`cargo fmt --check`, `cargo clippy --workspace --all-targets --no-deps -- -D warnings`, `cargo build --workspace`, `cargo test --workspace --exclude coxswain-e2e`, relevant `scripts/check-*.sh`). Each commit must satisfy its gate before the next is authored.
- **Verification.** The pre-push e2e + conformance gate from `/run-e2e`: routing, tls, status_conditions, provisioning, resilience, observability, discovery, conformance. Reset the cluster between every suite per the run-e2e procedure.
- **Memories to save post-approval.** The non-obvious design decisions noted in Phase 3, each with a `Why:` line (incident or constraint that motivated the rule) and a `How to apply:` line (when/where the rule kicks in).
- **Post-PR follow-ups.** Items intentionally out of scope of this PR but worth tracking. Each is either a v0.X-milestoned issue (if the work is committed) or a backlog item.

## Phase 6 — ExitPlanMode

Once the plan reads cleanly: call `ExitPlanMode`. The user reviews and approves.

## Phase 7 — Implementation (post-approval)

Save the memories noted in Phase 5 first — before any code edit, so the rules apply to the implementation. Then file the pre-implementation issues so commit footers reference real numbers. Then execute the plan per its commit sequence. Pause for `AskUserQuestion` before each commit per CLAUDE.md's issue workflow. Per memory `feedback_no_skip_signing`, never bypass commit signing; stop and ask the user to touch the hardware key if signing fails.

## When to use

- After a wave of feature work (3+ medium-to-large PRs) when the user wants a thorough review.
- Periodically before milestone close to catch drift before it ships.
- When a user reports "things feel inconsistent" or "have we drifted".

## When NOT to use

- For a single small PR's quality review — use `/code-review` (the per-diff focused review) instead.
- When the user is mid-implementation and wants a quick "is this approach right" check — that's a `/grill-me` situation.
- For documentation-bloat reviews — use `/audit-docs`.
