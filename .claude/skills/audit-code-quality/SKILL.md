---
name: audit-code-quality
description: In-depth code-quality audit of the entire workspace leveraging /rust-skills. Produces a remediation plan (does not refactor directly); the user reviews findings and approves which workstreams to execute. Use when the user wants a thorough review after a wave of feature work — for example "audit the workspace", "check for drift", "review code quality", "have we drifted on conventions". Dispatches up to 3 Explore agents in parallel, verifies each BLOCKER claim against source, cross-checks findings against existing GitHub issues, and writes a remediation plan with commit sequencing.
---

I need an in-depth code-quality review of the entire workspace. Recent feature work has introduced architectural and feature changes, and I'm concerned quality has drifted.

1. Enter plan mode
2. Invoke /rust-skills so the audit criteria are loaded into context.
3. Orient on the repo: read CLAUDE.md, the workspace Cargo.toml, run `git log --oneline -30`, list source files with line counts (`find crates -name "*.rs" | xargs wc -l | sort -n | tail -20`), and check any pinned memories that affect this codebase.

Then dispatch THREE parallel Explore agents (single message, three tool calls), each with a clearly partitioned scope. Suggested split for a multi-crate Rust workspace:
- Agent 1: the largest / most-recently-modified crate (the controller in our case)
- Agent 2: the runtime-critical paths (proxy + core for us)
- Agent 3: cross-cutting concerns (workspace Cargo.toml, lint setup, module organization, naming consistency across crates, documentation coverage, entry-point review)

Each agent's prompt MUST instruct it to:
- Judge against the rust-skills rules at .claude/skills/rust-skills/rules/ (quote rule names when citing findings)
- Cover at minimum these categories: (a) idiomatic Rust failures (.unwrap/.expect outside tests, clones over borrows, &String/&Vec params, format! in hot paths, locks across .await, stringly-typed APIs, large unboxed enum variants); (b) naming consistency (acronym casing, prefix conventions, rename leftovers);
  (c) module organization (file size, conceptual coherence, flat-vs-subdirectory mix); (d) documentation gaps (missing //!, missing ///, missing #[must_use], missing #[non_exhaustive], missing # Errors); (e) AI-slop / over-engineering / dead code / "for future use" hooks; (f) error handling consistency; for
  proxy/runtime code also (g) async correctness (locks across await, bounded channels, cancellation) and (h) hot-path performance
- Pay SPECIAL attention to the newest code — compare it line-by-line against equivalent older code in the same crate. Is it stylistically consistent? Did it introduce new patterns where established ones existed?
- Report each finding as: file:line, one-sentence issue, severity (BLOCKER/MAJOR/MINOR/NIT), one-sentence concrete fix
- End with a "Top 10 priorities to fix first" list

After the agents return:
- VERIFY each BLOCKER claim by reading the actual source. Agents sometimes overstate severity; primary sources are authoritative.
- Cross-check findings against existing GitHub issues (`gh issue list --search "<keyword>"` for any divergence/known-deferred topics) BEFORE proposing new work for them.
- Save any non-obvious design decisions you uncover as project-type memories with **Why:** and **How to apply:** lines.

Then ask focused scoping questions with genuine tradeoffs (one recommended option labeled clearly):
- How to sequence the work (one PR vs many, one issue vs many)
- Whether invasive/perf workstreams should be in scope
- How to handle anything that's already known-deferred (drop, link, or implement)
- Lint-block strictness (strict first vs warn-first vs incremental)

Finally, write the plan as a REMEDIATION PLAN structured around:
- Context (what was reviewed, headline assessment, what's NOT a finding/already-tracked)
- User-confirmed scope decisions (echoed back so they're durable)
- Workstreams (one per concern area, with concrete file paths and rule references)
- Commit sequencing (gates between commits; what must build green before the next)
- Verification (per-commit gates + scenario-specific e2e tests + conformance suite)
- Post-PR follow-ups (anything intentionally not implemented but needing tracking)

Plan mode constraints: only the plan file is writable. Use AskUserQuestion for clarifications; use ExitPlanMode for approval. Never propose fixes that contradict CLAUDE.md or pinned memories.
