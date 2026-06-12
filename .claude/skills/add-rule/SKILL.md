---
name: add-rule
description: Before adding a new policy rule to CLAUDE.md, decide whether a CI mechanism could enforce it. Encodes the "rules go to CI first" principle. Use when about to write a new bullet in CLAUDE.md's Code Quality section, when generalising a recurring code-review correction, or when a recent bug suggests a project-wide invariant should be guarded. Triggers on phrases like "add a rule that X", "let's document X", "no one should do X anymore", or "we keep getting hit by X".
---

When a new project rule is being proposed, this skill walks through the enforcement decision BEFORE the rule lands as prose in CLAUDE.md. The premise: every rule that can be checked mechanically should be, so the doc stays a tight set of behavioural policies — not a wishlist.

## Step 1 — Read the proposed rule back

State the rule clearly in imperative form: "X must happen" or "X must not happen". If the user gave the rule as a phenomenon ("we keep hitting X"), restate it as the corresponding invariant. Do not skip this step — vague rule statements lead to prose that doesn't enforce anything.

## Step 2 — Determine the enforcement mechanism

Use `AskUserQuestion` with a single-select question (header "Enforcement"):

- **Clippy lint** — the rule maps to an existing clippy lint (or to `unwrap_used`/`expect_used`/`type_complexity`/etc. in workspace lints) and can be promoted from `warn` to `deny`. Cheapest enforcement; runs on every commit. Recommended when the rule is about Rust idioms.
- **`scripts/check-*.sh` grep** — the rule is a workspace-wide structural property checkable by a shell + Python script (analogous to `scripts/check-public-types-stability.sh`). Recommended when the rule is project-specific (naming, file structure, attribute presence).
- **`deny.toml` policy** — the rule constrains the dependency tree or licence/source policy. Recommended for supply-chain rules.
- **Doc-only, because no mechanical check is tractable** — the rule is a behavioural policy that depends on judgment (e.g. hot-path allocation budgets, panic-message form, parameter-grouping struct naming). Recommended ONLY when the previous three were genuinely considered and rejected.

If the answer is "doc-only", ask a follow-up: "What's the trigger condition under which a future contributor will discover this rule applies?" If the answer is "they have to read CLAUDE.md cover-to-cover and remember it", the rule is too weak — push back: either tighten it to a checkable form, or accept that it will drift.

## Step 3 — Draft the artefact

Based on the answer:

- **Clippy lint**: identify the lint name and the target level (`warn`/`deny`). Show the diff to `[workspace.lints.clippy]` in `Cargo.toml`. Also propose the row to add to CLAUDE.md's "Enforced rules" table.

- **`scripts/check-*.sh`**: draft the script template, modelled on `scripts/check-public-types-stability.sh`. The template should:
  - Bash heredoc preamble explaining the rule.
  - Set `-euo pipefail`.
  - Implement the check (typically `find` + grep, or a Python heredoc for structural walks).
  - Print `OK: <count> things checked.` on success.
  - Print `FAIL: <count> offenders:` + the offender list, then a remediation hint.
  - `exit 1` on failure.
  Also draft the CI job entry for `.github/workflows/ci.yml` (paths filter + single-step job). Also propose the row to add to CLAUDE.md's "Enforced rules" table.

- **`deny.toml`**: identify the section (`bans`, `licenses`, `advisories`) and the entry. Show the diff. Propose the row to add to CLAUDE.md's "Enforced rules" table.

- **Doc-only**: draft the CLAUDE.md prose (one paragraph max, in the "Policies the CI gates don't cover" section). The prose should state the rule in imperative form, the rationale in one sentence, and the trigger condition for when the rule applies.

## Step 4 — Verify before committing

If a script was drafted, run it against the current tree to confirm it passes (or to enumerate pre-existing offenders that need fixing in the same commit). If a clippy lint was promoted, run `cargo clippy --workspace --all-targets --no-deps -- -D warnings` to confirm zero new errors.

## Step 5 — Commit advice

A new rule's commit should typically be split into:
1. Fix any pre-existing offenders.
2. Add the enforcement (lint promotion, script + CI job, or deny.toml entry).
3. Update CLAUDE.md to mention the rule and link to its enforcer.

Steps 1 and 2 can be the same commit when the offender list is short (≤5 sites). Step 3 lands in the doc-trim commit alongside other CLAUDE.md edits, or as its own one-line `docs(claude): record new <X> rule` commit.

## How to invoke

The skill is conversational + minimally interventional. It is NOT a one-shot generator. Walk the user through each step using `AskUserQuestion` for the enforcement-mechanism choice; show drafts using normal text output and offer to write them to files (the user accepts via the standard tool-call flow). Do not auto-write files without the user's explicit go-ahead per step.

## When to use

- A user proposes a new rule for CLAUDE.md.
- A recurring code-review correction has been seen 2+ times.
- A recent bug or regression suggests a project-wide invariant that should be guarded.

## When NOT to use

- The user is just asking a question about an existing rule. Use normal conversation, not this skill.
- The "rule" is actually a docs-site improvement (clearer prose in `docs/src/`). That's not a policy decision.
- The user is mid-implementation and the proposed rule is really a one-off design decision in the current PR. Capture it in the PR description, not CLAUDE.md.
