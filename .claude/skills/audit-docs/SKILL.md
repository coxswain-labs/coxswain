---
name: audit-docs
description: Audit CLAUDE.md and DEVELOPMENT.md for drift — stale closed-issue references, prose-only rules that CI could enforce, pasted source-of-truth blocks, stale "deferred limitations", taxonomies discoverable via the CLI. Read-only. Use periodically (e.g. before milestone close) to flush bloat before it compounds. Triggers on phrases like "audit the docs", "check CLAUDE.md for drift", "are the docs still accurate", or "make sure the rules are still load-bearing".
---

Run a read-only audit of `CLAUDE.md` and `DEVELOPMENT.md` and produce a structured report of drift signals. Do not edit either file as part of this skill — the report informs a separate edit pass.

## What the audit must enumerate

For EACH file (CLAUDE.md and DEVELOPMENT.md), produce a markdown section covering all of:

1. **Stale issue references.** Every `#NNN` in the file. Check via `gh issue view NNN --repo coxswain-labs/coxswain --json state,closedAt --jq .` whether each is OPEN or CLOSED. Closed-issue references embedded as prose ("as of #X", "fixed by #Y", "Step N (#Z)") are drift candidates — they describe history, not guidance.

2. **Historical phrasing.** Grep for `as of #`, `Step [0-9]+`, `WS[0-9]+`, `original sweep`, `landed in #` and similar narrative markers. Each match is a paragraph that narrates what a PAST PR did rather than what to DO now.

3. **Rules that COULD be CI-enforced but currently are prose.** Walk every numbered/bulleted rule. For each, judge whether a grep script, clippy lint, or `deny.toml` policy could enforce it. Mention the specific mechanism. Today's CI-enforced rule list (do not re-flag these): `unwrap_used`/`expect_used` deny, `scripts/check-public-types-stability.sh`, `scripts/check-module-headers.sh`, `scripts/check-no-anyhow-libs.sh`, `scripts/check-workspace-lints-decl.sh`, `scripts/check-no-per-site-allow.sh`, `scripts/check-supported-features.sh`. Anything ELSE that's prose-only is a candidate.

4. **Pasted source-of-truth content.** Any code block or table in the doc that duplicates a file elsewhere in the repo (e.g. the workspace lints config, the labels list, a script body). These drift silently when the source file changes.

5. **Procedural sections that should be a script.** Any multi-step shell sequence inlined in markdown is a candidate for extraction to `scripts/<name>.sh` (with a one-line invocation left in the doc).

6. **Taxonomies discoverable via `gh`/`cargo`/etc.** Lists of labels, milestones, available CLI subcommands, or any other content the user could enumerate with a CLI command. Flag each.

7. **"Known limitations (deferred)" sections.** Check whether each referenced issue is still OPEN. Sections referencing closed issues describe state that already shipped; they're stale.

8. **Contradictions or gaps between the two files.** Anywhere CLAUDE.md says one thing and DEVELOPMENT.md says another, or anywhere one file would lead an agent to a wrong action because the other file's policy isn't surfaced.

9. **Missing rules an agent would actually need.** Don't fabricate — flag only what the audit reveals. Examples: undocumented platform differences, undocumented CI behaviour that contradicts local behaviour.

10. **Line-count breakdown by section.** For each file, list each top-level section's start line and length. The output identifies where bulk lives so a follow-up trim knows where to cut.

## Output format

For each file, produce a markdown report with the 10 categories above. Be specific: cite exact line numbers, exact issue numbers, exact filenames. Don't propose rewrites — that's the job of a follow-up `add-rule` or trim pass. Just enumerate what's there.

End with a "Top 5 highest-leverage cuts" ranked list — the changes that would reduce drift risk most per line removed.

End with an "Anti-drift principles" reminder, 3–5 bullets the AI agent should internalise so future PRs don't re-add bloat. These are the standing rules; if the audit reveals new principles, propose them as additions.

## How to invoke

This skill is read-only. Use the `Bash` tool to run `gh issue view`, `wc -l`, `grep`, and similar enumerations. Use `Read` to read CLAUDE.md and DEVELOPMENT.md. Do NOT use `Edit` or `Write` against either file from within this skill — the audit produces a report, and the user decides what to act on.

Cap the report at ~600 lines. If it grows beyond that, drop category 10 (line counts) — it's the lowest-value bullet for an LLM reader.

## When to use

- Periodically (e.g. monthly, or just before a `v0.N` milestone close), to catch bloat before it compounds.
- After a large PR (think #242-scale) that added rules or callouts to either doc.
- When a contributor reports the docs feel "long" or "hard to navigate".
- Before adding a new rule to either doc — the audit may reveal an existing one that can be cut or extracted, keeping the file's line budget under control.

## When NOT to use

- For a typo / small-correction PR. The audit is for systemic review, not incremental edits.
- For changes to the `docs/src/` site. Those are user-facing pages with their own conventions.
- For `RELEASE.md` or per-script header comments. The audit covers the two agent-facing docs only.
