---
name: audit-guardrails
description: Audit the project's guardrail docs — CLAUDE.md, DEVELOPMENT.md, CONTRIBUTING.md, RELEASE.md — for drift. Checks for stale closed-issue references, prose-only rules that CI could enforce, pasted source-of-truth blocks, stale "deferred limitations", taxonomies discoverable via the CLI, audience-mismatch (a rule written in the wrong file for its audience), and source-of-truth contradictions. These are the four .md files at the repo root that encode HOW we work on the project — distinct from the product docs under `docs/src/`. Read-only. Use periodically (e.g. before milestone close) to flush bloat before it compounds. Triggers on phrases like "audit the guardrails", "check CLAUDE.md for drift", "are the conventions still accurate", or "make sure the rules are still load-bearing".
---

Run a read-only audit of the project's four guardrail docs and produce a structured report of drift signals. Do not edit any of them as part of this skill — the report informs a separate edit pass.

## Scope

The guardrail set: four `.md` files at the repo root, each with a distinct audience.

| File | Audience | Concern |
|---|---|---|
| `CLAUDE.md` | AI agents (and humans reading agent guidance) | Coding rules, hot-path budget, test layout, commit conventions, issue workflow |
| `DEVELOPMENT.md` | Contributors setting up locally | Dev environment, e2e + conformance procedures, troubleshooting |
| `CONTRIBUTING.md` | First-time contributors | How to file issues, send PRs, preview docs locally |
| `RELEASE.md` | Maintainers cutting releases | cargo-release flow, recovery procedures, docs-site versioning, PAT rotation |

The product docs under `docs/src/` (mkdocs site) are EXPLICITLY OUT OF SCOPE — those are user-facing pages with different conventions, audited by a separate skill (when one exists). The line is: guardrail docs say HOW to work on this project; product docs say how to USE this project.

## What the audit must enumerate

For EACH of the four guardrail docs, produce a markdown section covering all of:

1. **Stale issue references.** Every `#NNN` in the file. Check via `gh issue view NNN --repo coxswain-labs/coxswain --json state,closedAt --jq .` whether each is OPEN or CLOSED. Closed-issue references embedded as prose ("as of #X", "fixed by #Y", "Step N (#Z)") are drift candidates — they describe history, not guidance.

2. **Historical phrasing.** Grep for `as of #`, `Step [0-9]+`, `WS[0-9]+`, `original sweep`, `landed in #` and similar narrative markers. Each match is a paragraph that narrates what a PAST PR did rather than what to DO now.

3. **Rules that COULD be CI-enforced but currently are prose.** Walk every numbered/bulleted rule. For each, judge whether a grep script, clippy lint, or `deny.toml` policy could enforce it. Mention the specific mechanism. Today's CI-enforced rule list (do not re-flag these): `unwrap_used`/`expect_used` deny, `scripts/check-public-types-stability.sh`, `scripts/check-module-headers.sh`, `scripts/check-no-anyhow-libs.sh`, `scripts/check-workspace-lints-decl.sh`, `scripts/check-no-per-site-allow.sh`, `scripts/check-supported-features.sh`. Anything ELSE that's prose-only is a candidate.

4. **Pasted source-of-truth content.** Any code block or table in the doc that duplicates a file elsewhere in the repo (e.g. the workspace lints config block paste-from-Cargo.toml, the labels list paste-from-`gh label list`, a script body paste-from-`scripts/*.sh`, a workflow step paste-from-`.github/workflows/*.yml`). These drift silently when the source file changes.

5. **Procedural sections that should be a script.** Any multi-step shell sequence inlined in markdown is a candidate for extraction to `scripts/<name>.sh` (with a one-line invocation left in the doc).

6. **Taxonomies discoverable via `gh`/`cargo`/etc.** Lists of labels, milestones, available CLI subcommands, or any other content the user could enumerate with a CLI command. Flag each.

7. **"Known limitations (deferred)" sections.** Check whether each referenced issue is still OPEN. Sections referencing closed issues describe state that already shipped; they're stale.

8. **Audience-mismatch and cross-file contradiction.** Anywhere a rule belongs to a different audience than where it's written — e.g. release mechanics in CONTRIBUTING.md (maintainer concern in a contributor doc), AI-agent procedure in DEVELOPMENT.md (CLAUDE.md territory in a dev-setup doc), contributor onboarding in RELEASE.md. The audience mismatch is a drift indicator: the rule will be missed by its actual audience and lived-with by the wrong one. Also flag any case where one guardrail doc says X and another says X' — anyone following one will take a different action than someone following the other.

9. **Source-of-truth verification for hard claims.** Anywhere the doc claims a concrete behavior of CI / scripts / build pipeline, verify against the actual file. (Example: docs-site versioning claims about mike aliases or version keys must be checked against `.github/workflows/release.yml`'s actual step bodies — at the time of writing, the live workflow uses `unstable` as the main-push version key and `stable latest` as the tag aliases. Don't assume from memory; grep the source.) Flag every hard claim that isn't verifiable from source.

10. **Missing rules an agent / contributor / maintainer would actually need.** Don't fabricate — flag only what the audit reveals. Examples: undocumented platform differences, undocumented CI behaviour that contradicts local behaviour, undocumented pre-release flow.

11. **Line-count breakdown by section.** For each file, list each top-level section's start line and length. The output identifies where bulk lives so a follow-up trim knows where to cut.

## Output format

For each file, produce a markdown report with the 11 categories above. Be specific: cite exact line numbers, exact issue numbers, exact filenames. Don't propose rewrites — that's the job of a follow-up `/add-rule` or trim pass. Just enumerate what's there.

End with a "Top 5 highest-leverage cuts" ranked list — the changes that would reduce drift risk most per line removed.

End with an "Anti-drift principles" reminder, 3–5 bullets the AI agent should internalise so future PRs don't re-add bloat. These are the standing rules; if the audit reveals new principles, propose them as additions.

## How to invoke

This skill is read-only. Use the `Bash` tool to run `gh issue view`, `wc -l`, `grep`, and similar enumerations. Use `Read` to read each guardrail doc and any source-of-truth file you're cross-checking against. Do NOT use `Edit` or `Write` against any guardrail doc from within this skill — the audit produces a report, and the user decides what to act on.

Cap the report at ~800 lines (scope is four files; cap scales with scope). If it threatens to exceed that, drop category 11 (line counts) first — it's the lowest-value bullet for an LLM reader; the file lengths can be re-derived with `wc -l` on demand.

## When to use

- Periodically (e.g. monthly, or just before a `v0.N` milestone close), to catch bloat before it compounds.
- After a large PR that added rules, callouts, or workflow steps to any of the four files.
- When a contributor or maintainer reports the docs feel "long", "hard to navigate", or "doesn't match what the workflow actually does".
- Before adding a new rule to any of the four files — the audit may reveal an existing one that can be cut or extracted, keeping the file's line budget under control.

## When NOT to use

- For a typo / small-correction PR. The audit is for systemic review, not incremental edits.
- For changes to the `docs/src/` site. Those are product docs with their own conventions; the line is hard.
- For per-script header comments. Those are technically guardrails but they live with their script; the audit covers the four root `.md` files only.
