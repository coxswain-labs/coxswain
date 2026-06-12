---
name: update-product-docs
description: Audit and update the product documentation under `docs/src/` (the mkdocs site that ships to coxswain-labs.github.io/coxswain) against the canonical conventions embedded in this skill (two macro deployment models — Shared and Dedicated — and the supporting naming and diagram rules). Audits first, presents the proposed diff, applies on user approval. Covers naming-convention violations in prose and mermaid diagrams (e.g. "Per-Gateway proxy pod" → "Dedicated proxy pool"), broken internal links, pages referenced in `docs/mkdocs.yml` nav but missing on disk (or vice versa), and `mkdocs build --strict` warnings. Sibling to `audit-guardrails` but action-oriented — the verb is `update`, not `audit`. Triggers on phrases like "update the product docs", "fix the docs", "the docs are drifting", "refresh the architecture page", "the diagrams are out of sync".
---

Maintain `docs/src/` (the mkdocs site published to `coxswain-labs.github.io/coxswain`) against the project's naming conventions, link integrity, and build cleanliness. The skill runs in three phases — audit, apply, verify — and pauses for user approval before any edit lands.

## Scope

`docs/src/` covers user-facing product documentation:

| Section | Purpose |
|---|---|
| `docs/src/index.md` | Landing page |
| `docs/src/getting-started.md` | First-install walkthrough |
| `docs/src/installation/*.md` | Helm / Kustomize / raw manifest install paths |
| `docs/src/guides/*.md` | Topic guides (Ingress, Gateway API, dedicated-mode, TLS, production deployment, troubleshooting, verifying releases) |
| `docs/src/reference/*.md` | Configuration and observability reference |
| `docs/src/architecture.md` | The architecture page with the deployment-model diagram |
| `docs/src/faq.md` | FAQ |
| `docs/mkdocs.yml` | mkdocs nav + theme + plugins (validated, not rewritten by this skill) |

**Out of scope:** the four repo-root guardrail docs (`CLAUDE.md`, `DEVELOPMENT.md`, `CONTRIBUTING.md`, `RELEASE.md`) — those are owned by `/audit-guardrails` (read-only). Per-script header comments are owned by the scripts themselves.

## Conventions (canonical)

These rules ARE the source of truth — don't go looking for them elsewhere. If the framework changes, edit this file; it's what every audit run grades against.

### Deployment-model framework

**Two macro deployment models**:

- **Shared** — one cluster-wide proxy pool serves Ingress and all non-dedicated Gateways. *Ingress-only* is a runtime variant of Shared when Gateway-API CRDs are absent at startup (the controller probes and drops the Gateway pipelines).
- **Dedicated** — per-Gateway proxy, provisioned on the controller when a `Gateway` carries `spec.infrastructure.parametersRef` → `CoxswainGatewayParameters`. Each dedicated Gateway gets its own Deployment + Service + ServiceAccount + RBAC.

**Per-namespace is intentionally NOT a deployment model.** The Gateway API spec has only per-Gateway data-plane customization (`Gateway.spec.infrastructure.parametersRef`, GEP-1762) and per-class (`GatewayClass.spec.parametersRef`); no namespace-scoped axis exists. Per-Gateway and per-namespace are nested, not orthogonal — per-Gateway is strictly more granular. Don't introduce a per-namespace pool framing in docs.

**CLI subcommands are a separate axis from deployment models.** The binary's `serve dev` / `serve controller` / `serve proxy --shared` / `serve proxy --dedicated` are pod-role choices; the **two** deployment models are data-plane shape. Document them on separate axes; do not conflate counting.

### Prose naming rules

- **Introduce "dedicated proxy (per Gateway)" once per page or section, then shorten to "dedicated" plain.** No "dedicated per-Gateway proxy" mouthful in body text.
- **"shared proxy" / "dedicated proxy"** (space-separated) in prose. The hyphenated form (`shared-proxy`, `dedicated-proxy`) is only valid inside literal identifiers — `coxswain-shared-proxy`, CLI flags, code symbols, K8s resource names.
- Never write "all four modes" / "four deployment models" — there are two.
- Never write `proxy --gateway` — the CLI flag is `proxy --dedicated`.
- Never write `coxswain.io` — the project domain is always `coxswain-labs.dev`. Applies to CRD groups, condition types, finalizers, label/annotation keys, and any DNS-form identifier in prose.

### Diagram label convention

For mermaid blocks in `docs/src/`:

- `Shared proxy pool` — the multi-replica shared Deployment box
- `Dedicated proxy pool` — the multi-replica dedicated Deployment box
- `Controller pod` — single replica (leader-elected)
- Do NOT use `Per-Gateway proxy pod` (old framing) or `Shared-proxy pods` (hyphenated form in a label).

## Phase 1 — Audit

Enumerate findings without editing anything. Categorize each finding by type, severity (BLOCKER / MAJOR / MINOR / NIT), and file:line.

### Categories

1. **Naming-convention prose violations.** Grep `docs/src/**/*.md` for:
   - `Per-Gateway` (replace with the per-page convention: introduce once as "dedicated proxy (per Gateway)" then "dedicated" plain)
   - `shared-proxy ` followed by a space and a non-identifier word (hyphenated form in prose; should be "shared proxy" space-separated). Allowed only inside literal identifiers (`coxswain-shared-proxy`, `proxy.shared.enabled`, CLI flags, code symbols)
   - `dedicated per-Gateway proxy` repeated more than once per page (the parenthetical goes on first mention only)
   - `per-namespace proxy` / `per-namespace pool` (not a deployment model; flag any reference)
   - `all four modes` / `four deployment models` / `four models` (category error; two macro models is the correct framing)
   - `coxswain.io` anywhere (always `coxswain-labs.dev`)
   - `proxy --gateway` (the CLI flag is `proxy --dedicated`; `--gateway` is the legacy name)

2. **Diagram label violations.** For each mermaid block in `docs/src/`:
   - `Per-Gateway proxy pod` (replace with `Dedicated proxy pool`)
   - `Shared-proxy pods` (replace with `Shared proxy pool`)
   - `Controller pod` (correct — single replica, not a pool)
   - Any diagram label that mixes hyphens and spaces inconsistently (`Shared-proxy pool` is wrong; either `Shared proxy pool` or `coxswain-shared-proxy` if labelling the literal K8s identifier)

3. **Broken internal links.** Walk every `[text](relative.md)` / `[text](relative.md#anchor)` link in `docs/src/`; flag any that don't resolve to an existing file + anchor.

4. **mkdocs nav drift.** Compare `docs/mkdocs.yml`'s `nav:` block against the actual `docs/src/**/*.md` filesystem state:
   - Files referenced in nav but missing on disk → BLOCKER (the site won't build)
   - Files present on disk but absent from nav → MAJOR (page is unreachable)
   - Files in subdirectories under `docs/src/installation/`, `docs/src/guides/`, `docs/src/reference/` should appear in their respective nav subsections.

5. **`mkdocs build --strict` warnings.** Run `cd docs && mkdocs build --strict 2>&1` and capture any warnings / errors. The same gate the `docs-build` CI job in `.github/workflows/distribution.yml` runs against every PR.

6. **`PACKAGE_VERSION` substitution sanity check.** Run `cd docs && PACKAGE_VERSION=0.1.2 mkdocs build --strict` (a SemVer that should trigger substitutions). If the build succeeds with the substitution but produces 404s or rendering errors, flag them. The substitution mechanism is documented in `RELEASE.md` — don't re-derive the rule, just check the behaviour.

7. **Stale "planned" qualifiers for shipped features.** Grep for `planned`, `coming soon`, `not yet implemented`, `will be added`. For each match, check whether the referenced feature has shipped (look for the corresponding issue's state via `gh issue view N --json state`). If shipped, the qualifier is stale; flag for removal.

8. **Stale issue / PR references.** Every `#NNN` in `docs/src/`. Check the issue's state via `gh issue view NNN --json state,closedAt`. Closed-issue references in prose ("as of #N", "fixed in #N") are drift candidates — they belong in the PR description that closed the issue, not in user-facing docs. (Issue references *as feature documentation* are fine — e.g. "Tracked in #229" for a known limitation.)

## Phase 2 — Apply

Present the audit as a structured report (markdown). For each finding the skill proposes a concrete fix, grouped by file. The user reviews the proposed diff per-file via `AskUserQuestion` (one question per file with options: apply / skip / show me the exact diff first). Apply on approval; skip without prompting again on decline.

For naming-convention fixes that span multiple paragraphs in one file, propose the entire diff at once so the user can see the cascade (first-mention introduces "dedicated proxy (per Gateway)", subsequent mentions shorten to "dedicated").

For diagram changes, render the proposed mermaid block in the AskUserQuestion preview so the user sees what the new diagram will look like.

The skill does NOT rewrite pages from scratch. New content additions (new feature pages, new guides) are out of scope — those require a separate human-authored PR. The skill maintains existing pages.

## Phase 3 — Verify

After applying changes:

1. `cd docs && mkdocs build --strict 2>&1` — exits zero.
2. `cd docs && PACKAGE_VERSION=0.1.2 mkdocs build --strict 2>&1` — exits zero (substitution path).
3. `grep -rE "Per-Gateway|shared-proxy [a-z]|all four modes|coxswain\.io|proxy --gateway" docs/src/` — returns no matches in prose (matches inside code blocks for literal K8s identifiers like `coxswain-shared-proxy` are fine).
4. Optional spot-check: `cd docs && mkdocs serve` and visit the rebuilt pages in a browser (especially the architecture diagram and any page where naming was changed). The skill prints the URL and pauses so the user can confirm visually.

If any verification step fails, the skill reports which step + the failure mode and asks the user whether to revert the in-this-session edits.

## How to invoke

The skill uses `Read` and `Bash` for the audit phase (grep, mkdocs build, gh issue view) and `Edit` / `Write` only during the apply phase, after each per-file user approval. It never invokes `mkdocs gh-deploy` or `mike deploy` — publishing is a release-pipeline concern (see `RELEASE.md`), not a maintenance concern.

Cap the audit report at ~500 lines. If the report threatens to exceed that, focus on BLOCKER and MAJOR findings only; drop MINOR / NIT.

## When to use

- When the user reports a docs page is drifting from the agreed conventions ("the architecture diagram is using the old name").
- After a naming framework change in the `feedback_proxy_terminology` memory — run the audit to find every page that needs to catch up.
- Periodically (e.g. before a milestone close), to catch incremental drift accumulated across small PRs.
- Before a release tag — pages with `PACKAGE_VERSION` substitution should render cleanly under the imminent version.

## When NOT to use

- For the four repo-root guardrail docs (`CLAUDE.md`, `DEVELOPMENT.md`, `CONTRIBUTING.md`, `RELEASE.md`). Use `/audit-guardrails` for those — it's the read-only sibling skill for the process-doc surface.
- For per-script header comments. Those are technically docs but they live with their script.
- For writing new feature pages. Authoring new pages is human-authored work; this skill maintains existing pages against the agreed convention.
- For rewriting the conventions themselves. If the framework changes, edit the **Conventions** section at the top of this file — that is the canonical source the audit grades against.
