---
name: security-audit
description: Repeatable security audit of the coxswain workspace — threat model, per-surface verification, adversarial refutation, and a full-coverage matrix diffed against the previous run. Use when the user asks to audit security, threat-model the project, check for vulnerabilities, or re-verify after a wave of changes. Reads the checked-in attack-surface register at .claude/security/surface.yaml, returns a verdict for every row (never a bare findings list), refutes each candidate before reporting it, dedupes against open issues, and writes the register back.
---

A security audit whose findings differ every run is not an audit — it is a
sample. This skill exists to make the sampling deterministic.

The variance in an ad-hoc audit does not come from the prompt. It comes from
**the enumeration being inferred at runtime**: with no fixed target list, each
run decides afresh what to look at across ~130k lines, examines a different
subset, and reports a different set of findings. A better prompt improves each
sample; it does not make two samples comparable.

So the enumeration lives in `.claude/security/surface.yaml`, and this skill's
contract is: **every row gets a verdict, every run.** What remains variable is
per-row judgement, which is far more stable and — because the output is a matrix
rather than a list — diffable against the previous run.

## Rules (meta)

1. **Prose is never evidence.** A doc comment, a `//!` header, a `docs/src/`
   page, or a test *name* proves nothing about behaviour. Read the executing
   path. This repo's prose is unusually good, which makes trusting it cheap and
   wrong: a prior audit credited ReferenceGrant revocation as sound on the
   strength of a passing revocation e2e while #692 sat in the epoch fold.
2. **Every row ends at `safe`, `finding`, or `unverified`.** `unverified` is a
   legitimate answer and must carry a `why`. Omitting a row is not — silence is
   indistinguishable from safe, and that is precisely the failure this skill
   exists to remove.
3. **No finding without a reproducer.** Adversary class, precondition, concrete
   input, code path with `file:line`, asset exposed. Missing any one → record it
   as `unverified` with the hypothesis, not as a finding.
4. **Do not re-flag what a gate already decides.** Enumerate `scripts/check-*.sh`
   and the `deny`-level lints first; a finding CI mechanically catches is noise.
5. **Audit ≠ fix.** This skill writes a report, updates the register, and
   proposes issues. Code changes happen after the user picks.

## Phase 0 — Orient

1. Read `.claude/security/surface.yaml`. It is the target list.
2. Read `CLAUDE.md` and `.claude/skills/security-audit/severity.md`.
3. Enumerate what CI already decides — `ls scripts/check-*.sh` and the
   `[workspace.lints]` `deny` entries — so those questions are not re-litigated.
4. `git log --oneline "$(yq .audited_at .claude/security/surface.yaml)"..HEAD`
   — everything since the last pass is the highest-yield area. Fresh code is
   where the register is most likely to be stale.

## Phase 1 — Drift check (before any analysis)

The register decays into a comfortable checklist unless reality is enumerated
against it. Mechanically enumerate, then diff:

| What | How |
|---|---|
| Bound listeners | `ListenerSpec` construction sites and the health/telemetry/operator/discovery ports in `charts/coxswain/values.yaml` |
| gRPC surface | every `rpc` in `proto/coxswain/discovery/v1/discovery.proto` |
| Secret-bearing wire fields | proto fields matching `key\|secret\|password\|token\|jwks\|cert\|credential` |
| Tenant-writable input | `crates/coxswain-core/src/crd/` spec fields; every `ingress.coxswain-labs.dev/*` annotation |
| RBAC | every rule in `charts/coxswain/templates/controller-rbac.yaml` and `deploy/manifests/` |
| Controller egress | every `reqwest`/`hyper` client construction outside `coxswain-e2e` |
| HTTP routes on management ports | the dispatch table in `crates/coxswain-admin/src/lib.rs` |

Anything present in reality and absent from the register becomes a new row,
audited this run. Anything in the register whose `anchors` no longer resolve is
a **finding about the register** — the surface moved and the row went stale.

## Phase 2 — Verify each row

Dispatch one subagent per boundary (`TB1`…`TB6`), in parallel, each handed only
its own rows. Every agent prompt carries:

- the rows verbatim, including each row's `asks` — those are the questions that
  make the row reproducible across runs, and they are answered in order;
- Rule 1 (prose is never evidence) and Rule 3 (no finding without a reproducer),
  restated in full;
- the CI exclusion list from Phase 0;
- "Return one entry per row with `verdict`, `evidence` (file:line for `safe` and
  `finding` alike), and for `unverified` a `why` naming what was not read."

A `safe` verdict needs evidence too. "I looked and found nothing" is not a
verdict; "the check is at `file:line` and covers case X" is.

## Phase 3 — Refute

Every candidate `finding` goes to the `security-verify` agent, which is
instructed to **break** it: name the control that stops the attack, with
`file:line`, or concede. Only conceded findings survive to the report. Refuted
candidates are recorded in the run log with the control that killed them —
that record is what stops the same false positive reappearing next run.

Findings that survive but whose reproducer the refuter could not follow are
downgraded to `unverified` with the disagreement noted, never silently kept.

## Phase 4 — Dedupe and score

1. `gh issue list --state all --search "<surface keyword>"` for each surviving
   finding. An existing issue means the row's `findings` list gets the number,
   not a new issue.
2. Score with the fixed rubric in `severity.md`. It is a lookup, not a judgment
   call — two runs that agree on reachability and asset tier produce the same
   severity, which is what makes the ranking reproducible.

## Phase 5 — Report and write back

1. Emit the report per `report-template.md`: **coverage matrix first**, then
   findings, then the coverage gaps as their own section. A findings list alone
   cannot be compared across runs.
2. Diff every row's verdict against the register's stored value and render the
   delta. A `safe` → `unverified` transition is a regression in coverage and is
   called out as loudly as a new finding.
3. Write the register back: updated `verdict`, `evidence`/`why`, `findings`,
   `audited`, and the new `audited_at` / `audited_on` at the top. The register is
   checked in, so the diff *is* the audit history.

## Phase 6 — Close the loop

Every confirmed finding must leave behind something that answers its question
without a model next time. Per CLAUDE.md's weakest-mechanism ladder:

1. a `scripts/check-*.sh` gate with a `scripts/tests/<gate>/{good,bad}` fixture
   pair, where the question is grep- or parse-decidable (e.g. *a new `Scope::`
   variant may not be added without an arm in the subscribe authorization
   match*) — cheapest, and it fires in the authoring loop;
2. otherwise an **attack test** in the `security` e2e plane;
3. otherwise the row is flagged `manual: true` and re-verified every run.

An attack test is not a feature test. A feature test is written from the
control's specification — *a valid credential is admitted, an invalid one is
rejected, a missing CR fails closed*. An attack test is written from the
attacker's goal, and asserts on the **asset they must not reach**, usually on a
path the feature's author never considered. Both belong in the suite; only the
second discharges a finding.

Three requirements, all load-bearing:

- **It must have been observed red against the unfixed code.** CLAUDE.md already
  holds `scripts/check-*.sh` to this bar via its `{good,bad}` fixture pair; the
  e2e suite has never been held to it. #692 is what that costs: a revocation e2e
  passes green while revocation does not land, because the test exercises a grant
  shape whose epoch contribution does not cancel.
- **It is named for the attack and the asset**, not the feature —
  `foreign_namespace_cannot_claim_hostname_tls`, not
  `ingress_tls_cert_selection`. Greppable by intent.
- **The register row records which test owns its question**, so the next audit
  can see at a glance which rows are still carried by model attention alone.

**The gate encodes the attack, not the feature.**

`manual: true` is reserved for questions a test structurally cannot decide —
universal negatives ("no other path reaches this", "the re-asserted field list is
complete"). Keep the count small and watch it: a growing manual set means the
architecture is accumulating claims nothing can falsify.

## Proposing issues

One issue per finding, in the house style — `## Problem`, `## Evidence`
(file:line), `## Attack`, `## Resolution`, `## Notes`. Title is
`fix(<scope>): <what an attacker achieves>`, never `<what is missing>`. Labels:
a `priority:`, `area: security`, the affected `area:`/`api:`, and `type: bug`.
Milestone and `Track: Security` on the project board; `Order` per the severity
rubric's placement rule.

Ask before filing. The user picks the milestone.
