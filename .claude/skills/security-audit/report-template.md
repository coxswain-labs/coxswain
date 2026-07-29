# Report shape

The output contract. Deviating from it breaks run-to-run comparison, which is
the only thing this skill is for.

**The coverage matrix comes first, before any finding.** A findings list is not
comparable across runs — two runs can both look thorough and share nothing. A
matrix makes the delta explicit, and makes a row that quietly stopped being
examined as visible as a new break.

---

## 1. Header

```
Security audit — <commit> (<date>)
Previous pass: <commit> (<date>)
Rows: <n> total · <n> safe · <n> finding · <n> unverified
Drift: <n> new rows added · <n> stale anchors
```

## 2. Coverage matrix

Every row in the register. No omissions, no "N/A".

| Surface | Boundary | Verdict | Δ vs last | Evidence / why |
|---|---|---|---|---|
| `discovery-subscribe-authz` | TB4 | finding | = | `server/mod.rs:293-297` defaults to SharedPool |
| `auth-jwt` | TB1 | safe | = | alg from JWK, `policy/auth.rs:919-979` |
| `podtemplate-overlay` | TB2 | unverified | ⚠ was safe | filter implementation not read |

`Δ` values: `=` unchanged · `NEW` first audit of this row · `↑` improved ·
`↓` regressed · `⚠` coverage lost (anything → `unverified`).

**A `⚠` is reported as prominently as a new finding.** A row that silently
stopped being examined is how an audit rots into theatre.

## 3. Findings

Only refuted-and-survived candidates. One block each, severity-ordered per
`severity.md`:

```
### <severity> — <what the attacker achieves>
Surface: <row id> · Reachability: R<n> · Asset: A<n> · Adversary: AC<n>

Precondition: <what the attacker must already hold>
Attack:       <concrete inputs, in order>
Path:         <file:line → file:line>
Exposure:     <the asset, named>
Existing issue: #<n> | none — proposed below
Gate on fix:  <check-*.sh name | e2e name | manual: true, because …>
```

A block missing `Precondition`, `Attack`, or `Path` does not belong in this
section — it belongs in §5 as a hypothesis.

## 4. Refuted

Every candidate that did not survive Phase 3, with the control that killed it
and its `file:line`. This section is not filler: it is what stops the same false
positive being re-derived next run, and it is the honest record of what the
audit considered.

| Candidate | Killed by |
|---|---|
| ext_authz reachable without a grant | `reference_grants.rs:…` fails closed on an absent grant |

## 5. Coverage gaps

Every `unverified` row, with what it would take to close it. Ordered by the
severity the row *would* carry if the hypothesis holds — an unexamined R1/A1
surface is the most important line in the whole report.

| Surface | Hypothesis | To close |
|---|---|---|
| `podtemplate-overlay` | tenant overlay may reach a field the envelope does not re-assert | read the filter, enumerate re-asserted fields against the PSS restricted set |

## 6. Register diff

The `git diff` of `.claude/security/surface.yaml`. The register is checked in, so
this diff is the audit's permanent record — the report itself is disposable.

## 7. Proposed issues

Title, labels, milestone, `Track`, `Order`, and the body per the house style.
**Ask before filing.**
