---
name: add-rule
description: Before adding a project rule, pick the weakest mechanism that can actually decide it, and prove that mechanism can fail. Use when about to write a new rule into CLAUDE.md, when generalising a recurring review correction, or when a bug suggests a project-wide invariant. Triggers on "add a rule that X", "let's document X", "no one should do X anymore", "we keep getting hit by X".
---

Walk the enforcement decision BEFORE a rule lands anywhere.

## The failure this skill exists to prevent

This repo once had 19 `scripts/check-*.sh` gates and **no test for any of them**.
Four passed unconditionally for their entire life:

- `check-no-per-site-allow.sh` filtered two paths that could never appear in its
  own output — dead code, green forever.
- `check-e2e-single-poller.sh` matched `fn poll_until` *definitions only*, so a
  `kubectl wait --timeout=300s` shell-out lived inside the canonical waiter
  module, invisible to the gate whose stated purpose was preventing it.
- `check-public-types-stability.sh` matched `^\s*pub (enum|struct)` — bare `pub`
  only — so every `pub(crate)` type escaped it.
- `check-no-anyhow-libs.sh` grepped `src/` usage, not `Cargo.toml`.

The previous version of this skill told you to verify a new script by *running
it against the current tree to confirm it passes*. All four pass that check. A
gate reporting OK is indistinguishable from a gate that cannot fail.

**A green gate is worse than no gate: it certifies compliance nobody verified.**

## Step 1 — State the rule as an invariant

Imperative form: "X must happen" / "X must not happen". If given as a phenomenon
("we keep hitting X"), restate it as the invariant. Then ask the question that
kills most proposed rules:

> **What breaks if this is violated, and would anyone notice?**

Mechanical enforcement is justified when the failure is **silent or delayed** and
traceable to a real incident. If violating the rule produces something a reviewer
sees immediately, it is a convention — write it down if you like, but do not
build machinery for it. Consistency is not a defect.

## Step 2 — Pick the weakest sufficient mechanism

In order. Stop at the first one that can actually decide the rule.

**1. The compiler.** A clippy lint or `[workspace.lints]` entry, or a
`clippy.toml` `disallowed-{types,methods,macros}` entry. Best by far: it parses
Rust (no regex blind spots), and it runs inside the authoring loop for free.
Check whether the lint already exists before writing anything — `Result` is
already `#[must_use]`, `unused_must_use` is on by default, and
`return_self_not_must_use` covers builders.

Do **not** reach for `forbid`. It cannot be overridden by any `#[allow]`,
including ones injected by dependency macros: `#[tokio::test]` emits
`allow(clippy::expect_used)` and clap's `derive(Parser)` emits
`allow(clippy::style)`. Nothing here compiles under `forbid`.

**2. `deny.toml`.** For genuine dependency-graph rules (licences, sources,
advisories). Note `[bans]` + `wrappers` operates on the *graph*, so it cannot
express "our crates must not use X in their source" without enumerating every
vendor crate that happens to depend on X.

**3. A `scripts/check-*.sh` gate — only if it comes with a negative test.**
For cross-file, project-specific properties no compiler can see. See Step 3.

**4. A dimension in `.claude/agents/code-review.md`.** For rules that need
judgment: panic reachability, per-event allocation, doc quality,
architectural-vs-work-saving. These cannot be grepped and should not be faked
with a proxy metric — counting `///` presence measures nothing, since it is
satisfiable with pure noise.

**5. Prose in CLAUDE.md.** Last resort. Prose competes with the task for
attention and is followed unreliably. If you land here, ask: "what trigger makes
a future contributor discover this rule applies?" If the answer is "read
CLAUDE.md cover to cover and remember", the rule will drift — accept that
explicitly or tighten it.

## Step 3 — If it is a script, the fixture comes first

**Write `scripts/tests/<gate-name>/bad/` before writing the gate.** The `bad/`
tree is a miniature repo (mirroring `crates/<crate>/src/...`, since gates resolve
roots relative to cwd) containing the defect the rule forbids — ideally the one
that actually shipped, not a synthetic stand-in. Add a `good/` tree that must
pass. `scripts/tests/run.sh` picks both up automatically.

Then write the gate until `bad/` fails and `good/` passes.

Scope the gate from the real layout: `crates/*/{src,benches,tests}` and
`xtask/src`. Do not glob `crates/*/src/` and then filter paths that cannot appear
in that output — that is the exact bug in three of the four broken gates.

Wire it into `scripts/gates.sh` so it runs at authoring time via the
`PostToolUse` hook, not only in CI after a push.

## Step 4 — Verify by breaking it

Running the gate on a clean tree proves nothing. Two required checks:

1. `bash scripts/tests/run.sh` — the gate rejects `bad/` and accepts `good/`.
2. **Neuter the gate** (delete a grep clause, or point its root somewhere
   unmatchable) and confirm the self-test goes red. If it stays green, the
   fixture does not exercise the gate.

For a lint: introduce a real violation and confirm `cargo clippy` fails.

## Step 5 — Record it

Add a row to CLAUDE.md's "Enforced rules" table naming the mechanism — but only
once its negative test exists. A rule listed as enforced when it is not is worse
than an unlisted rule, because it stops anyone from looking.

Commit shape: fix pre-existing offenders, add the enforcement plus its fixture,
update the doc. First two can share a commit when the offender list is short.

## When NOT to use

- A question about an existing rule — just answer it.
- A `docs/src/` prose improvement — not a policy decision.
- A one-off design decision in the current PR — put it in the PR description.
- A consistency preference with no failure mode. Say so and move on.
