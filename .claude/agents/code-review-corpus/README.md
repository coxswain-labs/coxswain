# code-review corpus

Fixtures that measure whether `.claude/agents/code-review.md` actually works.

An untested review agent is the 19 untested gate scripts again with more tokens:
it emits confident prose, and nothing distinguishes a version that catches real
defects from one that has quietly stopped. Unlike a script it is also
non-deterministic, so it can regress without any edit.

**Measured in both directions.** Recall alone is the wrong target: an agent tuned
only to catch things learns to flag everything, becomes noise, and gets ignored
within a week — which is strictly worse than no reviewer, because it also
consumes attention. So the corpus carries clean controls that must produce an
empty report.

## Cases

`bad/` — each must be caught. All are drawn from defect classes this repo has
actually shipped or that CLAUDE.md names explicitly.

| Case | Dimension | Defect |
|---|---|---|
| `01-panic-reachable-by-config.rs` | panic reachability | `panic!` on a parse of an **operator-supplied** bind address. Config reaches it, so it is not an invariant — it is a missing typed `Err`. Fails the reachability test in CLAUDE.md. |
| `02-alloc-in-request-filter.rs` | per-event allocation | Three per-request allocations on the HTTP hot path: a `format!` route key, a `.clone()` of it, and a `Vec<String>` of formatted headers built even when the debug subscriber is off. |
| `03-tenant-unbounded-retry.rs` | tenant-controlled input | `max_retries` and `backoff_ms` come from a namespace user's HTTPRoute CR. Unbounded values turn one inbound request into arbitrarily many upstream requests held for arbitrarily long — an amplification vector. |
| `04-narrating-doc-stringly-error.rs` | doc quality + error typing | `/// Resolves the backend policy.` on `resolve_backend_policy` restates the name; `# Errors` says only *that* it fails. `Result<_, String>` is stringly-typed where a `thiserror` variant belongs. |

`good/` — each must produce **no** finding.

| Case | Why it is correct |
|---|---|
| `01-invariant-panic-is-fine.rs` | The `debug_assert!` guards a condition only reachable by a logic bug in the same file — no config, peer bytes, or contention path reaches it. This is the one shape CLAUDE.md permits. |
| `02-cold-path-alloc-is-fine.rs` | The `format!` is on the error branch, paid once per failing request rather than per request. The hot path reads an `ArcSwap` snapshot and allocates nothing. |

## Running it

The agent is dispatched per directory and its findings compared to the tables
above. Report both numbers:

- **Recall** — bad cases caught / 4.
- **False-positive rate** — findings raised across `good/` (target: 0).

A run that catches all four but flags a clean control has *not* passed. Note
that `.claude/agents/` is loaded at session start, so a freshly-edited agent is
only dispatchable after a restart; to measure it in the same session, have a
`general-purpose` agent read `code-review.md` and adopt its body as
instructions.

## Results

Recorded per run, newest first. A regression here means the agent prompt drifted
and needs repair — not that the corpus is wrong.

### Initial run (agent introduced)

**Recall 4/4. False positives 0/2.**

All four planted defects were caught, in two independent runs. The clean-control
run returned an empty report and explicitly discarded two candidates rather than
padding — one because clippy already covers it (`unused_mut`), one because it
could not be stated as inputs → failure.

The agent also found defects that were **not** planted, which is the outcome
worth protecting:

- **Unbounded metric cardinality** in `bad/02` — the metric label embeds the raw
  request path, so an unauthenticated client minting distinct paths creates one
  permanently-retained time series per request. Found by both runs
  independently. This is a real availability bug the fixture author missed.
- **Credential leakage** in `bad/02` — the header dump formats `Authorization`
  and `Cookie` into a debug log the cluster aggregator persists.
- **`uri.host()` returns `None` for HTTP/1.1 origin-form requests**, so the
  host label silently collapses to `""` across every virtual host.
- Non-idempotent retry replay (a lost response to `POST` duplicates the write)
  and unjittered fixed backoff synchronising a retry cohort onto a recovering
  upstream, both in `bad/03`.

It grounded claims before reporting them — checking that no existing
`with_label_values` call site in the repo uses an open-set label, and that bind
addresses are already typed at the clap boundary (`coxswain-bin/src/services.rs`),
which is the fix `bad/01` declines to use.

Note the fixtures are therefore *richer* than the table above describes. Keep the
table as the pass/fail bar; treat the extras as evidence the agent reads rather
than pattern-matches.
