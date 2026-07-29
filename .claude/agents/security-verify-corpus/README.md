# security-verify corpus

Fixtures that measure whether `.claude/agents/security-verify.md` actually
refutes.

A refuter that concedes everything is an amplifier: it turns every plausible
hypothesis into a filed issue and the audit's precision collapses. A refuter that
kills everything is worse — it silently suppresses real breaks and the audit
reports clean. Both failure modes look identical from the outside, which is why
this is measured in **both directions**, exactly like the `code-review` corpus.

Every case is drawn from this repository's real code at `78a2d363`. The
`refuted/` cases are not strawmen: each is an attack that genuinely works against
many ingress controllers, is the first thing a competent auditor tries, and is
stopped here by a specific control that the agent has to find. An agent that
concedes them is not being cautious — it has failed to read.

## Cases

`confirmed/` — each must return `CONFIRMED`. All three are live findings filed
against v0.6.

| Case | Surface | Why it is real |
|---|---|---|
| `01-shared-pool-subscribe-unauthorized.md` | `discovery-subscribe-authz` | `Scope::SharedPool` has no open-time identity check and bootstrap has no allowlist, so an RBAC-less pod reaches every shared TLS private key. #726 |
| `02-ingress-hostname-mtls-denial.md` | `ingress-hostname-claims` | Client-cert config is keyed by `(port, host)` with no ownership check and is last-writer-wins; an unresolvable CA fails closed for that SNI. #727 |
| `03-xff-private-range-skip.md` | `http-client-ip` | The rightmost-untrusted walk skips private ranges as well as trusted hops, so a privately-sourced client controls the returned address. #731 |

`refuted/` — each must return `REFUTED`, **naming the control below**. A
`REFUTED` verdict with no `file:line`, or with a doc comment as the control, is a
failure even though the verdict letter is right.

| Case | The control it must find |
|---|---|
| `01-jwt-algorithm-confusion.md` | `crates/coxswain-proxy/src/policy/auth.rs:919-979` — the verification algorithm comes from the **JWK's** declared `alg`, never the token header, and `oct` key material is rejected outright. The adversarial unit test at `:1132-1147` is the same attack. |
| `02-jwks-uri-metadata-ssrf.md` | `crates/coxswain-reflector/src/egress.rs` — `EgressPolicy` denies all 24 reserved ranges including `169.254.0.0/16` by default; `GuardedResolver` enforces on the **resolved** address, and `jwks.rs:fetch_one` separately checks a literal-IP host because it bypasses the resolver. Plaintext `http://` additionally requires an operator allowlist entry. |
| `03-tls-resumption-skips-mtls.md` | `crates/coxswain-proxy/src/edge/accept.rs:1604-1611` — the shared acceptor sets `SslSessionCacheMode::OFF` and `SslOptions::NO_TICKET`, disabling resumption specifically so a resumed handshake cannot skip per-SNI mTLS. The comment there names this attack. |

## Running it

Dispatch the agent once per case file, handing it only that file's contents plus
the repository. Compare against the tables above and report both numbers:

- **Recall** — `confirmed/` cases returned `CONFIRMED`, out of 3.
- **False-refutation rate** — `confirmed/` cases wrongly `REFUTED`, out of 3.
  Target 0. This is the dangerous direction: a wrongly-refuted finding is a real
  break that the audit reports as safe.
- **Precision** — `refuted/` cases returned `REFUTED` **with the right control**,
  out of 3. Citing a different control, or prose, does not count.

`UNPROVEN` is scored separately and is not a failure on its own; a run that
returns `UNPROVEN` for a `refuted/` case has not found the control but has also
not falsely conceded, which is the acceptable degradation.

`.claude/agents/` is loaded at session start, so a freshly-edited agent is only
dispatchable after a restart. To measure it in the same session, have a
`general-purpose` agent read `security-verify.md` and adopt its body as
instructions — the same workaround the `code-review` corpus documents.

## Maintaining it

Every finding that survives an audit's refutation phase and turns out to be
**wrong** gets added to `refuted/` with the control that should have caught it.
Every finding that is refuted and turns out to be **real** gets added to
`confirmed/`. The corpus is how the refuter's calibration is retained across
prompt edits rather than rediscovered.

Keep the counts balanced. A corpus that drifts toward `confirmed/` trains the
reader of these results to expect concessions.

## Results

Recorded per run, newest first. A regression means the agent prompt drifted and
needs repair — not that the corpus is wrong.

### Initial run (agent introduced), 78a2d363

**Recall 3/3. False-refutation 0/3. Precision 3/3** (every `REFUTED` cited an
executing control at `file:line`; none cited a doc comment or test name).

`confirmed/`: all three returned `CONFIRMED`, each restating the path in the
agent's own `file:line`s rather than the ones it was handed — `01` traced
through `token_review.rs` and `bootstrap_server.rs` to the missing `SharedPool`
arm in `server/mod.rs`; `02` through the reflector fold in `route_builder.rs` to
the fail-closed `Unavailable` state in `edge/tls.rs`; `03` through
`resolve_client_ip` to the same downstream `RateLimitKey::ClientIp` consumer,
found independently (see below).

`refuted/`: all three named the real control and, for `03`, correctly refused to
credit the `//!` SECURITY comment that describes the exact attack — it based the
verdict on the two executing lines the comment describes, not the comment
itself. `01` and `02` each additionally verified two or three plausible pivots
around the primary control (symmetric-key JWK, redirect-based SSRF, proxy-env
smuggling) rather than stopping at the first block.

Each run also surfaced something outside its assigned claim, correctly kept
under `ADJACENT` rather than folded into the verdict:

- **`01`'s `ADJACENT`** is a second, independent finding: `bootstrap_server.rs:483-487`
  degrades an undecodable `scope` DTO to `Scope::SharedPool` via
  `.unwrap_or(Scope::SharedPool)`, where the sibling stream handler rejects the
  same input with `INVALID_ARGUMENT` — a fail-open shape on the bootstrap
  surface distinct from the missing-authorization claim it was asked to verify.
- **`01` also surfaced that this exact path already has a live e2e** —
  `coxswain-e2e/tests/discovery.rs:799-1000` runs a rogue pod through this
  identical bootstrap-then-SharedPool-subscribe sequence and asserts, in the
  test's own comment, "the rogue DOES connect (Subscribe/connect is scope-only,
  not identity-gated)". The behaviour is tested and documented as current
  behaviour, not merely unnoticed — #726 is filed against a gap the suite
  already demonstrates rather than one nothing exercises.
- **`02`'s `ADJACENT`** found the same unfiltered cluster-wide Ingress fold
  reaches the **server**-cert store by the identical mechanism (`ingress/tls.rs`
  → `core/tls.rs:386-402`, sorted ECDSA-first/newest-`notAfter`-first with no
  ownership check) — the cert-displacement variant of #727, not just the
  mTLS-denial variant the claim named.
- **`03`'s `ADJACENT`** found the same forged `client_ip` also keys per-client
  rate limiting (`policy/rate_limit.rs:187`), so the XFF forgery lets an
  attacker rotate rate-limit buckets per request, not only bypass
  `IpAccessControl`.
- **`03`'s CONFIRMED path** cited the repo's own unit test
  (`access_control.rs:327-331`) as executing evidence for the exploit shape —
  correctly, since a unit test asserting `rightmost_untrusted_ip` returns the
  forged address *is* the vulnerable behavior running, not a claim about it.

No regression to chase, and no corpus edit needed before relying on this run's
`/security-audit` output.
