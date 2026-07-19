# e2e-triage corpus

Fixtures that measure whether `.claude/agents/e2e-triage.md` actually works.

Triage is judgment work with an expensive error in both directions: calling a
regression a flake ships a bug and teaches everyone to re-run red suites;
calling an environment problem a regression burns hours on code that is fine.
So the corpus deliberately mixes classes — an agent that answers "environment"
to everything scores as badly as one that answers "regression" to everything.

## Cases

Each `cases/*.log` is a run's output plus the operator context captured after it.

| Case | Correct verdict | The tell |
|---|---|---|
| `01-mutator-cliff.log` | shared-fixture damage | 25 failures across four unrelated planes, all at exactly 30.0s, while the proxy pod is `Running` with a clean log that reads `proxy_protocol=required`. Mass cliff + healthy proxy. |
| `02-stale-image.log` | environment (stale image) | `imageID` digest was pulled 3 days ago though the tag was just rebuilt; the asserted-against reason is the *pre-change* value. Code under test is not deployed. |
| `03-orbstack-udp.log` | environment (OrbStack UDP) | Context is `orbstack`, and 100 of 200 datagrams were never received — loss, not misdistribution. Single-backend UDP and weighted HTTP both pass. |
| `04-real-regression.log` | real regression | Failed 3/3 including twice in isolation, 60/61 siblings pass, and the response is a confident **200 from the wrong backend** — a race yields a timeout or 404, never that. |

`04` is the load-bearing control: an agent biased toward "flaky, re-run it" fails
here, and that is the failure mode that actually costs releases.

## Running it

Dispatch the agent over all four cases at once, as unrelated runs, and compare
verdicts to the table. Report **verdicts correct / 4**.

`.claude/agents/` is loaded at session start, so a freshly-edited agent is only
dispatchable after a restart; to measure in the same session, have a
`general-purpose` agent read `e2e-triage.md` and adopt its body as instructions.

## Results

Newest first. A regression here means the agent prompt drifted — not the corpus.

### Initial run (agent introduced)

**4/4 verdicts correct.**

Each verdict came with the observation that ruled out the other classes, and no
case was resolved as "re-run it". Beyond the table, the run produced findings the
fixtures did not encode:

- **Case 01** — noticed the proxy pod's `AGE` (2m) exceeded the whole run's
  duration (31.9s), so the release was *already* mutated before the run started;
  and that the mutator test **passed**, which the mutate-mid-run hypothesis
  cannot explain. It then found that an explicit `-E` selection **replaces**
  nextest's `default-filter`, so a correctly-placed `mod serial` test can still
  be pulled into the parallel pass. Concluded the missing invariant is
  teardown/restore rather than serialization — a different fix than the one the
  fixture was built around, and a better one.
- **Case 03** — identified a sharper discriminator than the fixture's: `100 of
  200 datagrams were never received` is loss, whereas a weighting regression
  would deliver ~200 with a skewed split. Also observed that a permanently-red
  known-environmental case trains people to ignore the suite, so it should be
  skipped rather than reported failing.
- **Case 04** — localized the bug without a cluster: `coxswain-core`'s wildcard
  tests construct the routing table with an explicit `WildcardKind`, so they
  never exercise kind *selection*; the defect must sit upstream in the reflector
  or in the controller→proxy wire bool. Named the two candidate files and a
  seconds-long command to discriminate.

It also flagged a genuine coverage hole: every wildcard-kind test lives within a
single layer, and nothing asserts a multi-label Gateway listener survives
reflector → wire → proxy intact.
