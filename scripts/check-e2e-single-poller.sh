#!/usr/bin/env bash
# Enforce the e2e charter's one-canonical-poller rule (no ad-hoc poll loops): the e2e
# suite must define `poll_until` exactly once — the canonical
# `crates/coxswain-e2e/src/harness/wait.rs` implementation — and the test bodies
# under `tests/` must define no poller of their own. A shadow poller drifts from
# the canonical timeout/diagnostics behaviour and reintroduces the very flakes
# the single-poller rule prevents.
#
# Run from the repo root. Exits non-zero on a duplicate or test-local definition.

set -euo pipefail

CRATE="crates/coxswain-e2e"
CANONICAL="$CRATE/src/harness/wait.rs"

# Count `poll_until` *definitions* (an `fn poll_until`, async or not) across the
# whole crate. References/calls are fine; only definitions are constrained.
defs=$(grep -rnE 'fn[[:space:]]+poll_until[[:space:]]*[(<]' "$CRATE" --include='*.rs' || true)
def_count=$(printf '%s' "$defs" | grep -c . || true)

# Any poller definition that lives outside the canonical file is an offender.
shadow=$(printf '%s\n' "$defs" | grep -v "^$CANONICAL:" | grep -v '^$' || true)

if [ "$def_count" -ne 1 ] || [ -n "$shadow" ]; then
  echo "FAIL: expected exactly one 'poll_until' definition ($CANONICAL), found $def_count:" >&2
  printf '%s\n' "$defs" | sed 's/^/  /' >&2
  echo "" >&2
  echo "Per the e2e charter, delete the shadow poller and route waits through" >&2
  echo "'wait::poll_until' (or add a wait_for_* wrapper there)." >&2
  exit 1
fi

# NOTE: this gate does not catch a `kubectl wait` subprocess used as a waiter —
# which is how `wait.rs::wait_for_deployments` hid a shadow poller (its own
# `--timeout=300s`, and a failure carrying no world state) inside this very
# module. That call site is now routed through `poll_until`, but the *rule* is
# still unenforced.
#
# It is deliberately not enforced here rather than enforced badly: the pattern
# spans lines (`Command::new("kubectl")` then `.args(&["wait", ...])`), so a
# line-oriented grep misses it, and `bootstrap.rs` makes legitimate `kubectl
# wait` calls for one-time cluster bring-up (cert-manager, CRD establishment)
# that a naive match would flag. A check that is both too narrow and too broad is
# worse than none — it reports OK while missing the real case.
echo "OK: exactly one 'poll_until' definition ($CANONICAL); no shadow pollers."
