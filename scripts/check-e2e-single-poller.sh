#!/usr/bin/env bash
# Enforce e2e rubric #4/#9 (one canonical poller; no ad-hoc poll loops): the e2e
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
  echo "Per e2e rubric #4/#9, delete the shadow poller and route waits through" >&2
  echo "'wait::poll_until' (or add a wait_for_* wrapper there)." >&2
  exit 1
fi

echo "OK: exactly one 'poll_until' definition ($CANONICAL); no shadow pollers."
