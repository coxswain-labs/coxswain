#!/usr/bin/env bash
# Enforce e2e rubric #4 ("poll the real post-condition, never sleep"): no bare
# sleep CALL in the e2e test bodies under `crates/coxswain-e2e/tests/`. A fixed
# wait races with the cluster — every blind wait must route through
# `wait::poll_until`, which polls a real post-condition with a generous deadline.
#
# Scope is the test bodies only. Harness poll-interval sleeps in
# `crates/coxswain-e2e/src/harness/` are legitimate (they ARE the poller's
# interval, e.g. `wait::poll_until`'s `time::sleep(interval)`), so they're out of
# scope here. `Duration::from_secs(..)` is NOT matched — in `tests/` those are
# timeout *arguments* passed to waiters, not sleeps.
#
# Run from the repo root. Exits non-zero with a list of offending sites.

set -euo pipefail

TESTS_DIR="crates/coxswain-e2e/tests"

# Match a sleep call expression: `sleep(`, `time::sleep(`, `thread::sleep(`,
# `tokio::time::sleep(` (with optional whitespace before the paren). This is the
# blocking/async wait we forbid; `Duration` literals are deliberately untouched.
offenders=$(grep -rnE '(^|[^a-zA-Z0-9_])(tokio::time::|time::|thread::|std::thread::)?sleep[[:space:]]*\(' \
  "$TESTS_DIR" --include='*.rs' || true)

if [ -n "$offenders" ]; then
  count=$(printf '%s\n' "$offenders" | wc -l | tr -d ' ')
  echo "FAIL: $count bare sleep call(s) in e2e test bodies:" >&2
  printf '%s\n' "$offenders" | sed 's/^/  /' >&2
  echo "" >&2
  echo "Per e2e rubric #4, replace the fixed wait with a real post-condition:" >&2
  echo "route the wait through 'wait::poll_until' (or a wait_for_* wrapper)." >&2
  exit 1
fi

echo "OK: no bare sleep calls in $TESTS_DIR — all waits poll a post-condition."
