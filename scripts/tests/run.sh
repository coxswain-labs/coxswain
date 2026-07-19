#!/usr/bin/env bash
# Negative tests for the repo's quality gates.
#
# A gate that cannot fail is not a check — it is a green light nobody reads.
# Four of the gates in this repo passed unconditionally for their whole life
# (dead path filters, definition-only matching, bare-`pub`-only regexes), and
# none of that was visible because no test ever asserted a gate rejects
# anything. This harness makes "the gate fires" an executable claim.
#
# Layout — one directory per gate under `scripts/tests/<gate-name>/`:
#
#   good/   a miniature repo tree the gate MUST accept (exit 0)
#   bad/    a miniature repo tree the gate MUST reject (exit non-zero)
#
# The trees mirror the real repo layout (`crates/<crate>/src/...`), because the
# gates resolve their scan roots relative to the working directory and document
# "run from the repo root". Running a gate with `cd`-into-fixture therefore
# exercises the real script, unmodified, against controlled input.
#
# Each `bad/` fixture encodes a defect that was actually shipped or that the
# gate's own header claims to prevent — not a synthetic one.
#
# Run from the repo root. Exits non-zero if any gate fails either direction.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TESTS_DIR="$REPO_ROOT/scripts/tests"

pass=0
fail=0

fail_msg() {
  printf '  \033[31mFAIL\033[0m  %s\n' "$1" >&2
  fail=$((fail + 1))
}
pass_msg() {
  printf '  \033[32mok\033[0m    %s\n' "$1"
  pass=$((pass + 1))
}

for gate_dir in "$TESTS_DIR"/*/; do
  gate="$(basename "$gate_dir")"
  script="$REPO_ROOT/scripts/${gate}.sh"

  if [ ! -x "$script" ] && [ ! -f "$script" ]; then
    fail_msg "$gate: no such gate script ($script)"
    continue
  fi

  # good/ must be accepted.
  if [ -d "$gate_dir/good" ]; then
    if (cd "$gate_dir/good" && bash "$script" >/dev/null 2>&1); then
      pass_msg "$gate: accepts good/"
    else
      fail_msg "$gate: REJECTED good/ (false positive)"
    fi
  fi

  # bad/ must be rejected. This is the direction that has never been tested.
  if [ -d "$gate_dir/bad" ]; then
    if (cd "$gate_dir/bad" && bash "$script" >/dev/null 2>&1); then
      fail_msg "$gate: ACCEPTED bad/ — the gate does not fire"
    else
      pass_msg "$gate: rejects bad/"
    fi
  fi
done

echo ""
if [ "$fail" -gt 0 ]; then
  echo "gate self-tests: $pass passed, $fail FAILED" >&2
  exit 1
fi
echo "gate self-tests: $pass passed, 0 failed"
