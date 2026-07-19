#!/usr/bin/env bash
# Enforce the e2e charter's execution-class-by-behaviour-plane rule: every top-level
# integration-test file under `crates/coxswain-e2e/tests/` must be one of the
# approved planes. The by-plane layout is what makes the parallel/serial boundary
# fall out of the file structure; an unclassified grab-bag file (`misc.rs`,
# `tmp.rs`) silently escapes that classification.
#
# Subdirectories (e.g. `tests/common/`) hold shared helpers, not test binaries,
# so they're out of scope — only the top-level `tests/*.rs` are planes.
#
# Run from the repo root. Exits non-zero listing any off-plane file.

set -euo pipefail

TESTS_DIR="crates/coxswain-e2e/tests"

# The approved set of behaviour planes. A test belongs to the plane of its
# *primary assertion target* (see each file's header). Keep this sorted.
ALLOWED=(
  discovery
  observability
  provisioning
  resilience
  routing
  security
  status_conditions
  tls
  traffic_policy
)

offenders=()
while IFS= read -r path; do
  stem=$(basename "$path" .rs)
  ok=0
  for plane in "${ALLOWED[@]}"; do
    if [ "$stem" = "$plane" ]; then ok=1; break; fi
  done
  if [ "$ok" -eq 0 ]; then
    offenders+=("$path")
  fi
done < <(find "$TESTS_DIR" -maxdepth 1 -name '*.rs' -type f | sort)

if [ "${#offenders[@]}" -gt 0 ]; then
  echo "FAIL: ${#offenders[@]} e2e test file(s) outside the approved plane set:" >&2
  printf '  %s\n' "${offenders[@]}" >&2
  echo "" >&2
  echo "Per the e2e charter, place the test in the plane of its primary assertion" >&2
  echo "target. Approved planes: ${ALLOWED[*]}." >&2
  exit 1
fi

count=$(find "$TESTS_DIR" -maxdepth 1 -name '*.rs' -type f | wc -l | tr -d ' ')
echo "OK: $count e2e test file(s) all belong to an approved behaviour plane."
