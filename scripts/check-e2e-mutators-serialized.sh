#!/usr/bin/env bash
# Enforce the e2e global-config-mutator serialization invariant: every test
# that reconfigures the ONE shared Helm release (any test whose body constructs
# non-default `ControllerOptions` / calls `start_with_options`) must be
# EXCLUDED from the parallel `e2e` profile AND INCLUDED in the serial
# `e2e-serial` profile — or live in an always-serial binary. A mutator running
# in the parallel pass rolls the shared proxy mid-run (e.g. into
# PROXY-protocol-required mode) and every concurrent plain-HTTP test then fails
# with connection resets: the exact 20+-test "cliff" that broke the security
# suite (#529).
#
# This is FAST STATIC FEEDBACK. The airtight enforcement is the runtime guard in
# `helm_install` (crates/coxswain-e2e/src/harness/bootstrap.rs): a non-default
# HelmOverrides under a nextest process without COXSWAIN_E2E_SERIAL=1 panics at
# the mutation site, so a mutator constructed via a helper the grep below can't
# attribute still fails loudly (just at run time, not lint time). This script
# catches the common literal cases before the expensive e2e run.
#
# The nextest filters use exact `test(=name)` matches, which fail SILENTLY on
# rename or addition — so this gate also fails on stale filter entries that no
# longer match any test (the drift signature of a rename).
#
# Detection scope: `ControllerOptions`-based mutators whose literal sits inside
# the test's own `async fn`. Mutations via a shared helper, or that don't go
# through ControllerOptions (e.g. a global catchall route), are covered by the
# runtime guard, not here; keep those in the filters by hand.
#
# Run from the repo root. Exits non-zero listing every violation.

set -euo pipefail

TESTS_DIR="crates/coxswain-e2e/tests"
NEXTEST_TOML=".config/nextest.toml"

fail=0

# Binaries excluded wholesale from the parallel profile (`and not binary(X)`).
# `|| true` keeps `set -e`/pipefail from killing the script silently when the
# pattern matches nothing (a refactor that drops whole-binary exclusions must
# still produce readable output, not a bare exit 1).
serial_binaries=$( { grep -oE 'and not binary\([a-z_]+\)' "$NEXTEST_TOML" || true; } \
  | sed -E 's/and not binary\(([a-z_]+)\)/\1/' | sort -u)

# Slice the two profile bodies so membership can be checked PER PROFILE (a name
# listed twice in one profile and zero times in the other must NOT pass). The
# `e2e` body runs from its header to the `e2e-serial` header; the `e2e-serial`
# body from its header to EOF.
e2e_body=$(awk '/^\[profile\.e2e\]/{f=1} /^\[profile\.e2e-serial\]/{f=0} f' "$NEXTEST_TOML")
serial_body=$(awk '/^\[profile\.e2e-serial\]/{f=1} f' "$NEXTEST_TOML")

# 1. Every ControllerOptions-constructing test is serialized: excluded from the
#    e2e body AND included in the e2e-serial body (or in a serial-only binary).
mutators=$(for f in "$TESTS_DIR"/*.rs; do
  awk -v bin="$(basename "$f" .rs)" '
    /async fn /       { fn=$0; sub(/.*async fn /, "", fn); sub(/\(.*/, "", fn) }
    /ControllerOptions \{|start_with_options\(/ {
      if ($0 !~ /ControllerOptions::default\(\)/ && fn != "") print bin " " fn
    }' "$f"
done | sort -u)

while read -r bin test; do
  [ -z "$bin" ] && continue
  if printf '%s\n' "$serial_binaries" | grep -qx "$bin"; then
    continue # whole binary is serial-only
  fi
  in_e2e=$(printf '%s\n' "$e2e_body" | grep -cF "test(=$test)" || true)
  in_serial=$(printf '%s\n' "$serial_body" | grep -cF "test(=$test)" || true)
  if [ "$in_e2e" -lt 1 ] || [ "$in_serial" -lt 1 ]; then
    echo "FAIL: $bin::$test constructs non-default ControllerOptions but is not serialized in $NEXTEST_TOML (e2e-exclusion=$in_e2e serial-inclusion=$in_serial; both must be >=1)" >&2
    fail=1
  fi
done <<<"$mutators"

# 2. No stale filter entries: every `test(=name)` must match a real test fn.
while read -r name; do
  [ -z "$name" ] && continue
  if ! grep -rqE "async fn $name\(" "$TESTS_DIR"; then
    echo "FAIL: stale filter entry test(=$name) in $NEXTEST_TOML matches no test — renamed or deleted without updating the filter" >&2
    fail=1
  fi
done < <(grep -oE 'test\(=[a-z_0-9]+\)' "$NEXTEST_TOML" | sed -E 's/test\(=([a-z_0-9]+)\)/\1/' | sort -u)

if [ "$fail" -ne 0 ]; then
  echo "" >&2
  echo "Global-config mutators must run in the serial pass: add the test name to BOTH" >&2
  echo "the [profile.e2e] exclusion list and the [profile.e2e-serial] inclusion list" >&2
  echo "in $NEXTEST_TOML, and remove entries for renamed/deleted tests. Mutators built" >&2
  echo "via a shared helper are caught at run time by the helm_install guard instead." >&2
  exit 1
fi

echo "OK: all ControllerOptions mutators serialized (per-profile); no stale filter entries."
