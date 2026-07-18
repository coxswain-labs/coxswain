#!/usr/bin/env bash
# Enforce the e2e global-config-mutator serialization invariant: every test
# that reconfigures the ONE shared Helm release (any test whose body constructs
# non-default `ControllerOptions` / calls `start_with_options`) must live
# inside a `mod serial { }` block in its plane file — or in an always-serial
# binary. A mutator running in the parallel pass rolls the shared proxy
# mid-run (e.g. into PROXY-protocol-required mode) and every concurrent
# plain-HTTP test then fails with connection resets: the exact 20+-test
# "cliff" that broke the security suite (#529).
#
# Membership is by module, not by name: `.config/nextest.toml` matches serial
# tests via `test(/serial::/)`, a nextest test ID produced by nesting the test
# inside `mod serial { }`. This script enforces that every real mutator is
# actually inside that block — nextest.toml itself never needs editing when a
# mutator is added, renamed, or removed.
#
# This is FAST STATIC FEEDBACK. The airtight enforcement is the runtime guard in
# `helm_install` (crates/coxswain-e2e/src/harness/bootstrap.rs): a non-default
# HelmOverrides under a nextest process without COXSWAIN_E2E_SERIAL=1 panics at
# the mutation site, so a mutator constructed via a helper the grep below can't
# attribute still fails loudly (just at run time, not lint time). This script
# catches the common literal cases before the expensive e2e run.
#
# Detection scope: `ControllerOptions`-based mutators whose literal sits inside
# the test's own `async fn`. Mutations via a shared helper, or that don't go
# through ControllerOptions (e.g. a global catchall route), are covered by the
# runtime guard, not here; keep those inside `mod serial` by hand.
#
# `mod serial { }` is a per-file convention placed as the LAST top-level item in
# the plane file (mirrors the existing `mod grpcecho { }` precedent in
# security.rs/traffic_policy.rs). This script treats every line from the
# `mod serial {` header to EOF as "inside serial" rather than depth-matching
# braces — cheap and correct as long as the convention holds; a mutator placed
# after a *misplaced* mod serial block would be silently passed, but that's an
# adjacent-code-review concern the runtime guard still catches at run time.
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

# Every ControllerOptions-constructing test must be inside `mod serial { }`
# (or in a whole-serial binary, checked separately below).
mutators=$(for f in "$TESTS_DIR"/*.rs; do
  awk -v bin="$(basename "$f" .rs)" '
    /^mod serial[[:space:]]*\{/ { in_serial=1 }
    /async fn /       { fn=$0; sub(/.*async fn /, "", fn); sub(/\(.*/, "", fn) }
    /ControllerOptions \{|start_with_options\(/ {
      if ($0 !~ /ControllerOptions::default\(\)/ && fn != "") print bin " " fn " " (in_serial ? 1 : 0)
    }' "$f"
done | sort -u)

while read -r bin test in_serial; do
  [ -z "$bin" ] && continue
  if printf '%s\n' "$serial_binaries" | grep -qx "$bin"; then
    continue # whole binary is serial-only
  fi
  if [ "$in_serial" -ne 1 ]; then
    echo "FAIL: $bin::$test constructs non-default ControllerOptions but is not inside a \`mod serial { }\` block in $TESTS_DIR/$bin.rs" >&2
    fail=1
  fi
done <<<"$mutators"

# Sanity-check nextest.toml still wires the module-based filter and the
# whole-serial binaries — catches an accidental revert to name enumeration.
if ! grep -qF 'test(/serial::/)' "$NEXTEST_TOML"; then
  echo "FAIL: $NEXTEST_TOML no longer references test(/serial::/) — the module-based serial filter is missing" >&2
  fail=1
fi
for b in resilience status_conditions discovery; do
  if ! grep -qF "binary($b)" "$NEXTEST_TOML"; then
    echo "FAIL: $NEXTEST_TOML missing a binary($b) reference — a whole-serial binary lost its wholesale exclusion/inclusion" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "" >&2
  echo "Global-config mutators must run in the serial pass: move the test inside a" >&2
  echo "\`mod serial { use super::*; ... }\` block in its plane file. Mutators built via" >&2
  echo "a shared helper are caught at run time by the helm_install guard instead." >&2
  exit 1
fi

echo "OK: all ControllerOptions mutators live inside \`mod serial\`; nextest.toml wiring intact."
