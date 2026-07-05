#!/usr/bin/env bash
# Enforce the e2e global-config-mutator serialization invariant: every test
# that reconfigures the ONE shared Helm release (any test whose body constructs
# non-default `ControllerOptions` / calls `start_with_options`) must be
# excluded from the parallel `e2e` nextest profile and included in the serial
# `e2e-serial` profile — or live in an always-serial binary. A mutator running
# in the parallel pass rolls the shared proxy mid-run (e.g. into
# PROXY-protocol-required mode) and every concurrent plain-HTTP test then fails
# with connection resets: the exact 20+-test "cliff" that broke the security
# suite when `mapped_v6_client_matches_deny_v4_cidr` landed unserialized and
# `forwarded_header_all_private_under_trusted_peer_falls_back_to_l4` was
# renamed without updating the filter.
#
# The nextest filters use exact `test(=name)` matches, which fail SILENTLY on
# rename or addition — so this gate also fails on stale filter entries that no
# longer match any test (the drift signature of a rename).
#
# Detection scope: `ControllerOptions`-based mutators only. Mutations that
# don't go through ControllerOptions (e.g. installing a global catchall route,
# as `default_backend_alone_serves_all_hosts` does) cannot be detected
# mechanically; keep listing those in the filters by hand.
#
# Run from the repo root. Exits non-zero listing every violation.

set -euo pipefail

TESTS_DIR="crates/coxswain-e2e/tests"
NEXTEST_TOML=".config/nextest.toml"

fail=0

# Binaries excluded wholesale from the parallel profile (`and not binary(X)`).
serial_binaries=$(grep -oE 'and not binary\([a-z_]+\)' "$NEXTEST_TOML" \
  | sed -E 's/and not binary\(([a-z_]+)\)/\1/' | sort -u)

# 1. Every ControllerOptions-constructing test is serialized.
#    Pair each `start_with_options(`/`ControllerOptions {` occurrence with its
#    enclosing `async fn`; `ControllerOptions::default()` is the harness's own
#    default path and is ignored.
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
  # The name must appear in BOTH profile filters (excluded from e2e, included
  # in e2e-serial) — i.e. at least twice in the file.
  count=$(grep -cF "test(=$test)" "$NEXTEST_TOML" || true)
  if [ "$count" -lt 2 ]; then
    echo "FAIL: $bin::$test constructs non-default ControllerOptions but is not serialized in $NEXTEST_TOML (found $count of 2 required filter entries)" >&2
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
  echo "in $NEXTEST_TOML, and remove entries for renamed/deleted tests." >&2
  exit 1
fi

echo "OK: all ControllerOptions mutators serialized; no stale filter entries."
