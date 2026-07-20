#!/usr/bin/env bash
# Verify that the Rust SUPPORTED_FEATURES table and the Go gatedFeatures table
# declare the same Gateway API features. Run this script from the repo root.
#
# Both sides carry a per-feature capability requirement (#641) so a single build
# can run against several Gateway API versions. The requirement itself is
# deliberately NOT compared: the two express it differently (Rust names a
# `GatewayApiKind`/`GatewayApiField` enum variant, Go names a plural CRD or a
# schema-probe string), and what must not drift is the *set of declared
# features* — that is what lands in `GatewayClass.status` on one side and in the
# conformance report on the other.
#
# Exits 0 if both lists (sorted) are identical, non-zero otherwise.
set -euo pipefail

RUST_FILE="crates/coxswain-controller/src/controller/gateway_class_status.rs"
GO_FILE="conformance/features.go"

for f in "$RUST_FILE" "$GO_FILE"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: $f not found — run this from the repo root."
    exit 1
  fi
done

# Rust: scoped to the SUPPORTED_FEATURES table so a quoted string elsewhere in
# the file cannot be misread as a feature name. Entries are `("Name", Req)` and
# rustfmt splits longer ones across lines, so the name is matched as a quoted
# string within the table rather than by whole-line shape.
rust_features=$(awk '
  /const SUPPORTED_FEATURES/ { in_table=1; next }
  in_table && /^\];/ { exit }
  in_table
' "$RUST_FILE" \
  | { grep -v '^\s*//' || true; } \
  | { grep -oE '"[A-Za-z0-9]+"' || true; } \
  | tr -d '"' \
  | sort -u)

# Go: `{name: "Xxx", ...}` entries in the gatedFeatures table, excluding
# commented-out lines. Plain strings rather than `features.SupportXxx`
# constants because 11 of those constants do not exist in the Gateway API v1.4
# module and naming them would break compilation there — see features.go.
#
# `|| true` on the greps: with `set -e`, a grep that matches nothing exits 1 and
# kills the script before the "extracted zero" guard below can say so, which
# turns a broken extraction into a silent failure — the exact way a gate stops
# being a check.
go_features=$(awk '
  /^var gatedFeatures/ { in_table=1; next }
  in_table && /^\}/ { exit }
  in_table
' "$GO_FILE" \
  | { grep -v '^\s*//' || true; } \
  | { grep -oE '\{name: "[A-Za-z0-9]+"' || true; } \
  | sed 's/{name: "//; s/"//' \
  | sort -u)

if [ -z "$rust_features" ]; then
  echo "ERROR: extracted zero features from $RUST_FILE — check the awk/grep pattern."
  exit 1
fi

if [ -z "$go_features" ]; then
  echo "ERROR: extracted zero features from $GO_FILE — check the awk/grep pattern."
  exit 1
fi

if [ "$rust_features" = "$go_features" ]; then
  echo "OK: SUPPORTED_FEATURES in Rust and Go are in sync ($(echo "$rust_features" | wc -l | tr -d ' ') features)."
  exit 0
fi

echo "ERROR: SUPPORTED_FEATURES mismatch between Rust and Go."
echo ""
echo "--- Rust ($RUST_FILE)"
echo "+++ Go ($GO_FILE)"
diff <(echo "$rust_features") <(echo "$go_features") || true
echo ""
echo "Update both files to match, keeping the Rust list sorted ascending."
exit 1
