#!/usr/bin/env bash
# Verify that the Rust SUPPORTED_FEATURES const and the Go opts.SupportedFeatures
# set are in sync. Run this script from the repo root.
#
# Exits 0 if both lists (sorted) are identical, non-zero otherwise.
set -euo pipefail

RUST_FILE="crates/coxswain-controller/src/controller/gateway_class_status.rs"
GO_FILE="conformance/main_test.go"

# Extract quoted strings from the SUPPORTED_FEATURES array only — scoped to
# between its declaration and closing `];` so a quoted string anywhere else
# in the file (e.g. a "True"/"False" condition-status literal) can't be
# misread as a feature name.
rust_features=$(awk '
  /const SUPPORTED_FEATURES/ { in_array=1; next }
  in_array && /\];/ { exit }
  in_array
' "$RUST_FILE" \
  | grep -E '^\s+"[A-Za-z0-9]+",' \
  | sed 's/[^"]*"\([^"]*\)".*/\1/' \
  | sort)

# Extract feature names from active (non-commented-out) features.SupportXxx
# symbols in the Go file, stripping the "Support" prefix to match the Rust names.
go_features=$(grep -v '^\s*//' "$GO_FILE" \
  | grep -oE 'features\.Support[A-Za-z0-9]+' \
  | sed 's/features\.Support//' \
  | sort)

if [ -z "$rust_features" ]; then
  echo "ERROR: extracted zero features from $RUST_FILE — check the grep pattern."
  exit 1
fi

if [ -z "$go_features" ]; then
  echo "ERROR: extracted zero features from $GO_FILE — check the grep pattern."
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
