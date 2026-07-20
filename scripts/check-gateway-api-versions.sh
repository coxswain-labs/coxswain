#!/usr/bin/env bash
# Validate `.gateway-api-versions.json`, the single source of truth for which
# Gateway API versions Coxswain supports and which one is current.
#
# There used to be two files — a `.gateway-api-version` pin plus a plural
# manifest — and a gate that checked the pin appeared in the manifest. One file
# with a `"latest": true` flag makes that whole class of drift unrepresentable,
# so what is left to check is the schema itself:
#
#   - valid JSON, non-empty array
#   - every entry has gatewayApiVersion / reportDir / latest /
#     conformanceModule / buildTags
#   - conformanceModule is "main" or "separate"
#   - no duplicate versions
#   - EXACTLY ONE entry marked latest
#
# That lives in scripts/gateway-api-versions.sh, the single parser every other
# consumer goes through, so this gate exercises the same code path the build
# does rather than a second reimplementation of it.
#
# It ALSO checks `conformance/go.mod` pins the same version the manifest marks
# latest. That is a third place the Gateway API version lives, and a mismatch is
# not cosmetic: the suite refuses to start with "the installed CRDs version is
# different from the suite version", so a bump that misses go.mod fails every
# conformance run at the default version. That is exactly how it was found.
#
# Run from the repo root. Exits non-zero on a malformed manifest or a mismatch.
set -euo pipefail

scripts/gateway-api-versions.sh --validate

latest="$(scripts/gateway-api-versions.sh --latest)"
gomod="conformance/go.mod"

if [ ! -f "$gomod" ]; then
  echo "ERROR: $gomod not found — run this from the repo root."
  exit 1
fi

status=0
for module in "sigs.k8s.io/gateway-api" "sigs.k8s.io/gateway-api/conformance"; do
  pinned="$(awk -v m="$module" '$1 == m { print $2 }' "$gomod" | head -1)"
  if [ -z "$pinned" ]; then
    echo "ERROR: $gomod does not require $module."
    status=1
  elif [ "$pinned" != "$latest" ]; then
    echo "ERROR: $gomod pins $module $pinned but the manifest's latest is $latest."
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo ""
  echo "Bumping the Gateway API version means updating conformance/go.mod too:"
  echo "  cd conformance"
  echo "  go mod edit -require=sigs.k8s.io/gateway-api@${latest}"
  echo "  go mod edit -require=sigs.k8s.io/gateway-api/conformance@${latest}"
  echo "  go mod tidy"
  exit 1
fi

echo "OK: conformance/go.mod pins ${latest}, matching the manifest."
