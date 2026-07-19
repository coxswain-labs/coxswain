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
#   - every entry has gatewayApiVersion / reportDir / latest
#   - no duplicate versions
#   - EXACTLY ONE entry marked latest
#
# All of that lives in scripts/gateway-api-versions.sh, the single parser every
# other consumer goes through, so this gate exercises the same code path the
# build does rather than a second reimplementation of it.
#
# Run from the repo root. Exits non-zero on a malformed manifest.
set -euo pipefail

exec scripts/gateway-api-versions.sh --validate
