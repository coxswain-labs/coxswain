#!/usr/bin/env bash
# Read `.gateway-api-versions.json`, the single source of truth for which
# Gateway API versions Coxswain supports and which one is current.
#
# This is the ONLY JSON parser in the shell/CI surface. Every other script and
# workflow step calls it and gets plain text back, so no consumer needs `jq` and
# none of them can disagree about the schema.
#
# Schema — an array of objects:
#   gatewayApiVersion  the CRD release tag installed for this leg (e.g. v1.5.1)
#   reportDir          upstream conformance report directory (e.g. v1.5). NOT a
#                      mechanical transform: upstream keeps per-patch dirs
#                      through v1.4.x but unified minor dirs from v1.5.
#   latest             exactly one entry is true — the version that drives
#                      codegen, e2e bootstrap and kubeconform.
#
# Usage:
#   gateway-api-versions.sh --latest              # v1.6.1
#   gateway-api-versions.sh --versions            # one version per line
#   gateway-api-versions.sh --list                # "<version>\t<reportDir>" per line
#   gateway-api-versions.sh --report-dir v1.5.1   # v1.5
#   gateway-api-versions.sh --json                # the raw array (for a matrix)
#
# Run from the repo root. Exits non-zero on a malformed manifest.
set -euo pipefail

MANIFEST=".gateway-api-versions.json"

if [ ! -f "$MANIFEST" ]; then
  echo "error: $MANIFEST not found; run from the repo root" >&2
  exit 1
fi

# python3 rather than jq: it ships on macOS and every GitHub runner, whereas jq
# does not ship on macOS. The reproduction path has to work on a contributor's
# laptop, not just in CI.
read_manifest() {
  python3 - "$MANIFEST" "$1" "${2-}" <<'PY'
import json, sys

path, mode, arg = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    entries = json.load(open(path))
except (OSError, ValueError) as e:
    sys.exit(f"error: {path} is not valid JSON: {e}")

if not isinstance(entries, list) or not entries:
    sys.exit(f"error: {path} must be a non-empty array")

seen = set()
for entry in entries:
    missing = {"gatewayApiVersion", "reportDir", "latest"} - set(entry)
    if missing:
        sys.exit(f"error: entry {entry!r} is missing {sorted(missing)}")
    version = entry["gatewayApiVersion"]
    if version in seen:
        sys.exit(f"error: {version} is listed more than once")
    seen.add(version)

latest = [e["gatewayApiVersion"] for e in entries if e["latest"]]
if len(latest) != 1:
    sys.exit(
        f"error: exactly one entry must have \"latest\": true, found {len(latest)}"
        f" ({', '.join(latest) or 'none'})"
    )

if mode == "--latest":
    print(latest[0])
elif mode == "--versions":
    for e in entries:
        print(e["gatewayApiVersion"])
elif mode == "--list":
    for e in entries:
        print(f"{e['gatewayApiVersion']}\t{e['reportDir']}")
elif mode == "--json":
    print(json.dumps([e["gatewayApiVersion"] for e in entries]))
elif mode == "--report-dir":
    match = [e["reportDir"] for e in entries if e["gatewayApiVersion"] == arg]
    if not match:
        sys.exit(
            f"error: {arg} is not listed in {path}\n  "
            + "\n  ".join(e["gatewayApiVersion"] for e in entries)
        )
    print(match[0])
elif mode == "--validate":
    print(f"OK: {len(entries)} supported Gateway API versions, latest {latest[0]}.")
else:
    sys.exit(f"error: unknown mode {mode}")
PY
}

case "${1-}" in
  --latest|--versions|--list|--json|--validate)
    read_manifest "$1"
    ;;
  --report-dir)
    if [ -z "${2-}" ]; then
      echo "error: --report-dir needs a version" >&2
      exit 2
    fi
    read_manifest --report-dir "$2"
    ;;
  -h|--help)
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    echo "error: expected one of --latest --versions --list --json --report-dir --validate" >&2
    exit 2
    ;;
esac
