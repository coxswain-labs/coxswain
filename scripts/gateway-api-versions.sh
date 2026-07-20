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
#   conformanceModule  "main"     — the suite ships inside sigs.k8s.io/gateway-api
#                      "separate" — it is its own module, .../gateway-api/conformance
#                      It only became separate at v1.5.0; requiring
#                      `.../conformance@v1.4.x` fails with `unknown revision`,
#                      because no such tag was ever pushed.
#   skipTests          `[{name, reason}]` — conformance tests that are
#                      unrunnable for this version through no fault of the
#                      implementation. The reason is REQUIRED and is published
#                      verbatim in the report's README, because a skipped test
#                      in a conformance claim has to justify itself.
#   buildTags          Go build tags the suite needs for this version, or "".
#                      `ConformanceOptions.ConformanceProfiles` and
#                      `.SupportedFeatures` were sets through v1.5 and became
#                      slices at v1.6; no single assignment compiles against
#                      both, so a tagged shim selects one.
#
# The CRD install URL is deliberately NOT stored: it is a mechanical transform
# of the version, and four near-identical URLs would be four chances for a typo
# no gate could catch.
#
# Usage:
#   gateway-api-versions.sh --latest              # v1.6.1
#   gateway-api-versions.sh --versions            # one version per line
#   gateway-api-versions.sh --list                # "<version>\t<reportDir>" per line
#   gateway-api-versions.sh --report-dir v1.5.1   # v1.5
#   gateway-api-versions.sh --field v1.4.1 buildTags
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
REQUIRED = {
    "gatewayApiVersion", "reportDir", "latest",
    "conformanceModule", "buildTags", "skipTests",
}
for entry in entries:
    missing = REQUIRED - set(entry)
    if missing:
        sys.exit(f"error: entry {entry!r} is missing {sorted(missing)}")
    version = entry["gatewayApiVersion"]
    if version in seen:
        sys.exit(f"error: {version} is listed more than once")
    seen.add(version)
    module = entry["conformanceModule"]
    if module not in ("main", "separate"):
        sys.exit(f"error: {version} has conformanceModule {module!r}, expected 'main' or 'separate'")
    for skip in entry["skipTests"]:
        if not isinstance(skip, dict) or not skip.get("name") or not skip.get("reason"):
            sys.exit(
                f"error: {version} skipTests entry {skip!r} needs both a name and a reason — "
                "an unjustified skip in a conformance claim is not publishable"
            )

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
elif mode == "--field":
    key, version = arg.split("=", 1)
    match = [e for e in entries if e["gatewayApiVersion"] == version]
    if not match:
        sys.exit(f"error: {version} is not listed in {path}")
    if key not in match[0]:
        sys.exit(f"error: unknown field {key!r}")
    value = match[0][key]
    if key == "skipTests":
        # Names only: this feeds the runner's env var. Reasons come from
        # `--skip-reasons`, which the README generator uses.
        print(",".join(s["name"] for s in value))
    elif isinstance(value, list):
        print(",".join(value))
    else:
        print(value)
elif mode == "--skip-reasons":
    match = [e for e in entries if e["gatewayApiVersion"] == arg]
    if not match:
        sys.exit(f"error: {arg} is not listed in {path}")
    for skip in match[0]["skipTests"]:
        print(f"{skip['name']}\t{skip['reason']}")
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
  --field)
    if [ -z "${2-}" ] || [ -z "${3-}" ]; then
      echo "error: --field needs a version and a field name" >&2
      exit 2
    fi
    read_manifest --field "$3=$2"
    ;;
  --skip-reasons)
    if [ -z "${2-}" ]; then
      echo "error: --skip-reasons needs a version" >&2
      exit 2
    fi
    read_manifest --skip-reasons "$2"
    ;;
  -h|--help)
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    echo "error: expected one of --latest --versions --list --json --report-dir --field --skip-reasons --validate" >&2
    exit 2
    ;;
esac
