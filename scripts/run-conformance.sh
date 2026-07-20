#!/usr/bin/env bash
# Run the Gateway API conformance suite against the cluster the current
# kubecontext points at, optionally pinned to a Gateway API version other than
# the latest supported one. Run this script from the repo root.
#
# The cluster must already be prepared — see scripts/setup-conformance.sh, and
# pass it the SAME --gateway-api-version. Gateway API CRDs are cluster-scoped
# singletons, so each version needs its own fresh cluster.
#
# Usage:
#   scripts/run-conformance.sh [--gateway-api-version vX.Y.Z] [--report-output PATH]
#
# The suite module is pinned by copying `conformance/` to a temporary directory
# and running `go mod edit -require` there. Nothing tracked is modified, so a
# run against an older version cannot leave the working tree dirty — which
# matters because the pinned `go.mod` would otherwise look like an intentional
# downgrade of the project's own Gateway API dependency.
set -euo pipefail

GATEWAY_API_VERSION=""
REPORT_OUTPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gateway-api-version)
      GATEWAY_API_VERSION="$2"
      shift 2
      ;;
    --report-output)
      REPORT_OUTPUT="$2"
      shift 2
      ;;
    -h|--help)
      sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown flag: $1" >&2
      exit 2
      ;;
  esac
done

if [ ! -f .gateway-api-versions.json ] || [ ! -d conformance ]; then
  echo "error: run from the repo root" >&2
  exit 1
fi

LATEST_VERSION=$(scripts/gateway-api-versions.sh --latest)
if [ -z "$GATEWAY_API_VERSION" ]; then
  GATEWAY_API_VERSION="$LATEST_VERSION"
fi

# The upstream report directory is not a mechanical transform of the version
# (per-patch through v1.4.x, unified minors from v1.5), so it is looked up
# rather than derived. This also rejects an unsupported version.
REPORT_DIR=$(scripts/gateway-api-versions.sh --report-dir "$GATEWAY_API_VERSION")
# Per-version build facts, kept in the manifest so the script and CI cannot
# disagree about them (see scripts/gateway-api-versions.sh for what they mean).
CONFORMANCE_MODULE=$(scripts/gateway-api-versions.sh --field "$GATEWAY_API_VERSION" conformanceModule)
BUILD_TAGS=$(scripts/gateway-api-versions.sh --field "$GATEWAY_API_VERSION" buildTags)
# Tests the suite itself cannot run at this version (see the manifest for why).
CONFORMANCE_SKIP_TESTS=$(scripts/gateway-api-versions.sh --field "$GATEWAY_API_VERSION" skipTests)
export CONFORMANCE_SKIP_TESTS

# On the tagged release commit this yields a clean `v0.5.0` — the tag IS the
# commit ref, so a hash would be redundant noise, and upstream reports use the
# bare version. Off-tag it yields `v0.5.0-40-g6352459`, which carries the hash
# because there the tag alone would not identify the tree.
#
# Requires a full checkout (`fetch-depth: 0`): a shallow one has no tag history,
# and describe silently degrades to a bare hash with no version at all.
IMPL_VERSION=$(git describe --tags --always --dirty)
if [ -z "$REPORT_OUTPUT" ]; then
  REPORT_OUTPUT="conformance/reports/${REPORT_DIR}/coxswain-coxswain/standard-${IMPL_VERSION}-default-report.yaml"
fi
# Resolve to an absolute path: the suite runs from a temp directory, so a
# relative --report-output would land there and be deleted with it.
mkdir -p "$(dirname "$REPORT_OUTPUT")"
REPORT_OUTPUT="$(cd "$(dirname "$REPORT_OUTPUT")" && pwd)/$(basename "$REPORT_OUTPUT")"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
cp -R conformance/. "$WORKDIR/"

if [ "$GATEWAY_API_VERSION" != "$LATEST_VERSION" ]; then
  echo ">>> pin conformance suite to Gateway API $GATEWAY_API_VERSION (in $WORKDIR)"
  (
    cd "$WORKDIR"
  # Whether the suite is its own module is a per-version fact from the manifest,
  # not something to re-derive here: it only became separate at v1.5.0, and
  # requiring `.../conformance@v1.4.x` fails with `unknown revision`.
  go mod edit -require="sigs.k8s.io/gateway-api@${GATEWAY_API_VERSION}"
  if [ "$CONFORMANCE_MODULE" = "main" ]; then
    go mod edit -droprequire="sigs.k8s.io/gateway-api/conformance"
  else
    go mod edit -require="sigs.k8s.io/gateway-api/conformance@${GATEWAY_API_VERSION}"
  fi
  go mod tidy
  )
fi

echo ">>> run conformance against Gateway API $GATEWAY_API_VERSION"
echo ">>> report: $REPORT_OUTPUT"
# The suite writes its report even when tests fail, and a failing report is
# still worth having — so a non-zero exit must not skip the README generation
# below. Capture the status and re-raise it at the end.
set +e
(
  cd "$WORKDIR"
  go test -tags="$BUILD_TAGS" -v -timeout 60m -run TestConformance \
    -args \
    --organization=coxswain-labs \
    --project=coxswain \
    --url=https://github.com/coxswain-labs/coxswain \
    --version="$IMPL_VERSION" \
    --contact=https://github.com/coxswain-labs/coxswain/issues \
    --report-output="$REPORT_OUTPUT"
)

SUITE_STATUS=$?
set -e

# Upstream requires a README.md beside the reports in each implementation
# folder; regenerate it so a locally-produced set is submittable as-is.
scripts/render-conformance-readmes.sh >/dev/null

echo ">>> wrote $REPORT_OUTPUT"
if [ "$SUITE_STATUS" -ne 0 ]; then
  echo ">>> conformance FAILED (exit $SUITE_STATUS) — report and README still written"
fi
exit "$SUITE_STATUS"
