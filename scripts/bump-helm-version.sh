#!/usr/bin/env bash
# Keep charts/coxswain/Chart.yaml in sync with the Cargo workspace version.
# Called by cargo-release as a pre-release hook with the post-bump version as $1.
# Bumps both `version` (chart schema version) and `appVersion` (app binary version)
# in lockstep. Exits non-zero on any error so cargo-release aborts the release.
set -euo pipefail

VERSION="${1:?usage: bump-helm-version.sh <version>}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHART="$REPO_ROOT/charts/coxswain/Chart.yaml"

if [[ ! -f "$CHART" ]]; then
  echo "error: $CHART not found — run from the repo root or the charts directory" >&2
  exit 1
fi

if [[ "$OSTYPE" == darwin* ]]; then
  sed -i '' "s/^version:.*$/version: ${VERSION}/"         "$CHART"
  sed -i '' "s/^appVersion:.*$/appVersion: \"${VERSION}\"/" "$CHART"
else
  sed -i "s/^version:.*$/version: ${VERSION}/"         "$CHART"
  sed -i "s/^appVersion:.*$/appVersion: \"${VERSION}\"/" "$CHART"
fi

grep -q "^version: ${VERSION}$"           "$CHART" || { echo "error: version not updated in $CHART" >&2; exit 1; }
grep -q "^appVersion: \"${VERSION}\"$"    "$CHART" || { echo "error: appVersion not updated in $CHART" >&2; exit 1; }

echo "bumped $CHART → version: ${VERSION}, appVersion: \"${VERSION}\""
