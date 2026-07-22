#!/usr/bin/env bash
# Fail if the raw-manifest base has drifted from the Helm chart.
#
# The chart (charts/coxswain) is the single source of truth. Two ways the base
# used to silently diverge — both caused real bugs and both are gated here:
#   1. deploy/manifests/coxswain.yaml no longer matches a fresh render of the
#      chart (e.g. the chart gained the controller discovery Service and the base
#      did not).
#   2. A CRD file exists in deploy/manifests/crds/ but is not referenced by the
#      Kustomization (e.g. jwtauths.yaml shipped nowhere).
#
# Fix drift with: scripts/render-manifests.sh  (and add any missing crds/ entry
# to deploy/manifests/kustomization.yaml).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

status=0

# 1. Rendered manifest matches the chart.
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
bash scripts/render-manifests.sh "$tmp" >/dev/null
if ! diff -u deploy/manifests/coxswain.yaml "$tmp"; then
  echo "FAIL: deploy/manifests/coxswain.yaml is out of sync with charts/coxswain." >&2
  echo "      Run: scripts/render-manifests.sh" >&2
  status=1
fi

# 2. Every CRD on disk is referenced by the Kustomization.
kustomization="deploy/manifests/kustomization.yaml"
while IFS= read -r crd; do
  base="crds/$(basename "$crd")"
  if ! grep -qF "$base" "$kustomization"; then
    echo "FAIL: $base exists but is not referenced in $kustomization." >&2
    status=1
  fi
done < <(find deploy/manifests/crds -maxdepth 1 -name '*.yaml' | sort)

[ "$status" -eq 0 ] && echo "OK: raw manifests in sync with the chart."
exit "$status"
