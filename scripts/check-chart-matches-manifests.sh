#!/usr/bin/env bash
# Produce a normalized diff between the Helm chart's default rendering and the
# raw manifests in deploy/manifests/. Intended for human review on PRs — exits
# 0 regardless of diff output, so it does not block CI.
#
# Expected differences that are by design and not regressions:
#   - Resource names differ: chart uses Helm release-name conventions
#     (e.g. "coxswain") while raw manifests use descriptive names
#     (e.g. "coxswain-gateway", "coxswain-controller").
#   - The chart adds two Service resources (coxswain-gateway, coxswain-internal)
#     that do not exist in the raw manifests.
#   - The chart explicitly sets env vars that match the binary's built-in
#     defaults (e.g. COXSWAIN_PROXY_BIND_ADDRESS, COXSWAIN_CONTROLLER_LEASE_TTL)
#     while the raw manifests omit them and rely on the binary default.
#   - The chart uses imagePullPolicy: IfNotPresent; the raw manifest uses Always.
#
# Blocking chart-related CI checks (helm lint, helm template) live in ci.yml.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHART_DIR="$REPO_ROOT/charts/coxswain"
RAW_DIR="$REPO_ROOT/deploy/manifests"
NORMALIZER="$REPO_ROOT/scripts/_chart_normalize.py"

if ! command -v helm &>/dev/null; then
  echo "error: helm is not installed" >&2
  exit 1
fi
if ! command -v python3 &>/dev/null; then
  echo "error: python3 is not installed" >&2
  exit 1
fi
python3 -c "import yaml" 2>/dev/null || {
  echo "error: python3 pyyaml is not installed (pip install pyyaml)" >&2
  exit 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Render chart with defaults, pinning image.tag to match the raw manifest image.
helm template coxswain "$CHART_DIR" \
  --namespace coxswain-system \
  --set "image.tag=0.1.0" \
  > "$WORK/chart.yaml"

# Concatenate raw manifests, adding explicit --- separators between files so
# the YAML stream parser handles each file as a distinct document.
for f in "$RAW_DIR"/*.yaml; do
  printf -- "---\n"
  cat "$f"
done > "$WORK/raw.yaml"

python3 "$NORMALIZER" "$WORK/chart.yaml" > "$WORK/chart.norm.yaml"
python3 "$NORMALIZER" "$WORK/raw.yaml"   > "$WORK/raw.norm.yaml"

echo "=== Normalized diff: deploy/manifests/ vs charts/coxswain default rendering ==="
echo "    (--- raw manifests  +++ chart output)"
echo "    Expected differences are documented at the top of this script."
echo ""
diff -u "$WORK/raw.norm.yaml" "$WORK/chart.norm.yaml" || true
echo ""
echo "Review the diff above. Unexpected content changes should be fixed in the chart."
