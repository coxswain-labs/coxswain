#!/usr/bin/env bash
# Generate the per-implementation README.md that kubernetes-sigs/gateway-api
# REQUIRES alongside every submitted conformance report.
#
# Upstream's conformance/reports/README.md makes this mandatory, not optional:
# each `<gateway-api-version>/<implementation>/` folder must contain a README
# with a table of contents (one row per report) and a "Reproduce" section. A
# report set without them is not submittable.
#
# The table is derived from the report YAMLs themselves — `gatewayAPIChannel`,
# `implementation.version` and `mode` are read out of each file — so it cannot
# drift from what was actually run. Upstream also requires the version to be a
# semver matching `implementation.version`, which is why a publishable report
# must come from a tagged commit: an off-tag `git describe` produces
# `v0.5.0-40-g<sha>`, which has no release page to link to.
#
# Usage:
#   scripts/render-conformance-readmes.sh [reports-root]
#
# `reports-root` defaults to `conformance/reports`. Idempotent — rewrites each
# README from the reports currently present.
set -euo pipefail

ROOT="${1:-conformance/reports}"

if [ ! -d "$ROOT" ]; then
  echo "error: $ROOT not found; run from the repo root" >&2
  exit 1
fi

python3 - "$ROOT" <<'PY'
import os, re, sys

root = sys.argv[1]
REPO = "https://github.com/coxswain-labs/coxswain"


def scalar(text, key, default=""):
    """Pull a top-level-ish scalar out of a report without a YAML dependency.

    The conformance report is machine-generated with a stable shape, and this
    runs in the publishing path where adding a Python YAML dependency would be
    one more thing to install on a contributor's laptop.
    """
    m = re.search(rf"^\s*{re.escape(key)}:\s*['\"]?([^'\"\n]+)['\"]?\s*$", text, re.M)
    return m.group(1).strip() if m else default


written = 0
for version_dir in sorted(os.listdir(root)):
    impl_dir = os.path.join(root, version_dir, "coxswain-coxswain")
    if not os.path.isdir(impl_dir):
        continue

    reports = sorted(f for f in os.listdir(impl_dir) if f.endswith("-report.yaml"))
    if not reports:
        continue

    rows = []
    for name in reports:
        text = open(os.path.join(impl_dir, name)).read()
        channel = scalar(text, "gatewayAPIChannel", "standard")
        # `version:` appears under `implementation:`; the first match is it.
        impl_version = scalar(text, "version", "unknown")
        mode = scalar(text, "mode", "default")
        release = f"[{impl_version}]({REPO}/releases/tag/{impl_version})"
        rows.append(f"| {channel} | {release} | {mode} | [link](./{name}) |")

    readme = f"""# Coxswain

[Coxswain]({REPO}) is a pure-Rust Kubernetes Ingress and Gateway API controller
backed by [Pingora](https://github.com/cloudflare/pingora).

## Table of Contents

| API channel | Implementation version | Mode | Report |
|-------------|------------------------|------|--------|
{chr(10).join(rows)}

## Overview

Coxswain detects which Gateway API kinds and schema fields the installed CRDs
actually serve and runs with exactly that feature set, so one build supports
several Gateway API versions. A report produced against an older version
therefore claims fewer conformance profiles and advertises fewer
`supportedFeatures` — by design, not as a partial result. The full matrix is
documented at
[`docs/src/reference/capability-matrix.md`]({REPO}/blob/main/docs/src/reference/capability-matrix.md).

This report was produced against Gateway API **{version_dir}**.

## Reproduce

Gateway API CRDs are cluster-scoped singletons, so each version needs its own
fresh cluster.

1. Clone the repository and check out the release under test:

   ```bash
   git clone {REPO}.git && cd coxswain
   git checkout <version>
   ```

2. Create a cluster and install Coxswain plus the Gateway API CRDs for this
   version:

   ```bash
   kind create cluster --name coxswain-conformance
   ./scripts/setup-conformance.sh --gateway-api-version {version_dir} --reset ''
   ```

3. Run the suite:

   ```bash
   ./scripts/run-conformance.sh --gateway-api-version {version_dir}
   ```

   The report is written to
   `conformance/reports/{version_dir}/coxswain-coxswain/`.

Both scripts take the same `--gateway-api-version`; the supported values are
listed in
[`.gateway-api-versions.json`]({REPO}/blob/main/.gateway-api-versions.json).
"""

    with open(os.path.join(impl_dir, "README.md"), "w") as fh:
        fh.write(readme)
    print(f"wrote {os.path.join(impl_dir, 'README.md')} ({len(rows)} report(s))")
    written += 1

if written == 0:
    print(f"no reports found under {root}; nothing to do")
PY
