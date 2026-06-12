#!/usr/bin/env bash
# Enforce CLAUDE.md's "Never add '#[allow(...)]' or '#[expect(...)]' to
# silence a lint" rule. Per-site lint suppression locks an inconsistency in
# forever; fix the root cause or alias upstream-imposed names at the crate
# boundary instead.
#
# Exemptions per CLAUDE.md:
# - '#![allow(missing_docs)]' at the top of bench files and
#   'crates/coxswain-e2e/tests/*' — criterion/e2e macros expand to `pub fn`
#   items the author can't annotate.
#
# Run from the repo root. Exits non-zero with a list of offending sites.

set -euo pipefail

# Find '#[allow(...)]' and '#[expect(...)]' in non-test, non-bench, non-e2e-tests
# source under `crates/`. Exclude '#![allow(missing_docs)]' at file-scope (it's
# the documented exception).
offenders=$(grep -rnE '^\s*#!?\[(allow|expect)\(' crates/*/src/ \
  --include='*.rs' \
  | grep -v 'allow_attributes' \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#!\[allow\(missing_docs\)\]' \
  || true)

# Trim entries inside bench / e2e tests paths.
offenders=$(printf '%s\n' "$offenders" \
  | grep -vE 'crates/[^/]+/benches/' \
  | grep -vE 'crates/coxswain-e2e/tests/' \
  | grep -v '^$' \
  || true)

if [ -n "$offenders" ]; then
  count=$(printf '%s\n' "$offenders" | wc -l | tr -d ' ')
  echo "FAIL: $count per-site '#[allow]' / '#[expect]' site(s) found:" >&2
  printf '  %s\n' "$offenders" | sed 's/^/  /' >&2
  echo "" >&2
  echo "Per CLAUDE.md, fix the root cause instead of suppressing the lint." >&2
  echo "For >7-arg functions: refactor into a parameter-grouping struct." >&2
  echo "For upstream-imposed names: re-export with a project-canonical alias at the crate boundary." >&2
  exit 1
fi

echo "OK: no per-site '#[allow]' / '#[expect]' attributes in non-test source."
