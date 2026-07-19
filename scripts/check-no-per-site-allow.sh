#!/usr/bin/env bash
# Enforce CLAUDE.md's "never add '#[allow(...)]' or '#[expect(...)]' to silence a
# lint" rule. Per-site suppression locks an inconsistency in forever; fix the
# root cause, or alias upstream-imposed names at the crate boundary instead.
#
# Why a script rather than a lint level: `forbid` in `[workspace.lints]` would
# make an `#[allow]` a hard E0453 error, but it also overrules allows injected
# by *dependency* macros — `#[tokio::test]` emits `allow(clippy::expect_used)`
# and clap's `derive(Parser)` emits `allow(clippy::style)`, so nothing in this
# workspace compiles under `forbid`. The rule is therefore checked textually.
#
# Scope: every first-party Rust source tree — `crates/*/{src,benches,tests}` and
# `xtask/src`. The previous version scanned only `crates/*/src/` and then
# filtered `crates/*/benches/` and `crates/coxswain-e2e/tests/`, neither of which
# can appear in the output of a scan rooted at `src/`: those filters were dead
# code, and benches, e2e tests and xtask were never scanned at all.
#
# Exemptions, each an *inner* attribute (`#![...]`) scoping a whole file or test
# module — never an outer `#[allow]` on a single item, which is what the rule is
# actually about:
# - '#![allow(missing_docs)]' and '#![allow(dead_code)]' anywhere. Both fire
#   structurally rather than on a defect: criterion / e2e macros expand to
#   `pub fn` items the author cannot annotate, `#[cfg(test)] mod tests` items
#   are not shipped docs, and a `tests/common/` helper module is compiled into
#   several test binaries that each use a different subset. Neither lint can
#   conceal a correctness bug.
# - '#![allow(unsafe_code)]' under 'crates/*/tests/' and 'crates/*/benches/'
#   only — the allocation-budget harness installs a counting `GlobalAlloc`,
#   which cannot be written safely. Production source stays covered.
# - 'crates/gateway-api-types/src/**' — generated wholesale by the repo-root
#   'xtask' crate (#510); kopium emits a per-file '#[allow(unused_imports)]' on
#   its internal `prelude` module. Same trust model as the committed CRDs.
#
# Run from the repo root. Exits non-zero with a list of offending sites.

set -euo pipefail

roots=()
for d in crates/*/src crates/*/benches crates/*/tests xtask/src; do
  [ -d "$d" ] && roots+=("$d")
done

# Match the attribute anywhere on the line, not only at line start: both
# `#[allow(x)] fn f()` and `#[cfg_attr(feature = "x", allow(y))]` count.
offenders=$(grep -rnE '#!?\[[[:space:]]*(allow|expect)\(|cfg_attr\([^)]*[[:space:]](allow|expect)\(' \
  "${roots[@]}" --include='*.rs' 2>/dev/null | grep -v 'allow_attributes' || true)

# Drop the documented exemptions.
offenders=$(printf '%s\n' "$offenders" \
  | grep -vE '^crates/gateway-api-types/src/' \
  | grep -vE ':[0-9]+:[[:space:]]*#!\[[[:space:]]*allow\((missing_docs|dead_code)\)\]' \
  | grep -vE '^crates/[^/]+/(tests|benches)/[^:]*:[0-9]+:[[:space:]]*#!\[[[:space:]]*allow\(unsafe_code\)\]' \
  | grep -v '^$' \
  || true)

if [ -n "$offenders" ]; then
  count=$(printf '%s\n' "$offenders" | wc -l | tr -d ' ')
  echo "FAIL: $count per-site '#[allow]' / '#[expect]' site(s) found:" >&2
  printf '%s\n' "$offenders" | sed 's/^/  /' >&2
  echo "" >&2
  echo "Per CLAUDE.md, fix the root cause instead of suppressing the lint." >&2
  echo "For >7-arg functions: refactor into a parameter-grouping struct." >&2
  echo "For upstream-imposed names: re-export with a project-canonical alias at the crate boundary." >&2
  exit 1
fi

echo "OK: no per-site '#[allow]' / '#[expect]' attributes in first-party source."
