#!/usr/bin/env bash
# Enforce CLAUDE.md's "no crash site in a data-plane wildcard arm" rule (#619).
#
# `#[non_exhaustive]` on a `coxswain-core` enum FORCES a `_ =>` (or bound
# catch-all) arm in every cross-crate `match`, because the compiler can never
# prove the match exhaustive across the crate boundary. A `panic!` /
# `unreachable!` / `todo!` in that arm therefore compiles clean workspace-wide
# and then aborts the process at runtime the moment someone adds a core variant —
# halting snapshot encode/decode and routing convergence for every proxy. The
# "update wire.rs when adding new variants" comments those sites carried promised
# a compile-time guarantee that does not exist (#619 removed 16 such sites plus a
# 17th the compiler could not flag, `decode.rs`'s `HeaderModError` arm).
#
# The data plane (`coxswain-proxy`, `coxswain-discovery`) sits at the strict bar:
# a crash there drops live traffic or halts convergence. A wildcard arm must
# degrade — a typed `Err` on a fallible path, a fail-closed/last-good fallback on
# an infallible one — never panic. This gate stops a new one from landing.
#
# Why not clippy `disallowed-macros`: `clippy.toml` is workspace-global with no
# per-crate scoping, so it would also condemn the proxy's ~19 legitimate
# metric-registration and CIDR-literal invariant panics, and per-site `#[allow]`
# is forbidden by `check-no-per-site-allow.sh`.
#
# Scope: `crates/coxswain-{proxy,discovery}/src`, production code only —
# `#[cfg(test)]` modules are skipped, since test arms legitimately
# `other => panic!("expected X, got {other:?}")` as assertions.
#
# A wildcard arm is `_ =>`, `&_ =>`, or a bare lowercase-identifier binding
# (`other =>`) — enum-variant arms are `UpperCamel::`, so a lowercase bare name
# before `=>` binds everything. The arm is flagged when its body (same line, the
# next expression line, or a braced block) contains `panic!`/`unreachable!`/
# `todo!`.
#
# Run from the repo root. Exits non-zero with a list of offending sites.

set -euo pipefail

roots=(crates/coxswain-proxy/src crates/coxswain-discovery/src)
offenders=""

while IFS= read -r -d '' path; do
  hits=$(awk '
    function braces(s,   t, o, c) {
      t = s; o = gsub(/{/, "{", t)
      t = s; c = gsub(/}/, "}", t)
      return o - c
    }
    BEGIN { depth = 0; in_test = 0; test_depth = 0; pend_cfg = 0; pend_expr = 0; arm_depth = 0; in_arm = 0 }
    {
      line = $0
      is_comment = (line ~ /^[[:space:]]*\/\//)
      is_attr = (line ~ /^[[:space:]]*#\[/)
      is_blank = (line ~ /^[[:space:]]*$/)
      # ---- track #[cfg(test)] mod skipping (production-only scope) ----
      if (line ~ /^[[:space:]]*#\[cfg\(test\)\]/) { pend_cfg = 1 }
      is_mod = (line ~ /(^|[[:space:]])mod[[:space:]]+[A-Za-z0-9_]+/)
      if (is_mod && (pend_cfg || line ~ /mod[[:space:]]+tests?\b/) && line ~ /{/) {
        in_test = 1; test_depth = depth
      }
      # A #[cfg(test)] attribute guards only the item it immediately precedes.
      # Once a meaningful (non-attribute, non-comment, non-blank) line passes —
      # whether that item is the `mod` we just tested or some other item the
      # attribute actually guarded — the pending flag is consumed, so a LATER
      # production `mod` is never mistaken for a test module.
      if (!is_attr && !is_comment && !is_blank) { pend_cfg = 0 }

      has_macro = (line ~ /(panic|unreachable|todo)[[:space:]]*!/)

      if (!in_test && !is_comment) {
        # ---- braced wildcard arm: scan its body ----
        if (in_arm) {
          if (has_macro) print FILENAME ":" FNR ": " line
          arm_depth += braces(line)
          if (arm_depth <= 0) in_arm = 0
        } else {
          # single-expression arm whose macro is on the next line
          if (pend_expr) {
            if (has_macro) print FILENAME ":" FNR ": " line
            pend_expr = 0
          }
          is_wild = (line ~ /(^|[^A-Za-z0-9_])(_|&_|[a-z][A-Za-z0-9_]*)[[:space:]]*(if[^=]*)?=>/)
          if (is_wild) {
            if (has_macro) {
              print FILENAME ":" FNR ": " line
            } else if (line ~ /=>[[:space:]]*{[[:space:]]*$/ || (line ~ /=>[[:space:]]*{/ && braces(line) > 0)) {
              in_arm = 1; arm_depth = braces(line)
            } else if (line ~ /=>[[:space:]]*$/) {
              pend_expr = 1
            }
          }
        }
      }

      # ---- running brace depth + test-module exit ----
      depth += braces(line)
      if (in_test && depth <= test_depth) in_test = 0
    }
  ' "$path")
  if [ -n "$hits" ]; then
    offenders+="$hits"$'\n'
  fi
done < <(find "${roots[@]}" -name '*.rs' -print0)

offenders=$(printf '%s' "$offenders" | grep -v '^$' || true)

if [ -n "$offenders" ]; then
  count=$(printf '%s\n' "$offenders" | wc -l | tr -d ' ')
  echo "FAIL: $count data-plane wildcard arm(s) that panic:" >&2
  printf '%s\n' "$offenders" | sed 's/^/  /' >&2
  echo "" >&2
  echo "A #[non_exhaustive] core enum forces this catch-all across the crate boundary, so a" >&2
  echo "new variant compiles clean then aborts the data plane at runtime — halting routing" >&2
  echo "convergence for every proxy. Degrade instead: a typed Err on a fallible path, a" >&2
  echo "fail-closed/last-good fallback on an infallible one. See CLAUDE.md and #619." >&2
  exit 1
fi

echo "OK: no panicking wildcard arms in production data-plane code under ${roots[*]}."
