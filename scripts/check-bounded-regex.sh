#!/usr/bin/env bash
# Enforce CLAUDE.md's "tenant-supplied regexes compile via the bounded
# compile_bounded helper, never bare Regex::new" rule (issue #519).
#
# Route/CRD/annotation patterns (HTTPRoute & GRPCRoute header/query matches,
# PathRewriteRegex, path regexes) are attacker-controllable — any namespace user
# who can create a route/CR supplies the pattern. `regex::Regex::new` uses the
# crate default 10 MB compiled-program `size_limit`, so a tenant can force ~10 MB
# of controller memory per matcher: a reflector memory-exhaustion DoS. Every such
# compile must go through `coxswain_core::routing::compile_bounded` (or
# `compile_path_regex`, which delegates to it), which caps the program at
# `REGEX_SIZE_LIMIT`.
#
# Scope: `coxswain-core` + `coxswain-reflector` src. Per this repo's inline-test
# convention (unit tests live in a bottom `#[cfg(test)] mod tests`), the scan stops
# at the first `#[cfg(test)]` so test patterns using `Regex::new` are exempt.
# Comment lines are skipped. `RegexSet::new` / `RegexBuilder::new` do not contain
# the `Regex::new` token and are not matched (the builder forms carry their own
# size_limit at their call sites).
#
# Run from the repo root. Exits non-zero with a list of offending sites.

set -euo pipefail

roots=(crates/coxswain-core/src crates/coxswain-reflector/src)
offenders=""

while IFS= read -r -d '' path; do
  hits=$(awk '
    /#\[cfg\(test\)\]/ { exit }
    /^[[:space:]]*\/\// { next }
    /Regex::new[[:space:]]*\(/ { printf "%s:%d:%s\n", FILENAME, NR, $0 }
  ' "$path")
  if [ -n "$hits" ]; then
    offenders+="$hits"$'\n'
  fi
done < <(find "${roots[@]}" -name '*.rs' -print0)

offenders=$(printf '%s' "$offenders" | grep -v '^$' || true)

if [ -n "$offenders" ]; then
  count=$(printf '%s\n' "$offenders" | wc -l | tr -d ' ')
  echo "FAIL: $count bare Regex::new site(s) on potentially tenant-supplied input:" >&2
  printf '%s\n' "$offenders" | sed 's/^/  /' >&2
  echo "" >&2
  echo "Compile route/CRD/annotation patterns via coxswain_core::routing::compile_bounded" >&2
  echo "(size-limited to REGEX_SIZE_LIMIT). Bare Regex::new uses the 10 MB default — a" >&2
  echo "reflector memory-exhaustion DoS vector. See CLAUDE.md and [[project_bounded_regex_compilation]]." >&2
  exit 1
fi

echo "OK: no bare Regex::new on tenant-supplied input in core/reflector src."
