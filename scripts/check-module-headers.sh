#!/usr/bin/env bash
# Enforce CLAUDE.md's "every `.rs` file opens with a '//!' module header" rule.
#
# Scope: all `.rs` files under `crates/*/src/` excluding the test directories
# (which are CFG-test-gated and their headers add no shipped-doc value) and
# excluding `crates/*/benches/` + `crates/coxswain-e2e/tests/` per CLAUDE.md
# (those allow '#![allow(missing_docs)]' because criterion / e2e macros expand
# to `pub fn` items the author can't annotate).
#
# Run from the repo root. Exits non-zero with a list of offenders.

set -euo pipefail

offenders=()
while IFS= read -r -d '' path; do
  # Skip `mod.rs` files that are pure module aggregators (just `mod x; mod y;`)
  # because they often have no semantic responsibility worth documenting.
  if [[ "$(basename "$path")" == "mod.rs" ]]; then
    # mod.rs IS subject to the rule, but skip if its only content is `mod` decls
    # — that's a structural file with no semantics. Heuristic: if every non-blank,
    # non-attribute line starts with `mod ` (or `pub mod `, `pub use`), skip.
    if awk '/^[[:space:]]*$/ {next} /^[[:space:]]*#\[/ {next} /^[[:space:]]*(pub )?(use|mod) / {next} /^[[:space:]]*\/\// {next} {exit 1}' "$path"; then
      continue
    fi
  fi
  first_nonblank=$(awk 'NF {print; exit}' "$path")
  if [[ "$first_nonblank" != "//!"* ]]; then
    offenders+=("$path")
  fi
done < <(find crates -name '*.rs' \
  -not -path '*/tests/*' \
  -not -path '*/benches/*' \
  -not -path 'crates/coxswain-e2e/tests/*' \
  -print0)

if [ "${#offenders[@]}" -gt 0 ]; then
  echo "FAIL: ${#offenders[@]} .rs file(s) missing '//!' module header:" >&2
  printf '  %s\n' "${offenders[@]}" >&2
  echo "" >&2
  echo "Add a one-paragraph '//!' header stating what the module owns." >&2
  echo "See CLAUDE.md's Documentation policy." >&2
  exit 1
fi

count=$(find crates -name '*.rs' \
  -not -path '*/tests/*' \
  -not -path '*/benches/*' \
  -not -path 'crates/coxswain-e2e/tests/*' \
  | wc -l | tr -d ' ')
echo "OK: $count .rs files all carry '//!' module headers."
