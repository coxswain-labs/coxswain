#!/usr/bin/env bash
# Enforce CLAUDE.md's "every 'crates/*/Cargo.toml' declares `[lints] workspace
# = true`" rule. Without this declaration, a crate silently escapes every
# workspace lint, defeating the single-source-of-truth policy.
#
# Run from the repo root. Exits non-zero with a list of offending Cargo.toml
# files.

set -euo pipefail

offenders=()
for cargo_toml in crates/*/Cargo.toml; do
  # Look for the '[lints]' section followed (eventually) by 'workspace = true'.
  if ! awk '
    /^\[lints\]/ { in_lints=1; next }
    /^\[/ { in_lints=0 }
    in_lints && /^workspace[[:space:]]*=[[:space:]]*true/ { found=1; exit }
    END { exit (found ? 0 : 1) }
  ' "$cargo_toml"; then
    offenders+=("$cargo_toml")
  fi
done

if [ "${#offenders[@]}" -gt 0 ]; then
  echo "FAIL: ${#offenders[@]} crate Cargo.toml(s) missing '[lints] workspace = true':" >&2
  printf '  %s\n' "${offenders[@]}" >&2
  echo "" >&2
  echo "Add:" >&2
  echo "  [lints]" >&2
  echo "  workspace = true" >&2
  echo "to each offender. See CLAUDE.md's Per-crate Cargo manifest policy." >&2
  exit 1
fi

count=$(ls crates/*/Cargo.toml | wc -l | tr -d ' ')
echo "OK: $count crate manifests declare '[lints] workspace = true'."
