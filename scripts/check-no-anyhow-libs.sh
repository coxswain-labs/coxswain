#!/usr/bin/env bash
# Enforce CLAUDE.md's "library crates never use 'anyhow'" rule. 'anyhow' is
# reserved for 'coxswain-bin' at the binary boundary; library crates emit
# typed errors via 'thiserror' so consumers can match on variants.
#
# Run from the repo root. Exits non-zero with a list of offending files.

set -euo pipefail

LIB_CRATES=(
  coxswain-core
  coxswain-reflector
  coxswain-proxy
  coxswain-controller
  coxswain-admin
  coxswain-health
)

offenders=()
for crate in "${LIB_CRATES[@]}"; do
  while IFS= read -r path; do
    offenders+=("$path")
  done < <(grep -rln -E 'use anyhow|anyhow::' "crates/$crate/src/" 2>/dev/null || true)
done

if [ "${#offenders[@]}" -gt 0 ]; then
  echo "FAIL: ${#offenders[@]} library-crate file(s) use 'anyhow':" >&2
  printf '  %s\n' "${offenders[@]}" >&2
  echo "" >&2
  echo "Library crates emit typed errors via 'thiserror'. 'anyhow' is reserved" >&2
  echo "for 'coxswain-bin' at the binary boundary. See CLAUDE.md's Error types." >&2
  exit 1
fi

echo "OK: no 'anyhow' references in ${#LIB_CRATES[@]} library crates."
