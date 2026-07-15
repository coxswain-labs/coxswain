#!/usr/bin/env bash
# Guard against a runtime panic: every reflector readiness check name the
# data-plane reflector uses MUST be registered in the controller subsystem's
# check constants in status_writer.rs. `SubsystemHandle::set` panics on an
# unregistered check, which crash-loops the controller at startup.
#
# Registration is dynamic (built from *_CHECKS const arrays based on enabled
# surfaces), so this script extracts registered names from the const-array source
# regions rather than from the old static `register(...)` literal. The manually
# managed `gateway_api_crds` check appears in GATEWAY_API_CHECKS but not in a
# reflector spawn call — that is expected and not flagged.
#
# Since #59 (multi-namespace watch) reflectors are spawned via the `ScopedSpawn`
# fan-out helper, so the check name is no longer the literal 3rd arg of
# `ReflectorEffects::new(...)` (that arg is now a variable). Two literal forms
# carry the check name today:
#   1. `ScopedSpawn::{namespaced,cluster}(..., "<check>", "<Label>")` — the check
#      (snake_case) immediately precedes the CamelCase display label.
#   2. A direct `ReflectorEffects::new(&trigger, &health, "<check>", ...)` for the
#      few watches on their own trigger (e.g. the fleet `Pod` watch).
#
# Run from the repo root. Exits non-zero listing any unregistered check names.

set -euo pipefail

REFLECTOR_SRC="crates/coxswain-reflector/src/reconciler/proxy.rs"
REGISTRY_SRC="crates/coxswain-controller/src/status_writer.rs"

# Check names used by the reflector, from both literal forms above. `perl`
# exits 0 even with no matches, so this is safe under `set -o pipefail`.
used=$( {
  # Form 1: the (check, label) pair — snake_case literal followed by a
  # CamelCase display-label literal — at every ScopedSpawn spawn site.
  perl -0777 -ne 'while(/"([a-z_]+)"\s*,\s*"[A-Z][A-Za-z]*"/g){print "$1\n"}' "$REFLECTOR_SRC"
  # Form 2: the 3rd arg of a direct ReflectorEffects::new(&x, &y, "<check>", ...).
  perl -0777 -ne 'while(/ReflectorEffects::new\(\s*&[A-Za-z0-9_.]+\s*,\s*&[A-Za-z0-9_.]+\s*,\s*"([a-z_]+)"/g){print "$1\n"}' "$REFLECTOR_SRC"
} | sort -u)

# Names registered on the controller subsystem — extracted from the *_CHECKS
# const-array blocks (ALWAYS_ON_CHECKS, INGRESS_CHECKS, GATEWAY_API_CHECKS).
# Each block ends with `];`.
registered=$(awk '/const [A-Z_]*_CHECKS/{f=1} f{print} /\];/{if(f){f=0}}' "$REGISTRY_SRC" \
  | grep -o '"[a-z_]*"' | tr -d '"' | sort -u)

missing=$(comm -23 <(echo "$used") <(echo "$registered"))

if [ -n "$missing" ]; then
  echo "error: reflector readiness check(s) not registered on the controller subsystem:" >&2
  echo "$missing" | sed 's/^/  - /' >&2
  echo >&2
  echo "Add them to the appropriate *_CHECKS const in $REGISTRY_SRC," >&2
  echo "or the controller will panic at startup when the reflector marks them." >&2
  exit 1
fi

count=$(echo "$used" | grep -c .)
echo "OK: all $count reflector readiness checks are registered on the controller subsystem."
