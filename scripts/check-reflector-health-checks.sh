#!/usr/bin/env bash
# Guard against a runtime panic: every reflector readiness check name passed to
# `ReflectorEffects::new(..., "<name>", ...)` in the data-plane reflector MUST be
# registered in the controller subsystem's check constants in status_writer.rs.
# `SubsystemHandle::set` panics on an unregistered check, which crash-loops the
# controller at startup.
#
# Registration is dynamic (built from *_CHECKS const arrays based on enabled
# surfaces), so this script extracts registered names from the const-array source
# regions rather than from the old static `register(...)` literal. The manually
# managed `gateway_api_crds` check appears in GATEWAY_API_CHECKS but not in
# ReflectorEffects::new() calls — that is expected and not flagged.
#
# Run from the repo root. Exits non-zero listing any unregistered check names.

set -euo pipefail

REFLECTOR_SRC="crates/coxswain-reflector/src/reconciler/proxy.rs"
REGISTRY_SRC="crates/coxswain-controller/src/status_writer.rs"

# Check names used by the reflector: the 3rd argument string literal of every
# ReflectorEffects::new(...) call.
used=$(grep -o 'ReflectorEffects::new([^)]*)' "$REFLECTOR_SRC" \
  | grep -o '"[a-z_]*"' | tr -d '"' | sort -u)

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
