#!/usr/bin/env bash
# Enforce e2e rubric #11 (knob coverage): every `ingress.coxswain-labs.dev/*`
# annotation constant must carry BOTH
#   (a) a parsing unit test — the const is referenced in the `#[cfg(test)]`
#       region of its defining file, AND
#   (b) a named e2e effect test — the annotation key string appears in the e2e
#       suite (`crates/coxswain-e2e/{fixtures,tests}/`), proving the knob's
#       runtime effect is exercised on live traffic.
# Modeled on check-supported-features.sh: extract a set from source, assert a
# property over it.
#
# Quarantine-with-ticket (rubric #10): annotations whose e2e effect test is not
# yet written are listed in E2E_ALLOWLIST below, each tied to a tracking issue.
# An allowlisted annotation still REQUIRES a parsing unit test — only the e2e
# half is deferred. A NEW annotation is never auto-exempt: it must ship an e2e
# test or be added here (which forces a ticket).
#
# Run from the repo root. Exits non-zero listing any uncovered annotation.

set -euo pipefail

ANNOTATIONS_RS="crates/coxswain-reflector/src/ingress/annotations.rs"
E2E_DIR="crates/coxswain-e2e"

# Annotation keys whose e2e effect test is tracked, not yet landed.
#   connect-timeout / read-timeout / send-timeout → #331
#   backend-protocol                              → #339
E2E_ALLOWLIST=(
  "ingress.coxswain-labs.dev/connect-timeout"   # #331
  "ingress.coxswain-labs.dev/read-timeout"      # #331
  "ingress.coxswain-labs.dev/send-timeout"      # #331
  "ingress.coxswain-labs.dev/backend-protocol"  # #339
)

is_allowlisted() {
  local key="$1"
  for a in "${E2E_ALLOWLIST[@]}"; do
    [ "$a" = "$key" ] && return 0
  done
  return 1
}

# Line where the `#[cfg(test)]` test module starts — the parse-test region.
test_start=$(grep -nE '^[[:space:]]*#\[cfg\(test\)\]' "$ANNOTATIONS_RS" | head -1 | cut -d: -f1 || true)
if [ -z "$test_start" ]; then
  echo "ERROR: no '#[cfg(test)]' module found in $ANNOTATIONS_RS — check the layout." >&2
  exit 1
fi
test_region=$(tail -n "+$test_start" "$ANNOTATIONS_RS")

# Extract (const-name, annotation-key) pairs. Skip PREFIX (value ends in '/',
# i.e. it has no per-annotation key). `mapfile` is avoided for bash-3.2 (macOS)
# portability — the rest of scripts/ uses while-read loops too.
consts=()
while IFS= read -r line; do
  consts+=("$line")
done < <(grep -E 'const [A-Z_]+: &str = "ingress\.coxswain-labs\.dev/[^"]+"' "$ANNOTATIONS_RS" || true)

if [ "${#consts[@]}" -eq 0 ]; then
  echo "ERROR: extracted zero annotation constants from $ANNOTATIONS_RS — check the grep pattern." >&2
  exit 1
fi

missing_parse=()
missing_e2e=()
checked=0

for line in "${consts[@]}"; do
  name=$(printf '%s' "$line" | sed -E 's/.*const ([A-Z_]+): &str.*/\1/')
  key=$(printf '%s' "$line" | sed -E 's/.*"(ingress\.coxswain-labs\.dev\/[^"]+)".*/\1/')
  # PREFIX has a trailing slash and no key segment; skip it.
  case "$key" in */) continue ;; esac
  checked=$((checked + 1))

  # (a) parse-test: const name referenced (whole-word) in the test region.
  if ! printf '%s\n' "$test_region" | grep -qw "$name"; then
    missing_parse+=("$name ($key)")
  fi

  # (b) e2e effect test: annotation key string (literal) present in the e2e suite.
  if ! grep -rqF "$key" "$E2E_DIR" 2>/dev/null; then
    if ! is_allowlisted "$key"; then
      missing_e2e+=("$name ($key)")
    fi
  fi
done

fail=0
if [ "${#missing_parse[@]}" -gt 0 ]; then
  echo "FAIL: ${#missing_parse[@]} annotation(s) missing a parsing unit test in $ANNOTATIONS_RS:" >&2
  printf '  %s\n' "${missing_parse[@]}" >&2
  fail=1
fi
if [ "${#missing_e2e[@]}" -gt 0 ]; then
  echo "FAIL: ${#missing_e2e[@]} annotation(s) missing a named e2e effect test (and not allowlisted):" >&2
  printf '  %s\n' "${missing_e2e[@]}" >&2
  echo "" >&2
  echo "Per e2e rubric #11, add an effect test under $E2E_DIR/tests/ that applies the" >&2
  echo "annotation and asserts its runtime effect. If deferred, add the key to" >&2
  echo "E2E_ALLOWLIST in this script with a tracking issue reference." >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "OK: $checked Ingress annotation(s) all carry a parsing unit test; e2e effect tests present or allowlisted (${#E2E_ALLOWLIST[@]} tracked)."
