#!/usr/bin/env bash
# Run the quality gates that actually cover a changed file.
#
# The gates live in CI, which means they fire only after a push — far too late
# to shape code while it is being written. This dispatcher puts them in the
# authoring loop instead: it is wired as a Claude Code `PostToolUse` hook on
# Edit/Write (see `.claude/settings.json`) and, given a path, runs only the
# gates whose scan roots cover it. Every gate here is a grep, so the common
# case costs milliseconds.
#
# Usage:
#   scripts/gates.sh <path>...        # explicit paths
#   echo '<hook json>' | scripts/gates.sh   # reads .tool_input.file_path
#
# Exits non-zero if any applicable gate fails, printing that gate's own
# diagnostics. Unknown / unmatched paths are a no-op.

set -uo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

paths=("$@")

# No args: read the hook payload from stdin and pull the edited file out of it.
# `while read` rather than `mapfile` — macOS ships bash 3.2, which has no
# `mapfile`, and a hook that silently reads nothing is exactly the failure mode
# this dispatcher exists to prevent.
if [ "${#paths[@]}" -eq 0 ] && [ ! -t 0 ]; then
  payload="$(cat)"
  if command -v jq >/dev/null 2>&1; then
    extracted="$(printf '%s' "$payload" \
      | jq -r '.tool_input.file_path // .tool_input.notebook_path // empty' 2>/dev/null)"
  else
    extracted="$(printf '%s' "$payload" \
      | sed -n 's/.*"file_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  fi
  while IFS= read -r line; do
    [ -n "$line" ] && paths+=("$line")
  done <<< "$extracted"
fi

[ "${#paths[@]}" -eq 0 ] && exit 0

gates=()
add() { case " ${gates[*]-} " in *" $1 "*) ;; *) gates+=("$1") ;; esac; }

for raw in "${paths[@]}"; do
  [ -z "$raw" ] && continue
  # Normalise to a repo-relative path.
  p="${raw#"$PWD"/}"

  case "$p" in
    # A changed gate must still fire — this is the check that four gates in
    # this repo silently failed for their whole life.
    scripts/check-*.sh|scripts/tests/*) add scripts/tests/run.sh ;;
  esac

  case "$p" in
    crates/coxswain-proxy/src/edge/*) add scripts/check-no-peek-readable.sh ;;
  esac
  case "$p" in
    crates/coxswain-core/src/*|crates/coxswain-reflector/src/*) add scripts/check-bounded-regex.sh ;;
  esac
  case "$p" in
    crates/coxswain-proxy/src/*|crates/coxswain-discovery/src/*) add scripts/check-no-wildcard-panic.sh ;;
  esac
  case "$p" in
    crates/*/src/*.rs|crates/*/tests/*.rs|crates/*/benches/*.rs|xtask/src/*.rs)
      add scripts/check-no-per-site-allow.sh ;;
  esac
  case "$p" in
    crates/coxswain-e2e/tests/*.rs)
      add scripts/check-no-e2e-sleeps.sh
      add scripts/check-e2e-plane-layout.sh
      add scripts/check-e2e-single-poller.sh
      add scripts/check-e2e-mutators-serialized.sh ;;
  esac
  case "$p" in
    crates/coxswain-e2e/src/harness/*) add scripts/check-e2e-single-poller.sh ;;
  esac
  case "$p" in
    crates/coxswain-e2e/src/fixtures/*|crates/coxswain-e2e/fixtures/*)
      add scripts/check-e2e-images-pinned.sh ;;
  esac
  case "$p" in
    crates/*/Cargo.toml|Cargo.toml) add scripts/check-workspace-lints-decl.sh ;;
  esac
  case "$p" in
    crates/*/src/*.rs) add scripts/check-no-anyhow-libs.sh ;;
  esac
  case "$p" in
    crates/coxswain-reflector/src/*) add scripts/check-reflector-health-checks.sh ;;
  esac
  case "$p" in
    crates/coxswain-reflector/src/ingress/annotations*) add scripts/check-annotation-coverage.sh ;;
  esac
  case "$p" in
    crates/coxswain-controller/src/controller/gateway_class_status.rs|conformance/*)
      add scripts/check-supported-features.sh ;;
  esac
  case "$p" in
    .gateway-api-versions.json|scripts/gateway-api-versions.sh)
      add scripts/check-gateway-api-versions.sh ;;
  esac
done

[ "${#gates[@]}" -eq 0 ] && exit 0

rc=0
for g in "${gates[@]}"; do
  if ! out="$(bash "$g" 2>&1)"; then
    printf '%s\n' "$out" >&2
    rc=1
  fi
done
exit "$rc"
