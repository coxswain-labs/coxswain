#!/usr/bin/env bash
# Enforce e2e rubric #7 (hermetic SUT; external images digest-pinned): every
# external container image the e2e fixtures run must be pinned by `@sha256:`
# digest, so a registry tag mutation or `:latest` re-push can't silently change
# what a test exercises.
#
# Two surfaces are checked:
#   1. The image constants in `src/fixtures/images.rs` (the single source of
#      truth) must each carry `@sha256:`.
#   2. Any literal `image:` value in `fixtures/**/*.yaml` must be either a
#      `${...}` substitution token (resolved from images.rs at apply time) or an
#      inline `@sha256:`-pinned ref. No bare tags / `:latest`.
#
# Allowlisted exception: the intentionally non-resolvable
# `registry.invalid/...:does-not-exist` image used to drive ImagePullBackOff in
# `gateway_api/cutover_crash_loop.yaml` — a digest is meaningless when the image
# must fail to pull.
#
# Run from the repo root. Exits non-zero listing any unpinned image.

set -euo pipefail

CRATE="crates/coxswain-e2e"
IMAGES_RS="$CRATE/src/fixtures/images.rs"
FIXTURES_DIR="$CRATE/fixtures"

# Image refs allowed to be unpinned because the test depends on them NOT pulling.
ALLOW_UNPINNED='registry.invalid/'

offenders=()

# (1) Every image-ref string literal in images.rs is `@sha256:`-pinned. The file
# holds only image-ref constants, so every quoted `<repo>:<tag>` literal is one
# (the const may span two lines, so match the literal, not the declaration line).
while IFS= read -r value; do
  case "$value" in
    *'registry.invalid/'*) continue ;;  # negative-test ref, never pinned
    *'@sha256:'*) continue ;;             # pinned — good
    *) offenders+=("$IMAGES_RS: $value") ;;
  esac
done < <(grep -oE '"[^"]*:[^"]*"' "$IMAGES_RS" || true)

# (2) Every literal `image:` in fixture YAML is a `${...}` token or `@sha256:`-pinned.
while IFS= read -r hit; do
  # hit form: path:lineno:        image: <value>
  value=$(printf '%s' "$hit" | sed -E 's/^[^:]+:[0-9]+:[[:space:]]*image:[[:space:]]*//')
  case "$value" in
    "\${"*) continue ;;                    # substitution token → resolved from images.rs
    *"$ALLOW_UNPINNED"*) continue ;;       # allowlisted negative-test ref
    *'@sha256:'*) continue ;;              # inline pinned ref
    *) offenders+=("$hit") ;;
  esac
done < <(grep -rnE '^[[:space:]]*image:[[:space:]]*\S' "$FIXTURES_DIR" --include='*.yaml' || true)

if [ "${#offenders[@]}" -gt 0 ]; then
  echo "FAIL: ${#offenders[@]} unpinned e2e image reference(s):" >&2
  printf '  %s\n' "${offenders[@]}" >&2
  echo "" >&2
  echo "Per e2e rubric #7, pin by '@sha256:' index digest. Resolve with:" >&2
  echo "  docker buildx imagetools inspect <ref> --format '{{.Manifest.Digest}}'" >&2
  echo "Fixtures should reference a \${IMAGE} token defined in $IMAGES_RS." >&2
  exit 1
fi

echo "OK: all e2e images are \${token}-substituted or @sha256:-pinned."
