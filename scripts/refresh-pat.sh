#!/usr/bin/env bash
# Refreshes one of the project's GitHub PAT secrets.
# Run this when a token expires (GitHub will email you when it's close to expiry).
#
# Usage: scripts/refresh-pat.sh [labeler|docs]
#   Omit the argument to select interactively.
set -euo pipefail

REPO="coxswain-labs/coxswain"

list_tokens() {
  cat <<'EOF'
Available tokens:
  labeler  → GH_LABELER_PAT  (labeler workflow; PR event propagation)
  docs     → GH_DOCS_PAT     (docs publish workflow; cross-repo push)
EOF
}

show_requirements() {
  case "$1" in
    labeler)
      cat <<'EOF'
Settings for the new PAT (GH_LABELER_PAT):
  Resource owner : coxswain-labs
  Repository     : coxswain-labs/coxswain (only this repo)
  Permission     : Pull requests → Read and write

Used by .github/workflows/label.yml.  A fine-grained PAT is required
(not GITHUB_TOKEN) so labeler-emitted label events can trigger downstream
workflows — GITHUB_TOKEN-generated events are intentionally blocked from
doing so.
EOF
      ;;
    docs)
      cat <<'EOF'
Settings for the new PAT (GH_DOCS_PAT):
  Resource owner : coxswain-labs
  Repository     : coxswain-labs/coxswain-labs.github.io (only)
  Permission     : Contents → Read and write

Used by .github/workflows/docs.yml to push built documentation into the
org-level Pages repo under the coxswain/ subdirectory.  Do NOT add the
main coxswain repo to the access list.
EOF
      ;;
    *)
      echo "Unknown token: $1"
      list_tokens
      exit 1
      ;;
  esac
}

secret_name() {
  case "$1" in
    labeler) echo "GH_LABELER_PAT" ;;
    docs)    echo "GH_DOCS_PAT"    ;;
    *)       echo "Unknown token: $1"; exit 1 ;;
  esac
}

TOKEN="${1:-}"
if [ -z "$TOKEN" ]; then
  list_tokens
  printf '\nWhich token to refresh? '
  read -r TOKEN
fi

echo ""
show_requirements "$TOKEN"
SECRET="$(secret_name "$TOKEN")"

echo ""
echo "Opening GitHub in your browser..."
open "https://github.com/settings/personal-access-tokens/new"
echo ""
echo "Paste the new PAT when prompted below (input is hidden by gh):"
gh secret set "$SECRET" --repo "$REPO"

echo ""
echo "Done — $SECRET updated on $REPO."
