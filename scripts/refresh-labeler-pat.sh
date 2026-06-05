#!/usr/bin/env bash
# Refreshes the GH_LABELER_PAT secret used by the labeler workflow.
# Run this when the PAT expires (GitHub will email you when it's close to expiry).
#
# The PAT needs a single permission: Pull requests → Read and write
# Scope it to the coxswain-labs/coxswain repository only.
set -euo pipefail

REPO="coxswain-labs/coxswain"
SECRET="GH_LABELER_PAT"

echo "Settings for the new PAT:"
echo "  Resource owner : coxswain-labs"
echo "  Repository     : coxswain-labs/coxswain (only this repo)"
echo "  Permission     : Pull requests → Read and write"
echo ""
echo "Opening GitHub in your browser..."
open "https://github.com/settings/personal-access-tokens/new"
echo ""
read -rsp "Paste the new PAT and press Enter: " pat
echo

gh secret set "$SECRET" --repo "$REPO" --body "$pat"

echo "Done — $SECRET updated on $REPO."
echo "The labeler workflow will use the new token on the next PR push."
