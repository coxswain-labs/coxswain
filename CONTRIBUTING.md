# Contributing to coxswain

Thanks for your interest in coxswain — a pure-Rust Kubernetes Ingress & Gateway API controller backed by [Pingora](https://github.com/cloudflare/pingora).

## Getting started

- **Local dev setup** (Rust, cluster, run-locally, e2e + conformance): see [`DEVELOPMENT.md`](DEVELOPMENT.md).
- **Codebase conventions and rules** (lints, error types, hot-path budget, test layout, commit footers): see [`CLAUDE.md`](CLAUDE.md).
- **Roadmap and issue triage**: [Coxswain Roadmap Project](https://github.com/orgs/coxswain-labs/projects/2).

## Filing issues

Labels: discover the live taxonomy with `gh label list --repo coxswain-labs/coxswain`. Every issue carries at least one `type:` and one `area:` or `api:`. Use `status: backlog` for triaged-but-uncommitted issues; promotion to a `v0.N` milestone happens when scope solidifies.

## Pull requests

- Branch off `main`: `git checkout -b issue-N` (replace `N` with the issue number you're working on).
- Reference the issue in every commit footer: `Refs #N` (intermediate) or `Fixes #N` (final). `Fixes #N` auto-closes the issue and flips the Project's `Status` to `Done` on merge.
- Run `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test --workspace --exclude coxswain-e2e` before pushing.
- Squash-merge from the GitHub UI or `gh pr merge --squash --delete-branch`.

The CI pipeline runs the full e2e suite + conformance against every PR; the same procedures you ran locally are exercised again on Linux runners.

## Documentation site

The user-facing docs live under `docs/src/` and are built with [mkdocs-material](https://squidfunk.github.io/mkdocs-material/), versioned with [mike](https://github.com/jimporter/mike), and published to `coxswain-labs.github.io/coxswain/`.

### Preview locally

```bash
cd docs
uv venv .venv
uv pip install -r requirements.txt
source .venv/bin/activate
mkdocs serve          # live-reload at http://localhost:8000
mike serve            # serves the versioned site (requires a prior mike deploy)
```

`.venv/` is gitignored. The `--system` flag used in CI does not work on Homebrew-managed Python.

The `PACKAGE_VERSION` env var drives a page hook that rewrites `X.Y.Z` placeholders in install and verification pages. Substitution only fires when `PACKAGE_VERSION` parses as a SemVer (e.g. `0.1.2`); on `main` or any non-SemVer value the placeholders stay literal — several substituted commands (`helm --version`, GitHub release-asset URLs, signed chart tags) only have valid values for tagged releases:

```bash
PACKAGE_VERSION=0.1.2 mkdocs serve
```

### How versioning works

- **Push to `main`** → publishes under the `dev` alias (latest unreleased docs).
- **Push a tag `vX.Y.Z`** → publishes under the `X.Y` key and updates `stable`.
- Patches overwrite their minor version key (`0.1.1` → `0.1`, same as `0.1.0`).
- The site root redirects to `stable`.

Publishing happens automatically as the `publish-docs` job at the tail of `.github/workflows/release.yml`, after `publish-image`, `trivy-scan`, `publish-chart`, and `publish-kustomize`. A failed earlier step skips docs promotion and leaves the site unchanged. The job pushes into the `coxswain/` subdirectory of the `coxswain-labs/coxswain-labs.github.io` repo using a cross-repo PAT.

PR-time validation (`mkdocs build --strict`) runs as the `docs-build` job in `.github/workflows/distribution.yml`.

## CI secrets / PAT rotation

All PAT secrets are managed through one script:

```bash
./scripts/refresh-pat.sh [labeler|docs]
```

Run without arguments to select interactively. The script prints the required PAT scopes before opening the GitHub token creation page. The header comments in `scripts/refresh-pat.sh` document the two tokens, their workflows, and the required permissions; GitHub emails you when a token approaches expiry — run the script to rotate.
