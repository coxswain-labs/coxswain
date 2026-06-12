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

## Editing the docs site

The user-facing docs live under `docs/src/` and are built with [mkdocs-material](https://squidfunk.github.io/mkdocs-material/). Preview your changes locally before opening the PR:

```bash
cd docs
uv venv .venv
uv pip install -r requirements.txt  # versions pinned exactly — see requirements.txt
source .venv/bin/activate
mkdocs serve          # live-reload at http://localhost:8000
```

`.venv/` is gitignored. The `--system` flag used in CI does not work on Homebrew-managed Python.

Versions in `requirements.txt` are pinned exactly because mkdocs-material is in maintenance mode (security patches only through ~Nov 2026). When a security advisory lands, bump the pins in a dedicated PR rather than running `uv pip install -U`.

PR-time validation (`mkdocs build --strict`) runs as the `docs-build` job in `.github/workflows/distribution.yml`; the same check runs against your PR before merge. Mike versioning, the `publish-docs` job, and the `PACKAGE_VERSION` substitution behavior are maintainer concerns — see [`RELEASE.md`](RELEASE.md) for those.
