# Release Procedure

Coxswain uses [`cargo-release`](https://github.com/crate-ci/cargo-release) to version, tag, and publish releases.

## Install

```bash
cargo install cargo-release
```

## Ship a release

```bash
cargo release patch   # 0.2.0 → 0.2.1  (bug fixes)
cargo release minor   # 0.2.0 → 0.3.0  (new milestone)
cargo release major   # 0.9.0 → 1.0.0  (GA)
```

This single command:
1. Bumps the version in `Cargo.toml`
2. Runs `scripts/bump-helm-version.sh` to keep `charts/coxswain/Chart.yaml` (`version` and `appVersion`) in sync
3. Commits the version change
4. Creates a `v{version}` git tag
5. Pushes the commit and tag

CI picks up the tag and runs the release pipeline automatically:
- **OCI image** — multi-arch `ghcr.io/coxswain-labs/coxswain:{tag}` (and floating tags `:X.Y`, `:X`, `:latest`)
- **Helm chart** — `oci://ghcr.io/coxswain-labs/charts/coxswain:{X.Y.Z}`
- **install.yaml** — pre-rendered Kustomize manifest attached to the GitHub Release
- **Signatures** — both the image and the chart are signed with cosign (keyless, Sigstore)

The release pipeline blocks publication if `cargo deny check` finds a disallowed license or advisory, or if `trivy image` detects a HIGH or CRITICAL CVE in the published image.

## Recovering from a failed release

Where the failure happens determines what you can do:

| Stage | What's out | Recovery |
|-------|-----------|----------|
| Pre-release hook crashes (before commit) | Nothing — `cargo-release` aborts cleanly | Fix the hook, re-run the same version |
| Tag pushed, **transient** CI failure (network, timeout) | Tag only; artifact missing | Use **Re-run failed jobs** in GitHub Actions |
| Tag pushed, `cargo-deny` fails | Tag only; no image | Delete the remote tag (`git push origin :refs/tags/vX.Y.Z`), fix the advisory/license, re-run the same version |
| Tag pushed, `trivy-scan` fails (real CVE) | Image published and signed; no chart or GitHub Release | Fix the vulnerability and cut a **new patch version** — the vulnerable image is already at that digest and reusing the tag would break the cosign signature |

**Never force-push or move a tag that already has a published, cosign-signed image.** The signature is bound to the digest, not the tag, so the signed artifact remains in the registry regardless.

## Dry run

```bash
cargo release minor --dry-run
```

Shows exactly what would happen without making any changes.

## Documentation site versioning

The docs site is built with [mike](https://github.com/jimporter/mike) on top of mkdocs-material and published to `coxswain-labs.github.io/coxswain/`. Mike serves a versioned site so old releases stay reachable. Behavior is driven by `.github/workflows/release.yml`'s `publish-docs` job — see the `Determine version and aliases` step for the source of truth.

- **Push to `main`** → publishes under the `unstable` version key with no aliases. `PACKAGE_VERSION` is set to the literal string `main` so the `X.Y.Z` placeholder hook stays inert (substituted commands like `helm --version` and GitHub release-asset URLs are only valid against a tagged release).
- **Push a tag `vX.Y.Z`** → publishes under the `X.Y` version key (MAJOR.MINOR) and applies the aliases `stable` + `latest`. `PACKAGE_VERSION` is set to the full SemVer so install/verification pages render with the right tag references.
- Patches overwrite their minor version key (`0.1.1` → `0.1`, same as `0.1.0`).
- The site root redirects to `stable` (mike's default alias).

Publishing happens automatically as the `publish-docs` job at the tail of `release.yml`, after `publish-image`, `trivy-scan`, `publish-chart`, and `publish-kustomize`. A failed earlier step skips docs promotion and leaves the site unchanged. The job pushes into the `coxswain/` subdirectory of the `coxswain-labs/coxswain-labs.github.io` Pages repo using the `GH_DOCS_PAT` cross-repo PAT.

When previewing a tagged release locally:

```bash
PACKAGE_VERSION=0.1.2 mkdocs serve
```

PR-time validation (`mkdocs build --strict`) lives in `.github/workflows/distribution.yml` as the `docs-build` job.

### Pre-release tagging (UNDEFINED — needs design review)

The current `Determine version and aliases` step matches `refs/tags/v*` indiscriminately, so a hypothetical `v0.2.0-rc.1` tag would publish under the same `0.2` version key as the eventual `v0.2.0` release AND apply the `stable` + `latest` aliases — which is almost certainly the wrong behavior for a pre-release. The documented `cargo release patch|minor|major` flow doesn't emit pre-release tags today, so no one has hit this footgun yet, but it remains a latent bug.

Open questions to resolve before publishing the first pre-release:

- Should pre-release tags publish under a separate version key (e.g. `0.2-rc`) or update the same `0.2` key the eventual stable will land on?
- Should pre-release tags update the `stable` / `latest` aliases (presumably NOT) or only a `next` / `rc` alias?
- Should `cargo release` learn a `--pre rc` flow that bumps the SemVer pre-release segment without affecting Cargo.toml's main version line?
- Does the `PACKAGE_VERSION` substitution hook need updating to surface "this is a pre-release, install at your own risk" warnings on the rendered pages?

Until these are answered and the workflow is updated, do not push `v*-rc.*` / `v*-beta.*` / `v*-alpha.*` tags through `cargo release` or by hand.

## CI secrets / PAT rotation

All PAT secrets are managed through one script:

```bash
./scripts/refresh-pat.sh [labeler|docs]
```

Run without arguments to select interactively. The script prints the required PAT scopes before opening the GitHub token creation page. The header comments in `scripts/refresh-pat.sh` document the two tokens (`GH_LABELER_PAT` for the PR labeler workflow, `GH_DOCS_PAT` for the cross-repo docs publish), their workflows, and the required permissions. GitHub emails maintainers when a token approaches expiry — run the script to rotate.
