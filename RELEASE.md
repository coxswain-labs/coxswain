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

## Dry run

```bash
cargo release minor --dry-run
```

Shows exactly what would happen without making any changes.
