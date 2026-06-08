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
