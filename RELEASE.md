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
2. Commits the version change
3. Creates a `v{version}` git tag
4. Pushes the commit and tag

CI picks up the tag and publishes the Docker image automatically. Helm chart publishing will be added in #28.

## Dry run

```bash
cargo release minor --dry-run
```

Shows exactly what would happen without making any changes.
