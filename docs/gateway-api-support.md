# Gateway API Support

## Compatibility matrix

| Coxswain | Gateway API |
|----------|-------------|
| v0.1     | v1.5.x      |

When upgrading coxswain, install the matching Gateway API CRDs from
[gateway-api releases](https://github.com/kubernetes-sigs/gateway-api/releases)
before deploying the new coxswain version.

## Feature lifecycle

Each Gateway API feature goes through one or more of these stages before coxswain advertises it:

| Stage | Meaning |
|-------|---------|
| **Planned** | GitHub issue open, ROADMAP item checked off, no code yet |
| **Implemented (unverified)** | Code landed but conformance tests not yet passing — NOT in `SUPPORTED_FEATURES` |
| **Conformance-passing** | Conformance tests pass; added to `SUPPORTED_FEATURES` and `conformance/main_test.go` in the **same PR** |
| **Experimental-only** | Behind `--features experimental`; never advertised in standard builds |
| **Deprecated** | Upstream removed an alpha feature we had implemented; kept one minor release with a warning, then removed |

A feature enters `GatewayClass.status.supportedFeatures` (the public contract users see) **only** when it reaches _Conformance-passing_. Never add it earlier.

## Bumping the Gateway API version

When a new upstream release ships:

1. Update `.gateway-api-version` at the repo root to the new tag (e.g. `v1.6.0`).
2. Bump `gateway-api = "..."` in the workspace `Cargo.toml` to the matching crate version.
3. Run `cargo check` and `cargo check --features experimental` — fix any new API surface.
4. Check if new `features.SupportXxx` constants appeared upstream. For each new feature that coxswain supports, add it to:
   - `SUPPORTED_FEATURES` in `crates/coxswain-controller/src/controller/gateway_class_status.rs` (keep sorted).
   - `opts.SupportedFeatures` in `conformance/main_test.go`.
   - Run `bash scripts/check-supported-features.sh` to confirm parity.
5. Update the echo-basic image tags in `crates/coxswain-e2e/fixtures/` (grep for `echo-basic:`) to the new release's image tag (format: `v<date>-<version>`; find the exact tag on [gcr.io/k8s-staging-gateway-api](https://console.cloud.google.com/gcr/images/k8s-staging-gateway-api) or the upstream release notes).
6. Update the compatibility matrix above.
6. Run `cd conformance && go vet ./...` to validate the Go feature constant names.

## Experimental channel

The `gateway-api` crate exposes alpha resources and experimental fields under the `experimental` cargo feature. This feature is **never enabled in release builds**; it is for contributors and CI preview builds only.

To build locally with experimental types enabled:

```bash
cargo build -p coxswain-bin --features experimental
```

Code paths that use alpha-only types must be gated:

```rust
#[cfg(feature = "experimental")]
// ... alpha-only code
```

Adding support for an experimental resource (e.g. `GRPCRoute` once it was still alpha) means the implementation compiles only with `--features experimental`, never runs in a standard release, and is not added to `SUPPORTED_FEATURES` until the resource is promoted to standard and conformance passes.
