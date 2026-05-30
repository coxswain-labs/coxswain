# Development Guide

## Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- A local Kubernetes cluster with `kubectl` configured (`~/.kube/config`)

Any local distribution works: 

- [OrbStack](https://orbstack.dev/)
- [Docker Desktop](https://docs.docker.com/desktop/kubernetes/)
- [minikube](https://minikube.sigs.k8s.io/)
- [kind](https://kind.sigs.k8s.io/)
- [k3d](https://k3d.io/)
- etc.

## Local development (no Docker required)

When developing locally, run the binary directly on your machine. It discovers the cluster via `~/.kube/config` and talks to Kubernetes without needing to be inside a pod.

### 1. Install the Gateway API CRDs

The Gateway API CRDs are not bundled with Kubernetes and must be installed once per cluster:

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml
```

### 2. Apply the cluster manifests

Apply everything except the Deployment — the binary runs on your machine instead:

```bash
kubectl apply -f deploy/manifests/namespace.yaml
kubectl apply -f deploy/manifests/rbac.yaml
kubectl apply -f deploy/manifests/gateway-class.yaml
```

> The RBAC grants are scoped to the `coxswain-controller` ServiceAccount inside the cluster. When running locally, your kubeconfig identity is used instead, which typically has cluster-admin on local distributions.

### 3. Run the binary

```bash
cargo run --bin coxswain -- --log-format console
```

`--log-format console` produces human-readable output instead of JSON. All ports bind on localhost at their defaults:

| Port | Purpose |
|------|---------|
| `8080` | HTTP proxy (data plane) |
| `8081` | Health endpoints (`/healthz`, `/readyz`) |
| `8082` | Admin endpoints (`/metrics`, `/routes`, `/status`) |

### 4. Verify

```bash
# Health
curl -s http://localhost:8081/healthz      # ok
curl -s http://localhost:8081/readyz       # ok (after initial sync completes)

# Admin diagnostics
curl -s http://localhost:8082/status       # {"version":"...","synced":true,"host_count":0}
curl -s http://localhost:8082/routes       # {"hosts":[]}
curl -s http://localhost:8082/metrics      # Prometheus text

# Kubernetes
kubectl get gatewayclass                   # should show "coxswain" accepted
```

`synced` in `/status` flips to `true` once both Ingress and HTTPRoute watch streams complete their initial LIST. You will see `ingress initial sync complete` in the logs when this happens.

## Testing routing with dev manifests

The `deploy/dev/` directory contains lightweight test fixtures for exercising both routing paths without any application code.

### Apply backends and routes

```bash
# Three echo servers (echo-a, echo-b, echo-c) — apply once
kubectl apply -f deploy/dev/echo-backends.yaml

# Gateway API routes (requires Gateway API CRDs from step 1)
kubectl apply -f deploy/dev/httproute.yaml

# Classic Ingress routes
kubectl apply -f deploy/dev/ingress.yaml
```

### Test Gateway API routes

```bash
# echo.local — path-based routing, single backend per rule
curl -H "Host: echo.local" http://localhost:8080/a          # hello from echo-a
curl -H "Host: echo.local" http://localhost:8080/b          # hello from echo-b
curl -H "Host: echo.local" http://localhost:8080/           # hello from echo-a (catchall)

# split.local — both echo-a and echo-b are pooled into one upstream;
# coxswain round-robins across all ready pod addresses from both services
curl -H "Host: split.local" http://localhost:8080/          # hello from echo-a
curl -H "Host: split.local" http://localhost:8080/          # hello from echo-b

# *.wildcard.local — any subdomain matches
curl -H "Host: foo.wildcard.local" http://localhost:8080/   # hello from echo-c
curl -H "Host: bar.wildcard.local" http://localhost:8080/   # hello from echo-c
```

### Test classic Ingress routes

```bash
# ingress.local
curl -H "Host: ingress.local" http://localhost:8080/a       # hello from echo-a
curl -H "Host: ingress.local" http://localhost:8080/b       # hello from echo-b

# ingress2.local — second Ingress resource
curl -H "Host: ingress2.local" http://localhost:8080/c      # hello from echo-c
curl -H "Host: ingress2.local" http://localhost:8080/       # hello from echo-a (catchall)
```

### Observe the routing table

```bash
curl -s http://localhost:8082/routes | jq .    # lists all active hostnames
```

## Cutting a release

Coxswain uses [`cargo-release`](https://github.com/crate-ci/cargo-release) to version, tag, and publish releases.

### Install

```bash
cargo install cargo-release
```

### Ship a release

```bash
cargo release patch   # 0.2.0 → 0.2.1  (bug fixes)
cargo release minor   # 0.2.0 → 0.3.0  (new milestone)
cargo release major   # 0.9.0 → 1.0.0  (GA)
```

This single command:
1. Bumps the version in `Cargo.toml`
2. Updates `charts/coxswain/Chart.yaml` `appVersion` via a pre-release hook
3. Commits the version change
4. Creates a `v{version}` git tag
5. Pushes the commit and tag

CI picks up the tag and publishes the Docker image and Helm chart automatically. You never edit `Cargo.toml` or create git tags manually.

### Dry run

```bash
cargo release minor --dry-run
```

Shows exactly what would happen without making any changes.

---

## Common commands

```bash
# Build
cargo build

# Check (fast, no codegen)
cargo check

# Run tests
cargo test

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt
```
