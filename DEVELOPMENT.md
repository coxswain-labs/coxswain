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
