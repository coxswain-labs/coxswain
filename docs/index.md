# Coxswain

!!! warning "Early development"
    Coxswain is under active development and not yet ready for external contributions. Contribution guidelines will follow as the project matures.

A pure-Rust Kubernetes Ingress & Gateway API controller backed by [Pingora](https://github.com/cloudflare/pingora) as the proxy engine.

Coxswain aims to be a lightweight, operationally simple ingress controller for teams that want reliable, zero-downtime routing without configuration file generation or process restarts. Routing updates are applied atomically as Kubernetes resources change, TLS certificates are hot-reloaded from Secrets, and multiple replicas can run simultaneously without coordination overhead.

## Why Coxswain?

| Feature | Detail |
|---------|--------|
| **Zero-reload routing** | The routing table is swapped atomically via `arc-swap`; no locks or channels on the hot path |
| **Gateway API + Ingress** | Both `HTTPRoute` and classic `Ingress` resources, side-by-side in the same cluster |
| **Multi-replica safe** | Lease-based leader election coordinates status writes; standby replicas serve traffic without feedback loops |
| **TLS hot-reload** | Watches `kubernetes.io/tls` Secrets and reloads cert material without restarts |
| **Prometheus metrics** | Live metrics via `/metrics` on the admin port |
| **Structured logging** | JSON (production) or human-readable console format |

## Quick install

```bash
# 1. Install Gateway API CRDs
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml

# 2. Install Coxswain
kubectl apply -f https://github.com/coxswain-labs/coxswain/releases/latest/download/install.yaml
```

See [Getting started](getting-started.md) for the complete walkthrough, or [Installation](installation/index.md) for all install methods.

## Roadmap

The [Coxswain Roadmap Project](https://github.com/orgs/coxswain-labs/projects/2){target=_blank} tracks current scope per milestone.
