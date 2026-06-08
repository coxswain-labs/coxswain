# Coxswain

[![E2E & Conformance](https://github.com/coxswain-labs/coxswain/actions/workflows/e2e.yml/badge.svg)](https://github.com/coxswain-labs/coxswain/actions/workflows/e2e.yml)

A pure-Rust Kubernetes Ingress & Gateway API controller backed by [Pingora](https://github.com/cloudflare/pingora) as the proxy engine.

Coxswain watches Kubernetes `Ingress` and `HTTPRoute` resources and dynamically updates its routing table without a process restart or config reload. Multiple replicas can run simultaneously using Kubernetes Lease-based leader election — all replicas maintain a hot routing table, but only the active leader writes status back to the API server.

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

## Project status

> **Early development.** Not yet accepting external contributions. Bug reports and feature requests in issues are welcome; contribution guidelines will be added as the project matures.

The [Coxswain Roadmap Project](https://github.com/orgs/coxswain-labs/projects/2) tracks current scope per milestone.
