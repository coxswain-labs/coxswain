# Coxswain

!!! info "Pre-1.0 — early adopter release"
    Coxswain's core proxy is functional and ships a complete `ingress.coxswain-labs.dev/*` annotation surface with admission-time validation.
    Active development continues toward v0.4 (discovery re-architecture) and v0.5 (Gateway API extended features). Feedback and contributions are welcome.

!!! warning "Production use"
    Coxswain is under active development, production use is at your own risk.

## Overview

A Kubernetes Ingress and Gateway API controller written in Rust, backed by [Pingora](https://github.com/cloudflare/pingora) — Cloudflare's battle-tested proxy library.

- Bridges classic `Ingress` and Gateway API `HTTPRoute` in a single proxy fleet
- Routing changes and TLS certificate rotations take effect without restarting the proxy
- Controller/proxy split with a strict RBAC boundary — proxy pods hold zero write permissions
- Rich `ingress.coxswain-labs.dev/*` annotation surface with admission-time validation via `ValidatingAdmissionPolicy`

See [Architecture](architecture.md) for the deployment models and RBAC boundary.

## Quick install

```bash
# 1. Install Gateway API CRDs
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml

# 2. Install Coxswain
kubectl apply -f https://github.com/coxswain-labs/coxswain/releases/latest/download/install.yaml
```

See [Getting started](getting-started.md) for the complete walkthrough, or [Installation](installation/index.md) for all install methods.

