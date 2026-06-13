# Coxswain

!!! info "Pre-1.0 — early adopter release"
    Coxswain's core proxy is functional and passes the full Gateway API standard conformance suite.
    The per-Ingress annotation surface is under active development (v0.3).
    **Production use is at your own risk.** Feedback and contributions are welcome.

Coxswain is a Kubernetes Ingress and Gateway API controller written in Rust, using [Pingora](https://github.com/cloudflare/pingora) — Cloudflare's battle-tested proxy library — as the data plane. It serves both `Ingress` and `HTTPRoute` resources from the same proxy fleet, applies routing changes without restarts, and hot-reloads TLS certificates as Secrets change.

The controller and proxy run as separate pod roles with a strict RBAC boundary: the controller holds all write permissions; proxy pods are read-only. This split makes multi-replica, multi-tenant, and dedicated-mode deployments straightforward.

## Quick install

```bash
# 1. Install Gateway API CRDs
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml

# 2. Install Coxswain
kubectl apply -f https://github.com/coxswain-labs/coxswain/releases/latest/download/install.yaml
```

See [Getting started](getting-started.md) for the complete walkthrough, or [Installation](installation/index.md) for all install methods.

## Roadmap

| Milestone | Theme | Status |
|-----------|-------|--------|
| **v0.1** | Foundation — Gateway API conformant (standard channel), Ingress support, signed OCI image, Helm chart | Done |
| **v0.2** | Architecture — controller/proxy split, dedicated proxy mode, operator web UI | In progress |
| **v0.3** | Ingress completeness — `ingress.coxswain-labs.dev/*` annotation surface, nginx migration path | Planned |
| **v0.4** | Gateway API extended — BackendTLSPolicy, client/backend mTLS, HTTP/2 downstream, ListenerSet | Planned |

The [Coxswain Roadmap Project](https://github.com/orgs/coxswain-labs/projects/2){target=_blank} has the full issue-level breakdown.
