# Coxswain

!!! warning "Early development"
    Coxswain is under active development and not yet ready for external contributions. Contribution guidelines will follow as the project matures.

A Rust Kubernetes Ingress and Gateway API controller backed by [Pingora](https://github.com/cloudflare/pingora) as the proxy engine.

Coxswain combines controller and proxy in a single binary. Routing updates from Kubernetes watch events are published to the proxy as an immutable snapshot behind an atomic pointer, so routes change without a config reload or process restart. TLS certificates from `kubernetes.io/tls` Secrets are picked up the same way. Multiple replicas can run concurrently — every replica serves traffic, and a Kubernetes `Lease` coordinates only which replica writes status conditions back to the API server.

## What Coxswain does

| Feature | Detail |
|---------|--------|
| **Routing updates** | Routes are applied via an immutable-snapshot atomic-pointer swap on every reconcile — no config reload, no process restart |
| **Gateway API + Ingress** | Both `HTTPRoute` and classic `Ingress` resources in the same binary; both contribute to the same routing table |
| **Multi-replica** | All replicas reconcile and serve traffic; a Kubernetes `Lease` coordinates which replica writes status conditions |
| **TLS hot-reload** | New and renewed certificates are picked up from `kubernetes.io/tls` Secrets without a restart |
| **Prometheus metrics** | `/metrics` on the admin port |
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
