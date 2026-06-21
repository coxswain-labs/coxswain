# Installation overview

## Prerequisites

- **Kubernetes 1.30+**
- **Gateway API CRDs** (standard channel, v1.5.x or later matching the Coxswain release):

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml
```

## Install methods

Choose the one that fits your workflow:

| Method | When to use |
|--------|-------------|
| [Helm](helm.md) | Production; values-driven configuration, easy upgrades, includes Services and PodDisruptionBudgets |
| [Kustomize](kustomize.md) | GitOps without Helm; customise with overlays |
| [Raw manifests](manifests.md) | Quick evaluations; no tooling beyond `kubectl` |

All three methods install the Coxswain CRDs and a `ValidatingAdmissionPolicy` for Ingress annotation validation (silently skipped on Kubernetes < 1.30). Services and `PodDisruptionBudget` are Helm-only.

## Kubernetes distributions

Any conformant Kubernetes 1.30+ distribution should work. Tested on kind (CI and local development) and OrbStack. File an issue if you encounter distribution-specific behaviour.

## Resource requirements

Default resource requests in the Helm chart:

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 100m | 500m |
| Memory | 128Mi | 256Mi |

See [Running in production](../guides/running-in-production.md) for tuning guidance.
