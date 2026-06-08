# Installation overview

Coxswain can be installed three ways. Choose the one that fits your workflow:

| Method | When to use |
|--------|-------------|
| [Helm](helm.md) | Production; values-driven configuration, easy upgrades |
| [Kustomize](kustomize.md) | GitOps without Helm; customise with overlays |
| [Raw manifests](manifests.md) | Quick evaluations; no tooling beyond `kubectl` |

## Prerequisites

All install methods share the same prerequisites:

- **Kubernetes 1.30+**
- **Gateway API CRDs** (standard channel, v1.5.x or later matching the Coxswain release):

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml
```

- RBAC permission to create `ClusterRole`, `ClusterRoleBinding`, `Namespace`, and `Lease` objects.

## Supported Kubernetes distributions

Coxswain has been tested on:

- OrbStack (local)
- kind (CI and local)
- Vanilla kubeadm clusters

Any conformant Kubernetes 1.30+ distribution should work. File an issue if you encounter distribution-specific behaviour.

## Resource requirements

Default resource requests in the Helm chart:

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 100m | 500m |
| Memory | 64Mi | 256Mi |

See [Going to production](going-to-production.md) for tuning guidance.
