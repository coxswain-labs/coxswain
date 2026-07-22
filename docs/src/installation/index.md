# Installation overview

## Prerequisites

- **Kubernetes 1.30+**
- **Gateway API CRDs** (standard channel, **v1.4.0 or later**). Coxswain detects
  which kinds and fields the installed CRDs serve and runs with that feature set,
  so it can share a cluster with an implementation pinned to an older version —
  see the [capability matrix](../reference/capability-matrix.md):

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml
```

## Install methods

Choose the one that fits your workflow:

| Method | When to use |
|--------|-------------|
| [Helm](helm.md) | Production; values-driven configuration and easy upgrades |
| [Kustomize](kustomize.md) | GitOps without Helm; customise with overlays |
| [Raw manifests](manifests.md) | Quick evaluations; no tooling beyond `kubectl` |

All three install the **same resources** — the Helm chart is the single source of truth, and the Kustomize base and raw `install.yaml` are rendered from it. That means CRDs, RBAC, the controller Deployment and its Services, the shared-proxy data-plane `Service`, a `PodDisruptionBudget`, and a `ValidatingAdmissionPolicy` for Ingress annotation validation (silently skipped on Kubernetes < 1.30) in every method. Helm is recommended for production because of values-driven configuration and upgrades, not because it installs more.

## Kubernetes distributions

Any conformant Kubernetes 1.30+ distribution should work. Tested on kind (CI and local development) and OrbStack. File an issue if you encounter distribution-specific behaviour.

## Resource requirements

Default requests and limits, per pod role:

| Role | CPU request | CPU limit | Memory request | Memory limit |
|------|-------------|-----------|----------------|--------------|
| Controller | 50m | 250m | 64Mi | 128Mi |
| Shared proxy | 100m | 500m | 128Mi | 256Mi |
| Relay | 50m | _(none)_ | 64Mi | 256Mi |

Only the controller and shared proxy run on a default install. **Relay** pods are provisioned on demand by the controller once the discovery tier activates (see [Proxy topology → relay tier](../architecture/proxy-topology.md#discovery-relay-tier)); each relay deliberately has no CPU limit, since throttling would cap its fan-out. Dedicated proxies are sized per Gateway via `CoxswainGatewayParameters`.

See [Running in production](../operations/running-in-production.md) for tuning guidance.
