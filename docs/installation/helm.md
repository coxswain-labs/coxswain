# Helm install

Coxswain is published as an OCI Helm chart at `ghcr.io/coxswain-labs/charts/coxswain`.

## Install

```bash
# Install Gateway API CRDs first (prerequisite — once per cluster)
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml

# Install the latest release
helm install coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system --create-namespace
```

To pin a specific version:

```bash
helm install coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --version 0.1.0 \
  --namespace coxswain-system --create-namespace
```

## Upgrade

```bash
helm upgrade coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system
```

## Inspect default values

```bash
helm show values oci://ghcr.io/coxswain-labs/charts/coxswain
```

## Common values

| Value | Default | Description |
|-------|---------|-------------|
| `replicaCount` | `2` | Number of controller replicas |
| `image.tag` | _(chart appVersion)_ | Image tag to deploy |
| `controller.name` | `coxswain-labs.dev/gateway-controller` | GatewayClass `controllerName` to claim |
| `controller.watchNamespace` | `""` | Restrict watch to a single namespace; empty = cluster-wide |
| `proxy.httpPort` | `80` | HTTP proxy listener port |
| `proxy.httpsPort` | `443` | HTTPS proxy listener port |
| `proxy.threads` | `2` | Worker threads per proxy service |
| `resources.requests.cpu` | `100m` | CPU request |
| `resources.requests.memory` | `64Mi` | Memory request |
| `resources.limits.cpu` | `500m` | CPU limit |
| `resources.limits.memory` | `256Mi` | Memory limit |

See the [Helm chart README](https://github.com/coxswain-labs/coxswain/blob/main/charts/coxswain/README.md) for the full values reference.

## Namespace-scoped install

By default Coxswain watches the entire cluster. To restrict to a single namespace:

```bash
helm install coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system --create-namespace \
  --set controller.watchNamespace=my-namespace
```

!!! note
    This changes the RBAC from a `ClusterRole`/`ClusterRoleBinding` to a namespaced `Role`/`RoleBinding` plus a residual `ClusterRole` for `GatewayClass` and `IngressClass` (cluster-scoped resources). Review the generated manifests with `helm template` before applying.

## Uninstall

```bash
helm uninstall coxswain --namespace coxswain-system
kubectl delete namespace coxswain-system
```

The Gateway API CRDs are not removed — uninstalling them would delete all `Gateway` and `HTTPRoute` objects in the cluster.
