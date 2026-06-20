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
  --version X.Y.Z \
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
| `replicaCount` | `1` | Number of controller replicas (run `≥ 2` in production) |
| `image.tag` | _(chart appVersion)_ | Image tag to deploy |
| `controller.name` | `coxswain-labs.dev/gateway-controller` | GatewayClass `controllerName` to claim |
| `controller.watchNamespace` | `""` | Restrict watch to a single namespace; empty = cluster-wide |
| `proxy.http.port` | `80` | HTTP proxy listener port |
| `proxy.https.port` | `443` | HTTPS proxy listener port |
| `proxy.threads` | `2` | Worker threads per proxy service |
| `resources.requests.cpu` | `100m` | CPU request |
| `resources.requests.memory` | `128Mi` | Memory request |
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
    `controller.watchNamespace` only narrows what the controller reads — the chart still installs the cluster-wide `ClusterRole`/`ClusterRoleBinding`. To scope RBAC as well, render the manifests with `helm template` and edit them by hand before applying.

## ValidatingAdmissionPolicy

On Kubernetes ≥ 1.30, the chart installs a `ValidatingAdmissionPolicy` that rejects Ingresses carrying malformed `ingress.coxswain-labs.dev/*` annotation values at `kubectl apply` time. The policy is enabled by default and silently skipped on clusters that do not advertise `admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy`, so installing on an older cluster is safe.

To disable it explicitly:

```bash
helm install coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system --create-namespace \
  --set vap.enabled=false
```

## Uninstall

```bash
helm uninstall coxswain --namespace coxswain-system
kubectl delete namespace coxswain-system
```

!!! warning
    The Gateway API CRDs are not removed — uninstalling them would delete all `Gateway` and `HTTPRoute` objects in the cluster.
