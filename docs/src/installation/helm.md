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
| `controller.replicas` | `1` | Number of controller replicas (run `≥ 2` in production) |
| `image.tag` | _(chart appVersion)_ | Image tag to deploy |
| `controllerName` | `coxswain-labs.dev/gateway-controller` | GatewayClass `controllerName` to claim |
| `watchNamespace` | `""` | Restrict watch to a single namespace; empty = cluster-wide |
| `proxy.ingress.http.port` | `80` | Ingress HTTP listener port |
| `proxy.ingress.https.port` | `443` | Ingress HTTPS listener port |
| `proxy.shared.threads` | `2` | Worker threads per shared proxy service |
| `proxy.shared.resources.requests.cpu` | `100m` | Shared proxy CPU request |
| `proxy.shared.resources.requests.memory` | `128Mi` | Shared proxy memory request |
| `proxy.shared.resources.limits.cpu` | `500m` | Shared proxy CPU limit |
| `proxy.shared.resources.limits.memory` | `256Mi` | Shared proxy memory limit |

See the [Helm chart README](https://github.com/coxswain-labs/coxswain/blob/main/charts/coxswain/README.md) for the full values reference.

## Namespace-scoped install

By default Coxswain watches the entire cluster. To restrict to a single namespace:

```bash
helm install coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system --create-namespace \
  --set watchNamespace=my-namespace
```

!!! note
    `watchNamespace` only narrows what the controller reads — the chart still installs the cluster-wide `ClusterRole`/`ClusterRoleBinding`. To scope RBAC as well, render the manifests with `helm template` and edit them by hand before applying.

## ValidatingAdmissionPolicy

On Kubernetes ≥ 1.30, the chart installs a `ValidatingAdmissionPolicy` that rejects Ingresses carrying malformed `ingress.coxswain-labs.dev/*` annotation values at `kubectl apply` time. The policy is enabled by default and silently skipped on clusters that do not advertise `admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy`, so installing on an older cluster is safe.

To disable it explicitly:

```bash
helm install coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system --create-namespace \
  --set vap.enabled=false
```

## Control-plane CA

The controller secures the controller↔proxy discovery channel with mandatory
mTLS. By default (`discovery.ca.mode=auto`) it self-generates the CA and works
out of the box — nothing to provision. To consume a cert-manager-managed or
bring-your-own CA instead, set `discovery.ca.mode=external` and supply the
Secret. See [Control-plane security](../guides/control-plane-security.md).

## Uninstall

```bash
helm uninstall coxswain --namespace coxswain-system
kubectl delete namespace coxswain-system
```

!!! warning
    The Gateway API CRDs are not removed — uninstalling them would delete all `Gateway` and `HTTPRoute` objects in the cluster.
