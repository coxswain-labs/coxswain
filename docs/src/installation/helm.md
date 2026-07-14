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
| `controller.replicas` | `2` | Controller replica count; PDB is only provisioned when `≥ 2` |
| `controller.podDisruptionBudget.enabled` | `true` | Provision a PDB for the controller (effective when `replicas ≥ 2`) |
| `image.tag` | _(chart appVersion)_ | Image tag to deploy |
| `controllerName` | `coxswain-labs.dev/gateway-controller` | GatewayClass `controllerName` to claim |
| `watchNamespace` | `""` | Restrict watch to a single namespace; empty = cluster-wide |
| `proxy.ingress.http.port` | `80` | Ingress HTTP listener port |
| `proxy.ingress.https.port` | `443` | Ingress HTTPS listener port |
| `proxy.shared.replicas` | `1` | Static replica count (ignored when `autoscaling.enabled`) |
| `proxy.shared.autoscaling.enabled` | `false` | Enable HPA for the shared proxy |
| `proxy.shared.autoscaling.minReplicas` | `2` | HPA lower bound; must be `≥ 2` for the PDB to be active |
| `proxy.shared.autoscaling.maxReplicas` | `10` | HPA upper bound |
| `proxy.shared.autoscaling.targetCPUUtilizationPercentage` | `80` | HPA CPU utilization target |
| `proxy.shared.podDisruptionBudget.enabled` | `true` | Provision a PDB for the shared proxy (effective when floor `≥ 2`) |
| `proxy.shared.threads` | `2` | Worker threads per shared proxy service |
| `proxy.shared.resources.requests.cpu` | `100m` | Shared proxy CPU request |
| `proxy.shared.resources.requests.memory` | `128Mi` | Shared proxy memory request |
| `proxy.shared.resources.limits.cpu` | `500m` | Shared proxy CPU limit |
| `proxy.shared.resources.limits.memory` | `256Mi` | Shared proxy memory limit |

See the [Helm chart README](https://github.com/coxswain-labs/coxswain/blob/main/charts/coxswain/README.md) for the full values reference.

## Discovery relay tier

The optional [relay tier](../architecture/deployment-models.md#discovery-relay-tier) scales leader fan-out by inserting zero-RBAC cache pods between the controller and the proxies. It is **off by default** — a relay-free install is byte-identical to one without the feature — and is configured under `relay.*`, split into two independent families:

| Value | Default | Description |
|-------|---------|-------------|
| `relay.shared.enabled` | `false` | Render the shared-pool relay **and** repoint the shared proxies at it |
| `relay.shared.replicas` | `2` | Shared-relay replica count (ignored when autoscaling) |
| `relay.shared.autoscaling.enabled` | `false` | Enable HPA for the shared relay (it fronts the whole pool, so it can scale) |
| `relay.shared.resources` | `{}` | Shared-relay container resources |
| `relay.dedicated.enabled` | `false` | Enable controller-provisioned per-namespace relays (→ `--relay-enabled`) |
| `relay.dedicated.replicas` | `2` | HA replica count for each provisioned namespace relay |
| `relay.dedicated.minProxyReplicas` | `8` | Break-even threshold: a namespace gets a relay only once its desired dedicated-proxy replicas reach this (below it, direct-to-controller) |
| `relay.dedicated.resources.{cpuRequest,memoryRequest,memoryLimit}` | `50m` / `64Mi` / `256Mi` | Resources for each provisioned namespace relay (CPU request only — a limit would throttle fan-out) |

`relay.shared.*` renders Deployment/Service/SA/PDB/HPA directly (static install infra). `relay.dedicated.*` is passed to the controller, which provisions the per-namespace relays dynamically — there are no dedicated-relay templates to render. Only the shared relay is a raw-manifest resource; enabling the tier on a non-Helm install is a Helm-only path today.

```bash
# Enable both relay families
helm upgrade coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system \
  --set relay.shared.enabled=true \
  --set relay.dedicated.enabled=true
```

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
