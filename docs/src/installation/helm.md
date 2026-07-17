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

The [relay tier](../architecture/deployment-models.md#discovery-relay-tier) scales leader fan-out by inserting zero-RBAC cache pods between the controller and the proxies. It is **on by default (opt-out)**, but the break-even gate keeps it inert until a scope's demand earns a relay — so a small install provisions no relays and is byte-identical to a relay-free one. The **controller** owns the whole tier (both the shared-pool relay and the per-namespace dedicated relays); these `relay.*` values map onto its `--relay-*` flags — there are no relay templates to render:

| Value | Default | Description |
|-------|---------|-------------|
| `relay.enabled` | `true` | Master switch (→ `--relay-enabled`). Set `false` to disable the whole tier — any already-provisioned relay (shared or per-namespace) is torn down, not orphaned |
| `relay.replicas` | `2` | HA replica count / autoscaling floor for a provisioned relay |
| `relay.maxReplicas` | `10` | Shared-relay autoscaling ceiling (→ `--relay-max-replicas`) — the mandatory cap on the upstream streams the shared relay opens against the leader. Dedicated relays cap via `CoxswainRelayPolicy` |
| `relay.minProxyReplicas` | `8` | Break-even **activation** threshold: a scope gets a relay only once its demand (a namespace's live dedicated-proxy count, or the shared pool's replica count) reaches this (below it, direct-to-controller) |
| `relay.targetProxiesPerReplica` | `50` | Capacity ratio — proxies per relay replica the sizing loop targets. Decoupled from the break-even threshold |
| `relay.cooldown` | `300s` | Deactivation cooldown: an active relay is torn down after demand holds below break-even for this long (a genuinely-drained scope tears down at once) |
| `relay.scaleDownStabilization` | `300s` | Scale-down stabilization window for an autoscaled relay (scale up promptly, down only on the trailing-window peak) |
| `relay.tolerance` | `0.10` | Relative sizing deadband — the replica count changes only when load deviates from target by more than this fraction |
| `relay.resources.{cpuRequest,memoryRequest,memoryLimit}` | `50m` / `64Mi` / `256Mi` | Resources for each provisioned relay (CPU request only — a limit would throttle fan-out) |

Per-namespace overrides for the **dedicated** relays (force-on/off, replicas, resources, `podTemplate` scheduling, autoscaling) come from the namespaced [`CoxswainRelayPolicy`](../reference/relay-policy.md) CRD; the shared relay is global and reads the `relay.*` flag values directly.

```bash
# Disable the relay tier entirely
helm upgrade coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system \
  --set relay.enabled=false
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
