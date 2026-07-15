# Coxswain Helm Chart

Helm chart for [Coxswain](https://github.com/coxswain-labs/coxswain) — a pure-Rust
Kubernetes Ingress & Gateway API controller backed by Pingora.

## Prerequisites

- Kubernetes 1.25+
- Helm 3.10+
- [Gateway API CRDs](https://gateway-api.sigs.k8s.io/guides/#installing-gateway-api) installed

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml
```

## Quick start

```bash
helm install coxswain charts/coxswain \
  --namespace coxswain-system \
  --create-namespace
```

Verify the controller is ready:

```bash
kubectl -n coxswain-system get pods
kubectl get gatewayclass coxswain
```

## Configuration

All values can be overridden with `--set key=value` or a custom `values.yaml`.

### Core settings

| Key | Default | Description |
|-----|---------|-------------|
| `replicaCount` | `1` | Number of pod replicas |
| `image.repository` | `ghcr.io/coxswain-labs/coxswain` | Container image repository |
| `image.tag` | `""` (uses Chart.AppVersion) | Container image tag |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy |

### Controller settings

| Key | Default | Description |
|-----|---------|-------------|
| `controller.replicas` | `2` | Controller replica count; PDB is only provisioned when `≥ 2` |
| `controller.podDisruptionBudget.enabled` | `true` | Provision a PDB for the controller (effective when `replicas ≥ 2`) |
| `controller.podDisruptionBudget.maxUnavailable` | `1` | Maximum disrupted controller pods during voluntary disruptions |
| `controller.name` | `coxswain-labs.dev/gateway-controller` | GatewayClass controllerName to claim |
| `watchNamespace` | `""` (cluster-wide) | Restrict the controller to one namespace, or a comma-separated list (`ns1,ns2,ns3`). Enables namespaced-Role RBAC lockdown |
| `controller.statusAddress` | `""` | External IP/hostname written to Ingress/Gateway status |
| `controller.ingressDefaultBackend` | `""` | Fallback backend (`<ns>/<svc>:<port>`) |
| `controller.gatewayApi.enabled` | `true` | Enable Gateway API surface (HTTPRoute, GatewayClass, etc.) |
| `controller.ingress.enabled` | `true` | Enable Ingress API surface and listener ports |
| `controller.leaseTtl` | `15s` | Leader lease validity duration |
| `controller.leaseRenewInterval` | `5s` | Leader lease renewal interval |

### Shared proxy settings

| Key | Default | Description |
|-----|---------|-------------|
| `proxy.shared.replicas` | `1` | Static replica count (ignored when `autoscaling.enabled`) |
| `proxy.shared.podDisruptionBudget.enabled` | `true` | Provision a PDB (effective when floor `≥ 2`) |
| `proxy.shared.autoscaling.enabled` | `false` | Enable HPA for the shared proxy |
| `proxy.shared.autoscaling.minReplicas` | `2` | HPA lower bound; must be `≥ 2` for the PDB to be active |
| `proxy.shared.autoscaling.maxReplicas` | `10` | HPA upper bound |
| `proxy.shared.autoscaling.targetCPUUtilizationPercentage` | `80` | HPA CPU utilization target |

### Proxy settings

| Key | Default | Description |
|-----|---------|-------------|
| `proxy.threads` | `2` | Worker threads per proxy service |
| `proxy.bindAddress` | `0.0.0.0` | IP address all listeners bind to |
| `proxy.ingress.http.port` | `80` | Ingress HTTP listener service port |
| `proxy.ingress.https.port` | `443` | Ingress HTTPS listener service port |
| `proxy.shutdownGracePeriod` | `30s` | Drain window before final shutdown |
| `proxy.shutdownTimeout` | `5s` | Hard deadline after grace period |
| `proxy.acceptProxyProtocol` | `false` | Accept HAProxy PROXY protocol v1/v2 on **Ingress listeners** only. Gateway listeners configure per-listener PROXY via `ClientTrafficPolicy` CRD. |
| `proxy.trustedSources` | `[]` | CIDRs allowed to send PROXY headers on Ingress listeners |
| `proxy.defaultRequestTimeout` | `""` | Global default total request timeout |
| `proxy.defaultBackendRequestTimeout` | `""` | Global default backend request timeout |

### Observability

| Key | Default | Description |
|-----|---------|-------------|
| `health.port` | `8081` | Health endpoint port (`/healthz`, `/readyz`) |
| `admin.port` | `8082` | Admin endpoint port (`/metrics`, `/routes`, `/status`) |
| `logFormat` | `json` | Log format: `json` or `console` |
| `logFilter` | `info,coxswain_proxy=debug` | Log verbosity (RUST_LOG syntax) |

### Security

| Key | Default | Description |
|-----|---------|-------------|
| `security.rootless` | `false` | Enable rootless mode for PSS `restricted` namespaces |

When `security.rootless: true`, the container binds 8080/8443 instead of 80/443 and
`NET_BIND_SERVICE` is dropped from capabilities. The gateway Service still exposes
80/443, mapping to the higher container ports via named `targetPort`.

### Services

Two Services are created:

- **`<release>-gateway`** — exposes data-plane ports (80/443). Type is configurable
  via `service.gateway.type` (default `LoadBalancer`).
- **`<release>-internal`** — exposes health (8081) and admin (8082) as `ClusterIP`.

| Key | Default | Description |
|-----|---------|-------------|
| `service.gateway.type` | `LoadBalancer` | Service type for the data-plane service |
| `service.gateway.annotations` | `{}` | Annotations for the gateway Service |
| `service.gateway.loadBalancerIP` | `""` | Pin LB to a specific IP (cloud-dependent) |
| `service.gateway.loadBalancerSourceRanges` | `[]` | Restrict LB to source CIDRs |
| `service.gateway.externalTrafficPolicy` | `""` | Set `Local` to preserve client IPs |
| `service.internal.annotations` | `{}` | Annotations for the internal Service |

### Resources

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

## Examples

### Gateway API only (no Ingress)

```yaml
controller:
  ingress:
    enabled: false
```

Disables Ingress API processing and the static Ingress listener ports (80/443).
Gateway listener ports are allocated dynamically via per-Gateway VIP Services.

### Rootless mode (PSS restricted)

```yaml
security:
  rootless: true
```

Clients still connect to ports 80/443. The container binds 8080/8443 without
`NET_BIND_SERVICE`.

### Namespace-scoped watch

```yaml
controller:
  watchNamespace: my-namespace
```

### Custom resource limits

```yaml
replicaCount: 3
resources:
  requests:
    cpu: 250m
    memory: 256Mi
  limits:
    cpu: 1000m
    memory: 512Mi
```
