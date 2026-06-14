# Configuration reference

Coxswain is configured via environment variables. Each setting maps to an environment variable (the `COXSWAIN_*` family, plus the Downward-API `POD_NAME` / `POD_NAMESPACE`) and an equivalent CLI flag.

## Setting configuration

=== "Helm"

    Pass values at install or upgrade time:

    ```bash
    helm upgrade coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
      --namespace coxswain-system \
      --set proxy.http.port=80 \
      --set proxy.https.port=443 \
      --set watchNamespace=my-namespace
    ```

    Or via a `values.yaml` file:

    ```bash
    helm upgrade coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
      --namespace coxswain-system \
      -f my-values.yaml
    ```

    See the [Helm install guide](../installation/helm.md) for the full values reference.

=== "Raw manifests / Kustomize"

    Set environment variables directly on the relevant `Deployment` (controller or shared proxy):

    ```yaml
    env:
      - name: COXSWAIN_INGRESS_HTTP_PORT
        value: "80"
      - name: COXSWAIN_INGRESS_HTTPS_PORT
        value: "443"
      - name: COXSWAIN_STATUS_ADDRESS
        value: "203.0.113.10"
    ```

## Settings

| Env var | Flag | Default | Description |
|---------|------|---------|-------------|
| `COXSWAIN_ACCESS_LOG` | `--access-log` | `true` | Emit one structured access-log event per proxied request on the `coxswain_proxy::access` target; set `false` to silence. See [Observability](observability.md#access-logs) |
| `COXSWAIN_ACCESS_LOG_PATH_MODE` | `--access-log-path-mode` | `full` | What the access-log `path` field records: `full`, `pattern`, or `none` |
| `COXSWAIN_ADMIN_PORT` | `--admin-port` | `8082` | Port for admin, metrics, and diagnostics endpoints |
| `COXSWAIN_CONTROLLER_LEASE_RENEW_INTERVAL` | `--controller-lease-renew-interval` | `5s` | How often the leader renews its lease; must be ≤ 1/3 of the TTL |
| `COXSWAIN_CONTROLLER_LEASE_TTL` | `--controller-lease-ttl` | `15s` | How long a lease stays valid without renewal; must be ≥ 3× the renew interval |
| `COXSWAIN_CONTROLLER_NAME` | `--controller-name` | `coxswain-labs.dev/gateway-controller` | GatewayClass `spec.controllerName` to claim |
| `COXSWAIN_HEALTH_PORT` | `--health-port` | `8081` | Port for liveness and readiness health endpoints |
| `COXSWAIN_INGRESS_DEFAULT_BACKEND` | `--ingress-default-backend` | _(none)_ | Cluster-wide fallback backend for `Ingress` requests that match no rule, expressed as `<namespace>/<service>:<port>` |
| `COXSWAIN_INGRESS_HTTP_PORT` | `--ingress-http-port` | _(none)_ | Port for inbound HTTP traffic; unset to bind no static Ingress HTTP listener |
| `COXSWAIN_INGRESS_HTTPS_PORT` | `--ingress-https-port` | _(none)_ | Port for inbound HTTPS traffic (SNI TLS); unset to bind no static Ingress HTTPS listener |
| `COXSWAIN_LOG` | `--log` | `info` | Log level; supports `RUST_LOG` directive syntax (e.g. `info,coxswain=debug`) |
| `COXSWAIN_LOG_FORMAT` | `--log-format` | `json` | `json` (production) or `console` (human-readable) |
| `COXSWAIN_MANAGEMENT_BIND_ADDRESS` | `--management-bind-address` | `0.0.0.0` | IP the health (`/healthz`, `/readyz`) and admin (`/metrics`, `/routes`) servers bind to |
| `COXSWAIN_PROXY_ACCEPT_PROXY_PROTOCOL` | `--proxy-accept-proxy-protocol` | `false` | Require HAProxy PROXY v1/v2 on inbound connections; must be combined with `--proxy-trusted-sources` |
| `COXSWAIN_PROXY_BIND_ADDRESS` | `--proxy-bind-address` | `0.0.0.0` | IP the data-plane HTTP/HTTPS proxy listeners bind to; health and admin bind separately via `--management-bind-address` |
| `COXSWAIN_PROXY_DEFAULT_BACKEND_REQUEST_TIMEOUT` | `--proxy-default-backend-request-timeout` | _(none)_ | Default upstream-only timeout when `HTTPRouteRule.timeouts.backendRequest` is not set |
| `COXSWAIN_PROXY_DEFAULT_REQUEST_TIMEOUT` | `--proxy-default-request-timeout` | _(none)_ | Default total request timeout (client → proxy → upstream → client) when `HTTPRouteRule.timeouts.request` is not set |
| `COXSWAIN_PROXY_LISTENER_DRAIN_TIMEOUT` | `--proxy-listener-drain-timeout` | `30s` | Drain window for in-flight requests when a Gateway listener is removed at runtime |
| `COXSWAIN_PROXY_SHUTDOWN_GRACE_PERIOD` | `--proxy-shutdown-grace-period` | `30s` | Drain window after shutdown signal |
| `COXSWAIN_PROXY_SHUTDOWN_TIMEOUT` | `--proxy-shutdown-timeout` | `5s` | Hard deadline after the grace period; remaining connections are forcibly closed |
| `COXSWAIN_PROXY_THREADS` | `--proxy-threads` | `2` | Worker threads per proxy service; set to CPU core count for maximum throughput |
| `COXSWAIN_PROXY_TRUSTED_SOURCES` | `--proxy-trusted-sources` | _(none)_ | Comma-separated CIDRs allowed to send PROXY-protocol headers; only meaningful with `--proxy-accept-proxy-protocol` |
| `COXSWAIN_STATUS_ADDRESS` | `--status-address` | _(none)_ | IP or hostname written to `Ingress.status` and `Gateway.status.addresses`; required for cert-manager HTTP-01 and external-dns |
| `COXSWAIN_WATCH_NAMESPACE` | `--watch-namespace` | _(cluster-wide)_ | Restrict the controller and proxy watch to a single namespace; both pods must be set to the same value |
| `POD_NAME` | `--pod-name` | `coxswain-local` | Pod name used as the leader-election holder identity |
| `POD_NAMESPACE` | `--pod-namespace` | `coxswain-system` | Pod namespace used to scope the leader-election Lease |

!!! note
    The dedicated proxy provisioning flags (`--gateway-name`, `--gateway-namespace`, `--allow-cluster-wide-route-read`, `--allow-cluster-wide-namespace-read`, `--proxy-watch-namespaces`) are set by the controller on the proxy Deployments it provisions, or passed by hand only when running a dedicated proxy manually. See [Dedicated proxy pools](../guides/dedicated-mode.md).

## Ports summary

| Port | Default | Env var | Endpoints |
|------|---------|---------|-----------|
| HTTP proxy | _(none)_ | `COXSWAIN_INGRESS_HTTP_PORT` | Inbound HTTP data plane |
| HTTPS proxy | _(none)_ | `COXSWAIN_INGRESS_HTTPS_PORT` | Inbound HTTPS data plane (SNI TLS) |
| Health | `8081` | `COXSWAIN_HEALTH_PORT` | `/healthz`, `/readyz` |
| Admin | `8082` | `COXSWAIN_ADMIN_PORT` | `/metrics`, `/routes`, `/api/v1/health` |

The proxy listeners are disabled unless their port is explicitly set. The Helm chart defaults `proxy.http.port` to `80` and `proxy.https.port` to `443`.

!!! note
    The data plane and the management surface bind independently: `COXSWAIN_PROXY_BIND_ADDRESS` for the HTTP/HTTPS proxy listeners, and `COXSWAIN_MANAGEMENT_BIND_ADDRESS` for the health and admin servers. Both default to `0.0.0.0`; set the management address to a management-network IP to keep `/metrics`, `/routes`, and the health endpoints off the data-plane interface.

## Leader election

All replicas maintain a current routing table and serve traffic; only the leader writes status back to `Ingress`, `Gateway`, and `HTTPRoute` objects. The lease parameters must satisfy `lease-ttl ≥ 3 × lease-renew-interval`.

The defaults (15 s TTL, 5 s renew interval) allow the leader to miss two renewal cycles before the lease expires. Reduce them if you need faster failover at the cost of more Kubernetes API traffic.

## Duration format

Duration values use [humantime](https://docs.rs/humantime) syntax: `300ms`, `5s`, `1m30s`, `2h`, `1.5s`. Unit-less integers are not accepted — always include a unit.

## POD_NAME and POD_NAMESPACE

These are required for correct leader-election identity and are typically injected via the Kubernetes Downward API. The Helm chart handles this automatically. For raw manifests, add to the `Deployment`:

```yaml
env:
  - name: POD_NAME
    valueFrom:
      fieldRef:
        fieldPath: metadata.name
  - name: POD_NAMESPACE
    valueFrom:
      fieldRef:
        fieldPath: metadata.namespace
```
