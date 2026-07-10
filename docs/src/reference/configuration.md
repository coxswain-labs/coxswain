# Configuration reference

Coxswain is configured via environment variables. Each setting maps to an environment variable (the `COXSWAIN_*` family, plus the Downward-API `POD_NAME` / `POD_NAMESPACE`) and an equivalent CLI flag.

## Setting configuration

=== "Helm"

    Pass values at install or upgrade time:

    ```bash
    helm upgrade coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
      --namespace coxswain-system \
      --set proxy.ingress.http.port=80 \
      --set proxy.ingress.https.port=443 \
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
| `COXSWAIN_DISCOVERY_BOOTSTRAP_ENDPOINT` | `--discovery-bootstrap-endpoint` | _(none)_ | _(proxy)_ `https://` URI of the controller bootstrap listener; where the proxy exchanges its SA token + CSR for an SVID. See [Control-plane security](../guides/control-plane-security.md) |
| `COXSWAIN_DISCOVERY_BOOTSTRAP_PORT` | `--discovery-bootstrap-port` | `50052` | _(controller)_ Port for the server-auth-only bootstrap gRPC listener |
| `COXSWAIN_DISCOVERY_CA_BUNDLE_PATH` | `--discovery-ca-bundle-path` | `/var/run/secrets/coxswain/trust-bundle/ca.crt` | _(proxy)_ Path to the mounted trust-bundle ConfigMap used to verify the controller |
| `COXSWAIN_DISCOVERY_CA_MODE` | `--discovery-ca-mode` | `auto` | _(controller)_ `auto` self-generates the CA Secret if absent; `external` requires a pre-existing Secret (fail closed) |
| `COXSWAIN_DISCOVERY_CA_SECRET` | `--discovery-ca-secret` | `coxswain-discovery-ca` | _(controller)_ Name of the CA Secret (`tls.crt`/`tls.key`) in the controller namespace |
| `COXSWAIN_DISCOVERY_ENDPOINT` | `--discovery-endpoint` | _(none; required for proxy)_ | _(proxy)_ Comma-separated controller discovery (Stream) endpoints; `https://host:port` for mTLS |
| `COXSWAIN_DISCOVERY_PORT` | `--discovery-port` | `50051` | _(controller)_ Port for the mTLS Stream gRPC listener (routing snapshots) |
| `COXSWAIN_DISCOVERY_SA_TOKEN_PATH` | `--discovery-sa-token-path` | `/var/run/secrets/coxswain/discovery-token/token` | _(proxy)_ Path to the projected ServiceAccount token presented at bootstrap |
| `COXSWAIN_DISCOVERY_SVID_TTL` | `--discovery-svid-ttl` | `24h` | _(controller)_ Lifetime of SVIDs issued to proxies; proxies refresh at ~50 % |
| `COXSWAIN_DISCOVERY_TRUST_DOMAIN` | `--discovery-trust-domain` | `cluster.local` | SPIFFE trust domain; must match across the controller and all proxies |
| `COXSWAIN_HEALTH_PORT` | `--health-port` | `8081` | Port for liveness and readiness health endpoints |
| `COXSWAIN_DISABLE_GATEWAY_API` | `--disable-gateway-api` | `false` | Disable the Gateway API surface entirely; no `HTTPRoute`/`GatewayClass` reflectors are started and the `gateway_api_crds` health check is not registered |
| `COXSWAIN_DISABLE_INGRESS` | `--disable-ingress` | `false` | Disable the Ingress surface entirely; no Ingress reflectors are started and no Ingress listener ports are bound |
| `COXSWAIN_INGRESS_DEFAULT_BACKEND` | `--ingress-default-backend` | _(none)_ | Cluster-wide fallback backend for `Ingress` requests that match no rule, expressed as `<namespace>/<service>:<port>` |
| `COXSWAIN_INGRESS_HTTP_PORT` | `--ingress-http-port` | _(none)_ | Port for inbound HTTP traffic; unset to bind no static Ingress HTTP listener |
| `COXSWAIN_INGRESS_HTTPS_PORT` | `--ingress-https-port` | _(none)_ | Port for inbound HTTPS traffic (SNI TLS); unset to bind no static Ingress HTTPS listener |
| `COXSWAIN_LOG` | `--log` | `info` | Log level; supports `RUST_LOG` directive syntax (e.g. `info,coxswain=debug`) |
| `COXSWAIN_LOG_FORMAT` | `--log-format` | `json` | `json` (production) or `console` (human-readable) |
| `COXSWAIN_MANAGEMENT_BIND_ADDRESS` | `--management-bind-address` | `0.0.0.0` | IP the health (`/healthz`, `/readyz`) and admin (`/metrics`, `/api/v1/health`) servers bind to |
| `COXSWAIN_INGRESS_ACCEPT_PROXY_PROTOCOL` | `--ingress-accept-proxy-protocol` | `false` | Require HAProxy PROXY v1/v2 on **Ingress** inbound connections; must be combined with `--ingress-proxy-trusted-sources`. Note: h2c prior-knowledge and h2 ALPN are not available on PROXY-wrapped connections (h1-only on that path). Gateway listeners use `ClientTrafficPolicy` instead (see below). |
| `COXSWAIN_PROXY_BIND_ADDRESS` | `--proxy-bind-address` | `0.0.0.0` | IP the data-plane HTTP/HTTPS proxy listeners bind to; health and admin bind separately via `--management-bind-address` |
| `COXSWAIN_PROXY_DEFAULT_BACKEND_REQUEST_TIMEOUT` | `--proxy-default-backend-request-timeout` | _(none)_ | Default upstream-only timeout when `HTTPRouteRule.timeouts.backendRequest` is not set |
| `COXSWAIN_PROXY_DEFAULT_REQUEST_TIMEOUT` | `--proxy-default-request-timeout` | _(none)_ | Default total request timeout (client → proxy → upstream → client) when `HTTPRouteRule.timeouts.request` is not set |
| `COXSWAIN_PROXY_LISTENER_DRAIN_TIMEOUT` | `--proxy-listener-drain-timeout` | `30s` | Drain window for in-flight requests when a Gateway listener is removed at runtime |
| `COXSWAIN_PROXY_SHUTDOWN_GRACE_PERIOD` | `--proxy-shutdown-grace-period` | `30s` | Drain window after shutdown signal |
| `COXSWAIN_PROXY_SHUTDOWN_TIMEOUT` | `--proxy-shutdown-timeout` | `5s` | Hard deadline after the grace period; remaining connections are forcibly closed |
| `COXSWAIN_PROXY_THREADS` | `--proxy-threads` | `2` | Worker threads per proxy service; set to CPU core count for maximum throughput |
| `COXSWAIN_PROXY_UPSTREAM_KEEPALIVE_POOL_SIZE` | `--proxy-upstream-keepalive-pool-size` | `128` | Maximum idle upstream connections in Pingora's keepalive pool; connections beyond the limit are evicted LRU |
| `COXSWAIN_INGRESS_PROXY_TRUSTED_SOURCES` | `--ingress-proxy-trusted-sources` | _(none)_ | Comma-separated CIDRs allowed to send PROXY-protocol headers on Ingress listeners; only meaningful with `--ingress-accept-proxy-protocol` |
| `COXSWAIN_RECONCILE_DEBOUNCE_MIN` | `--reconcile-debounce-min` | `20ms` | _(controller)_ Trailing quiet window for the rebuild debounce; a watch event resets it, and it firing with no further events rebuilds the routing table. Must be ≤ the max |
| `COXSWAIN_RECONCILE_DEBOUNCE_MAX` | `--reconcile-debounce-max` | `500ms` | _(controller)_ Hard ceiling on the same debounce, measured from the first event of a cycle; bounds convergence under sustained churn (e.g. a rolling deploy). Must be ≥ the min |
| `COXSWAIN_STATUS_ADDRESS` | `--status-address` | _(none)_ | IP or hostname written to `Ingress.status` and `Gateway.status.addresses`; required for cert-manager HTTP-01 and external-dns |
| `COXSWAIN_WATCH_NAMESPACE` | `--watch-namespace` | _(cluster-wide)_ | Restrict the controller and proxy watch to a single namespace; both pods must be set to the same value |
| `POD_NAME` | `--pod-name` | `coxswain-local` | Pod name used as the leader-election holder identity |
| `POD_NAMESPACE` | `--pod-namespace` | `coxswain-system` | Pod namespace used to scope the leader-election Lease |

!!! note
    The dedicated proxy scope flags (`--dedicated`, `--gateway-name`, `--gateway-namespace`) are set by the controller on the proxy Deployments it provisions, or passed by hand when running a dedicated proxy manually. The discovery flags (`--discovery-endpoint`, `--discovery-bootstrap-endpoint`) are also set by the controller on provisioned Deployments. See [Dedicated proxy pools](../guides/dedicated-mode.md).

## Ports summary

| Port | Default | Env var | Endpoints |
|------|---------|---------|-----------|
| HTTP proxy | _(none)_ | `COXSWAIN_INGRESS_HTTP_PORT` | Inbound HTTP data plane |
| HTTPS proxy | _(none)_ | `COXSWAIN_INGRESS_HTTPS_PORT` | Inbound HTTPS data plane (SNI TLS) |
| Health | `8081` | `COXSWAIN_HEALTH_PORT` | `/healthz`, `/readyz` |
| Admin | `8082` | `COXSWAIN_ADMIN_PORT` | `/metrics`, `/api/v1/health` (controller role also serves `/api/v1/{fleet,routing,problems,...}`) |
| Discovery (Stream) | `50051` | `COXSWAIN_DISCOVERY_PORT` | _(controller)_ mTLS gRPC routing-snapshot stream |
| Bootstrap | `50052` | `COXSWAIN_DISCOVERY_BOOTSTRAP_PORT` | _(controller)_ server-auth gRPC SVID issuance |

Both API surfaces are enabled by default. Use `controller.gatewayApi.enabled=false` for Ingress-only installs and `controller.ingress.enabled=false` for Gateway-API-only installs. Port numbers are configured via `proxy.ingress.http.port` (default `80`) and `proxy.ingress.https.port` (default `443`).

### Self-healing Gateway API CRD detection

When the Gateway API surface is enabled (`--disable-gateway-api` absent) but the Gateway API CRDs are not installed yet, Coxswain does not crash. Instead:

1. A `gateway_api_crds` health check is registered but stays `Pending`, blocking `/readyz` until resolved.
2. A background re-probe task polls every 30 seconds.
3. Once the CRDs appear, the Gateway API reflectors are started in-process and `gateway_api_crds` becomes `Ready` — no pod restart required.

The active API surfaces are visible in every pod's `/api/v1/health` response under `api_surfaces.gateway_api` and `api_surfaces.ingress`.

## HTTP/2 support

Coxswain supports HTTP/2 on both the downstream (client → proxy) and upstream (proxy → backend) legs:

- **h2 over TLS (HTTPS)** — automatic. The TLS acceptor advertises `h2` and `http/1.1` via ALPN; clients that don't offer `h2` fall back to HTTP/1.1 transparently.
- **h2c (cleartext HTTP/2, prior-knowledge)** — automatic on plain-TCP listeners. The h2c preface is detected non-destructively; HTTP/1.1 clients on the same port are unaffected.
- **Upstream h2c** — enabled per-route via `appProtocol: kubernetes.io/h2c` on the backend `Service` port (Gateway API GEP-1911 `HTTPRouteBackendProtocolH2C`).

**PROXY-protocol restriction:** when `--ingress-accept-proxy-protocol` is set, Ingress inbound connections are h1-only. h2c prior-knowledge and h2 ALPN are disabled on PROXY-wrapped connections.

## PROXY protocol

Coxswain supports HAProxy PROXY protocol v1 and v2 for real client-IP propagation behind L4 load balancers. The mechanism differs by listener origin:

### Gateway listeners — `ClientTrafficPolicy`

Gateway listeners (including TLS passthrough/hybrid) are configured per-listener through the `ClientTrafficPolicy` CRD. This is dynamic: the controller reconciles policies at runtime with no proxy restart.

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: ClientTrafficPolicy
metadata:
  name: my-ctp
  namespace: default
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: my-gateway
    # Optional: scope to one listener. Omit to apply to all listeners on the Gateway.
    sectionName: https
  proxyProtocol:
    enabled: true
    trustedSources:
    - 10.0.0.0/8
    - 192.168.0.0/16
```

**Precedence (GEP-713):** a section-scoped policy (with `sectionName`) beats a gateway-scoped one for the targeted listener. When two policies at the same scope target the same listener, the older `creationTimestamp` wins; the loser receives `Accepted=False / Conflicted=True` in `status.ancestors[]`.

**TLS passthrough:** PROXY headers are stripped before SNI detection, so passthrough routes work correctly whether or not PROXY headers are present. Without a `ClientTrafficPolicy`, PROXY headers on passthrough listeners are treated as raw connection bytes and cause the SNI lookup to fail.

### Ingress listeners — flags

Ingress listeners are configured globally via two flags (or the equivalent Helm values). This applies to the entire Ingress plane; per-listener granularity is not available for Ingress because both `:80` and `:443` share a single L4 front load balancer.

| Flag | Helm value | Default | Description |
|------|-----------|---------|-------------|
| `--ingress-accept-proxy-protocol` | `proxy.shared.acceptProxyProtocol` | `false` | Enable PROXY v1/v2 on Ingress listeners |
| `--ingress-proxy-trusted-sources` | `proxy.shared.trustedSources` | _(none)_ | CIDRs whose connections carry PROXY headers |

These flags do not affect Gateway listeners. Gateway listeners are always governed by `ClientTrafficPolicy`.

## Discovery control plane

The controller and proxy communicate over a secured gRPC discovery channel:
the controller acts as a CA, proxies bootstrap an SVID with their ServiceAccount
token, and routing snapshots flow over mandatory mTLS. The `COXSWAIN_DISCOVERY_*`
settings above configure it; see [Control-plane security](../guides/control-plane-security.md)
for the model, CA provisioning modes (`auto` / `external` + cert-manager / BYO),
SVID rotation, and troubleshooting.

!!! note
    The data plane and the management surface bind independently: `COXSWAIN_PROXY_BIND_ADDRESS` for the HTTP/HTTPS proxy listeners, and `COXSWAIN_MANAGEMENT_BIND_ADDRESS` for the health and admin servers. Both default to `0.0.0.0`; set the management address to a management-network IP to keep `/metrics`, `/api/v1/health`, and the health endpoints off the data-plane interface.

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
