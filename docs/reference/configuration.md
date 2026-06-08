# Configuration reference

All CLI flags have environment variable equivalents. Most use a `COXSWAIN_*` prefix and are safe to set via Kubernetes `env:` or `envFrom:`. `POD_NAME` and `POD_NAMESPACE` are typically injected by the Kubernetes Downward API.

Pass flags to the `serve` subcommand:

```bash
coxswain serve --proxy-http-port 80 --proxy-https-port 443
```

## Flags

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--admin-port` | `COXSWAIN_ADMIN_PORT` | `8082` | Port for admin, metrics, and diagnostics endpoints |
| `--controller-lease-renew-interval` | `COXSWAIN_CONTROLLER_LEASE_RENEW_INTERVAL` | `5s` | How often the leader renews its lease; must be ≤ 1/3 of `--controller-lease-ttl` |
| `--controller-lease-ttl` | `COXSWAIN_CONTROLLER_LEASE_TTL` | `15s` | How long a lease stays valid without renewal; must be ≥ 3× `--controller-lease-renew-interval` |
| `--controller-name` | `COXSWAIN_CONTROLLER_NAME` | `coxswain-labs.dev/gateway-controller` | GatewayClass `spec.controllerName` to claim |
| `--controller-watch-namespace` | `COXSWAIN_CONTROLLER_WATCH_NAMESPACE` | _(cluster-wide)_ | Restrict watch to a single namespace |
| `--health-port` | `COXSWAIN_HEALTH_PORT` | `8081` | Port for liveness and readiness health endpoints |
| `--log` | `COXSWAIN_LOG` | `info` | Log level; supports `RUST_LOG` directive syntax (e.g. `info,coxswain=debug`) |
| `--log-format` | `COXSWAIN_LOG_FORMAT` | `json` | `json` (production) or `console` (local dev) |
| `--pod-name` | `POD_NAME` | `coxswain-local` | Pod name used as the leader-election holder identity |
| `--pod-namespace` | `POD_NAMESPACE` | `coxswain-system` | Pod namespace used to scope the leader-election Lease |
| `--proxy-bind-address` | `COXSWAIN_PROXY_BIND_ADDRESS` | `0.0.0.0` | IP address shared by all proxy, health, and admin listeners |
| `--proxy-http-port` | `COXSWAIN_PROXY_HTTP_PORT` | _(none)_ | Port for inbound HTTP traffic; omit to disable the HTTP listener |
| `--proxy-https-port` | `COXSWAIN_PROXY_HTTPS_PORT` | _(none)_ | Port for inbound HTTPS traffic (SNI TLS); omit to disable |
| `--proxy-shutdown-grace-period` | `COXSWAIN_PROXY_SHUTDOWN_GRACE_PERIOD` | `30s` | Drain window after shutdown signal; connections are given this long to complete |
| `--proxy-shutdown-timeout` | `COXSWAIN_PROXY_SHUTDOWN_TIMEOUT` | `5s` | Hard deadline for the final shutdown step after the grace period expires |
| `--proxy-threads` | `COXSWAIN_PROXY_THREADS` | `2` | Worker threads per proxy service; set to CPU core count for maximum throughput |
| `--status-address` | `COXSWAIN_STATUS_ADDRESS` | _(none)_ | IP or hostname written to `Ingress.status` and `Gateway.status.addresses`; required for cert-manager HTTP-01 and external-dns |

## Ports summary

| Port | Default | Flag | Endpoints |
|------|---------|------|-----------|
| HTTP proxy | `80` | `--proxy-http-port` | Inbound HTTP data plane |
| HTTPS proxy | `443` | `--proxy-https-port` | Inbound HTTPS data plane (SNI TLS) |
| Health | `8081` | `--health-port` | `/healthz`, `/readyz` |
| Admin | `8082` | `--admin-port` | `/metrics`, `/routes`, `/status` |

All ports bind to `--proxy-bind-address` (default `0.0.0.0`). To bind health and admin to localhost only:

```bash
coxswain serve \
  --proxy-http-port 80 \
  --proxy-https-port 443 \
  --proxy-bind-address 0.0.0.0 \
  --status-address 0.0.0.0   # overrides the status IP only
```

!!! note
    There is currently one bind address for all listeners. Separate bind addresses for proxy vs. admin/health will be added in a future release.

## Leader election

Coxswain uses a Kubernetes `Lease` object for leader election. All replicas maintain a current routing table and serve traffic; only the leader writes status to `Ingress`, `Gateway`, and `HTTPRoute` objects.

The lease parameters must satisfy `lease-ttl ≥ 3 × lease-renew-interval`. The defaults (`15s` TTL, `5s` renew interval) allow the leader to miss two renewal cycles before the lease expires. Reduce these values if you need faster failover at the cost of more Kubernetes API traffic:

```bash
--controller-lease-ttl=9s
--controller-lease-renew-interval=3s
```

## Duration format

Duration flags accept Go-style duration strings: `300ms`, `5s`, `1m30s`, `2h`. Fractional seconds are not supported.

## Kubernetes Downward API injection

The recommended way to inject `POD_NAME` and `POD_NAMESPACE` in a Deployment:

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

Both are required for correct leader-election identity. The Helm chart injects them automatically.
