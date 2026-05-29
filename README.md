# Coxswain

A pure-Rust Kubernetes Ingress & Gateway API controller backed by [Pingora](https://github.com/cloudflare/pingora) as the proxy engine.

Coxswain watches Kubernetes `Ingress` and `HTTPRoute` resources and dynamically updates its routing table without a process restart or config reload. Multiple replicas can run simultaneously using Kubernetes Lease-based leader election — all replicas maintain a hot routing table, but only the active leader writes status back to the API server.

## Features

- **Gateway API + Ingress** — supports both `HTTPRoute` (Gateway API) and classic `Ingress` resources side-by-side
- **Zero-reload routing** — the routing table is swapped atomically via `arc-swap`; no locks or channels on the hot path
- **Multi-replica safe** — Lease-based leader election coordinates status writes; standby replicas serve traffic without feedback loops
- **Prometheus metrics** — expose live metrics via `/metrics` on the admin port
- **Structured logging** — JSON (production) or human-readable console format

## Architecture

Six crates under `crates/`, with a strict dependency order:

```
coxswain-bin
  ├── coxswain-controller   watches K8s resources, elects leader, writes status
  │     └── coxswain-core   shared routing table (SharedRoutingTable, lock-free)
  ├── coxswain-proxy        Pingora reverse proxy, reads routing table on every request
  │     └── coxswain-core
  ├── coxswain-health       /healthz and /readyz endpoints
  │     └── coxswain-core
  └── coxswain-admin        /metrics, /routes, /status endpoints
        └── coxswain-core
```

### Ports (default)

| Port   | Service | Endpoints                        |
|--------|---------|----------------------------------|
| `8080` | proxy   | HTTP data plane                  |
| `8081` | health  | `/healthz`, `/readyz`            |
| `8082` | admin   | `/metrics`, `/routes`, `/status` |

## Getting Started

### Local development

See [DEVELOPMENT.md](DEVELOPMENT.md) for the full local dev setup, including how to run against a local cluster with echo backends.

### In-cluster deployment

```bash
# Install Gateway API CRDs
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml

# Apply Coxswain manifests
kubectl apply -f deploy/manifests/namespace.yaml
kubectl apply -f deploy/manifests/rbac.yaml
kubectl apply -f deploy/manifests/gateway-class.yaml
kubectl apply -f deploy/manifests/deployment.yaml
```

## Configuration

All flags have environment variable equivalents and are safe to configure via Kubernetes `env:` or `envFrom:`.

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--proxy-addr` | `COXSWAIN_PROXY_ADDR` | `0.0.0.0:8080` | Inbound HTTP proxy address |
| `--health-addr` | `COXSWAIN_HEALTH_ADDR` | `0.0.0.0:8081` | Health endpoints address |
| `--admin-addr` | `COXSWAIN_ADMIN_ADDR` | `0.0.0.0:8082` | Admin/metrics address |
| `--controller-name` | `COXSWAIN_CONTROLLER_NAME` | `coxswain-labs.dev/gateway-controller` | GatewayClass `spec.controllerName` to claim |
| `--controller-watch-namespace` | `COXSWAIN_WATCH_NAMESPACE` | _(cluster-wide)_ | Restrict watch to a single namespace |
| `--log-format` | `COXSWAIN_LOG_FORMAT` | `json` | `json` or `console` |
| `--log` | `COXSWAIN_LOG` | `info` | Log level; supports `RUST_LOG` syntax |

Run `coxswain --help` for the full list.

## License

Apache-2.0 — see [LICENSE](LICENSE).
