# Coxswain

[![E2E & Conformance](https://github.com/coxswain-labs/coxswain/actions/workflows/e2e.yml/badge.svg)](https://github.com/coxswain-labs/coxswain/actions/workflows/e2e.yml)

A pure-Rust Kubernetes Ingress & Gateway API controller backed by [Pingora](https://github.com/cloudflare/pingora) as the proxy engine.

Coxswain watches Kubernetes `Ingress` and `HTTPRoute` resources and dynamically updates its routing table without a process restart or config reload. Multiple replicas can run simultaneously using Kubernetes Lease-based leader election — all replicas maintain a hot routing table, but only the active leader writes status back to the API server.

> **Note**: This project is currently in early development and not accepting external contributions. Bug reports and feature requests in issues are welcome; we'll revisit contribution guidelines as the project matures.

**Roadmap**: see the [Coxswain Roadmap Project](https://github.com/orgs/coxswain-labs/projects/2) for current scope per milestone, with views by track, area, and status.

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
| `80`   | proxy   | HTTP data plane                  |
| `443`  | proxy   | HTTPS data plane (SNI TLS)       |
| `8081` | health  | `/healthz`, `/readyz`            |
| `8082` | admin   | `/metrics`, `/routes`, `/status` |

## Getting Started

### Local development

See [DEVELOPMENT.md](DEVELOPMENT.md) for the full local dev setup, including how to run against a local cluster with echo backends.

### TLS with cert-manager

Coxswain integrates with cert-manager out of the box for both Ingress and Gateway API.
See [docs/tls-cert-manager.md](docs/tls-cert-manager.md) for a step-by-step guide and ready-to-apply example manifests.

### In-cluster deployment

**Quick install (single command):**

```bash
# Install Gateway API CRDs (prerequisite)
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml

# Install Coxswain
kubectl apply -f https://github.com/coxswain-labs/coxswain/releases/latest/download/install.yaml
```

Each release publishes a pre-rendered `install.yaml` as a GitHub Release asset. It pins the image to the exact release tag and includes the Namespace, RBAC, GatewayClass, IngressClass, Services, PodDisruptionBudget, and Deployment. To target a specific version, replace `latest` in the URL with the tag name (e.g. `download/v0.1.0/install.yaml`).

**Helm (values-driven):**

```bash
# Install Gateway API CRDs
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml

# Install Coxswain from the OCI registry
helm install coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system --create-namespace
```

To pin a specific version, add `--version X.Y.Z`. To inspect available options:

```bash
helm show values oci://ghcr.io/coxswain-labs/charts/coxswain
```

**Raw manifests (development / resource inspection):**

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml
kubectl apply -f deploy/manifests/namespace.yaml
kubectl apply -f deploy/manifests/rbac.yaml
kubectl apply -f deploy/manifests/gateway-class.yaml
kubectl apply -f deploy/manifests/ingress-class.yaml
kubectl apply -f deploy/manifests/service.yaml
kubectl apply -f deploy/manifests/pdb.yaml
kubectl apply -f deploy/manifests/deployment.yaml
```

## Configuration

All flags have environment variable equivalents. Most use a `COXSWAIN_*` prefix and are safe to set via Kubernetes `env:` or `envFrom:`. `POD_NAME` and `POD_NAMESPACE` are typically injected by the Kubernetes Downward API.

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

## Verifying releases

Every released image and Helm chart is signed with [cosign](https://github.com/sigstore/cosign) using keyless Sigstore signing (GitHub Actions OIDC — no long-lived keys).

**Verify the OCI image:**

```bash
cosign verify \
  --certificate-identity-regexp \
    "https://github.com/coxswain-labs/coxswain/.github/workflows/release.yml" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/coxswain-labs/coxswain:v0.1.0
```

**Verify the Helm chart:**

```bash
cosign verify \
  --certificate-identity-regexp \
    "https://github.com/coxswain-labs/coxswain/.github/workflows/release.yml" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/coxswain-labs/charts/coxswain:0.1.0
```

See [docs/verifying-releases.md](docs/verifying-releases.md) for full verification details, including SBOMs and policy enforcement with `cosign verify-blob`.

## Authors

Created and maintained by Matteo Giaccone, under the Coxswain Labs banner.

## License

Apache-2.0 — see [LICENSE](LICENSE).
