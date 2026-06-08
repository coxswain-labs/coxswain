# Production checklist

Work through this list before directing production traffic to Coxswain.

## Replicas and availability

- [ ] **Run at least 2 replicas.** A single replica is a single point of failure; leader election ensures only one replica writes status, but all replicas serve traffic.

  ```bash
  helm upgrade coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
    --set replicaCount=2
  ```

- [ ] **PodDisruptionBudget is configured.** The default Helm chart ships a PDB with `maxUnavailable: 1`. Verify it exists:

  ```bash
  kubectl -n coxswain-system get pdb
  ```

- [ ] **Pod anti-affinity is set.** The default chart prefers spreading replicas across nodes. Verify with `kubectl -n coxswain-system get deploy coxswain -o yaml | grep -A20 affinity`.

## Resource requests and limits

The default requests (`100m` CPU / `64Mi` memory) are conservative for evaluation. Size for your expected traffic:

| Traffic level | CPU request | Memory request | Proxy threads |
|---------------|-------------|----------------|---------------|
| Light (< 1k rps) | 100m–250m | 64Mi–128Mi | 2 |
| Medium (1k–10k rps) | 500m–1 | 128Mi–256Mi | 4 |
| Heavy (> 10k rps) | 2–4 | 256Mi–512Mi | ≥ CPU core count |

Set `proxy.threads` to match the number of CPU cores allocated to the container.

```bash
helm upgrade coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --set resources.requests.cpu=500m \
  --set resources.requests.memory=128Mi \
  --set resources.limits.cpu=2 \
  --set resources.limits.memory=512Mi \
  --set proxy.threads=4
```

## Readiness and health

- [ ] **Readiness probe is configured.** The default Helm chart wires `/readyz` on port `8081`. Coxswain reports `Ready` only after the initial routing table is built — do not skip this probe.

- [ ] **Liveness probe is configured.** `/healthz` always returns 200 as long as the process is running. Confirm the probe is present:

  ```bash
  kubectl -n coxswain-system get deploy coxswain -o jsonpath='{.spec.template.spec.containers[0].livenessProbe}'
  ```

## Graceful shutdown

By default Coxswain drains connections for 30 seconds before shutting down (`--proxy-shutdown-grace-period`). Verify this aligns with your load balancer's connection draining setting. Kubernetes sends `SIGTERM` when evicting a pod; the proxy accepts no new connections after the signal and waits for in-flight requests to complete.

If you have long-lived connections (WebSocket, SSE), increase the grace period:

```bash
--proxy-shutdown-grace-period=60s
--proxy-shutdown-timeout=10s
```

The hard timeout (`--proxy-shutdown-timeout`) fires after the grace period and forcibly closes remaining connections.

## Status address

Cert-manager HTTP-01 challenges and external-dns require Coxswain to write a routable address to `Ingress.status.loadBalancer.ingress` and `Gateway.status.addresses`. Set this to the IP or hostname of your load balancer:

```bash
--status-address=203.0.113.10
# or
--status-address=lb.example.com
```

Without this, cert-manager will not be able to solve HTTP-01 challenges.

## TLS

- [ ] **Secrets are in the correct namespace.** For `Ingress`, the TLS Secret must be in the same namespace as the `Ingress` object. For `Gateway`, the Secret must be in the `Gateway`'s namespace unless a `ReferenceGrant` allows cross-namespace access.

- [ ] **Cert-manager is installed and has an issuer.** See the [TLS guide](../guides/tls.md).

## Observability

- [ ] **Prometheus scrape is configured.** The admin port (`8082`) exposes `/metrics` in Prometheus text format. Add a `ServiceMonitor` or a Prometheus scrape config pointing at the service.

- [ ] **Log level is set appropriately.** Default is `info`; set `--log=warn` in production if you want to reduce noise. Use `--log-format=json` for structured log ingestion.

- [ ] **Monitor `/readyz`.** Alert if `/readyz` returns non-200 for more than one scrape interval — it means a subsystem is not ready and traffic may be misdirected.

See the [Observability reference](../reference/observability.md) for available metrics.

## RBAC

- [ ] **Review the ClusterRole.** The default RBAC grants Coxswain read access to `Ingress`, `Gateway`, `HTTPRoute`, `Secret`, `Service`, `Endpoints`, and `ReferenceGrant` resources cluster-wide, plus write access to `Lease` objects and status sub-resources.

- [ ] **Consider namespace-scoped install** if Coxswain should only manage resources in a single namespace. See the [Helm install guide](helm.md#namespace-scoped-install).

## Signed image verification

Every release image is signed with cosign. Enforce this in your cluster with a policy engine:

```bash
cosign verify \
  --certificate-identity-regexp \
    "https://github.com/coxswain-labs/coxswain/.github/workflows/release.yml" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/coxswain-labs/coxswain:vX.Y.Z
```

See [Verifying releases](../guides/verifying-releases.md) for full details including SBOM verification.
