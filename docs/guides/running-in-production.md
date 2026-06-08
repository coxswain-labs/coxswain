# Running in production

Review each section below before directing production traffic to Coxswain.

## Replicas and availability

Run at least two replicas. A single replica is a single point of failure — leader election only coordinates status writes, so both replicas serve traffic independently.

```bash
helm upgrade coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system \
  --set replicaCount=2
```

The default Helm chart includes a `PodDisruptionBudget` (`maxUnavailable: 1`). Verify it is in place:

```bash
kubectl -n coxswain-system get pdb
```

Pod anti-affinity is not set by default. Add it via your `values.yaml` to spread replicas across nodes:

```yaml
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          topologyKey: kubernetes.io/hostname
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: coxswain
```

## Resource requests and limits

The default requests (`100m` CPU / `64Mi` memory) are sized for evaluation. Adjust for your expected traffic:

| Traffic level | CPU request | Memory request | Proxy threads |
|---------------|-------------|----------------|---------------|
| Light (< 1k rps) | 100m–250m | 64Mi–128Mi | 2 |
| Medium (1k–10k rps) | 500m–1 | 128Mi–256Mi | 4 |
| Heavy (> 10k rps) | 2–4 | 256Mi–512Mi | ≥ CPU core count |

Set `proxy.threads` to match the CPU cores allocated to the container:

```bash
helm upgrade coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system \
  --set resources.requests.cpu=500m \
  --set resources.requests.memory=128Mi \
  --set resources.limits.cpu=2 \
  --set resources.limits.memory=512Mi \
  --set proxy.threads=4
```

## Health probes

The default Helm chart wires both probes automatically. Do not disable them:

- **Readiness** (`/readyz`, port `8081`) — Coxswain reports `Ready` only after the initial routing table is built. Kubernetes will not send traffic to the pod until this probe passes.
- **Liveness** (`/healthz`, port `8081`) — always 200 while the process is running.

Verify the probes are present on the deployed pod:

```bash
kubectl -n coxswain-system get deploy coxswain \
  -o jsonpath='{.spec.template.spec.containers[0].readinessProbe}'
```

## Graceful shutdown

Coxswain drains connections for 30 seconds after receiving `SIGTERM` before shutting down (`--proxy-shutdown-grace-period`). Make sure this aligns with your load balancer's connection draining timeout.

For long-lived connections (WebSocket, SSE), increase the grace period:

```bash
--proxy-shutdown-grace-period=60s
--proxy-shutdown-timeout=10s
```

`--proxy-shutdown-timeout` is the hard deadline after the grace period — any remaining connections are forcibly closed.

## Status address

Set `--status-address` to the external IP or hostname of your load balancer. Without it, `Ingress.status` and `Gateway.status.addresses` are left empty, which breaks cert-manager HTTP-01 challenges and external-dns.

```bash
--status-address=203.0.113.10
# or
--status-address=lb.example.com
```

## TLS

TLS Secrets must be in the correct namespace — for `Ingress`, the same namespace as the `Ingress` object; for `Gateway`, the same namespace as the `Gateway` unless a `ReferenceGrant` permits cross-namespace access. See the [TLS guide](../guides/tls.md) for cert-manager setup.

## Observability

Configure a Prometheus scrape against the admin port (`8082`) — see the [Observability reference](../reference/observability.md) for the ServiceMonitor and scrape_config examples. Alert on `/readyz` returning non-200 for more than one scrape interval.

Set `--log-format=json` for structured log ingestion and `--log=warn` in production to reduce noise.

## RBAC

The default ClusterRole grants Coxswain read access to `Ingress`, `Gateway`, `HTTPRoute`, `Secret`, `Service`, `EndpointSlice`, and `ReferenceGrant` resources cluster-wide, plus write access to status sub-resources and `Lease` objects. Review this against your security policy before deploying.

If Coxswain should only manage resources in a single namespace, use a namespace-scoped install. See the [Helm install guide](../installation/helm.md#namespace-scoped-install).

## Signed image verification

Every release image is signed with cosign. Verify the signature before deploying to a production cluster:

```bash
cosign verify \
  --certificate-identity-regexp \
    "https://github.com/coxswain-labs/coxswain/.github/workflows/release.yml" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/coxswain-labs/coxswain:vX.Y.Z
```

See [Verifying releases](../guides/verifying-releases.md) for full details including SBOM verification.
