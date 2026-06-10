# Running in production

Review each section below before directing production traffic to Coxswain.

## Replicas and availability

The Helm chart defaults to `replicaCount: 1`, which is fine for evaluation but inadequate for production: a single replica is a single point of failure, and the default `PodDisruptionBudget` (`maxUnavailable: 1`) combined with one replica means a voluntary disruption can take the entire data plane offline. Run at least two replicas. Leader election only coordinates status writes, so all replicas serve traffic independently.

```bash
helm upgrade coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system \
  --set replicaCount=2
```

Verify the `PodDisruptionBudget` is in place:

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

The Helm chart defaults are sized for evaluation: requests `100m` CPU / `128Mi` memory, limits `500m` CPU / `256Mi` memory. Adjust for your expected traffic:

| Traffic level | CPU request | Memory request | Proxy threads |
|---------------|-------------|----------------|---------------|
| Light (< 1k rps) | 100m–250m | 128Mi | 2 |
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

- **Liveness** (`/healthz`, port `8081`) — always 200 while the process is running.
- **Readiness** (`/readyz`, port `8081`) — returns 200 only once every subsystem in the pod reaches `Ready` or `Degraded`.

Subsystems have four states:

| State | Meaning | Effect on `/readyz` |
|---|---|---|
| `Pending` | Still initialising | 503 |
| `Ready` | Fully operational | passes |
| `Degraded` | Partial fault, still serving | passes |
| `Failed` | Fatal error | 503 |

Readiness gates differ by mode:

- **Controller pod** — all Kubernetes reflectors must complete their initial list and the controller must have acquired (or be in standby for) the Lease.
- **Shared-proxy and gateway-proxy pods** — all Kubernetes reflectors must complete their initial list and the routing table must be built at least once. Proxy pods do not participate in leader election and do not wait for the controller.

Verify the probes are present on the deployed pod:

```bash
kubectl -n coxswain-system get deploy coxswain \
  -o jsonpath='{.spec.template.spec.containers[0].readinessProbe}'
```

If `/readyz` returns 503 on a running pod, inspect `/status` to see which subsystem is blocked — see [Troubleshooting](troubleshooting.md#readyz-returns-503-on-startup).

## Graceful shutdown

On `SIGTERM`, Coxswain drains in-flight connections for `--proxy-shutdown-grace-period` (default `30s`), then forcibly closes any remaining connections after `--proxy-shutdown-timeout` (default `5s`). Make sure the grace period aligns with your load balancer's connection draining timeout.

For long-lived connections (WebSocket, SSE), increase the grace period:

```bash
--proxy-shutdown-grace-period=60s
--proxy-shutdown-timeout=10s
```

## Live Gateway listener changes

When a Gateway's listener set changes (port added or removed), Coxswain reconciles listeners in-process without restarting. New ports are bound immediately; removed ports enter a drain window (`--proxy-listener-drain-timeout`, default `30s`) during which in-flight requests complete normally before the socket is released.

Tune the drain timeout to cover your longest expected upstream latency:

```bash
--proxy-listener-drain-timeout=60s
```

The `coxswain_proxy_requests_force_closed_total{reason="drain_exceeded"}` metric increments for any connection that could not finish within the window. It should remain at 0 under normal operation; a non-zero value means the drain timeout is too short for your workload.

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

The default `ClusterRole` grants Coxswain cluster-wide:

- Read on `services`, `endpoints`, `endpointslices`, `secrets`, `configmaps` (core API group).
- Read on `ingresses`, `ingressclasses` (`networking.k8s.io`).
- Read on `gatewayclasses`, `gateways`, `httproutes`, `referencegrants`, `backendtlspolicies` (`gateway.networking.k8s.io`).
- Status writes (`*/status`) on `ingresses`, `gateways`, `httproutes`, `backendtlspolicies`, and `gatewayclasses`.

A separate namespaced `Role` (in `coxswain-system`) grants `get`, `create`, `patch` on `coordination.k8s.io/leases` — used only by the controller pod for leader election. Review the rendered manifests with `helm template` or read `deploy/manifests/controller-rbac.yaml` and `deploy/manifests/shared-proxy-rbac.yaml` before deploying. The shared-proxy ServiceAccount has zero write verbs; verify with `kubectl auth can-i --list --as=system:serviceaccount:coxswain-system:coxswain-shared-proxy`.

If Coxswain should only manage resources in a single namespace, set `controller.watchNamespace`. Note that this only restricts what the controller reads; the chart still installs the cluster-wide `ClusterRole`/`ClusterRoleBinding`. To scope RBAC as well, edit the rendered manifests by hand.

## Signed image verification

Every release image is signed with cosign. Verify the signature before deploying to a production cluster:

```bash
cosign verify \
  --certificate-identity-regexp \
    "https://github.com/coxswain-labs/coxswain/.github/workflows/release.yml" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/coxswain-labs/coxswain:vX.Y.Z
```

See [Verifying releases](../guides/verifying-releases.md) for the cosign verification flow for both the image and the Helm chart.
