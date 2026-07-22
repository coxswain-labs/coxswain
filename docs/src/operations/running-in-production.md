# Running in production

Review each section below before directing production traffic to Coxswain.

## Replicas and availability

**Controller.** The chart defaults to `controller.replicas: 2` — two replicas with leader election. The `PodDisruptionBudget` (`maxUnavailable: 1`) is provisioned automatically when `replicas >= 2`, so a node drain never removes the last controller pod. The controller does not use an HPA (extra replicas are failover standby, not throughput).

On a leader failover (pod death, node drain, rolling upgrade) the warm standby takes the lease within one Lease TTL (15 s default) and immediately re-drives every reconciler — status writes, dedicated proxy provisioning, and per-Gateway VIP provisioning all resume without waiting for their periodic backstops. The discovery stream is leader-only: proxies reconnect to the new leader (sub-second once the lease moves, via the leader-labelled `coxswain-controller-discovery` Service) and keep serving their last-good routing throughout — a failover stalls routing *updates* briefly, never live traffic. A single failed lease renewal (an API-server blip) does not demote a healthy leader; demotion requires either a positive takeover by another replica or elapsed time since the last successful renew approaching the TTL.

**Shared proxy.** The chart defaults to `proxy.shared.replicas: 1`, which is fine for evaluation but inadequate for production. Run at least two replicas — the PDB is only provisioned when the effective replica floor is ≥ 2:

```bash
# Static replicas:
helm upgrade coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system \
  --set proxy.shared.replicas=2

# Or enable the HPA (minReplicas must also be ≥ 2 for the PDB to be active):
helm upgrade coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system \
  --set proxy.shared.autoscaling.enabled=true \
  --set proxy.shared.autoscaling.minReplicas=2 \
  --set proxy.shared.autoscaling.maxReplicas=10 \
  --set proxy.shared.autoscaling.targetCPUUtilizationPercentage=80
```

When the HPA is enabled, remove the static `proxy.shared.replicas` from your values — it is ignored while the HPA is active, and Helm will not fight the HPA on upgrades.

Verify both the `HorizontalPodAutoscaler` and `PodDisruptionBudget` are in place:

```bash
kubectl -n coxswain-system get hpa,pdb
```

Pod anti-affinity is not set by default. Add it via your `values.yaml` to spread shared proxy replicas across nodes:

```yaml
proxy:
  shared:
    affinity:
      podAntiAffinity:
        preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              topologyKey: kubernetes.io/hostname
              labelSelector:
                matchLabels:
                  app.kubernetes.io/name: coxswain
                  app.kubernetes.io/component: shared-proxy
```

## Resource requests and limits

The Helm chart defaults are sized for evaluation: requests `100m` CPU / `128Mi` memory, limits `500m` CPU / `256Mi` memory. Adjust for your expected traffic:

| Traffic level | CPU request | Memory request | Proxy threads |
|---------------|-------------|----------------|---------------|
| Light (< 1k rps) | 100m–250m | 128Mi | 2 |
| Medium (1k–10k rps) | 500m–1 | 128Mi–256Mi | 4 |
| Heavy (> 10k rps) | 2–4 | 256Mi–512Mi | ≥ CPU core count |

Set `proxy.shared.threads` to match the CPU cores allocated to the container:

```bash
helm upgrade coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
  --namespace coxswain-system \
  --set proxy.shared.resources.requests.cpu=500m \
  --set proxy.shared.resources.requests.memory=128Mi \
  --set proxy.shared.resources.limits.cpu=2 \
  --set proxy.shared.resources.limits.memory=512Mi \
  --set proxy.shared.threads=4
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
- **Shared proxy and dedicated proxy pods** — the discovery client must connect to the controller, bootstrap an SVID, and receive the first routing snapshot. Proxy pods do not participate in leader election; they will stay `NotReady` until the controller is reachable and the first snapshot lands.

Verify the probes are present on the deployed pod:

```bash
kubectl -n coxswain-system get deploy coxswain-shared-proxy \
  -o jsonpath='{.spec.template.spec.containers[0].readinessProbe}'
```

If `/readyz` returns 503 on a running pod, inspect `/api/v1/health` to see which subsystem is blocked — see [Troubleshooting](troubleshooting.md#readyz-returns-503-on-startup).

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

TLS Secrets must be in the correct namespace — for `Ingress`, the same namespace as the `Ingress` object; for `Gateway`, the same namespace as the `Gateway` unless a `ReferenceGrant` permits cross-namespace access. See the [TLS guide](tls.md) for cert-manager setup.

## Observability

Configure a Prometheus scrape against the admin port (`8082`) — see the [Observability reference](../reference/observability.md) for the PodMonitor and scrape_config examples. Alert on `/readyz` returning non-200 for more than one scrape interval.

The controller emits Kubernetes `Warning` Events on `Ingress` objects when a route conflict is detected (`reason: RouteConflict`) or an annotation value is invalid (`reason: InvalidAnnotation`). Set up an alerting rule or regularly query these events:

```bash
kubectl get events --field-selector reason=RouteConflict,type=Warning -A
kubectl get events --field-selector reason=InvalidAnnotation,type=Warning -A
```

See [Troubleshooting — route conflicts](troubleshooting.md#ingress-route-is-shadowed-by-a-conflict) and [annotation diagnostics](troubleshooting.md#ingress-annotation-has-no-effect) for remediation steps.

Set `--log-format=json` for structured log ingestion and `--log=warn` in production to reduce noise.

## Annotation validation

On Kubernetes ≥ 1.30, the Helm chart installs a `ValidatingAdmissionPolicy` that rejects `Ingress` objects carrying malformed `ingress.coxswain-labs.dev/*` annotation values at apply time, surfacing errors immediately rather than silently falling back to defaults. It is enabled by default; disable with `--set vap.enabled=false` if your cluster does not support the `admissionregistration.k8s.io/v1` API. See [Helm install — ValidatingAdmissionPolicy](../installation/helm.md#validatingadmissionpolicy).

## Per-class configuration

`CoxswainIngressClassParameters` lets you set class-level defaults that apply to every `Ingress` claiming the class. Useful for cluster-wide policies:

- **`spec.defaultAnnotations`** — default `ingress.coxswain-labs.dev/*` values; per-Ingress annotations override these per key.
- **`spec.accessLog`** — set `false` to suppress proxy access-log lines for all routes in the class (never force-enables — a `false` class setting cannot be overridden per Ingress). See the [Observability reference](../reference/observability.md#access-logs) for the full access-log configuration model.

## Security

Coxswain unconditionally strips `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Real-IP` from every upstream request before any route filter runs. The proxy owns these headers; client-supplied values are never forwarded. When PROXY protocol is enabled (via `--ingress-accept-proxy-protocol` for Ingress or a `ClientTrafficPolicy` for Gateway listeners), Coxswain injects a proxy-generated `Forwarded` header derived from the real PROXY-protocol client address.

## RBAC

The default `ClusterRole` grants Coxswain cluster-wide:

- Read on `services`, `endpoints`, `endpointslices`, `secrets`, `configmaps` (core API group).
- Read on `ingresses`, `ingressclasses` (`networking.k8s.io`).
- Read on `gatewayclasses`, `gateways`, `httproutes`, `referencegrants`, `backendtlspolicies` (`gateway.networking.k8s.io`).
- Status writes (`*/status`) on `ingresses`, `gateways`, `httproutes`, `backendtlspolicies`, and `gatewayclasses`.

A separate namespaced `Role` (in `coxswain-system`) grants `get`, `create`, `patch` on `coordination.k8s.io/leases` — used only by the controller pod for leader election — plus `get`, `list`, `patch` on `pods` in the same namespace, used by the lease holder to maintain the `discovery.coxswain-labs.dev/leader` pod label that routes proxy discovery dials to the leader (and to strip a stale label off a crashed ex-leader). Review the rendered manifests with `helm template` or read `deploy/manifests/controller-rbac.yaml` before deploying. The shared proxy and dedicated proxy ServiceAccounts hold **no Kubernetes RBAC** — they are identity-only SAs whose projected tokens are used solely for mTLS bootstrap with the controller; verify with `kubectl auth can-i --list --as=system:serviceaccount:coxswain-system:coxswain-shared-proxy` (output should show only Kubernetes baseline grants).

### Scoping the controller to specific namespaces

To restrict Coxswain to a fixed set of namespaces, set `watchNamespace` to a comma-separated list (`ns1,ns2,ns3`); a single value scopes to one namespace, omitted watches cluster-wide. This restricts the controller's reflectors — one namespaced watch per listed namespace, per resource type — so the ServiceAccount needs **no cluster-wide read** on the high-value tenant resources: `services`, `endpointslices`, **`secrets`**, `configmaps`, `ingresses`, the Gateway API routes/`gateways`/`backendtlspolicies`/`listenersets`, and the route-scoped coxswain CRDs. The proxy's discovery client is unaffected (it receives routing from the controller, not from Kubernetes directly).

This is the least-privilege lockdown for soft multi-tenancy: replace the cluster-wide `ClusterRole` read rules with a namespaced `Role` + `RoleBinding` in **each** listed namespace, granting the same read (and status-write) verbs there. Namespaced resources whose objects can also live in the controller's own namespace — `services` (besides tenant backend Services, the per-Gateway shared-VIP Services are provisioned in `coxswain-system`), `pods` (the shared proxy fleet pods live in `coxswain-system`, dedicated proxy pods in the Gateway namespaces), and `coxswaingatewayparameters` / `coxswainingressclassparameters` (a `parametersRef` default commonly lives in `coxswain-system`) — are watched in the listed namespaces **plus `coxswain-system`**, so they need a `Role` there too, not a cluster-wide grant. The only reads that stay cluster-wide are genuinely cluster-scoped Kubernetes resources (no namespace to scope by): `gatewayclasses`, `namespaces`, `nodes`, `ingressclasses`, and `tokenreviews`. Every coxswain-owned CRD is namespaced. The leader-election `Role` in `coxswain-system` is unchanged. See `deploy/manifests/controller-rbac-namespaced.yaml` for a worked example to replicate per listed namespace. Verify the lockdown with `kubectl auth can-i list secrets -A --as=system:serviceaccount:coxswain-system:coxswain-controller` (expect `no` outside the listed namespaces).

## Signed image verification

Every release image and chart is signed with cosign. Verify the signature before deploying to a production cluster — see [Verifying releases](verifying-releases.md).

See [Verifying releases](verifying-releases.md) for the cosign verification flow for both the image and the Helm chart.
