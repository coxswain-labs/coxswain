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

If `/readyz` returns 503 on a running pod, inspect `/statusz` on the telemetry port to see which subsystem is blocked — see [Troubleshooting](troubleshooting.md#readyz-returns-503-on-startup).

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

Configure a Prometheus scrape against the telemetry port (`8083`) — see the [Observability reference](../reference/observability.md) for the PodMonitor and scrape_config examples. Alert on `/readyz` returning non-200 for more than one scrape interval.

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

Coxswain unconditionally strips `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Real-IP`, and `X-SSL-Client-Cert` from every upstream request before any route filter runs. The proxy owns these headers; client-supplied values are never forwarded. When PROXY protocol is enabled (via `--ingress-accept-proxy-protocol` for Ingress or a `ClientTrafficPolicy` for Gateway listeners), Coxswain injects a proxy-generated `Forwarded` header derived from the real PROXY-protocol client address. On an mTLS host with `auth-tls-pass-certificate-to-upstream: "true"`, it re-inserts `X-SSL-Client-Cert` carrying the verified client certificate after the strip, so a client's own copy of the header is always replaced rather than trusted.

The same rule applies to `ext-auth`'s `allowedResponseHeaders`: every configured name is stripped from the client's request before the check runs, regardless of whether the auth service actually echoes it back. A route that allow-lists a header the auth service doesn't always return would otherwise let a client's forged value through untouched on the requests where it isn't returned.

### The management ports

Every Coxswain pod binds management ports on `management.bindAddress` (`0.0.0.0`
by default, so kubelet probes and Prometheus scraping work without
configuration). There are three, split by **who has to be able to reach them** —
a distinction a port can express and a path cannot:

- **Health, `8081`** — `/healthz` and `/readyz`. Probed by kubelet, whose traffic
  is node-sourced and therefore not selectable by most CNIs, so this port cannot
  meaningfully be fenced. It carries nothing but pass/fail.
- **Telemetry, `8083`** — `/metrics` and `/statusz`, on every role. Read by
  Prometheus, and by a controller probing its **peer controller replicas** —
  never a proxy or a relay, which report their own health over the discovery
  stream instead. **Never authenticated**: `PodMonitor` has no credential field, and a probing pod holds
  only the bcrypt *hash* of the operator credential, so it could not present one
  even in principle. Open to all sources by default; fenceable on request.
- **Operator, `8082`** — the operator UI and the `/api/v1/*` surface, on the
  **controller only**. Verbatim Kubernetes manifests
  (`/api/v1/manifests/{kind}/{ns}/{name}`, including Pod `spec.containers[].env`,
  which frequently holds credentials), Coxswain pod logs, and the routing
  topology. Fenced by default, and authenticated in full when `operatorAuth` is
  set. Proxy and relay pods do not bind it at all.

The operator port is reached through its own `Service`,
`coxswain-controller-operator`, which selects the **elected leader**. That is not
load-balancing avoidance: the topology, fleet, and problems views all read the
node registry, and only the leader accepts discovery streams, so a standby's
registry is empty rather than partial. A `Service` spanning replicas would serve
an empty topology — and a fleet in which every proxy reads as disconnected — at
random. During a leader election that `Service` briefly has no endpoints and the
UI is unreachable — deliberately, because the honest alternative to "no answer"
here is a view indistinguishable from a cluster-wide outage. Health and telemetry
stay reachable on the all-replica `coxswain-controller` `Service` throughout, so
diagnosing the election itself is unaffected. A standby reached directly anyway
answers `503` on those endpoints, naming the reason.

The Kubernetes pod network is flat, so an unfenced operator port is readable by
any pod in any namespace. That is a strong reconnaissance and credential-pivot
primitive in a multi-tenant cluster, where a tenant in namespace A could
otherwise read namespace B's Pod environment. Two controls address it.

**NetworkPolicy (operator port: on by default).** The controller's policy comes
from the chart. It admits the operator port from pods in the install namespace
only, and leaves the health, telemetry, and mTLS-authenticated discovery ports
open.

**NetworkPolicy (telemetry port: off by default).** Coxswain can also fence
`/metrics` and `/statusz` on every pod set — the shared pool, each dedicated
proxy, each relay — but does not do so unless you ask:

```yaml
networkPolicy:
  telemetry:
    fenced: true
    extraIngress:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: monitoring
```

The trade is deliberate and worth understanding before changing it. What fencing
protects is the **routing inventory**: the metric labels enumerate route objects
(`httproute/<ns>/<name>:<rule>`) and backend Service names. That is
reconnaissance material, not credentials, and anyone holding `get httproutes`
already has it. What fencing *costs*, if you enable it without listing your
scraper, is certain and silent: `PodMonitor` targets pod IPs directly, so a
Prometheus outside the pod's own namespace and the install namespace is simply
dropped — its targets sit at `context deadline exceeded` and a dashboard goes
empty, with nothing logged anywhere. Enable it when untrusted workloads share the
pod network, and add the scraper's namespace in the same change.

When the telemetry fence is on, it admits two peers automatically: pods in the
policy's own namespace, and pods in the install namespace. Between them they
cover a Prometheus deployed alongside either the workload or Coxswain itself; a
scraper anywhere else needs an `extraIngress` entry.

The controller does **not** probe this port on a proxy or relay. Those pods
report their own health up the discovery stream they already authenticate with
mTLS, so the controller reads their state from its node registry rather than
dialling them back over a channel it has no way to authenticate. Fencing
telemetry therefore cannot break the fleet view. The one exception is a
controller replica probing its **peer replicas** — controllers run a discovery
*server* and are never clients, so no stream carries a peer's health — and those
are same-namespace by construction, which the first rule already admits.

A proxy binds ports that are not knowable when the policy is written — the shared
pool allocates one internal port per Gateway listener, and a dedicated proxy binds
whatever its Gateway declares. Because a `NetworkPolicy` denies every port it does
not name, those policies allow the full port range *except* the fenced port,
rather than enumerating the data plane. Adding or removing a listener therefore
never requires the policy to be rewritten and can never be blocked by a stale one.

Set `networkPolicy.enabled: false` on clusters whose CNI does not enforce
`NetworkPolicy` (where the object is inert anyway), or if you fence the surface
with your own policy. Disabling removes any policy the controller previously
applied; it keeps the `networkpolicies` RBAC either way, since the delete verb is
exactly what reclaiming them needs.

**Basic auth (opt-in).** A second factor for the controller's operator port,
worth enabling whenever the port is reachable beyond the install namespace.
Create a Secret holding one bcrypt htpasswd line under the key `auth`:

```bash
htpasswd -nbB admin 's3cret' > auth
kubectl create secret generic coxswain-operator-auth \
  --namespace coxswain-system --from-file=auth
rm auth
```

```yaml
operatorAuth:
  secretName: coxswain-operator-auth
```

Only the Secret's *name* reaches the controller; it reads the Secret with the RBAC
it already holds and re-reads it every 30 seconds, so rotating the credential
needs no restart. Only bcrypt is accepted — a plaintext or SHA-1 entry is rejected
at load. If the Secret is deleted or becomes unreadable the operator surface
returns `503`; it never falls back to unauthenticated, so a typo in the name
cannot silently reopen it. A transient apiserver error does *not* clear the
credential — the last known-good one is kept until the apiserver gives a
definitive answer.

**Authentication covers every path on the operator port, with no exemptions.**
Earlier releases had to carve out three endpoints — `/metrics`, `/api/v1/health`
as a peer-probe target, and `/api/v1/topology/local` — because callers that
cannot authenticate had to reach them on that port. None of them lives there any
more: the first two moved to the telemetry listener, and the third was deleted
along with the controller-to-controller fan-out it existed to serve. The port
boundary now carries the distinction the exemption list used to, so enabling
Basic auth cannot break scraping or the fleet view.

**Content-Security-Policy (always on, not opt-in).** The three UI responses (`/`,
`/app.js`, `/app.css`) carry a strict `Content-Security-Policy` —
`default-src 'none'` with narrow, genuinely-true allowances for
`script-src 'self'`, `style-src 'self'`, `img-src 'self' data:`, and
`connect-src 'self'` — plus `X-Content-Type-Options: nosniff` and
`Referrer-Policy: no-referrer`. This is defense in depth for the operator UI's one
HTML-injection sink (a manifest viewer that renders syntax-highlighted,
tenant-supplied JSON): even if that sink were ever compromised, the CSP blocks a
same-origin fetch/script escalation and stops the browser from executing content
sniffed as script. It requires no configuration and cannot be disabled.

### Controller egress

`JwtAuth.spec.jwks.remote.uri` is tenant-authored (any namespace with create-rights on `JwtAuth` controls it), and the controller — a privileged, cluster-network-reachable pod — fetches it every 30 s–5 min. The controller refuses `remote.uri` unless it is `https://` and resolves to a public IP: every reserved/special-purpose range (RFC 1918 private space, loopback, link-local — including cloud metadata at `169.254.169.254` — CGNAT, documentation ranges, multicast) is denied by default, closing off SSRF against the cluster network or cloud metadata service. Set `controller.egressAllowCidrs` (`--egress-allow-cidr`) to permit specific additional destinations — typically an in-cluster identity provider's Service CIDR. A CIDR listed there is also the only destination class where a plaintext `http://` `remote.uri` is accepted; every other destination requires `https://`. See [JwtAuth](../gateway-api/route-extensions.md#jwt-authentication) and the [configuration reference](../reference/configuration.md).

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
