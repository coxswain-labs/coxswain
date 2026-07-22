# Ingress guide

Coxswain supports the standard Kubernetes `Ingress` resource (networking.k8s.io/v1). It handles `Ingress` and `HTTPRoute` simultaneously — no separate mode or flag is needed.

## IngressClass

An `IngressClass` tells Kubernetes which controller owns a given class name. Coxswain registers one named `coxswain`; reference it from any `Ingress` via `spec.ingressClassName: coxswain`.

### Example

```yaml
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: coxswain
spec:
  controller: coxswain-labs.dev/gateway-controller  # must match --controller-name
```

### Annotations

<div class="nowrap-col1" markdown>

| Annotation | Description |
|------------|-------------|
| `ingressclass.kubernetes.io/is-default-class` | Makes Coxswain the cluster default — handles `Ingress` objects with no class specified |

</div>

### Making Coxswain the cluster default

To handle `Ingress` objects that do not specify a class:

```bash
kubectl annotate ingressclass coxswain \
  ingressclass.kubernetes.io/is-default-class=true
```

## Ingress

An `Ingress` resource defines host- and path-based routing rules that map incoming HTTP(S) requests to backend Services.

### Example

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app
spec:
  ingressClassName: coxswain          # routes this Ingress to Coxswain
  rules:
    - host: app.example.com           # only matches this hostname
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: my-service
                port:
                  number: 80
```

### Annotations

<div class="nowrap-col1" markdown>

| Annotation | Description |
|------------|-------------|
| `kubernetes.io/ingress.class` | Legacy class selection; takes effect when `spec.ingressClassName` is absent. Use `spec.ingressClassName` on Kubernetes 1.18+ |

</div>

Coxswain also supports the `ingress.coxswain-labs.dev/*` annotation namespace for per-Ingress configuration (timeouts, retries, path rewrites, backend protocol). See [Ingress annotations](annotations.md) for the full reference.

### Supported fields

| Field | Support |
|-------|---------|
| `spec.ingressClassName` | Full |
| `spec.rules[].host` | Full (including wildcards) |
| `spec.rules[].http.paths[].path` | Full |
| `spec.rules[].http.paths[].pathType` | `Prefix`, `Exact`, `ImplementationSpecific` |
| `spec.tls[].hosts` | Full |
| `spec.tls[].secretName` | Full |
| `spec.defaultBackend` | Service backends only; Resource backends are skipped |
| `spec.rules[].http.paths[].backend.resource` | Not supported |

### Load balancer address

Set `--status-address` to the external IP or hostname of your load balancer. Coxswain writes it to `status.loadBalancer.ingress` on every managed Ingress. Without it, `ADDRESS` stays empty and cert-manager HTTP-01 challenges will not work.

```bash
kubectl get ingress my-app
# NAME     CLASS     HOSTS             ADDRESS         PORTS   AGE
# my-app   coxswain  app.example.com   203.0.113.10    80      1m
```

### Default backend

`spec.defaultBackend` defines a backend that receives any request that matches no rule at all. It is a top-level field on the `Ingress`, not part of `spec.rules`:

```yaml
spec:
  ingressClassName: coxswain
  defaultBackend:
    service:
      name: catch-all               # receives requests that match no rule
      port:
        number: 80
```

Only Service backends are supported; Resource backends are ignored.

### Path matching

`pathType` controls how the path is matched:

| `pathType` | Behaviour |
|------------|-----------|
| `Prefix` | Matches any request path with the given prefix. `/foo` matches `/foo`, `/foo/`, `/foo/bar`. |
| `Exact` | Matches only the exact path. `/foo` does not match `/foo/`. |
| `ImplementationSpecific` | Treated as `Prefix` by default; becomes regex matching when [`use-regex: "true"`](annotations.md#use-regex) is set on the Ingress. |

```yaml
rules:
  - host: app.example.com
    http:
      paths:
        - path: /api
          pathType: Prefix        # matches /api, /api/users, /api/v2/...
          backend:
            service:
              name: api-service
              port:
                number: 80
        - path: /healthz
          pathType: Exact         # matches only /healthz
          backend:
            service:
              name: health-service
              port:
                number: 8080
```

### Wildcard hostnames

Coxswain follows the Kubernetes Ingress spec for wildcard matching: `*.example.com` matches exactly one DNS label, so `foo.example.com` matches but `foo.bar.example.com` does not.

```yaml
rules:
  - host: "*.example.com"           # matches foo.example.com, not foo.bar.example.com
    http:
      paths:
        - path: /
          pathType: Prefix
          backend:
            service:
              name: wildcard-service
              port:
                number: 80
```

!!! note
    Gateway API wildcards differ: `*.example.com` in a `Gateway` listener or `HTTPRoute` matches any number of labels, including `foo.bar.example.com`. See the [Gateway API guide](../gateway-api/httproute.md#wildcard-hostnames) if you also use `HTTPRoute` objects in the cluster.

### Catch-all rule

A rule with no `host` field matches any hostname that is not claimed by a more specific host rule. Unlike `spec.defaultBackend`, path matching still applies — the request must match the rule's `path`:

```yaml
rules:
  - http:                           # no host — matches any unmatched hostname
      paths:
        - path: /
          pathType: Prefix
          backend:
            service:
              name: catch-all
              port:
                number: 80
```

### Multiple Ingresses on the same host

When multiple `Ingress` objects name the same host, Coxswain merges their paths automatically. Each `Ingress` is reconciled independently; all routes accumulate into a single per-host routing table, so serving different paths from separate `Ingress` objects works out of the box:

```yaml
# Ingress "api"
spec:
  ingressClassName: coxswain
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /api
            pathType: Prefix
            backend:
              service:
                name: api-service     # serves /api/*
                port:
                  number: 80
```

```yaml
# Ingress "web"
spec:
  ingressClassName: coxswain
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: web-service     # serves everything else
                port:
                  number: 80
```

Both `Ingress` objects are active simultaneously — `/api/*` goes to `api-service` and everything else to `web-service`.

**Collision precedence**

When two `Ingress` objects define the same `(host, path, pathType)`, exactly one wins. Since Ingress routes carry no method, header, or query predicates, Coxswain falls through to the timestamp tie-break: the `Ingress` with the **oldest `creationTimestamp`** serves the path; the newer one is shadowed.

```yaml
# Two Ingresses both define host app.example.com, path /foo, pathType Prefix:
#   old-app (created first)  → old-svc   — wins
#   new-app (created later)  → new-svc   — shadowed, never serves /foo
```

Delete or rename the conflicting path in one of the `Ingress` objects to restore it. Conflicts are reported via `GET /api/v1/problems` (`routing.conflicts`) on the controller admin port.

Routes with the same `(host, path)` but **different predicate conditions** — for example, an `HTTPRoute` rule with a method or header constraint on the same host and path — are not a conflict: they coexist and each serves its matching traffic.

!!! note
    The Kubernetes Ingress spec does not define how conflicts between `Ingress` objects on the same host are resolved — it delegates the behaviour to the controller. The merge model and precedence rules described here are Coxswain-specific.

### TLS

Add a `spec.tls` block and reference a `kubernetes.io/tls` Secret in the same namespace. Coxswain reloads the cert automatically when the Secret changes. See the [TLS guide](../operations/tls.md) for cert-manager integration.

```yaml
spec:
  ingressClassName: coxswain
  tls:
    - hosts:
        - app.example.com
      secretName: app-tls           # must exist in the same namespace
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: my-service
                port:
                  number: 80
```

The referenced Secret must have `type: kubernetes.io/tls` with `tls.crt` and `tls.key`.

## Graceful endpoint removal

When a pod is deleted (rolling deploy, scale-down, preStop hook), the Kubernetes EndpointSlice
controller marks its endpoint `terminating=true`. Coxswain's reflector reads this condition and
immediately removes the endpoint from the active routing pool: **no new requests are sent to the
pod once it enters the terminating state**.

Requests that are already in flight on an open connection to that pod complete naturally — the
underlying TCP stream is unaffected by routing-table swaps, so in-flight work is not interrupted.
New requests are routed to the remaining healthy endpoints.

The effective drain window is bounded by the pod's `terminationGracePeriodSeconds`. Design your
`preStop` hooks to complete within this budget.
