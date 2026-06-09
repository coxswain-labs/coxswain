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

| Annotation | Description |
|------------|-------------|
| `ingressclass.kubernetes.io/is-default-class` | Makes Coxswain the cluster default — handles `Ingress` objects with no class specified |

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

| Annotation | Description |
|------------|-------------|
| `kubernetes.io/ingress.class` | Legacy class selection; takes effect when `spec.ingressClassName` is absent. Use `spec.ingressClassName` on Kubernetes 1.18+ |

!!! note
    No `coxswain-labs.dev/*` annotations are defined yet. That namespace is reserved for future per-Ingress configuration such as rewrites and redirects.

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
| `ImplementationSpecific` | Treated as `Prefix` by Coxswain. |

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
    Gateway API wildcards differ: `*.example.com` in a `Gateway` listener or `HTTPRoute` matches any number of labels, including `foo.bar.example.com`. See the [Gateway API guide](gateway-api.md#wildcard-hostnames) if you also use `HTTPRoute` objects in the cluster.

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

### TLS

Add a `spec.tls` block and reference a `kubernetes.io/tls` Secret in the same namespace. Coxswain reloads the cert automatically when the Secret changes. See the [TLS guide](tls.md) for cert-manager integration.

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

The referenced Secret must have `type: kubernetes.io/tls` with `tls.crt` and `tls.key`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-tls
  namespace: default
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded certificate>
  tls.key: <base64-encoded private key>
```
