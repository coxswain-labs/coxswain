# Ingress guide

Coxswain supports the standard Kubernetes `Ingress` resource (networking.k8s.io/v1). It handles `Ingress` and `HTTPRoute` simultaneously — no separate mode or flag is needed.

## IngressClass

Coxswain registers an `IngressClass` named `coxswain`. Reference it via `spec.ingressClassName`:

```yaml
spec:
  ingressClassName: coxswain
```

To make Coxswain the cluster default (handles `Ingress` objects without an explicit class):

```bash
kubectl annotate ingressclass coxswain \
  ingressclass.kubernetes.io/is-default-class=true
```

## Basic example

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app
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
                name: my-service
                port:
                  number: 80
```

## Path matching

`pathType` controls how the path is matched:

| `pathType` | Behaviour |
|------------|-----------|
| `Prefix` | Matches any request path with the given prefix. `/foo` matches `/foo`, `/foo/`, `/foo/bar`. |
| `Exact` | Matches only the exact path. `/foo` does not match `/foo/`. |
| `ImplementationSpecific` | Treated as `Prefix` by Coxswain. |

## TLS

Add a `spec.tls` block and reference a `kubernetes.io/tls` Secret in the same namespace:

```yaml
spec:
  ingressClassName: coxswain
  tls:
    - hosts:
        - app.example.com
      secretName: app-tls
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

The Secret must have `type: kubernetes.io/tls` with `tls.crt` and `tls.key`. Coxswain reloads the cert automatically when the Secret changes. See the [TLS guide](tls.md) for cert-manager integration.

## Wildcard hostnames

Coxswain follows the Kubernetes Ingress spec for wildcard matching: `*.example.com` matches exactly one DNS label, so `foo.example.com` matches but `foo.bar.example.com` does not.

```yaml
rules:
  - host: "*.example.com"
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

## Default backend

A rule without a `host` field matches any hostname not matched by a more specific rule:

```yaml
rules:
  - http:
      paths:
        - path: /
          pathType: Prefix
          backend:
            service:
              name: catch-all
              port:
                number: 80
```

## Supported annotations

| Annotation | Scope | Description |
|------------|-------|-------------|
| `kubernetes.io/ingress.class` | `Ingress` | Legacy class selection; takes effect when `spec.ingressClassName` is absent. Use `spec.ingressClassName` on Kubernetes 1.18+ |
| `ingressclass.kubernetes.io/is-default-class` | `IngressClass` | Makes Coxswain the cluster default — handles `Ingress` objects with no class specified |

!!! note
    No `coxswain-labs.dev/*` annotations are defined yet. That namespace is reserved for future per-Ingress configuration such as rewrites and redirects.

## Status

Coxswain writes the proxy's external address to `status.loadBalancer.ingress` once the `--status-address` flag is set. Without it, status is left empty (cert-manager HTTP-01 will not work).

```bash
kubectl get ingress my-app
# NAME     CLASS     HOSTS             ADDRESS         PORTS   AGE
# my-app   coxswain  app.example.com   203.0.113.10    80      1m
```

## Supported fields

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
