# Getting started

This guide installs Coxswain into an existing cluster, creates a `GatewayClass`, deploys a test `HTTPRoute`, and verifies traffic flows end-to-end. It takes about 10 minutes.

## Prerequisites

- Kubernetes 1.30 or later
- Gateway API CRDs v1.5.1 or later (installed in Step 1)
- `kubectl` configured against your target cluster
- `helm` 3.x installed

## Step 1 — Install the Gateway API CRDs

Coxswain supports both Gateway API and classic Ingress. The Gateway API CRDs are not bundled with Kubernetes and must be installed once per cluster:

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml
```

## Step 2 — Install Coxswain

=== "Helm (recommended)"

    ```bash
    helm install coxswain oci://ghcr.io/coxswain-labs/charts/coxswain \
      --namespace coxswain-system --create-namespace
    ```

=== "Kustomize"

    ```bash
    kubectl apply -k github.com/coxswain-labs/coxswain//deploy/manifests?ref=v0.1.0
    ```

    Replace `v0.1.0` with the desired release tag. For local customisation, clone the repo and use `deploy/manifests/` as a Kustomize base.

=== "Raw manifests"

    ```bash
    kubectl apply -f https://github.com/coxswain-labs/coxswain/releases/latest/download/install.yaml
    ```

Wait for the controller to become ready:

```bash
kubectl -n coxswain-system rollout status deployment/coxswain
```

Verify the `GatewayClass` is accepted:

```bash
kubectl get gatewayclass coxswain
# NAME       CONTROLLER                              ACCEPTED   AGE
# coxswain   coxswain-labs.dev/gateway-controller    True       ...
```

## Step 3 — Create a Gateway

```yaml
# gateway.yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: example-gateway
  namespace: default
spec:
  gatewayClassName: coxswain
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: Same
```

```bash
kubectl apply -f gateway.yaml
kubectl wait gateway/example-gateway --for=condition=Programmed --timeout=30s
```

## Step 4 — Deploy a test backend

```yaml
# echo-backend.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      labels:
        app: echo
    spec:
      containers:
        - name: echo
          image: gcr.io/k8s-staging-gateway-api/echo-basic:latest
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: echo
spec:
  selector:
    app: echo
  ports:
    - port: 80
      targetPort: 8080
```

```bash
kubectl apply -f echo-backend.yaml
```

## Step 5 — Create an HTTPRoute

```yaml
# route.yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: echo-route
spec:
  parentRefs:
    - name: example-gateway
  hostnames:
    - echo.example.com
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: echo
          port: 80
```

```bash
kubectl apply -f route.yaml
kubectl wait httproute/echo-route --for=condition=Accepted --timeout=30s
```

## Step 6 — Verify traffic

The proxy port depends on your cluster and install method. For a local cluster with a `NodePort` or port-forwarded service:

```bash
# Find the proxy service address
kubectl -n coxswain-system get svc coxswain-proxy

# Test via Host header
curl -H "Host: echo.example.com" http://<proxy-address>/
# {"host":"echo.example.com","method":"GET","path":"/", ...}
```

## What's next?

- **Ingress** — see the [Ingress guide](guides/ingress.md) to use classic `Ingress` resources alongside Gateway API.
- **TLS** — see the [TLS guide](guides/tls.md) to add HTTPS with cert-manager or a manual Secret.
- **Production** — see the [Production checklist](installation/production-checklist.md) before going live.
