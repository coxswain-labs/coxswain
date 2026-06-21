# Getting started

This guide installs Coxswain into an existing cluster, creates a `GatewayClass`, deploys a test `HTTPRoute`, and verifies traffic flows end-to-end. It takes about 10 minutes.

## Prerequisites

- Kubernetes 1.30 or later
- Gateway API CRDs v1.5.x or later (installed in Step 1)
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

=== "Raw manifests"

    ```bash
    kubectl apply -f https://github.com/coxswain-labs/coxswain/releases/latest/download/install.yaml
    ```

Wait for the controller to become ready:

```bash
kubectl -n coxswain-system wait pod -l app.kubernetes.io/name=coxswain \
  --for=condition=Ready --timeout=90s
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
            - containerPort: 3000
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
      targetPort: 3000
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
kubectl get httproute echo-route
# NAME         HOSTNAMES            AGE
# echo-route   ["echo.example.com"]   5s
```

## Step 6 — Verify traffic

The proxy port depends on your cluster and install method. For a local cluster with a `NodePort` or port-forwarded service:

```bash
# Find the proxy service address
kubectl -n coxswain-system get svc coxswain-shared-proxy

# Test via Host header
curl -H "Host: echo.example.com" http://<proxy-address>/
# {"host":"echo.example.com","method":"GET","path":"/", ...}
```

## Step 7 — Open the operator console

The controller exposes a built-in web UI on its admin port. Forward it locally:

```bash
kubectl -n coxswain-system port-forward svc/coxswain-controller 8082:8082
```

Then open `http://localhost:8082` in your browser. The console shows cluster health, the live routing table across Gateways and Ingresses, per-pod fleet status, and recent events.

## What's next?

- **Gateway API** — see the [Gateway API guide](guides/gateway-api.md) for the full `HTTPRoute` feature surface, TLS listeners, and cross-namespace routing.
- **Ingress** — see the [Ingress guide](guides/ingress.md) to use classic `Ingress` resources.
- **TLS** — see the [TLS guide](guides/tls.md) to add HTTPS with cert-manager or a manual Secret.
- **Production** — see [Running in production](guides/running-in-production.md) before going live.
- **Troubleshooting** — if something isn't working, see the [Troubleshooting guide](guides/troubleshooting.md).
