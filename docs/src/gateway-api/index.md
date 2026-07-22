# Gateway API

Coxswain implements the [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) standard channel. It supports `GatewayClass`, `Gateway`, `ListenerSet`, `HTTPRoute`, `GRPCRoute`, `TLSRoute`, `TCPRoute`, and `UDPRoute` resources.

This section documents each resource on its own page. Start here for the resource map, then jump to the one you need.

## Supported resources

<div class="nowrap-col2" markdown>

| Resource | API version | Support |
|----------|-------------|---------|
| `GatewayClass` | `gateway.networking.k8s.io/v1` | Full |
| `Gateway` | `gateway.networking.k8s.io/v1` | HTTP, HTTPS, TLS passthrough/terminate, TCP, and UDP listeners — see [Gateway](gateway.md) |
| `ListenerSet` | `gateway.networking.k8s.io/v1` | Attach listeners to a Gateway across namespaces — see the [ListenerSet guide](listenerset.md) |
| `HTTPRoute` | `gateway.networking.k8s.io/v1` | Path, header, method, and query matching; weighted traffic split — see [HTTPRoute](httproute.md) |
| `GRPCRoute` | `gateway.networking.k8s.io/v1` | Service and method matching; cleartext h2c backends — see [GRPCRoute](grpcroute.md) |
| `TLSRoute` | `gateway.networking.k8s.io/v1` | SNI-keyed L4 passthrough and/or terminate — see [TLSRoute](tlsroute.md) |
| `TCPRoute` | `gateway.networking.k8s.io/v1` | Raw TCP proxy, port-keyed — see [TCP & UDP routes](tcp-udp-routes.md#tcproute) |
| `UDPRoute` | `gateway.networking.k8s.io/v1` | Session-tracked UDP datagram forwarding, port-keyed — see [TCP & UDP routes](tcp-udp-routes.md#udproute) |
| `ReferenceGrant` | `gateway.networking.k8s.io/v1beta1` | Cross-namespace backend and certificate access |
| `BackendTLSPolicy` | `gateway.networking.k8s.io/v1` | Upstream TLS configuration referencing a CA `ConfigMap` or `Secret` |
| `CoxswainBackendPolicy` | `gateway.coxswain-labs.dev/v1alpha1` | Coxswain-native per-`Service` connection policy: connect/idle timeouts, load-balancing algorithm, circuit breaker — see [CoxswainBackendPolicy](backend-policy.md) |
| `CoxswainExternalAuth` | `gateway.coxswain-labs.dev/v1alpha1` | External authorization (`ext_authz`, HTTP or gRPC) as an HTTPRoute `ExtensionRef` filter or a Gateway-attached `targetRefs` policy — see [Route extensions](route-extensions.md#external-authorization-ext_authz) |

</div>

The Coxswain-native `ExtensionRef` filters (`RateLimit`, `IpAccessControl`, `BasicAuth`, `JwtAuth`, `ExternalAuth`, `RequestSizeLimit`, `Compression`, `PathRewriteRegex`) are documented on the [Route extensions](route-extensions.md) page; rate limiting and retries have their own guides under [Traffic management](../operations/rate-limiting.md).

## GatewayClass

A `GatewayClass` identifies a controller implementation. Coxswain claims the class whose `spec.controllerName` matches `coxswain-labs.dev/gateway-controller`.

### Example

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: coxswain
spec:
  controllerName: coxswain-labs.dev/gateway-controller  # must match --controller-name
```

### Verifying the controller claimed it

```bash
kubectl get gatewayclass coxswain
# NAME       CONTROLLER                              ACCEPTED
# coxswain   coxswain-labs.dev/gateway-controller    True
```

### Advertised features

Coxswain writes the full list of supported Gateway API features to `status.supportedFeatures` on the `GatewayClass` object:

```bash
kubectl get gatewayclass coxswain \
  -o jsonpath='{.status.supportedFeatures}' | tr ',' '\n'
```

Implementation-specific capabilities — such as `RegularExpression` path, header, and query matching — are not listed in `supportedFeatures`. The Gateway API spec does not define conformance flags for them; they are supported under Coxswain's own dialect. See [Implementation-specific matching](httproute.md#implementation-specific-matching).

## Dedicated proxy pools

A **dedicated proxy (per Gateway)** is a proxy `Deployment` the controller provisions for a single named `Gateway`, serving only that Gateway's routes in isolation from the shared pool. It is a pool in its own right — a `Deployment` scaled by `CoxswainGatewayParameters.spec.replicas` (default `1`), not a single pod — with its own `Service` and `ServiceAccount`.

This is a Gateway API feature. A `Gateway` opts in through `spec.infrastructure.parametersRef`, or inherits the choice from its `GatewayClass`'s `spec.parametersRef`, pointing at a `CoxswainGatewayParameters` object. Classic `Ingress` has no equivalent of `parametersRef` and is always served by the [shared pool](../architecture/proxy-topology.md#shared) — as is every Gateway that doesn't opt in.

### Enabling

Create a `CoxswainGatewayParameters` object and point the `Gateway` at it via `spec.infrastructure.parametersRef`:

```yaml
apiVersion: gateway.coxswain-labs.dev/v1alpha1
kind: CoxswainGatewayParameters
metadata:
  name: tenant-a-defaults
  namespace: tenant-a
spec:
  replicas: 2              # scale the dedicated pool; defaults to 1
  serviceType: ClusterIP
  # image: defaults to the controller's own image when omitted
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: tenant-a-gw
  namespace: tenant-a
spec:
  gatewayClassName: coxswain
  infrastructure:
    parametersRef:
      group: gateway.coxswain-labs.dev
      kind: CoxswainGatewayParameters
      name: tenant-a-defaults     # in the Gateway's own namespace
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: Same
```

A `Gateway` can only reference a `CoxswainGatewayParameters` in its own namespace — the reference carries no namespace field. To set defaults for every dedicated Gateway cluster-wide, attach the `parametersRef` to the `GatewayClass` instead; a Gateway-level reference overlays the class-level one field by field.

Tunable fields on `CoxswainGatewayParameters`:

| Field | Effect | Default |
|-------|--------|---------|
| `replicas` | Static replica count (ignored when `autoscaling.enabled`) | `1` |
| `resources` | Resource requests/limits on the proxy container | controller default |
| `image` | Override the proxy image | controller's own image |
| `serviceType` | `LoadBalancer`, `NodePort`, or `ClusterIP` for the proxy Service | `LoadBalancer` |
| `podTemplate` | Partial `PodTemplateSpec` merged over the rendered template (nodeSelector, tolerations, env, sidecars, …) | — |
| `autoscaling.enabled` | Provision an HPA for the dedicated proxy Deployment | `false` |
| `autoscaling.minReplicas` | HPA lower bound; must be `≥ 2` for the PDB to be provisioned | — |
| `autoscaling.maxReplicas` | HPA upper bound | — |
| `autoscaling.targetCPUUtilizationPercentage` | HPA CPU utilization target | — |

When `autoscaling.enabled: true`, the controller provisions an `HorizontalPodAutoscaler` and, when `minReplicas ≥ 2`, a `PodDisruptionBudget` alongside the Deployment. The Deployment's `spec.replicas` is left unset so the HPA is the sole replica authority. All three objects carry the same name (`<gateway-name>-<gateway-class-name>`), the same owner reference, and the `coxswain-controller` field manager.

```yaml
spec:
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 80
```

### Automatic provisioning

The controller runs a provisioning loop that watches every `Gateway`. For any Gateway whose `parametersRef` (or whose `GatewayClass`'s `parametersRef`) resolves to a `CoxswainGatewayParameters`, the operator applies a dedicated proxy `Deployment` / `Service` / `ServiceAccount` via server-side-apply, owner-referenced to the parent Gateway so deletion cascades.

Verify the resources landed — all three carry the Gateway's name label:

```bash
kubectl get deploy,svc,sa -n tenant-a \
  -l gateway.networking.k8s.io/gateway-name=tenant-a-gw
```

Deleting the Gateway garbage-collects all three via the owner reference. If `parametersRef` targets a missing `CoxswainGatewayParameters`, the operator publishes `Accepted=False, reason=InvalidParameters` on the Gateway.

#### Cross-namespace routes

When a listener declares `allowedRoutes.namespaces.from: All` or `from: Selector`, no additional
operator action is needed. The controller's cluster-wide reflector already watches routes across all
namespaces; cross-namespace HTTPRoutes are resolved at reconcile time and compiled into the dedicated
snapshot before it is pushed to the dedicated proxy. The dedicated proxy receives the complete,
pre-scoped routing world from the controller — it has no cluster-wide reflector and no K8s RBAC of
its own.

#### RBAC

The dedicated proxy holds **zero Kubernetes API credentials**. The provisioned `ServiceAccount` exists
only as a pod identity — the controller stamps its name (`{gateway-name}-{gatewayclass-name}`) into the
Gateway's discovery registry entry, and the discovery server uses it to verify the proxy's SVID before
delivering any snapshot.

The Gateway carries a `gateway.coxswain-labs.dev/dedicated-cleanup` finalizer so the provisioned
`Deployment`, `Service`, and `ServiceAccount` are removed before Kubernetes finalizes the Gateway
deletion.
