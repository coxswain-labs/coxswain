# Dedicated proxy pools

A **dedicated proxy (per Gateway)** is a proxy `Deployment` the controller provisions for a single named `Gateway`, serving only that Gateway's routes in isolation from the shared pool. It is a pool in its own right — a `Deployment` scaled by `CoxswainGatewayParameters.spec.replicas` (default `1`), not a single pod — with its own `Service`, `ServiceAccount`, and narrowed RBAC.

This is a Gateway API feature. A `Gateway` opts in through `spec.infrastructure.parametersRef` (GEP-1762), or inherits the choice from its `GatewayClass`'s `spec.parametersRef`, pointing at a `CoxswainGatewayParameters` object. Classic `Ingress` has no equivalent of `parametersRef` and is always served by the [shared pool](../architecture.md#shared) — as is every Gateway that doesn't opt in.

## Opt a Gateway into a dedicated pool

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
| `replicas` | Replica count for the provisioned proxy Deployment | `1` |
| `resources` | Resource requests/limits on the proxy container | controller default |
| `image` | Override the proxy image | controller's own image |
| `serviceType` | `LoadBalancer`, `NodePort`, or `ClusterIP` for the proxy Service | `LoadBalancer` |
| `podTemplate` | Partial `PodTemplateSpec` merged over the rendered template (nodeSelector, tolerations, env, sidecars, …) | — |

## Automatic provisioning by the controller

`serve controller` (and `serve dev`) runs a provisioning operator that watches every `Gateway`. For any Gateway whose `parametersRef` (or whose `GatewayClass`'s `parametersRef`) resolves to a `CoxswainGatewayParameters` object, the operator applies a dedicated-proxy `Deployment` / `Service` / `ServiceAccount` to the cluster via server-side-apply under field manager `coxswain-controller`, owner-referenced to the parent Gateway so deletion cascades.

Apply the dev fixture set and verify the resources land:

```bash
kubectl apply -f deploy/dev/dedicated-gateway/

kubectl get deploy,svc,sa -n tenant-a \
  -l gateway.networking.k8s.io/gateway-name=tenant-a-gw
# Three resources named <gateway-name>-coxswain land in tenant-a.
```

Field-manager assertion:

```bash
kubectl get deployment tenant-a-gw-coxswain -n tenant-a -o json | \
  jq '.metadata.managedFields[].manager'
# "coxswain-controller"
```

Garbage collection on Gateway deletion (owner-ref cascade):

```bash
kubectl delete gateway tenant-a-gw -n tenant-a
# All three resources disappear within ~30s.
```

If `parametersRef` targets a missing `CoxswainGatewayParameters` object, the operator publishes an `Accepted=False, reason=InvalidParameters` condition on the Gateway via the shared override channel.

### Cross-namespace route attachment (`from: All` / `from: Selector`)

When a listener declares `allowedRoutes.namespaces.from: All` or `from: Selector`, the controller automatically:

1. Creates a `ClusterRoleBinding` granting the proxy SA cluster-wide `HTTPRoute` reads (`coxswain-gateway-proxy-cluster-wide-route-reader`).
2. For `from: Selector`: also creates a `ClusterRoleBinding` for cluster-wide `Namespace` reads (`coxswain-gateway-proxy-cluster-wide-namespace-reader`).
3. Renders `--allow-cluster-wide-route-read` (and `--allow-cluster-wide-namespace-read`) into the proxy Deployment args.
4. The proxy spawns a single cluster-wide `HTTPRoute` reflector instead of the per-namespace one, so routes from all namespaces become visible.

No `CoxswainGatewayParameters` fields or manual opt-in are needed — the Gateway spec is the single source of truth. The `ClusterRoleBinding`s are removed automatically when the listener mode changes back to `from: Same` or the Gateway is deleted.

### RBAC

The controller maintains two layers of RBAC for each dedicated proxy:

**Per-namespace `RoleBinding`s** — for every namespace the Gateway's HTTPRoutes route a backend into (gated by `ReferenceGrant` for cross-namespace refs), the controller reconciles a `RoleBinding` tying the provisioned `ServiceAccount` to `coxswain-gateway-proxy-reader`. The proxy pod's `--proxy-watch-namespaces` arg mirrors this binding set so they can't drift.

**`ClusterRoleBinding`s (auto-provisioned)** — when any listener declares `from: All` or `from: Selector`, the controller creates the cluster-wide bindings described above. They are deleted when the listener mode reverts to `from: Same` or the Gateway is removed.

The Gateway carries a `gateway.coxswain-labs.dev/dedicated-cleanup` finalizer so both per-namespace and cluster-wide bindings are removed before Kubernetes finalizes the Gateway deletion.

## Run a dedicated proxy manually

For debugging or for parity testing against the shared pool, you can run a dedicated proxy directly instead of having the controller provision it. The proxy filters the routing-table build to the named Gateway via its existing `parentRef` check — no `parametersRef` is required for the manual path.

Apply the dev Gateway fixture so there's something to attach to:

```bash
kubectl apply -f deploy/dev/echo-backends.yaml
kubectl apply -f deploy/dev/httproute.yaml   # creates the `coxswain-test` Gateway
```

Then start the dedicated proxy in its own terminal alongside the controller:

```bash
cargo run --bin coxswain -- serve proxy --dedicated \
  --gateway-name coxswain-test \
  --gateway-namespace default \
  --log-format console
```

Verify only that Gateway's routes are loaded:

```bash
curl -s http://localhost:8082/api/v1/routes | jq .
```

The output lists exactly the hosts the target Gateway's HTTPRoutes serve; Ingress routes and routes attached to other Gateways do not appear.

For a listener with `from: All` or `from: Selector`, pass the cluster-wide flags explicitly — the controller adds these automatically in provisioned mode:

```bash
cargo run --bin coxswain -- serve proxy --dedicated \
  --gateway-name coxswain-test \
  --gateway-namespace default \
  --allow-cluster-wide-route-read \
  --log-format console
```
