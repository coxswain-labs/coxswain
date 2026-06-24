# Dedicated proxy pools

A **dedicated proxy (per Gateway)** is a proxy `Deployment` the controller provisions for a single named `Gateway`, serving only that Gateway's routes in isolation from the shared pool. It is a pool in its own right — a `Deployment` scaled by `CoxswainGatewayParameters.spec.replicas` (default `1`), not a single pod — with its own `Service` and `ServiceAccount`.

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

`serve controller` runs a provisioning operator that watches every `Gateway`. For any Gateway whose `parametersRef` (or whose `GatewayClass`'s `parametersRef`) resolves to a `CoxswainGatewayParameters` object, the operator applies a dedicated proxy `Deployment` / `Service` / `ServiceAccount` to the cluster via server-side-apply under field manager `coxswain-controller`, owner-referenced to the parent Gateway so deletion cascades.

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

When a listener declares `allowedRoutes.namespaces.from: All` or `from: Selector`, no additional
operator action is needed. The controller's cluster-wide reflector already watches routes across all
namespaces; cross-namespace HTTPRoutes are resolved at reconcile time and compiled into the dedicated
snapshot before it is pushed to the dedicated proxy. The dedicated proxy receives the complete,
pre-scoped routing world from the controller — it has no cluster-wide reflector and no K8s RBAC of
its own.

### RBAC

The dedicated proxy holds **zero Kubernetes API credentials**. The provisioned `ServiceAccount` exists
only as a pod identity — the controller stamps its name (`{gateway-name}-{gatewayclass-name}`, per
GEP-1762) into the Gateway's discovery registry entry, and the discovery server uses it to verify the
proxy's SVID before delivering any snapshot.

The Gateway carries a `gateway.coxswain-labs.dev/dedicated-cleanup` finalizer so the provisioned
`Deployment`, `Service`, and `ServiceAccount` are removed before Kubernetes finalizes the Gateway
deletion.

## Run a dedicated proxy manually

For debugging or for parity testing against the shared pool, you can run a dedicated proxy directly
instead of having the controller provision it. The proxy subscribes to the controller with
`Scope::Gateway` and receives only its Gateway's compiled snapshot — no `parametersRef` is required
for the manual path.

Start the controller first (in a separate terminal), then start the dedicated proxy
alongside it:

```bash
cargo run --bin coxswain -- serve proxy --dedicated \
  --gateway-name coxswain-test \
  --gateway-namespace default \
  --discovery-endpoint https://localhost:50051 \
  --discovery-bootstrap-endpoint https://localhost:50052 \
  --log-format console
```

Verify only that Gateway's routes are loaded:

```bash
curl -s http://localhost:8082/api/v1/routes | jq .
```

The output lists exactly the hosts the target Gateway's HTTPRoutes serve; Ingress routes and routes
attached to other Gateways do not appear. Cross-namespace routes are included automatically — the
controller compiles them before pushing.
