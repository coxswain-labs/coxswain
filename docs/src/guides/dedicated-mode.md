# Dedicated-mode Gateways

Dedicated-mode runs a per-Gateway data plane: one coxswain-proxy pod that watches only the resources relevant to a single named Gateway. The shared-pool data plane (`serve proxy --shared`) keeps serving Ingress and non-dedicated Gateway traffic; the controller pod provisions and manages the dedicated pod through `CoxswainGatewayParameters`.

Two ways to run a dedicated proxy:

- **Automatic provisioning** (production): the controller pod (or `serve dev`) detects any Gateway whose `parametersRef` (or whose `GatewayClass`'s `parametersRef`) points at a `CoxswainGatewayParameters` object and provisions a `Deployment` / `Service` / `ServiceAccount` triple, owner-referenced to the parent Gateway so deletion cascades. The proxy pod runs with per-namespace RBAC narrowed to exactly the namespaces the target Gateway's HTTPRoutes need to read.
- **Manual** (for debugging or for parity testing against the shared pool): you run `serve proxy --dedicated --gateway-name=NAME --gateway-namespace=NS` directly. The proxy filters the routing-table build to the named Gateway via its existing `parentRef` check.

## Run a dedicated proxy manually

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
curl -s http://localhost:8082/routes | jq .
```

The output lists exactly the hosts the target Gateway's HTTPRoutes serve; Ingress routes and routes attached to other Gateways do not appear.

### Opt-in flags for cross-namespace route attachment

By default, dedicated mode treats listeners with `allowedRoutes.namespaces.from: All` or `from: Selector` as needing operator consent to broader RBAC scope. The two opt-in flags govern a startup warning today; listener-level refusal (`Accepted=false`) tracking under [#229](https://github.com/coxswain-labs/coxswain/issues/229).

| Flag | Gates listeners with |
|---|---|
| `--allow-cluster-wide-route-read` | `allowedRoutes.namespaces.from: All` |
| `--allow-cluster-wide-namespace-read` | `allowedRoutes.namespaces.from: Selector` |

Both default to false. Set them only on Gateways that genuinely accept cross-namespace route attachment:

```bash
cargo run --bin coxswain -- serve proxy --dedicated \
  --gateway-name coxswain-test \
  --gateway-namespace default \
  --allow-cluster-wide-route-read \
  --log-format console
```

## Automatic provisioning by the controller

`serve controller` (and `serve dev`) runs a provisioning operator that watches every `Gateway`. For any Gateway whose `parametersRef` (or whose `GatewayClass`'s `parametersRef`) points at a `CoxswainGatewayParameters` object, the operator applies a dedicated-proxy `Deployment` / `Service` / `ServiceAccount` to the cluster via server-side-apply under field manager `coxswain-controller`, owner-referenced to the parent Gateway so deletion cascades.

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

### Per-namespace RBAC

For every namespace the Gateway's HTTPRoutes route a backend into (gated by `ReferenceGrant` for cross-namespace refs), the controller reconciles a `RoleBinding` tying the provisioned `ServiceAccount` to the static `coxswain-gateway-proxy-reader` `ClusterRole` (shipped by the Helm chart and `deploy/manifests/dedicated-proxy-clusterrole.yaml`). The dedicated proxy pod uses the controller-rendered `--proxy-watch-namespaces` argument to spawn per-namespace reflectors matching the binding set. Multi-tenant installs get least-privilege RBAC by construction.

The Gateway carries a `gateway.coxswain-labs.dev/dedicated-cleanup` finalizer so cross-namespace bindings are removed before Kubernetes finalizes the Gateway deletion.

## Known limitation

Cluster-wide-mode opt-in flags (`spec.proxy.allowClusterWideRouteRead` / `spec.proxy.allowClusterWideNamespaceRead`) are not yet on the `CoxswainGatewayParameters` CRD — tracked in [#229](https://github.com/coxswain-labs/coxswain/issues/229). The CLI flags described above work for manual `serve proxy --dedicated` invocations; the CRD plumbing and the listener-level `Accepted=false` refusal land alongside the cluster-wide-mode ClusterRoles in that issue.
