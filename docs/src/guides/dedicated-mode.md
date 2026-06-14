# Dedicated-mode Gateways

Dedicated-mode runs a dedicated proxy (per Gateway): one coxswain-proxy pod that watches only the resources relevant to a single named Gateway. The shared proxy pool (`serve proxy --shared`) keeps serving Ingress and non-dedicated Gateway traffic; the controller provisions and manages the dedicated proxy through `CoxswainGatewayParameters`.

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

### Cross-namespace route attachment (`from: All` / `from: Selector`)

When a listener declares `allowedRoutes.namespaces.from: All` or `from: Selector`, the controller automatically:

1. Creates a `ClusterRoleBinding` granting the proxy SA cluster-wide `HTTPRoute` reads (`coxswain-gateway-proxy-cluster-wide-route-reader`).
2. For `from: Selector`: also creates a `ClusterRoleBinding` for cluster-wide `Namespace` reads (`coxswain-gateway-proxy-cluster-wide-namespace-reader`).
3. Renders `--allow-cluster-wide-route-read` (and `--allow-cluster-wide-namespace-read`) into the proxy Deployment args.
4. The proxy spawns a single cluster-wide `HTTPRoute` reflector instead of the per-namespace one, so routes from all namespaces become visible.

No `CoxswainGatewayParameters` fields or manual opt-in are needed — the Gateway spec is the single source of truth. The `ClusterRoleBinding`s are removed automatically when the listener mode changes back to `from: Same` or the Gateway is deleted.

For **manual invocations** (`serve proxy --dedicated`), pass the flags explicitly:

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

### RBAC

The controller maintains two layers of RBAC for each dedicated proxy:

**Per-namespace `RoleBinding`s** — for every namespace the Gateway's HTTPRoutes route a backend into (gated by `ReferenceGrant` for cross-namespace refs), the controller reconciles a `RoleBinding` tying the provisioned `ServiceAccount` to `coxswain-gateway-proxy-reader`. The proxy pod's `--proxy-watch-namespaces` arg mirrors this binding set so they can't drift.

**`ClusterRoleBinding`s (auto-provisioned)** — when any listener declares `from: All` or `from: Selector`, the controller creates the cluster-wide bindings described above. They are deleted when the listener mode reverts to `from: Same` or the Gateway is removed.

The Gateway carries a `gateway.coxswain-labs.dev/dedicated-cleanup` finalizer so both per-namespace and cluster-wide bindings are removed before Kubernetes finalizes the Gateway deletion.
