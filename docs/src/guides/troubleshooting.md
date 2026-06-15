# Troubleshooting

## Port forward

Most commands below query the admin port. Open a port-forward in a separate terminal first: 

```bash
kubectl -n coxswain-system port-forward svc/coxswain-shared-proxy-internal 8082:8082
```

## `/readyz` returns 503 on startup

The readiness endpoint gates on every registered subsystem reaching `Ready` or `Degraded`. During startup it stays `503` until:

1. All Kubernetes reflectors emit their first `InitDone` (requires CRDs to be installed and RBAC to be correct)
2. The routing table is built at least once

Inspect which subsystem is blocking:

```bash
curl -s http://localhost:8082/api/v1/health | jq .subsystems
```

A subsystem stuck in `Pending` looks like this — `httproute` hasn't seen its first list complete, typically because the CRD is missing:

```json
{
  "controller": {
    "status": "Pending",
    "checks": {
      "httproute": "Pending",
      "ingress": "Ready",
      "gateway": "Pending",
      "routing_table_built": "Pending"
    }
  },
  "proxy": {
    "status": "Pending",
    "checks": {
      "routing_table_loaded": "Pending"
    }
  }
}
```

Common causes:
- Gateway API CRDs not installed — install with `kubectl apply -f .../standard-install.yaml`
- RBAC is missing a permission — check `kubectl -n coxswain-system logs -l app.kubernetes.io/name=coxswain` for `forbidden` errors

## Routes are not being picked up

```bash
# Check the routing table
curl -s http://localhost:8082/api/v1/routes | jq .

# Check HTTPRoute status
kubectl describe httproute my-route

# Check Gateway status
kubectl describe gateway my-gateway
```

In the `kubectl describe httproute` output, look for a condition like this — `ResolvedRefs: False` means a backend Service cannot be found or a `ReferenceGrant` is missing for cross-namespace backends:

```
Status:
  Parents:
    Conditions:
      Message:               Backend "my-service" not found in namespace "default"
      Reason:                BackendNotFound
      Status:                False
      Type:                  ResolvedRefs
```

And in `curl -s http://localhost:8082/api/v1/routes | jq .` the host entry will either be absent or show no upstream addresses.

## TLS certificate is not being served

1. Verify the Secret exists and has the correct type:

   ```bash
   kubectl get secret my-tls -o jsonpath='{.type}'
   # Should print: kubernetes.io/tls
   ```

2. Check Coxswain logs for `TLS Secret unusable` messages.

3. Confirm the Secret is in the same namespace as the `Ingress` or `Gateway`.

## Leader election is not working

Check if the Lease exists and who holds it:

```bash
kubectl -n coxswain-system get lease
# NAME        HOLDER                          AGE
# <name>      coxswain-7d9f6b5c8-xk2pn        5m
```

If the `HOLDER` column is empty or the lease is expired, no replica has claimed leadership. Common causes:

- All replicas are crashing before they can acquire the lease — check `kubectl -n coxswain-system logs -l app.kubernetes.io/name=coxswain`.
- Clock skew between nodes — the default lease TTL (`--controller-lease-ttl=15s`) assumes clocks are synchronised within a few seconds.

## Dedicated proxy pod never becomes Ready

After the controller provisions a dedicated proxy (because a `Gateway` carries a `parametersRef` → `CoxswainGatewayParameters`), the pod should reach `Running` within the same time it takes any Deployment to pull its image and pass readiness checks.

If the pod is stuck:

```bash
# Check the Deployment events
kubectl -n <gateway-namespace> describe deployment <gateway-name>-coxswain

# Check the pod events
kubectl -n <gateway-namespace> describe pod -l gateway.networking.k8s.io/gateway-name=<gateway-name>

# Check controller logs for reconcile errors
kubectl -n coxswain-system logs -l app.kubernetes.io/component=controller --tail=100
```

Common causes:

- **`Accepted=False, reason=InvalidParameters` on the Gateway** — the `parametersRef` points at a `CoxswainGatewayParameters` object that doesn't exist or is in the wrong namespace. Create the object or fix the reference; the controller will reconcile and provision the pod.
- **Image pull error** — the dedicated proxy uses the same image as the controller; verify `imagePullSecrets` and registry credentials in the Gateway's target namespace.
- **RBAC missing** — the controller `ServiceAccount` needs permission to create `Deployment`, `Service`, `ServiceAccount`, and `RoleBinding` objects in the Gateway's namespace. If the Helm chart was upgraded without running `helm upgrade`, re-run it to restore the latest ClusterRole.

## RBAC denials in dedicated proxy logs

The dedicated proxy runs with per-namespace narrowed RBAC: its `ServiceAccount` holds read permissions only in the namespaces the Gateway's HTTPRoutes route backends into. A `forbidden` error in the proxy logs means the proxy is trying to read a resource outside its provisioned namespace set.

```bash
kubectl -n <gateway-namespace> logs deployment/<gateway-name>-coxswain | grep forbidden
```

Common causes:

- **Route backend in a namespace not covered by a `RoleBinding`** — the controller derives `--proxy-watch-namespaces` from the same set of namespaces it has provisioned `RoleBinding`s for. If a route refers to a backend in namespace `B` and no `RoleBinding` exists there, the proxy can't read `Service`/`EndpointSlice` objects in `B`. Check whether a `ReferenceGrant` exists from `B` allowing the route's parent namespace to reference it; without the grant, the backend is rejected by the controller before the proxy sees it.
- **Cross-namespace route attachment** — `allowedRoutes.namespaces.from: All` or `from: Selector` requires a `ClusterRoleBinding` for cluster-wide `HTTPRoute` reads. The controller creates these automatically when the listener mode is set. If the `ClusterRoleBinding` is missing, verify the controller is running and not in an error loop (`kubectl -n coxswain-system logs -l app.kubernetes.io/component=controller`).

## Provisioned resources not garbage-collected after Gateway deletion

When a `Gateway` is deleted, Kubernetes owner-reference GC removes the provisioned `Deployment`, `Service`, and `ServiceAccount` (all owner-referenced to the Gateway). Cross-namespace `RoleBinding`s are not owner-referenced (Kubernetes does not support cross-namespace owner references for namespaced resources), so they are cleaned up by the controller via the `gateway.coxswain-labs.dev/dedicated-cleanup` finalizer.

If resources are not disappearing after a `kubectl delete gateway`:

```bash
# Check whether the finalizer is still present (it should be removed by the controller)
kubectl get gateway <name> -n <ns> -o jsonpath='{.metadata.finalizers}'

# Check controller logs for cleanup errors
kubectl -n coxswain-system logs -l app.kubernetes.io/component=controller --tail=100 | grep dedicated-cleanup
```

Common causes:

- **Controller is not running or has lost the leader lease** — the finalizer is processed only by the active controller replica. If the controller is down or failing to elect a leader, the Gateway will be stuck in a terminating state until the controller recovers.
- **`RoleBinding` delete permission removed** — if the controller's `ClusterRole` was modified to remove `rolebinding` delete permissions, cleanup stalls. Re-apply the Helm chart to restore the correct ClusterRole.

## Controller stuck in Ingress-only mode

At startup, the controller probes for Gateway API CRDs (`gatewayclass.gateway.networking.k8s.io`, `gateway.gateway.networking.k8s.io`, `httproute.gateway.networking.k8s.io`). If any are absent, it drops the Gateway API reconciliation pipelines and runs as a pure Ingress controller.

Symptoms: no `GatewayClass`, `Gateway`, or `HTTPRoute` conditions are written; `kubectl get gatewayclass coxswain` returns nothing.

Fix: install the Gateway API CRDs and restart the controller.

```bash
# Install the standard-channel CRDs (adjust the version to match your cluster)
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/standard-install.yaml

# Restart the controller so it re-probes
kubectl -n coxswain-system rollout restart deployment/coxswain-controller
```

## High memory usage

The routing table is rebuilt from scratch on every reconcile. Very large clusters (thousands of `HTTPRoute` objects) may show elevated memory during rebuilds. Each completed rebuild releases the old table; the GC-free nature of Rust means this is deterministic rather than dependent on a garbage collector schedule.

Profile with:

```bash
curl -s http://localhost:8082/metrics | grep routing_table_rebuild_duration
```
