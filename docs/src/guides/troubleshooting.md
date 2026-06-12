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
curl -s http://localhost:8082/status | jq .subsystems
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
curl -s http://localhost:8082/routes | jq .

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

And in `curl -s http://localhost:8082/routes | jq .` the host entry will either be absent or show no upstream addresses.

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

## High memory usage

The routing table is rebuilt from scratch on every reconcile. Very large clusters (thousands of `HTTPRoute` objects) may show elevated memory during rebuilds. Each completed rebuild releases the old table; the GC-free nature of Rust means this is deterministic rather than dependent on a garbage collector schedule.

Profile with:

```bash
curl -s http://localhost:8082/metrics | grep routing_table_rebuild_duration
```

## Dedicated-mode proxy pod stuck `Pending` or `CrashLoopBackOff`

A `Gateway` opted into dedicated mode triggers the controller to provision a `Deployment`/`Service`/`ServiceAccount` in the Gateway's namespace, named `<gateway-name>-coxswain`. If the resulting pod doesn't reach `Ready`, the Gateway stays at `Programmed: False`.

```bash
# Find the provisioned pod.
kubectl get pods -n <gateway-namespace> \
  -l gateway.networking.k8s.io/gateway-name=<gateway-name>

# Read the pod's events and conditions.
kubectl describe pod -n <gateway-namespace> <pod-name>
```

Common causes:

- **Image pull fails** (`ErrImagePull` / `ImagePullBackOff`): the `CoxswainGatewayParameters.spec.image` override points at a tag or registry that's not reachable from the cluster. If `image` is omitted, the pod inherits the controller's own image — check `kubectl -n coxswain-system get deploy coxswain-controller -o jsonpath='{.spec.template.spec.containers[0].image}'` and that registry's pull credentials.
- **Pod scheduled but `0/1 Ready`**: inspect the pod logs (`kubectl logs -n <gateway-namespace> <pod-name>`) — the dedicated proxy gates its readiness on the routing table being built. If the proxy is logging Kubernetes API errors, jump to "RBAC denials" below.
- **No pod at all**: the controller did not provision. Check the controller logs (`kubectl -n coxswain-system logs deploy/coxswain-controller | grep <gateway-name>`) — a missing or invalid `parametersRef` surfaces as `Accepted=False, reason=InvalidParameters` on the Gateway.

## RBAC denials in dedicated-proxy logs

If the dedicated proxy's reflectors fail to initialise with `403 Forbidden` errors against `httproutes`, `services`, `endpointslices`, etc., the per-namespace `RoleBinding` the controller should have created for the proxy `ServiceAccount` is missing or scoped to the wrong namespace set.

```bash
# What namespaces should the proxy SA hold reads in?
kubectl -n <gateway-namespace> get gateway <gateway-name> \
  -o jsonpath='{.spec.listeners[*].allowedRoutes.namespaces.from}'

# What namespaces does it actually hold reads in?
kubectl get rolebindings -A \
  -l app.kubernetes.io/managed-by=coxswain-controller \
  -l gateway.networking.k8s.io/gateway-name=<gateway-name>
```

The set should match the namespaces the Gateway's HTTPRoutes route a backend into (with cross-namespace refs gated by `ReferenceGrant`). If a binding is missing for a namespace that has a `ReferenceGrant` for this Gateway, check the controller logs for reconcile errors during binding creation.

The binding refers to the static `coxswain-gateway-proxy-reader` `ClusterRole`. If that `ClusterRole` is missing entirely (e.g. installed with `proxy.dedicated.rbac.create=false`), every dedicated proxy will fail with `403`s — reinstall with the default or apply `deploy/manifests/dedicated-proxy-clusterrole.yaml`.

## Dedicated proxy resources not garbage-collected after `kubectl delete gateway`

The provisioned `Deployment`/`Service`/`ServiceAccount` carry an owner reference to their Gateway, so they're removed by Kubernetes GC within ~30 seconds of the Gateway being deleted. Cross-namespace `RoleBinding`s (which Kubernetes owner-ref GC cannot reach) are removed reconcile-driven by the `gateway.coxswain-labs.dev/dedicated-cleanup` finalizer the controller adds to every dedicated Gateway.

If the Gateway sits in `Terminating` state forever, the finalizer is the usual suspect:

```bash
kubectl get gateway <gateway-name> -n <gateway-namespace> \
  -o jsonpath='{.metadata.finalizers}{"\n"}'
# ["gateway.coxswain-labs.dev/dedicated-cleanup"]

kubectl -n coxswain-system logs deploy/coxswain-controller \
  | grep -E 'cleanup|finalizer' | grep <gateway-name>
```

The controller should log the cleanup reconcile and then remove the finalizer. If the controller pod is down (`kubectl -n coxswain-system get deploy coxswain-controller`) or stuck without a leader (`kubectl -n coxswain-system get lease`), the finalizer is never cleared. Restore the controller and the deletion completes within one reconcile loop. As a last resort, `kubectl patch gateway <name> -n <ns> -p '{"metadata":{"finalizers":null}}' --type=merge` clears the finalizer manually, but this leaves stale cross-namespace `RoleBinding`s behind — clean them up by hand with the label selector above.

## Controller logs `Gateway API CRDs not found; running in Ingress-only mode`

The controller probes for the `GatewayClass` API at startup. If the probe sees the resource is missing, the controller skips every Gateway API reflector and serves `Ingress` only. This is the intended behaviour for clusters without Gateway API CRDs installed (see the [Ingress-only deployment model](deployment-models.md#ingress-only)).

If you want Gateway API:

```bash
# Install the CRDs at the pinned version.
kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/$(cat .gateway-api-version)/standard-install.yaml"

# Restart both pods so they re-probe and start reconciling Gateway API.
kubectl -n coxswain-system rollout restart \
  deploy/coxswain-controller deploy/coxswain-shared-proxy
```

The probe runs once at startup — installing CRDs after the pods are running has no effect until they restart.
