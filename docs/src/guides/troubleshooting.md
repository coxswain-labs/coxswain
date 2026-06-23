# Troubleshooting

## Port forward

Most commands below query the admin port. Open a port-forward in a separate terminal first: 

```bash
kubectl -n coxswain-system port-forward svc/coxswain-shared-proxy-internal 8082:8082
```

## `/readyz` returns 503 on startup

The readiness endpoint gates on every registered subsystem reaching `Ready` or `Degraded`. During startup it stays `503` until each subsystem reports at least one successful completion:

- **Controller**: all Kubernetes reflectors emit their first `InitDone` (requires CRDs to be installed and controller RBAC to be correct), and the routing table is built at least once.
- **Proxy**: the discovery client connects to the controller, bootstraps an SVID, and receives its first routing snapshot.

Inspect which subsystem is blocking:

```bash
curl -s http://localhost:8082/api/v1/health | jq .subsystems
```

Controller subsystem stuck in `Pending` (CRD missing or controller RBAC wrong):

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
  }
}
```

Proxy subsystem stuck in `Pending` (discovery not yet connected or first snapshot not received):

```json
{
  "proxy": {
    "status": "Pending",
    "checks": {
      "routing_table_loaded": "Pending"
    }
  }
}
```

Common causes for the **controller** being `Pending`:
- Gateway API CRDs not installed — install with `kubectl apply -f .../standard-install.yaml`
- Controller RBAC missing a permission — check `kubectl -n coxswain-system logs -l app.kubernetes.io/name=coxswain` for `forbidden` errors

Common causes for the **proxy** being `Pending`:
- Discovery endpoint unreachable — verify `COXSWAIN_DISCOVERY_ENDPOINT` points at the controller's discovery `Service`
- Trust bundle not yet published — `kubectl -n coxswain-system get configmap coxswain-discovery-trust` must exist; the controller publishes it at startup
- Bootstrap rejected — check for `BootstrapRejected` events: `kubectl -n coxswain-system get events --field-selector reason=BootstrapRejected`
- Wire-version mismatch — proxy logs `FAILED_PRECONDITION` and backs off permanently; see [Wire-version skew](control-plane-security.md#wire-version-skew)

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
- **Controller RBAC missing** — the controller `ServiceAccount` needs permission to create `Deployment`, `Service`, and `ServiceAccount` objects in the Gateway's namespace. If the Helm chart was upgraded without running `helm upgrade`, re-run it to restore the latest ClusterRole.

## Dedicated proxy stuck `NotReady` or `Degraded`

The dedicated proxy is a discovery client: it bootstraps an SVID from the controller and then opens a mTLS stream to receive its Gateway's routing snapshot. The proxy stays `NotReady` until the first snapshot arrives; it transitions to `Degraded` on any subsequent reconnect window.

```bash
# Check proxy logs for discovery errors
kubectl -n <gateway-namespace> logs deployment/<gateway-name>-coxswain | tail -50

# Check for bootstrap rejections (controller is the sole event emitter)
kubectl -n coxswain-system get events --field-selector reason=BootstrapRejected
```

Common causes:

- **Discovery endpoint unreachable** — the dedicated proxy's `COXSWAIN_DISCOVERY_ENDPOINT` is rendered by the controller; verify the controller's discovery `Service` exists and the proxy pod can reach it.
- **SVID scope mismatch** — the stream server logs `PERMISSION_DENIED` if the proxy's SVID does not match the expected ServiceAccount for the Gateway. Check that the SA name follows the GEP-1762 pattern (`{gateway-name}-{gatewayclass-name}`) and that the controller's registry entry is current. Reconciling the Gateway again (e.g. by adding/removing an annotation) forces a registry refresh.
- **Wire-version mismatch** — proxy logs `FAILED_PRECONDITION`; see [Wire-version skew](control-plane-security.md#wire-version-skew).

## Provisioned resources not garbage-collected after Gateway deletion

When a `Gateway` is deleted, Kubernetes owner-reference GC removes the provisioned `Deployment`, `Service`, and `ServiceAccount` (all owner-referenced to the Gateway). The `gateway.coxswain-labs.dev/dedicated-cleanup` finalizer ensures the controller completes any remaining cleanup before Kubernetes finalizes the Gateway.

If resources are not disappearing after a `kubectl delete gateway`:

```bash
# Check whether the finalizer is still present (it should be removed by the controller)
kubectl get gateway <name> -n <ns> -o jsonpath='{.metadata.finalizers}'

# Check controller logs for cleanup errors
kubectl -n coxswain-system logs -l app.kubernetes.io/component=controller --tail=100 | grep dedicated-cleanup
```

Common cause: the controller is not running or has lost the leader lease — the finalizer is processed only by the active controller replica. If the controller is down or failing to elect a leader, the Gateway will be stuck in a terminating state until the controller recovers.

## Controller stuck in Ingress-only mode

At startup, the controller probes for Gateway API CRDs (`gatewayclass.gateway.networking.k8s.io`, `gateway.gateway.networking.k8s.io`, `httproute.gateway.networking.k8s.io`). If any are absent, it drops the Gateway API reconciliation pipelines and runs as a pure Ingress controller.

Symptoms: no `GatewayClass`, `Gateway`, or `HTTPRoute` conditions are written; `kubectl get gatewayclass coxswain` returns nothing.

Fix: install the Gateway API CRDs and restart the controller.

```bash
# Install the standard-channel CRDs
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml

# Restart the controller so it re-probes
kubectl -n coxswain-system rollout restart deployment/coxswain-controller
```

## Ingress route is shadowed by a conflict

When two `Ingress` objects claim the same host and path combination, only one wins (see [Multi-Ingress merging and conflict precedence](ingress.md#multiple-ingresses-on-the-same-host)). The losing Ingress's route is silently dropped from the routing table. The controller emits a `Warning` Event on the shadowed Ingress to make the conflict visible:

```bash
kubectl describe ingress <shadowed-ingress>
# ...
# Events:
#   Type     Reason         Age  From               Message
#   ----     ------         ---  ----               -------
#   Warning  RouteConflict  1m   coxswain           Route on host app.example.com path /api is shadowed by default/winning-ingress
```

You can also query events directly:

```bash
kubectl get events --field-selector reason=RouteConflict -A
```

To resolve: ensure only one Ingress claims a given `(host, path)` slot, or migrate the conflicting rules into a single Ingress object.

## Ingress annotation has no effect

If an `ingress.coxswain-labs.dev/*` annotation value is invalid, the controller ignores it (fail-open) and emits a `Warning` Event on the Ingress:

```bash
kubectl describe ingress <name>
# Events:
#   Type     Reason            Age  From               Message
#   ----     ------            ---  ----               -------
#   Warning  InvalidAnnotation  1m  coxswain           connect-timeout: invalid duration "5 seconds" — expected a Go duration string (e.g. "5s", "1m30s")
```

Query all annotation-parse warnings in the cluster:

```bash
kubectl get events --field-selector reason=InvalidAnnotation -A
```

On Kubernetes ≥ 1.30 with the Helm chart, the `ValidatingAdmissionPolicy` catches most invalid values at `kubectl apply` time — the admission rejection message matches the Event message format above.

## High memory usage

The routing table is rebuilt from scratch on every reconcile. Very large clusters (thousands of `HTTPRoute` objects) may show elevated memory during rebuilds. Each completed rebuild releases the old table; the GC-free nature of Rust means this is deterministic rather than dependent on a garbage collector schedule.

Profile with:

```bash
curl -s http://localhost:8082/metrics | grep routing_table_rebuild_duration
```
