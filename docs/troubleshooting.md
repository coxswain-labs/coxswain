# Troubleshooting

Most commands below query the admin port. Open a port-forward in a separate terminal first: `kubectl -n coxswain-system port-forward svc/coxswain 8082:8082`

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
- RBAC is missing a permission — check `kubectl -n coxswain-system logs deploy/coxswain` for `forbidden` errors

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
# NAME       HOLDER                                   AGE
# coxswain   coxswain-7d9f6b5c8-xk2pn                5m
```

If the `HOLDER` column is empty or the lease is expired, no replica has claimed leadership. Common causes:

- All replicas are crashing before they can acquire the lease — check `kubectl -n coxswain-system logs deploy/coxswain`.
- Clock skew between nodes — a Lease TTL of 15 s assumes clocks are synchronised within a few seconds.

## High memory usage

The routing table is rebuilt from scratch on every reconcile. Very large clusters (thousands of `HTTPRoute` objects) may show elevated memory during rebuilds. Each completed rebuild releases the old table; the GC-free nature of Rust means this is deterministic rather than dependent on a garbage collector schedule.

Profile with:

```bash
curl -s http://localhost:8082/metrics | grep routing_table_rebuild_duration
```
