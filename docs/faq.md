# FAQ

## General

### Why another Ingress controller?

Most existing controllers (nginx, Traefik, HAProxy, Envoy) are wrappers around a C/C++ proxy. Configuration changes typically require a reload or restart — even nginx's "graceful reload" creates a new worker process and drains the old one, which briefly increases memory usage and can drop connections under high load.

Coxswain's routing table is an immutable snapshot swapped atomically via `arc-swap`. There is no reload, no worker restart, and no brief connection drop. The hot path allocates nothing beyond the three captures at request entry.

It is written in Rust for memory safety without garbage collection — no GC pauses on the hot path.

### Is Coxswain production-ready?

Not yet. It is in active development toward a v0.1 release. The core routing, TLS, and leader election logic is solid, but some advanced features are missing and the API surface may change. See the [Roadmap](https://github.com/orgs/coxswain-labs/projects/2).

### Does Coxswain support Ingress and Gateway API at the same time?

Yes. Both `Ingress` and `HTTPRoute` objects contribute to the same routing table. You can migrate from Ingress to Gateway API incrementally — both can be active simultaneously.

## Comparison

### nginx Ingress vs. Coxswain

| | nginx Ingress | Coxswain |
|---|---|---|
| Hot reload | nginx master reloads config (brief worker restart) | Atomic swap, no reload |
| Multi-replica | No — each replica has independent nginx config | Yes — all replicas share the same routing via leader election |
| Gateway API | Beta/experimental support | First-class, conformance-tested |
| Language | Go controller + C nginx | Pure Rust |
| Annotations | Rich `nginx.ingress.kubernetes.io/*` ecosystem | v0.1: minimal (planned for future releases) |

### Traefik vs. Coxswain

| | Traefik | Coxswain |
|---|---|---|
| Hot reload | Dynamic config with polling or watch | Atomic swap, no polling |
| Proxy engine | Go stdlib / fasthttp | Pingora (Cloudflare's Rust proxy) |
| Gateway API | Supported via IngressRoute CRDs | Standard Gateway API (conformance-tested) |
| Leader election | No built-in multi-replica coordination | Lease-based, all replicas serve traffic |

### Envoy Gateway vs. Coxswain

| | Envoy Gateway | Coxswain |
|---|---|---|
| Architecture | xDS control plane + Envoy data plane (2 processes) | Single binary: controller + proxy in one process |
| Memory footprint | Higher (Envoy + control plane overhead) | Lower (Rust, no GC) |
| Gateway API | Full conformance, including alpha features | Standard channel conformance-tested |
| Complexity | High — designed for platform teams | Lower — designed for operators |

## Troubleshooting

### `/readyz` returns 503 on startup

The readiness endpoint gates on every registered subsystem reaching `Ready` or `Degraded`. During startup it stays `503` until:

1. All Kubernetes reflectors emit their first `InitDone` (requires CRDs to be installed and RBAC to be correct)
2. The routing table is built at least once

Inspect which subsystem is blocking:

```bash
curl -s http://localhost:8082/status | jq .subsystems
```

Common causes:
- Gateway API CRDs not installed — install with `kubectl apply -f .../standard-install.yaml`
- RBAC is missing a permission — check `kubectl -n coxswain-system logs deploy/coxswain` for `forbidden` errors

### Routes are not being picked up

```bash
# Check the routing table
curl -s http://localhost:8082/routes | jq .

# Check HTTPRoute status
kubectl describe httproute my-route

# Check Gateway status
kubectl describe gateway my-gateway
```

Look for `ResolvedRefs: False` — this means a backend Service cannot be found or a `ReferenceGrant` is missing for cross-namespace backends.

### TLS certificate is not being served

1. Verify the Secret exists and has the correct type:

   ```bash
   kubectl get secret my-tls -o jsonpath='{.type}'
   # Should print: kubernetes.io/tls
   ```

2. Check Coxswain logs for `TLS Secret unusable` messages.

3. Confirm the Secret is in the same namespace as the `Ingress` or `Gateway`.

### cert-manager HTTP-01 challenge is failing

HTTP-01 requires `--status-address` to be set to the proxy's external IP or hostname. Without it, `Ingress.status` is empty and cert-manager cannot determine where to send the ACME challenge.

```bash
kubectl get ingress my-ingress
# ADDRESS column should show your proxy's IP
```

If it is empty, set `--status-address=<your-load-balancer-ip>`.

### Leader election is not working

Check if the Lease exists:

```bash
kubectl -n coxswain-system get lease
```

If the Lease exists but no replica claims leadership, check for clock skew between nodes — a Lease TTL of 15 seconds assumes clocks are synchronized within a few seconds.

### High memory usage

The routing table is rebuilt from scratch on every reconcile. Very large clusters (thousands of `HTTPRoute` objects) may show elevated memory during rebuilds. Each completed rebuild releases the old table; the GC-free nature of Rust means this is deterministic rather than dependent on a garbage collector schedule.

Profile with `curl http://localhost:8082/metrics | grep routing_table_rebuild_duration` to see how long rebuilds take.
