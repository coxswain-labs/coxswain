# Architecture

## Zero-reload routing

The routing table is an immutable snapshot, not a mutable config file. When Kubernetes objects change, the controller builds a **complete new table** from scratch and swaps it in atomically. The proxy reads the current table on every request via a single atomic pointer load — no mutex, no lock, no channel.

The result: routing changes take effect on the next request after the swap, with no process restart, no graceful reload window, and no brief connection drop.

## Multi-replica and leader election

All replicas reconcile watch events and maintain their own routing table independently. They all serve traffic all the time. What leader election controls is narrower: only **status writes** (the conditions written back to `Ingress`, `Gateway`, and `HTTPRoute` objects).

```
Every replica:   watch → reconcile → update local table → serve traffic
Leader only:     watch → reconcile → write status to K8s objects
```

The leader is determined by a Kubernetes `Lease` in `coxswain-system`. When the leader is lost, status writes pause for up to one lease TTL (default 15 s) while the new leader is elected. Traffic continues uninterrupted on all replicas during the transition.

## TLS hot-reload

Coxswain watches all `kubernetes.io/tls` Secrets. When a Secret is created, updated, or deleted — including automatic renewals by cert-manager — the TLS store is rebuilt and swapped atomically. New connections immediately use the new certificate; connections already in progress complete with the old one. No restart is required.

## Request path

```
1. Proxy accepts TCP connection
2. If HTTPS: SNI TLS handshake selects certificate from TLS store
3. request_filter: read host, path, query from request (≤ 3 allocations)
4. Atomic load of current routing table snapshot (~2 ns)
5. Host lookup → rule matching (Exact before Prefix; longer before shorter)
6. Round-robin pick from the upstream address set
7. upstream_peer: return selected address
8. Response forwarded back to client
```

The routing lookup and upstream selection allocate nothing. The only allocations per request are the three captures at step 3 — host, path, and query.

## Readiness

`/readyz` returns 200 only after every subsystem has reported ready. During startup this means: all Kubernetes reflectors have completed their initial list (CRDs must be installed and RBAC must be correct), and the routing table has been built at least once. `/readyz` returning 503 on a running pod is a signal that something is wrong — inspect `/status` to see which subsystem is blocked.
