# Architecture

## Overview

```mermaid
flowchart LR
    Client([Client]) -->|HTTP / HTTPS| Proxy

    subgraph pod[Coxswain]
        direction TB
        Controller -->|atomic swap| RT[(Routing\nTable)]
        Controller -->|atomic swap| TLS[(TLS\nStore)]
        RT -->|atomic read| Proxy
        TLS -->|SNI handshake| Proxy
    end

    K8s[Kubernetes\nAPI Server] -->|watch events| Controller
    Controller -->|status writes\nleader only| K8s
    Proxy -->|forward| Upstream([Upstream\nPods])
```

The controller watches Kubernetes objects and maintains the routing and TLS tables. The proxy reads from those tables on every request via a single atomic load — no locks, no channels. Routing and TLS updates take effect on the next request after the swap, with no restart and no dropped connections.

## Multi-replica and leader election

All replicas reconcile watch events and maintain their own routing table independently. They all serve traffic all the time. What leader election controls is narrower: only **status writes** (the conditions written back to `Ingress`, `Gateway`, and `HTTPRoute` objects).

```mermaid
flowchart LR
    K8s[Kubernetes API]

    subgraph A[Replica A — leader]
        direction TB
        CA[Controller] --> RTA[(Routing Table)]
        RTA --> PA[Proxy]
    end

    subgraph B[Replica B]
        direction TB
        CB[Controller] --> RTB[(Routing Table)]
        RTB --> PB[Proxy]
    end

    K8s -->|watch| CA
    K8s -->|watch| CB
    CA -->|status writes| K8s

    Clients([Clients]) --> PA
    Clients --> PB
```

The leader is determined by a Kubernetes `Lease` in `coxswain-system`. When the leader is lost, status writes pause for up to one lease TTL (default 15 s) while the new leader is elected. Traffic continues uninterrupted on all replicas during the transition.

## TLS hot-reload

Coxswain watches all `kubernetes.io/tls` Secrets. When a Secret is created, updated, or deleted — including automatic renewals by cert-manager — the TLS store is rebuilt and swapped atomically. New connections immediately use the new certificate; connections already in progress complete with the old one. No restart is required.

## Request path

```mermaid
flowchart LR
    A([TCP connection]) --> B{HTTPS?}
    B -->|yes| C[SNI handshake]
    B -->|no| D
    C --> D[Read host/path/query]
    D --> E[Load routing table]
    E --> F[Host + rule matching]
    F -->|no match| G([404 / 503])
    F -->|match| H[Round-robin upstream]
    H --> I([Forward & respond])
```

## Readiness

`/readyz` returns 200 only after every subsystem has reported ready. During startup this means: all Kubernetes reflectors have completed their initial list (CRDs must be installed and RBAC must be correct), and the routing table has been built at least once. `/readyz` returning 503 on a running pod is a signal that something is wrong — inspect `/status` to see which subsystem is blocked.
