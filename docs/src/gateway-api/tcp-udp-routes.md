# TCP & UDP routes

`TCPRoute` and `UDPRoute` both route Layer-4 traffic purely by listener port — no SNI or hostname dimension, no HTTP-layer parsing. They share the same port-keyed model and precedence rule; the difference is that UDP is connectionless, so it is session-tracked rather than spliced.

## TCPRoute

A `TCPRoute` routes raw TCP connections purely by listener port. The proxy dials the bound backend on accept and splices the two byte streams together.

### Gateway listener

Use `protocol: TCP`. A `TCP` listener never shares a port with another protocol — Gateway API's own port-compatibility rules exclude the combination.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: coxswain
  listeners:
    - name: tcp-proxy
      port: 5432
      protocol: TCP
      allowedRoutes:
        namespaces:
          from: Same
```

### Example

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata:
  name: my-tcp-route
  namespace: default
spec:
  parentRefs:
    - name: my-gateway
  rules:
    - backendRefs:
        - name: my-tcp-service
          port: 5432
```

### Supported fields

| Field | Support |
|-------|---------|
| `spec.parentRefs` | Full (including `sectionName` and `port`) |
| `spec.rules[].backendRefs` | Service backends only |
| `spec.rules[].backendRefs[].weight` | Full |

The Standard channel constrains `TCPRoute` to exactly one rule with no matches; when two `TCPRoute`s bind the same listener port, the highest-precedence route (oldest `creationTimestamp`, then name) wins.

### Status conditions

| Condition | True when |
|-----------|-----------|
| `Accepted` | The route is attached to a `protocol: TCP` listener |
| `ResolvedRefs` | All `backendRefs` resolve to a reachable Service |

```bash
kubectl describe tcproute my-tcp-route
```

## UDPRoute

A `UDPRoute` forwards UDP datagrams purely by listener port — the same port-keyed model as `TCPRoute`.

UDP is connectionless, so the proxy can't reuse a dial-once-and-splice model. Instead, the first datagram from a client address picks a backend (via the same weighted load-balancing as every other route kind) and pins it for that client's session; a background task relays the backend's replies back to the client. A session with no activity for `--proxy-udp-session-timeout` (default `10s`) is evicted — the next datagram from that client picks a backend afresh.

### Gateway listener

Use `protocol: UDP`. Like `TCP`, a `UDP` listener never shares a port with another protocol.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: coxswain
  listeners:
    - name: udp-proxy
      port: 5353
      protocol: UDP
      allowedRoutes:
        namespaces:
          from: Same
```

### Example

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: UDPRoute
metadata:
  name: my-udp-route
  namespace: default
spec:
  parentRefs:
    - name: my-gateway
  rules:
    - backendRefs:
        - name: my-udp-service
          port: 5353
```

### Supported fields

| Field | Support |
|-------|---------|
| `spec.parentRefs` | Full (including `sectionName` and `port`) |
| `spec.rules[].backendRefs` | Service backends only |
| `spec.rules[].backendRefs[].weight` | Full — each new client session picks a backend independently, so weights converge across sessions rather than within a single client's traffic |

The Standard channel constrains `UDPRoute` to exactly one rule with no matches; when two `UDPRoute`s bind the same listener port, the highest-precedence route (oldest `creationTimestamp`, then name) wins.

### Status conditions

| Condition | True when |
|-----------|-----------|
| `Accepted` | The route is attached to a `protocol: UDP` listener |
| `ResolvedRefs` | All `backendRefs` resolve to a reachable Service |

```bash
kubectl describe udproute my-udp-route
```
