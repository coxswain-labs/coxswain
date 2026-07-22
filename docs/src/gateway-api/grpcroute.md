# GRPCRoute

A `GRPCRoute` routes gRPC traffic attached to a `Gateway` listener. gRPC is HTTP/2 `POST /{ServiceName}/{MethodName}`, so no special listener protocol is required — an ordinary `HTTP` listener on the Gateway accepts gRPC connections.

## Backend requirements

gRPC backends must advertise cleartext HTTP/2 (h2c) by setting `appProtocol: kubernetes.io/h2c` on the Service port. Coxswain uses prior-knowledge h2c to connect to the backend, which preserves gRPC trailers (`grpc-status`, `grpc-message`).

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-grpc-service
spec:
  selector:
    app: my-grpc-app
  ports:
    - port: 50051
      targetPort: 50051
      appProtocol: kubernetes.io/h2c   # required for gRPC backends
```

## Example

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: my-grpc-route
  namespace: default
spec:
  parentRefs:
    - name: my-gateway
  hostnames:
    - grpc.example.com
  rules:
    - matches:
        - method:
            type: Exact
            service: com.example.MyService
            method: SayHello
      backendRefs:
        - name: my-grpc-service
          port: 50051
```

## Method matching

| Spec | Behaviour |
|------|-----------|
| No `matches` (or empty `matches`) | Routes all gRPC traffic on attached listeners |
| `method.type: Exact`, service + method | Routes `/{service}/{method}` exactly |
| `method.type: Exact`, service only | Routes any method under `/{service}/` |
| `method.type: Exact`, method only | Routes the method name on any service |
| `method.type: RegularExpression` | `service` and `method` are RE2 patterns |

Header matching uses the same `Exact` and `RegularExpression` semantics as `HTTPRoute`.

## Supported fields

| Field | Support |
|-------|---------|
| `spec.parentRefs` | Full (including `sectionName` and `port`) |
| `spec.hostnames` | Full (including wildcards) |
| `spec.rules[].matches[].method` | `Exact` and `RegularExpression` |
| `spec.rules[].matches[].headers` | Full |
| `spec.rules[].filters` | `RequestHeaderModifier`, `ResponseHeaderModifier`, `ExtensionRef` (`RateLimit`, `IpAccessControl`, `JwtAuth`) |
| `spec.rules[].backendRefs` | Service backends only |
| `spec.rules[].backendRefs[].weight` | Full |

GRPCRoute supports the protocol-agnostic `ExtensionRef` filters — [`RateLimit`](../operations/rate-limiting.md), [`IpAccessControl`](route-extensions.md#ip-access-control), and [`JwtAuth`](route-extensions.md#jwt-authentication) (bearer/JWT auth is a common gRPC pattern, unlike `BasicAuth`) — which apply identically to gRPC (HTTP/2) traffic. `PathRewriteRegex` is not supported: for gRPC the request path *is* the `/{service}/{method}` RPC address, so rewriting it is meaningless. `BasicAuth` and `Compression` are HTTP-only idioms and are not supported either — gRPC clients authenticate with bearer tokens or mTLS, and gRPC compresses per-message at the framing layer rather than via HTTP `Content-Encoding`. `RequestSizeLimit` is also not enforced on gRPC — a mid-stream body cap over HTTP/2 deadlocks the client under pingora, so gRPC message sizes are left to the backend's `max_recv_msg_size` ([details](route-extensions.md#request-size-limit-is-not-enforced-on-grpcroute)). Any other `ExtensionRef` (and `RequestMirror`) is skipped with a WARN log line.

## Status conditions

| Condition | True when |
|-----------|-----------|
| `Accepted` | The route is attached to a Gateway listener |
| `Programmed` | The route is active in the data plane |
| `ResolvedRefs` | All `backendRefs` resolve to a reachable Service |

```bash
kubectl describe grpcroute my-grpc-route
```
