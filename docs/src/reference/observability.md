# Observability reference

## Metrics

Coxswain exposes the Prometheus endpoint at `http://<admin-address>:<admin-port>/metrics` (default port `8082`). Series are emitted under one of two prefixes that identify the pod role:

- `coxswain_proxy_*` — emitted by `serve proxy --shared`, `serve proxy --dedicated`, and the proxy half of `serve dev`.
- `coxswain_controller_*` — emitted by `serve controller` and the controller half of `serve dev`.

The `route` Prometheus label is a **stable rule identifier**, not a request path. Operators reading `coxswain_proxy_requests_total{route="httproute/checkout/api:0"}` see the same label value on the matching access-log line's `route_id` field, so a Grafana → Loki/Tempo pivot is an exact join (no fuzzy host/path matching). Path patterns stay on the access log for human-readable display.

Route id formats:

- HTTPRoute: `httproute/<namespace>/<name>:<rule_index>` — `rule_index` is the position in `spec.rules[]`.
- Ingress per-rule: `ingress/<namespace>/<name>:<r>.<p>` — nested `(rules, paths)` index, mirroring the YAML structure.
- Ingress `spec.defaultBackend`: `ingress/<namespace>/<name>:default`.
- The controller-wide `--ingress-default-backend` fallback: `ingress-default-backend/<service-namespace>/<service-name>`.

### Proxy-pod metrics (`coxswain_proxy_*`)

| Metric | Type | Labels |
|--------|------|--------|
| `coxswain_proxy_requests_total` | Counter | `listener`, `route`, `method`, `status_code` |
| `coxswain_proxy_request_duration_seconds` | Histogram | `listener`, `route` |
| `coxswain_proxy_upstream_errors_total` | Counter | `listener`, `route`, `upstream`, `error_type` (`connect`/`timeout`/`refused`/`tls`/`5xx`/`other`) |
| `coxswain_proxy_active_upstreams` | Gauge | `upstream` |
| `coxswain_proxy_routing_table_hosts` | Gauge | — |
| `coxswain_proxy_routing_table_routes` | Gauge | `kind` (`ingress`/`gateway`) |
| `coxswain_proxy_routing_table_rebuilds_total` | Counter | `result` (`ok`/`error`) |
| `coxswain_proxy_routing_table_rebuild_duration_seconds` | Histogram | — |
| `coxswain_proxy_tls_certs_loaded` | Gauge | `bucket` (`exact`/`wildcard`/`default`) |
| `coxswain_proxy_tls_cert_expiry_seconds` | Gauge | `sni` |
| `coxswain_proxy_tls_handshakes_total` | Counter | `result` (`ok`/`fail`), `version` |
| `coxswain_proxy_connections_active` | Gauge | `listener` |
| `coxswain_proxy_connections_total` | Counter | `listener` |
| `coxswain_proxy_connection_duration_seconds` | Histogram | `listener` |

The following listener-lifecycle metrics are also exposed: `coxswain_proxy_listeners_active`, `coxswain_proxy_listener_lifecycle_total`, `coxswain_proxy_listener_drain_duration_seconds`, `coxswain_proxy_requests_force_closed_total`.

### Controller-pod metrics (`coxswain_controller_*`)

| Metric | Type | Labels |
|--------|------|--------|
| `coxswain_controller_leader` | Gauge | — (1 when this replica holds the lease) |
| `coxswain_controller_leader_transitions_total` | Counter | — |
| `coxswain_controller_reconcile_total` | Counter | `controller`, `result` (`ok`/`error`) |
| `coxswain_controller_reconcile_duration_seconds` | Histogram | `controller` |
| `coxswain_controller_reconcile_errors_total` | Counter | `controller` |
| `coxswain_controller_status_patch_total` | Counter | `kind`, `result` (`ok`/`error`/`conflict`) |
| `coxswain_controller_status_patch_duration_seconds` | Histogram | `kind` |
| `coxswain_controller_watch_events_total` | Counter | `kind`, `event` (`init_done`/`apply`/`delete`/`restart`) |
| `coxswain_controller_watch_errors_total` | Counter | `kind` |
| `coxswain_controller_routing_table_hosts` | Gauge | — (mirrors the proxy view; drift indicates a stale snapshot) |
| `coxswain_controller_routing_table_routes` | Gauge | `kind` |
| `coxswain_controller_routing_table_rebuilds_total` | Counter | `result` |
| `coxswain_controller_routing_table_rebuild_duration_seconds` | Histogram | — |
| `coxswain_controller_tls_certs_loaded` | Gauge | `bucket` |

### Metric labels per Gateway

When you run a [dedicated proxy pool](../guides/dedicated-mode.md), you usually want to slice its metrics by Gateway. Coxswain does **not** bake the Gateway identity into the emitted series — a `gateway_name` / `gateway_namespace` label on every counter would multiply request-counter cardinality across every dedicated Gateway, and the shared pool has no single Gateway to name.

Instead the identity rides in as a **scrape-time target label**. Each proxy pod the controller provisions carries the Gateway it serves as two pod labels:

- `gateway.networking.k8s.io/gateway-name` — the Gateway name (the GEP-1762 well-known label).
- `gateway.coxswain-labs.dev/gateway-namespace` — the Gateway namespace (a Coxswain label; the upstream group defines no namespace label).

The chart's PodMonitor then copies those pod labels onto every scraped sample via `relabelings`, so they appear on the metrics without ever touching the series the proxy emits:

```yaml
relabelings:
  - sourceLabels:
      - __meta_kubernetes_pod_label_gateway_networking_k8s_io_gateway_name
    targetLabel: gateway_name
  - sourceLabels:
      - __meta_kubernetes_pod_label_gateway_coxswain_labs_dev_gateway_namespace
    targetLabel: gateway_namespace
```

(The `__meta_kubernetes_pod_label_*` source names are Prometheus's mangling of the pod-label keys — dots and slashes become underscores.) Pods in the shared pool don't carry those labels, so the relabel leaves `gateway_name` / `gateway_namespace` empty on shared pool samples — which is how you tell the two apart in a query.

## Health endpoints

| Endpoint | Port | Returns |
|----------|------|---------|
| `/healthz` | `8081` | Always `200 ok` while the process is running |
| `/readyz` | `8081` | `200` once all subsystems are Ready or Degraded; `503` otherwise |

`/readyz` returns 503 during startup until:

1. All Kubernetes reflectors emit their first `InitDone` event (CRDs must be installed)
2. The routing table is built for the first time

Inspect the per-subsystem detail via the admin port (open `kubectl -n coxswain-system port-forward svc/coxswain-shared-proxy-internal 8082:8082` in a separate terminal first; a non-default Helm release name `<rel>` prefixes the Service as `<rel>-coxswain-shared-proxy-internal`):

```bash
curl -s http://localhost:8082/api/v1/health | jq .
```

Example output:

```json
{
  "version": "0.1.0",
  "subsystems": {
    "controller": {
      "status": "Ready",
      "checks": {
        "httproute": "Ready",
        "ingress": "Ready",
        "gateway": "Ready",
        "routing_table_built": "Ready"
      }
    },
    "proxy": {
      "status": "Ready",
      "checks": {
        "routing_table_loaded": "Ready"
      }
    }
  }
}
```

## Routes endpoint

```bash
curl -s http://localhost:8082/routes | jq .
```

Returns the active routing table as JSON — all hostname entries, their rules, and resolved upstream addresses. Useful for debugging routing decisions without reading raw Kubernetes objects.

## Access logs

Coxswain emits one structured log event per proxied request at `INFO` level on the `coxswain_proxy::access` target. Access logs are active by default; set `--access-log=false` (or `COXSWAIN_ACCESS_LOG=false`) to disable them entirely.

### Log fields

| Field | Type | Description |
|-------|------|-------------|
| `host` | string | `Host` header value |
| `method` | string | HTTP method |
| `path` | string | Request path — see `--access-log-path-mode` below |
| `status` | integer | Response HTTP status code |
| `route_id` | string | Canonical rule identifier; same value as the `route` Prometheus label. Empty for requests that bypass routing (e.g. 404 with no matching host) |
| `upstream` | string | Name of the matched upstream service |
| `upstream_addr` | string | Selected endpoint `ip:port` |
| `duration_ms` | integer | Total request duration in milliseconds |
| `bytes_sent` | integer | Response body bytes sent to the client |
| `error` | string | Error message if the request failed (omitted on success) |

The `route_id` field is the **join key** for pivoting from a Grafana alert into a log slice. Copy the metric label value verbatim into a Loki / CloudWatch / Splunk filter to land on the exact rule's traffic.

The `timestamp` field is written automatically by the logging subscriber in RFC 3339 format.

### Path redaction

The `--access-log-path-mode` flag (or `COXSWAIN_ACCESS_LOG_PATH_MODE`) controls what the `path` field contains:

| Value | `path` field content | Use case |
|-------|----------------------|----------|
| `full` (default) | The concrete request path, e.g. `/users/42/orders/7` | Standard traffic analysis |
| `pattern` | The matched rule's registered path pattern, e.g. `/users/` | Cardinality reduction; the proxy holds this without config duplication |
| `none` | Field omitted entirely | Strict path redaction |

!!! tip "Prefer pipeline-side redaction"
    Redacting at the log-collection pipeline is the architecturally correct default — it keeps the proxy emitting ground truth while centralising PII policy. Use `pattern` or `none` only when the pipeline genuinely cannot filter.

### Filtering access logs

Access logs are emitted on the `coxswain_proxy::access` target, so they can be silenced independently of other logs:

```bash
# Silence access logs, keep controller logs at INFO
--log=info,coxswain_proxy::access=off

# Or via environment variable
COXSWAIN_LOG=info,coxswain_proxy::access=off
```

## Logging

Coxswain uses structured logging via `tracing`. Configure the level with `--log` (or `COXSWAIN_LOG`):

| Value | Effect |
|-------|--------|
| `error` | Only errors |
| `warn` | Errors and warnings |
| `info` | Normal operational messages (default) |
| `debug` | Detailed reconciler and routing events |
| `trace` | Very verbose; includes per-request proxy events |

Use `RUST_LOG` directive syntax for per-crate control:

```bash
--log=info,coxswain_controller=debug,coxswain_proxy=warn
```

### Log formats

| `--log-format` | Description |
|----------------|-------------|
| `json` | Structured JSON; one line per event. Use in production for log aggregation. |
| `console` | Human-readable; colourised in a terminal. Use for local development. |

## Prometheus scrape configuration

=== "Prometheus operator (PodMonitor)"

    The chart ships a `PodMonitor` template gated on `.Values.podMonitor.enabled`. Enable it with `--set podMonitor.enabled=true` (or `podMonitor.enabled: true` in your values file). One selector matches both the shared proxy pool and the operator-rendered dedicated proxies; the relabel block injects `gateway_name` / `gateway_namespace` on dedicated metrics only (see [Metric labels per Gateway](#metric-labels-per-gateway) above).

    Why `PodMonitor` and not `ServiceMonitor`? Dedicated proxy Services don't expose port `8082` — adding it would leak `/metrics` onto the LoadBalancer IP. PodMonitor scrapes the pod directly (port `admin`, `:8082`) and skips that issue entirely. Shared pool pods are also discovered the same way, so one resource covers every coxswain proxy in the cluster.

    Hardened installs that pin `podMonitorSelector` on the `Prometheus` resource must update it to include the chart's labels (`app.kubernetes.io/name: coxswain`) — by default kube-prometheus-stack matches both `ServiceMonitor` and `PodMonitor` broadly.

=== "Prometheus scrape_configs"

    The Service names below are for the default `coxswain` release and for raw-manifest installs; a non-default Helm release name `<rel>` prefixes them as `<rel>-coxswain-shared-proxy-internal` and `<rel>-coxswain-controller`. Dedicated proxy metrics aren't reachable through this Service surface — use the PodMonitor path for full coverage.

    ```yaml
    scrape_configs:
      - job_name: coxswain-shared
        static_configs:
          - targets: ['coxswain-shared-proxy-internal.coxswain-system.svc:8082']
        metrics_path: /metrics
      - job_name: coxswain-controller
        static_configs:
          - targets: ['coxswain-controller.coxswain-system.svc:8082']
        metrics_path: /metrics
    ```

## Grafana dashboard

A community Grafana dashboard for Coxswain is planned for a future release. In the meantime, the metrics above are compatible with standard Kubernetes proxy dashboards (e.g. `kubernetes-nginx-ingress` panels adapted for `coxswain_` prefix).
