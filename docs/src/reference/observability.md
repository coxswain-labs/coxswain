# Observability reference

!!! warning "Planned catalog — not yet implemented"
    The metrics tables below describe the **planned v0.2 catalog**. They are not emitted by the current build. The `/metrics` endpoint is reachable today but only exposes the default `prometheus` collector. Per-request and routing-table metrics land in [#20](https://github.com/coxswain-labs/coxswain/issues/20); access logging in [#21](https://github.com/coxswain-labs/coxswain/issues/21). Treat this page as a design preview, not a runtime reference.

## Metrics

Coxswain exposes the Prometheus endpoint at `http://<admin-address>:<admin-port>/metrics` (default port `8082`). The catalog below is the **planned** shape for v0.2 — none of these series are emitted by the current build.

### HTTP proxy metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `coxswain_requests_total` | Counter | `host`, `method`, `status` | Total HTTP requests processed by the proxy |
| `coxswain_request_duration_seconds` | Histogram | `host`, `method`, `status` | Request latency from proxy receipt to upstream response |
| `coxswain_upstream_connections_total` | Counter | `host`, `upstream` | Total connections opened to upstream services |
| `coxswain_upstream_connection_errors_total` | Counter | `host`, `upstream`, `error` | Upstream connection errors (timeout, refused, etc.) |
| `coxswain_active_connections` | Gauge | — | Current number of active proxy connections |

### Routing table metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `coxswain_routing_table_hosts` | Gauge | — | Number of hostnames in the active routing table |
| `coxswain_routing_table_rebuilds_total` | Counter | `reason` | Number of times the routing table was rebuilt |
| `coxswain_routing_table_rebuild_duration_seconds` | Histogram | — | Time taken to rebuild the routing table |

### Controller metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `coxswain_reconcile_total` | Counter | `resource`, `result` | Reconciliation cycles by resource type and outcome |
| `coxswain_reconcile_duration_seconds` | Histogram | `resource` | Time taken per reconciliation cycle |
| `coxswain_watch_events_total` | Counter | `resource`, `event_type` | Kubernetes watch events received |
| `coxswain_leader_transitions_total` | Counter | — | Number of leader election transitions |
| `coxswain_is_leader` | Gauge | — | `1` if this replica is the current leader, `0` otherwise |

### TLS metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `coxswain_tls_secrets_loaded` | Gauge | — | Number of TLS Secrets currently loaded |
| `coxswain_tls_secret_reloads_total` | Counter | `reason` | TLS Secret reloads (cert rotation, new Secret, etc.) |

## Health endpoints

| Endpoint | Port | Returns |
|----------|------|---------|
| `/healthz` | `8081` | Always `200 ok` while the process is running |
| `/readyz` | `8081` | `200` once all subsystems are Ready or Degraded; `503` otherwise |

`/readyz` returns 503 during startup until:

1. All Kubernetes reflectors emit their first `InitDone` event (CRDs must be installed)
2. The routing table is built for the first time

Inspect the per-subsystem detail via the admin port (open `kubectl -n coxswain-system port-forward svc/coxswain-shared-proxy-internal 8082:8082` in a separate terminal first; Helm installs use the Service name `<release>-internal`):

```bash
curl -s http://localhost:8082/status | jq .
```

Example output:

```json
{
  "version": "0.1.0",
  "synced": true,
  "leader": false,
  "host_count": 3,
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

The `synced` field is `true` when all subsystems are ready and is provided for dashboard compatibility.

## Routes endpoint

```bash
curl -s http://localhost:8082/routes | jq .
```

Returns the active routing table as JSON — all hostname entries, their rules, and resolved upstream addresses. Useful for debugging routing decisions without reading raw Kubernetes objects.

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

=== "Prometheus operator (ServiceMonitor)"

    Coxswain installs two Services that share the `app.kubernetes.io/name: coxswain` label: the proxy Service (`http`, `https` ports) and the internal Service (`health`, `admin` ports). The ServiceMonitor below selects both, but `port: admin` only matches the internal Service, so the proxy Service produces no scrape targets and is silently ignored.

    ```yaml
    apiVersion: monitoring.coreos.com/v1
    kind: ServiceMonitor
    metadata:
      name: coxswain
      namespace: coxswain-system
    spec:
      selector:
        matchLabels:
          app.kubernetes.io/name: coxswain
      endpoints:
        - port: admin
          path: /metrics
          interval: 15s
    ```

=== "Prometheus scrape_configs"

    Replace `<release>` with the Helm release name (or use `coxswain-shared-proxy-internal` for raw-manifest installs):

    ```yaml
    scrape_configs:
      - job_name: coxswain
        static_configs:
          - targets: ['<release>-internal.coxswain-system.svc:8082']
        metrics_path: /metrics
    ```

## Grafana dashboard

A community Grafana dashboard for Coxswain is planned for a future release. In the meantime, the metrics above are compatible with standard Kubernetes proxy dashboards (e.g. `kubernetes-nginx-ingress` panels adapted for `coxswain_` prefix).
