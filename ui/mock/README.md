# Mock dev server

`npm run dev` serves the operator UI at <http://localhost:5173> with hot-reload
and a mock `/api/v1/*` backend — no controller, cluster, or container needed.
Edit anything under `src/` and the browser updates instantly.

## How it works

`plugin.js` is a Vite dev middleware (wired in `vite.config.js`). It answers
`/api/v1/*` from JSON fixtures in `data/`, mapping a request path to a file by
replacing `/` with `_` (e.g. `/api/v1/proxies/foo/routes` →
`data/_api_v1_proxies_foo_routes.json`). Two paths are answered with synthetic
streams instead of fixtures: `/api/v1/events` is an SSE stream emitting the
controller's named events on a loop (so the live indicator goes green), and
`/api/v1/pods/{name}/logs` is a chunked NDJSON stream of mixed-level log lines
(so the Logs dialog tails real-looking output). The plugin is dev-only —
`vite build` never includes it or the fixtures.

### Filter + pagination

Paths that carry the shared list envelope are filtered + windowed in the plugin
so dev matches the controller (params absent → full dump):

- **Routing lists** (`routing/{gateways,httproutes,ingresses}`) honour
  `name`/`namespace`/`status`/`limit`/`offset` and return `total`/`returned`/
  `offset`.
- **Per-proxy route table** (`fleet/proxies/{name}/routes`) honours
  `host` (exact), `namespace` (exact, the route's ns), `path` (substring),
  `status=problem` and `limit`/`offset` — windowing **each block**
  (ingress/gateway) independently the way the controller's `routes_block` does
  (filter, window, regroup) with `total`/`returned`/`offset` per block. The same
  host/namespace/path scope also narrows each block's **conflict** list. The
  shared-proxy fixtures carry a synthetic slice (~60 gateway hosts) so
  ProxyDetail's pagination + filter dropdowns are exercised (#286).
- **Per-proxy filter facets** (`fleet/proxies/{name}/facets`) are *derived* from
  the proxy's routes fixture (distinct hosts + route namespaces), mirroring the
  controller — no separate fixture to maintain.

## Two ways to (re)generate fixtures

- **Synthetic, comprehensive** — `node mock/generate.mjs` writes one coherent
  cluster that exercises every distinct UI state (leader/standby/degraded/
  unreachable pods; programmed/not-programmed/not-accepted gateways; dead
  backends; conflicts; multi-tenant grouping; …). The state matrix is documented
  at the top of `generate.mjs`. This is the committed default. Route detail
  fixtures carry the interpreted effective config (rules + per-parentRef
  conditions), and each route also has a `…/check` fixture so the on-demand
  data-plane check button reaches its full matrix in dev — consistent, drift
  (a row missing on one proxy), dead backends, and an unreachable proxy.
- **Captured from a real controller** — port-forward the admin port, then
  `BASE=http://localhost:8082 mock/capture.sh`. Snapshots whatever state the
  live cluster is in. Use when you need to reproduce something real.

A missing fixture returns 404 with a hint on how to capture it.
