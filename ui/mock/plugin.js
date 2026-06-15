/**
 * Vite dev-server middleware that serves the operator API from captured
 * fixtures, so `npm run dev` gives a full hot-reloading UI with no controller,
 * cluster, or container in the loop.
 *
 * Fixtures in `mock/data/` are snapshots of a live controller's `/api/v1/*`
 * responses (recapture with `mock/capture.sh` against a port-forwarded
 * controller). A request path maps to a file by replacing every `/` with `_`
 * and appending `.json`, e.g. `/api/v1/proxies/foo/routes` →
 * `mock/data/_api_v1_proxies_foo_routes.json`. Files are read per-request, so
 * editing a fixture is reflected on the next reload without restarting Vite.
 *
 * `/api/v1/events` is answered with a synthetic SSE stream that emits the same
 * named events the real controller does, on a loop, so the live indicator goes
 * green and the Events screen has traffic.
 *
 * `/api/v1/pods/{name}/logs` is answered with a synthetic chunked NDJSON stream
 * (the same wire shape the controller relays from kubelet) so the Logs dialog
 * tails real-looking lines — a mix of levels plus a non-JSON line to exercise
 * the raw fallback — with no cluster in the loop.
 *
 * This plugin only registers a dev middleware (`configureServer`), so it is a
 * no-op in `vite build` — the production bundle never includes mock data.
 */
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const DATA_DIR = join(dirname(fileURLToPath(import.meta.url)), 'data');

/** Map an `/api/v1/...` request path to its fixture file on disk. */
function fixtureFile(urlPath) {
  return join(DATA_DIR, `${urlPath.replace(/\//g, '_')}.json`);
}

/** Routing list endpoints → the array key in their fixture. These honour the
 *  shared filter/pagination params (name/namespace/status/limit/offset) so dev
 *  matches the controller: filter the fixture's rows, then window them. */
const LIST_KEYS = {
  '/api/v1/routing/gateways': 'gateways',
  '/api/v1/routing/httproutes': 'httproutes',
  '/api/v1/routing/ingresses': 'ingresses',
};

/** Matches the per-proxy compiled route table `/api/v1/fleet/proxies/{name}/routes`. */
const ROUTES_RE = /^\/api\/v1\/fleet\/proxies\/[^/]+\/routes$/;
/** Matches the per-proxy filter facets `/api/v1/fleet/proxies/{name}/facets`. */
const FACETS_RE = /^\/api\/v1\/fleet\/proxies\/[^/]+\/facets$/;

/** Window one block (ingress|gateway) of a proxy's compiled route table the way
 *  the controller's `routes_block` does: filter rows by `host` (exact),
 *  `namespace` (exact, the route's ns), `path` (substring) and `status=problem`
 *  (dead backend), apply offset/limit, regroup into host-groups. The same
 *  host/namespace/path scope narrows the conflict list (problems is ignored for
 *  conflicts — a conflict is itself a problem). */
function pageRoutesBlock(block, params) {
  const host = (params.get('host') || '').toLowerCase();
  const ns = (params.get('namespace') || '').toLowerCase();
  const path = (params.get('path') || '').toLowerCase();
  const problems = params.get('status') === 'problem';

  const flat = [];
  for (const h of block.hosts ?? []) {
    for (const r of h.routes ?? []) {
      if (host && (h.host || '').toLowerCase() !== host) continue;
      if (ns && (r.namespace || '').toLowerCase() !== ns) continue;
      if (path && !(r.path || '').toLowerCase().includes(path)) continue;
      if (problems && (r.endpoints?.length ?? 0) !== 0) continue;
      flat.push({ port: h.port, host: h.host, route: r });
    }
  }
  const total = flat.length;
  const limit = Math.min(1000, Number.parseInt(params.get('limit') || '200', 10) || 200);
  const offset = Math.min(Math.max(0, Number.parseInt(params.get('offset') || '0', 10) || 0), total);
  const windowed = flat.slice(offset, offset + limit);
  const hosts = [];
  for (const { port, host: h, route } of windowed) {
    const last = hosts[hosts.length - 1];
    if (last && last.port === port && last.host === h) last.routes.push(route);
    else hosts.push({ port, host: h, routes: [route] });
  }
  const conflicts = (block.conflicts ?? []).filter(
    (c) =>
      (!host || (c.host || '').toLowerCase() === host) &&
      (!ns || (c.namespace || '').toLowerCase() === ns) &&
      (!path || (c.path || '').toLowerCase().includes(path)),
  );
  return { hosts, conflicts, total, returned: windowed.length, offset };
}

/** Window both blocks of a proxy's `/routes` fixture, preserving the
 *  `{pod_name, reachable, routes}` envelope. An unreachable proxy has no
 *  `routes` to page. */
function pageRoutes(fixture, params) {
  if (!fixture.routes) return fixture;
  const routes = {};
  for (const key of ['ingress', 'gateway']) {
    if (fixture.routes[key]) routes[key] = pageRoutesBlock(fixture.routes[key], params);
  }
  return { ...fixture, routes };
}

/** Derive a proxy's filter facets (distinct hosts + route namespaces) from its
 *  routes fixture, mirroring the controller's `/api/v1/facets`. */
function deriveFacets(fixture) {
  const hosts = new Set();
  const namespaces = new Set();
  for (const key of ['ingress', 'gateway']) {
    for (const h of fixture.routes?.[key]?.hosts ?? []) {
      hosts.add(h.host);
      for (const r of h.routes ?? []) if (r.namespace) namespaces.add(r.namespace);
    }
  }
  return { hosts: [...hosts].sort(), namespaces: [...namespaces].sort() };
}

/** Apply `?name=&namespace=&status=&limit=&offset=` to a list fixture, mirroring
 *  the backend's filter + window + envelope. */
function pageList(fixture, key, params) {
  let rows = fixture[key] ?? [];
  const name = (params.get('name') || '').toLowerCase();
  const ns = (params.get('namespace') || '').toLowerCase();
  if (name) rows = rows.filter((r) => (r.name || '').toLowerCase().includes(name));
  if (ns) rows = rows.filter((r) => (r.namespace || '').toLowerCase() === ns);
  if (params.get('status') === 'problem') rows = rows.filter((r) => r.status && r.status !== 'ok');
  const total = rows.length;
  const offset = Math.max(0, Number.parseInt(params.get('offset') || '0', 10) || 0);
  const limit = Math.min(1000, Number.parseInt(params.get('limit') || '200', 10) || 200);
  const windowed = rows.slice(offset, offset + limit);
  return { [key]: windowed, total, returned: windowed.length, offset };
}

/** Named events mirroring `events.rs`, looped to drive the live UI. */
const SSE_EVENTS = [
  ['rebuild.completed', { cycle: 7, published: true }],
  ['proxy.connected', { pod: 'tenant-a-gw-coxswain-7db74-j8cjt', mode: 'dedicated-proxy', admin_addr: '10.42.0.102:8082' }],
  ['controller.connected', { pod: 'coxswain-controller-7f9c8-stdby' }],
  ['ownership.changed', { gateway: 'tenant-b/tenant-b-gw', from: 'shared', to: 'dedicated' }],
  ['leader.changed', { pod: 'coxswain-controller-7f9c8-leadr', is_leader: true }],
];

/** Matches `/api/v1/pods/{name}/logs`. */
const LOGS_RE = /^\/api\/v1\/pods\/[^/]+\/logs$/;

/**
 * Synthetic log lines looped to drive the Logs dialog. Mostly JSON
 * (tracing-subscriber shape) across levels, plus one non-JSON line so the raw
 * fallback path stays exercised in dev.
 */
const LOG_LINES = [
  () => JSON.stringify({ timestamp: new Date().toISOString(), level: 'INFO', fields: { message: 'request_filter host=app.example.com path=/api status=200' }, target: 'coxswain_proxy::proxy' }),
  () => JSON.stringify({ timestamp: new Date().toISOString(), level: 'DEBUG', fields: { message: 'upstream_peer selected 10.42.0.7:8080' }, target: 'coxswain_proxy::peer' }),
  () => JSON.stringify({ timestamp: new Date().toISOString(), level: 'WARN', fields: { message: 'backend group has zero ready endpoints' }, target: 'coxswain_reflector::endpoints' }),
  () => 'plain non-JSON line: pingora listening on 0.0.0.0:8080',
  () => JSON.stringify({ timestamp: new Date().toISOString(), level: 'ERROR', fields: { message: 'TLS handshake failed: unknown SNI tenant-z.example.com' }, target: 'coxswain_proxy::tls' }),
  () => JSON.stringify({ timestamp: new Date().toISOString(), level: 'TRACE', fields: { message: 'routing table snapshot swapped (gen 42)' }, target: 'coxswain_core::routing' }),
];

export function mockApi() {
  return {
    name: 'coxswain-mock-api',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = (req.url || '').split('?')[0];
        if (!url.startsWith('/api/v1/')) return next();

        if (LOGS_RE.test(url)) {
          res.writeHead(200, {
            'Content-Type': 'text/plain; charset=utf-8',
            'Cache-Control': 'no-cache',
            Connection: 'keep-alive',
          });
          // Seed a few backlog lines immediately, then tail on an interval.
          let i = 0;
          for (let s = 0; s < 4; s++) res.write(`${LOG_LINES[i++ % LOG_LINES.length]()}\n`);
          const timer = setInterval(() => {
            res.write(`${LOG_LINES[i++ % LOG_LINES.length]()}\n`);
          }, 1200);
          req.on('close', () => clearInterval(timer));
          return;
        }

        if (url === '/api/v1/events') {
          res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            Connection: 'keep-alive',
          });
          res.write('retry: 2000\n\n');
          let i = 0;
          const timer = setInterval(() => {
            const [name, data] = SSE_EVENTS[i++ % SSE_EVENTS.length];
            res.write(`event: ${name}\ndata: ${JSON.stringify(data)}\n\n`);
          }, 3500);
          req.on('close', () => clearInterval(timer));
          return;
        }

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Cache-Control', 'no-store');
        const file = fixtureFile(url);

        // Routing list endpoints: serve a filtered + windowed page from the full
        // fixture so search/namespace/pagination behave like the controller.
        const listKey = LIST_KEYS[url];
        if (listKey && existsSync(file)) {
          const params = new URLSearchParams((req.url || '').split('?')[1] || '');
          const fixture = JSON.parse(readFileSync(file, 'utf8'));
          res.end(JSON.stringify(pageList(fixture, listKey, params)));
          return;
        }

        // Per-proxy compiled route table: window each block (ingress/gateway)
        // like the controller, so ProxyDetail's filter/pagination behaves in dev
        // (#286). Absent params reproduce the full dump (backward-compatible).
        if (ROUTES_RE.test(url) && existsSync(file)) {
          const params = new URLSearchParams((req.url || '').split('?')[1] || '');
          const fixture = JSON.parse(readFileSync(file, 'utf8'));
          const hasParams = ['host', 'namespace', 'path', 'status', 'limit', 'offset'].some((k) => params.get(k));
          res.end(JSON.stringify(hasParams ? pageRoutes(fixture, params) : fixture));
          return;
        }

        // Per-proxy filter facets: derived from the proxy's routes fixture (the
        // controller computes them from the live table), so dev's host/namespace
        // dropdowns are populated without a separate fixture.
        if (FACETS_RE.test(url)) {
          const routesFile = fixtureFile(url.replace(/\/facets$/, '/routes'));
          if (existsSync(routesFile)) {
            const fixture = JSON.parse(readFileSync(routesFile, 'utf8'));
            res.end(JSON.stringify(deriveFacets(fixture)));
          } else {
            res.end(JSON.stringify({ hosts: [], namespaces: [] }));
          }
          return;
        }

        if (existsSync(file)) {
          res.end(readFileSync(file));
        } else {
          res.statusCode = 404;
          res.end(JSON.stringify({
            error: `no mock fixture for ${url}`,
            hint: `capture it: curl $CONTROLLER${url} > mock/data/${url.replace(/\//g, '_')}.json`,
          }));
        }
      });
    },
  };
}
