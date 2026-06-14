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

/** Named events mirroring `events.rs`, looped to drive the live UI. */
const SSE_EVENTS = [
  ['rebuild.completed', { cycle: 7, published: true }],
  ['proxy.connected', { pod: 'tenant-a-gw-coxswain-7db74-j8cjt', mode: 'dedicated-proxy', admin_addr: '10.42.0.102:8082' }],
  ['controller.connected', { pod: 'coxswain-controller-7f9c8-stdby' }],
  ['ownership.changed', { gateway: 'tenant-b/tenant-b-gw', from: 'shared', to: 'dedicated' }],
  ['leader.changed', { pod: 'coxswain-controller-7f9c8-leadr', is_leader: true }],
];

export function mockApi() {
  return {
    name: 'coxswain-mock-api',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = (req.url || '').split('?')[0];
        if (!url.startsWith('/api/v1/')) return next();

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
