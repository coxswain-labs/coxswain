import { fetchJson } from './client.js';

// ── Query helper ────────────────────────────────────────────────────────────

/**
 * Build a `?…` query string from the shared list-endpoint params, omitting
 * empties so a no-arg call yields the param-less URL (the backend then returns
 * the full dump). For the per-proxy route table: `host` (exact) and `namespace`
 * (exact) are the dropdown picks, `path` is the search substring.
 * `status: 'problem'` filters to non-ok rows.
 *
 * @param {{name?: string, namespace?: string, host?: string, path?: string, limit?: number, offset?: number, status?: string}} [opts]
 */
export function buildQuery(opts = {}) {
  const q = new URLSearchParams();
  if (opts.name) q.set('name', opts.name);
  if (opts.namespace) q.set('namespace', opts.namespace);
  if (opts.host) q.set('host', opts.host);
  if (opts.path) q.set('path', opts.path);
  if (opts.limit != null) q.set('limit', String(opts.limit));
  if (opts.offset) q.set('offset', String(opts.offset));
  if (opts.status) q.set('status', opts.status);
  const s = q.toString();
  return s ? `?${s}` : '';
}

// ── Summaries (Dashboard tiles + routing tab badges) ──────────────────────────

export const getFleetSummary = () => fetchJson('/api/v1/fleet/summary');
export const getRoutingSummary = () => fetchJson('/api/v1/routing/summary');
export const getProblems = () => fetchJson('/api/v1/problems');
export const getTopology = () => fetchJson('/api/v1/topology');

// ── Fleet (all coxswain pods) ─────────────────────────────────────────────────

export const getProxies = () => fetchJson('/api/v1/fleet/proxies');
export const getProxy = (pod) => fetchJson(`/api/v1/fleet/proxies/${encodeURIComponent(pod)}`);
export const getProxyRoutes = (pod, opts) =>
  fetchJson(`/api/v1/fleet/proxies/${encodeURIComponent(pod)}/routes${buildQuery(opts)}`);
export const getProxyFacets = (pod) =>
  fetchJson(`/api/v1/fleet/proxies/${encodeURIComponent(pod)}/facets`);
export const getProxyHealth = (pod) =>
  fetchJson(`/api/v1/fleet/proxies/${encodeURIComponent(pod)}/health`);

export const getControllers = () => fetchJson('/api/v1/fleet/controllers');
export const getController = (pod) =>
  fetchJson(`/api/v1/fleet/controllers/${encodeURIComponent(pod)}`);
export const getControllerHealth = (pod) =>
  fetchJson(`/api/v1/fleet/controllers/${encodeURIComponent(pod)}/health`);

// ── Routing (config resources) ────────────────────────────────────────────────

export const getGateways = (opts) => fetchJson(`/api/v1/routing/gateways${buildQuery(opts)}`);
export const getGateway = (ns, name) =>
  fetchJson(`/api/v1/routing/gateways/${encodeURIComponent(ns)}/${encodeURIComponent(name)}`);

export const getHttproutes = (opts) => fetchJson(`/api/v1/routing/httproutes${buildQuery(opts)}`);

export const getIngresses = (opts) => fetchJson(`/api/v1/routing/ingresses${buildQuery(opts)}`);
export const getIngress = (ns, name) =>
  fetchJson(`/api/v1/routing/ingresses/${encodeURIComponent(ns)}/${encodeURIComponent(name)}`);

// ── Route detail (HTTPRouteDetail / IngressDetail) ────────────────────────────

export const getHttproute = (ns, name) =>
  fetchJson(
    `/api/v1/routing/routes/httproute/${encodeURIComponent(ns)}/${encodeURIComponent(name)}`,
  );
export const getIngressRoute = (ns, name) =>
  fetchJson(
    `/api/v1/routing/routes/ingress/${encodeURIComponent(ns)}/${encodeURIComponent(name)}`,
  );

// ── Manifests ─────────────────────────────────────────────────────────────────

export const getManifest = (kind, ns, name) =>
  fetchJson(
    `/api/v1/manifests/${encodeURIComponent(kind)}/${encodeURIComponent(ns)}/${encodeURIComponent(name)}`,
  );

// ── Health (also carries coxswain version + kubernetes_version + leader) ───────

export const getHealth = () => fetchJson('/api/v1/health');

// ── Pod logs ──────────────────────────────────────────────────────────────────

/**
 * Build the URL for the pod-log relay (`/api/v1/pods/{pod}/logs`). Returns a URL
 * string rather than a parsed JSON response — the body is a long-lived chunked
 * NDJSON stream consumed by `useLogStream`, not a one-shot fetch. The endpoint
 * is generic over component: any pod the controller's fleet tracks resolves by
 * name (namespace is resolved server-side from the fleet, never the URL).
 *
 * @param {string} pod                  pod name
 * @param {{tail?: number, follow?: boolean}} [opts]
 */
export function logStreamUrl(pod, { tail = 1000, follow = true } = {}) {
  const q = new URLSearchParams({ tail: String(tail), follow: String(follow) });
  return `/api/v1/pods/${encodeURIComponent(pod)}/logs?${q}`;
}
