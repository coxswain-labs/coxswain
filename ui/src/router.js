import { useState, useEffect } from 'preact/hooks';

/**
 * Parse location.hash into a { screen, params, query } object.
 *
 * Hash format — path optionally followed by a `?` view-state query string:
 *   #/dashboard
 *   #/fleet
 *   #/routing                     #/routing?filter=gateways
 *   #/proxies/<pod>               #/proxies/<pod>?tab=gateway
 *   #/routes/httproute/<ns>/<name>
 *   #/routes/ingress/<ns>/<name>
 *   #/gateways/<ns>/<name>
 *   #/health  #/events  #/problems
 *
 * The path selects the screen (a shareable deep link on its own); the query
 * carries permalinkable view-state (filters, tabs, expansion) so a copied URL
 * reproduces the exact view. Retired list hashes (#/gateways, #/ingresses with
 * no resource segments) fold into the unified Routing screen.
 */
function parseHash(hash) {
  const raw = hash.replace(/^#\/?/, '');
  const [pathPart, queryPart = ''] = raw.split('?');
  const query = Object.fromEntries(new URLSearchParams(queryPart));

  if (!pathPart) return { screen: 'dashboard', params: {}, query };

  const parts = pathPart.split('/');
  const [s0, s1, s2, s3] = parts;

  if (s0 === 'dashboard') return { screen: 'dashboard', params: {}, query };
  if (s0 === 'fleet')     return { screen: 'fleet', params: {}, query };
  if (s0 === 'routing')   return { screen: 'routing', params: {}, query };

  if (s0 === 'proxies' && s1) return { screen: 'proxy-detail', params: { pod: s1 }, query };
  if (s0 === 'controllers' && s1) return { screen: 'controller-detail', params: { pod: s1 }, query };
  if (s0 === 'routes' && s1 === 'httproute' && s2 && s3)
    return { screen: 'route-inspector', params: { kind: 'httproute', ns: s2, name: s3 }, query };
  if (s0 === 'routes' && s1 === 'ingress' && s2 && s3)
    return { screen: 'route-inspector', params: { kind: 'ingress', ns: s2, name: s3 }, query };
  if (s0 === 'gateways' && s1 && s2)
    return { screen: 'gateway-detail', params: { ns: s1, name: s2 }, query };

  // Retired flat list pages — redirect to the unified Routing surface.
  if (s0 === 'gateways' || s0 === 'ingresses') return { screen: 'routing', params: {}, query };

  if (s0 === 'events')   return { screen: 'events', params: {}, query };
  // Health page retired (its job split between Fleet per-pod chips and the
  // Dashboard degraded-pod triage) and Problems merged into the Dashboard —
  // keep both old hashes working.
  if (s0 === 'health' || s0 === 'problems') return { screen: 'dashboard', params: {}, query };

  return { screen: 'dashboard', params: {}, query };
}

/** Derive the nav-link key for a screen, used to highlight the active tab. */
export function navKeyFor(screen) {
  switch (screen) {
    case 'proxy-detail':
    case 'controller-detail':
      return 'fleet';
    case 'route-inspector':
    case 'gateway-detail':
      return 'routing';
    default:
      return screen;
  }
}

/** Custom hook: returns { screen, params, query } and updates on hash changes. */
export function useHashRoute() {
  const [route, setRoute] = useState(() => parseHash(location.hash));

  useEffect(() => {
    const onHashChange = () => setRoute(parseHash(location.hash));
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  return route;
}

/**
 * Merge `updates` into the current hash's query string, preserving the path so
 * the screen stays put. A `null`/`undefined`/empty value deletes the key
 * (keeps default views on a clean URL). This is how screens make their
 * view-state — filters, tabs, expansion — permalinkable.
 */
export function updateQuery(updates) {
  const raw = location.hash.replace(/^#\/?/, '');
  const [pathPart, queryPart = ''] = raw.split('?');
  const params = new URLSearchParams(queryPart);
  for (const [k, v] of Object.entries(updates)) {
    if (v == null || v === '') params.delete(k);
    else params.set(k, v);
  }
  const qs = params.toString();
  location.hash = `#/${pathPart}${qs ? `?${qs}` : ''}`;
}

/** Build a `#/path?query` hash string. */
function hashFor(path, query) {
  const qs = query ? new URLSearchParams(query).toString() : '';
  return `#/${path}${qs ? `?${qs}` : ''}`;
}

/**
 * Like {@link updateQuery}, but replaces the history entry instead of pushing a
 * new one. For high-frequency view-state (a search box updating per keystroke)
 * pushing would bury the back button under one entry per character. The URL
 * still reflects the state — so it stays shareable — it just doesn't accrete
 * history. Screens using this must drive their own rendering from local state,
 * since `replaceState` does not fire `hashchange`.
 */
export function replaceQuery(updates) {
  const raw = location.hash.replace(/^#\/?/, '');
  const [pathPart, queryPart = ''] = raw.split('?');
  const params = new URLSearchParams(queryPart);
  for (const [k, v] of Object.entries(updates)) {
    if (v == null || v === '') params.delete(k);
    else params.set(k, v);
  }
  const qs = params.toString();
  history.replaceState(null, '', `#/${pathPart}${qs ? `?${qs}` : ''}`);
}

/** Programmatic navigation helpers. Pass `query` to deep-link into view-state. */
export const nav = {
  dashboard: () => { location.hash = '#/dashboard'; },
  fleet: (query) => { location.hash = hashFor('fleet', query); },
  routing: (query) => { location.hash = hashFor('routing', query); },
  proxy: (pod, query) => { location.hash = hashFor(`proxies/${pod}`, query); },
  controller: (pod) => { location.hash = `#/controllers/${pod}`; },
  httproute: (ns, name, query) => { location.hash = hashFor(`routes/httproute/${ns}/${name}`, query); },
  ingressRoute: (ns, name, query) => { location.hash = hashFor(`routes/ingress/${ns}/${name}`, query); },
  gateway: (ns, name) => { location.hash = `#/gateways/${ns}/${name}`; },
  events: () => { location.hash = '#/events'; },
};
