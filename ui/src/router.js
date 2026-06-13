import { useState, useEffect } from 'preact/hooks';

/**
 * Parse location.hash into a { screen, params } object.
 *
 * Hash format:
 *   #/fleet
 *   #/proxies/<pod>
 *   #/routes/httproute/<ns>/<name>
 *   #/routes/ingress/<ns>/<name>
 *   #/gateways/<ns>/<name>
 *   #/health
 *   #/events
 *   #/problems
 */
function parseHash(hash) {
  const path = hash.replace(/^#\//, '').replace(/^#/, '');
  if (!path) return { screen: 'fleet', params: {} };

  const parts = path.split('/');
  const [s0, s1, s2, s3, s4] = parts;

  if (s0 === 'proxies' && s1) return { screen: 'proxy-detail', params: { pod: s1 } };
  if (s0 === 'routes' && s1 === 'httproute' && s2 && s3)
    return { screen: 'route-inspector', params: { kind: 'httproute', ns: s2, name: s3 } };
  if (s0 === 'routes' && s1 === 'ingress' && s2 && s3)
    return { screen: 'route-inspector', params: { kind: 'ingress', ns: s2, name: s3 } };
  if (s0 === 'gateways' && s1 && s2)
    return { screen: 'gateway-detail', params: { ns: s1, name: s2 } };
  if (s0 === 'health') return { screen: 'health', params: {} };
  if (s0 === 'events') return { screen: 'events', params: {} };
  if (s0 === 'problems') return { screen: 'problems', params: {} };

  return { screen: 'fleet', params: {} };
}

/** Derive the nav-link key for a screen, used to highlight the active tab. */
export function navKeyFor(screen) {
  switch (screen) {
    case 'proxy-detail':
    case 'route-inspector':
    case 'problems':
      return 'fleet';
    case 'gateway-detail':
      return 'gateways';
    default:
      return screen;
  }
}

/** Custom hook: returns { screen, params } and updates on hash changes. */
export function useHashRoute() {
  const [route, setRoute] = useState(() => parseHash(location.hash));

  useEffect(() => {
    const onHashChange = () => setRoute(parseHash(location.hash));
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  return route;
}

/** Programmatic navigation helpers. */
export const nav = {
  fleet: () => { location.hash = '#/fleet'; },
  proxy: (pod) => { location.hash = `#/proxies/${pod}`; },
  httproute: (ns, name) => { location.hash = `#/routes/httproute/${ns}/${name}`; },
  ingressRoute: (ns, name) => { location.hash = `#/routes/ingress/${ns}/${name}`; },
  gateway: (ns, name) => { location.hash = `#/gateways/${ns}/${name}`; },
  health: () => { location.hash = '#/health'; },
  events: () => { location.hash = '#/events'; },
  problems: () => { location.hash = '#/problems'; },
};
