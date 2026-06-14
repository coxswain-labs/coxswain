/**
 * Severity helpers shared by the routing screens.
 *
 * The reflector-computed per-resource `status` (ok/warn/error) covers the
 * binding/condition dimensions (Gateway programmed, route accepted/resolved,
 * dedicated-proxy ready). It does NOT cover routing-table conflicts/dead-routes
 * for *dedicated/cut-over* gateways — the controller drops those from its table,
 * so only the cross-proxy `/api/v1/problems` aggregate has the full picture.
 *
 * The UI therefore overlays `/problems` membership onto the reflector status:
 * `worseSeverity(row.status, inProblems ? 'warn' : 'ok')`. This is a cheap
 * lookup against data the screens already fetch — not a re-derivation of
 * severity — and it makes the per-row/tab/tile indicators agree with the
 * Problems panel for both shared and dedicated routes.
 */

const RANK = { ok: 0, warn: 1, error: 2 };

/** Return the worse (higher-ranked) of two severities; unknowns count as `ok`. */
export function worseSeverity(a, b) {
  return (RANK[a] ?? 0) >= (RANK[b] ?? 0) ? a ?? 'ok' : b ?? 'ok';
}

/**
 * Build a `Set` of `"kind/namespace/name"` keys for every route flagged in the
 * `/problems` routing aggregate (conflicts + dead routes). `kind` is the route's
 * own kind from its `route` ref (`HTTPRoute` | `Ingress`).
 */
export function problemRouteKeys(problems) {
  const routing = problems?.routing ?? {};
  const keys = new Set();
  for (const list of [routing.conflicts ?? [], routing.dead_routes ?? []]) {
    for (const p of list) {
      const r = p.route;
      if (r?.kind && r?.namespace && r?.name) keys.add(`${r.kind}/${r.namespace}/${r.name}`);
    }
  }
  return keys;
}

/** Key for a single resource, matching [`problemRouteKeys`]. */
export function routeKey(kind, namespace, name) {
  return `${kind}/${namespace}/${name}`;
}

/** Table-row class for a severity — a coloured left edge (no class for `ok`),
 *  the flag-problems vocabulary shared with the Dashboard tiles. */
export function sevClass(status) {
  return status === 'error' ? 'sev-error' : status === 'warn' ? 'sev-warn' : '';
}

/** Hover/title text for a non-`ok` severity (a11y affordance for the colour). */
export function sevTitle(status) {
  return status === 'error' ? 'Not serving traffic' : status === 'warn' ? 'Degraded' : undefined;
}

/** True when any `/problems` routing entry is attributed to a resource of `kind`. */
export function categoryHasProblem(problems, kind) {
  const routing = problems?.routing ?? {};
  return [...(routing.conflicts ?? []), ...(routing.dead_routes ?? [])].some(
    (p) => p.route?.kind === kind,
  );
}
