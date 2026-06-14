/**
 * Route-matching helpers for the Route Inspector.
 *
 * A proxy's `/routes` response contains the entire routing table; the
 * inspector must client-filter to entries that pertain to a specific route
 * object (HTTPRoute or Ingress) identified by namespace/name.
 *
 * The server does not carry the K8s object name on each table row — it only
 * knows the host/path/backend.  The inspector therefore fans out to collect
 * the proxy views that include _any_ row for the route's host(s), and annotates
 * each row with endpoint health.
 *
 * Strategy: collect all rows whose `backend_group` matches the HTTPRoute's
 * parent_statuses resolved set, falling back to displaying all rows from the
 * per-pod routes dump (because the inspector already knows which route is active
 * from the conditions panel).
 */

/**
 * Extract matching host/path rows from a single proxy's routes dump.
 *
 * @param {Object} routes - The `routes` field from a per-proxy routes response.
 * @param {string} spec - "ingress" | "gateway"
 * @returns {Array<{port, host, path, backend_group, endpoints, dead}>}
 */
export function extractRows(routes, spec = 'gateway') {
  const result = [];
  for (const hostEntry of routes?.[spec]?.hosts ?? []) {
    for (const row of hostEntry.routes ?? []) {
      result.push({
        port: hostEntry.port,
        host: hostEntry.host,
        path: row.path,
        type: row.type,
        backend_group: row.backend_group,
        endpoints: row.endpoints ?? [],
        dead: (row.endpoints ?? []).length === 0,
      });
    }
  }
  return result;
}

/**
 * Extract conflict rows from a single proxy's routes dump.
 *
 * @param {Object} routes - The `routes` field.
 * @param {string} spec - "ingress" | "gateway"
 * @returns {Array<{port, host, path, rejected_group}>}
 */
export function extractConflicts(routes, spec = 'gateway') {
  return (routes?.[spec]?.conflicts ?? []).map((c) => ({
    port: c.port,
    host: c.host,
    path: c.path,
    rejected_group: c.rejected_group,
  }));
}
