import { matchesSearch } from '../hooks/useSearch.js';
import { nav } from '../router.js';
import { DataTable, SeverityDot } from '../components/DataTable.jsx';
import { worseSeverity, routeKey } from '../severity.js';

/**
 * Ingresses section — a table of all Ingress resources the controller knows
 * about, each row linking to the Route Detail (per-proxy compilation view).
 * Presentational: the owning Routing screen supplies the filters (see
 * GatewaysSection).
 */
export function IngressesSection({ rows = [], total, loading = false, error = null, q = '', ns = 'all', problemKeys }) {
  const shown = rows.filter(
    (ing) => (ns === 'all' || ing.namespace === ns) && matchesSearch(ing.name, 'ingress', q),
  );
  // Overlay /problems (conflicts/dead-routes) onto the reflector-computed status.
  const rowStatus = (ing) =>
    worseSeverity(ing.status, problemKeys?.has(routeKey('Ingress', ing.namespace, ing.name)) ? 'warn' : 'ok');
  return (
    <DataTable
      columns={['Name', 'Namespace', 'Rules', 'Status']}
      rows={shown}
      total={total}
      loading={loading}
      error={error}
      emptyMsg="No Ingresses."
      renderRow={(ing) => (
        <tr
          key={`${ing.namespace}/${ing.name}`}
          class="clickable"
          onClick={() => nav.ingressRoute(ing.namespace, ing.name)}
        >
          <td>{ing.name}</td>
          <td>{ing.namespace}</td>
          <td>{ing.route_count ?? 0}</td>
          <td><SeverityDot status={rowStatus(ing)} /></td>
        </tr>
      )}
    />
  );
}
