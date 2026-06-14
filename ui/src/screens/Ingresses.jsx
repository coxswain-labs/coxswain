import { matchesSearch } from '../hooks/useSearch.js';
import { nav } from '../router.js';
import { DataTable } from '../components/DataTable.jsx';
import { worseSeverity, routeKey, sevClass, sevTitle } from '../severity.js';

/**
 * Ingresses section — a table of all Ingress resources the controller knows
 * about, each row linking to the Route Detail (per-proxy compilation view).
 * Presentational: the owning Routing screen supplies the filters (see
 * GatewaysSection).
 */
export function IngressesSection({ rows = [], total, page, loading = false, error = null, q = '', ns = 'all', problemsOnly = false, problemKeys }) {
  // Overlay /problems (conflicts/dead-routes) onto the reflector-computed status.
  const rowStatus = (ing) =>
    worseSeverity(ing.status, problemKeys?.has(routeKey('Ingress', ing.namespace, ing.name)) ? 'warn' : 'ok');
  const shown = rows.filter(
    (ing) =>
      (ns === 'all' || ing.namespace === ns) &&
      (!problemsOnly || rowStatus(ing) !== 'ok') &&
      matchesSearch(ing.name, 'ingress', q),
  );
  return (
    <DataTable
      columns={['Name', 'Namespace', 'Class', 'Address', 'Rules']}
      rows={shown}
      total={total}
      page={page}
      loading={loading}
      error={error}
      emptyMsg="No Ingresses."
      renderRow={(ing) => (
        <tr
          key={`${ing.namespace}/${ing.name}`}
          class={`clickable ${sevClass(rowStatus(ing))}`}
          title={sevTitle(rowStatus(ing))}
          onClick={() => nav.ingressRoute(ing.namespace, ing.name)}
        >
          <td>{ing.name}</td>
          <td>{ing.namespace}</td>
          <td>{ing.ingress_class || '—'}</td>
          <td>{ing.load_balancer || '—'}</td>
          <td>{ing.route_count ?? 0}</td>
        </tr>
      )}
    />
  );
}
