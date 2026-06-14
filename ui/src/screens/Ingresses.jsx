import { matchesSearch } from '../hooks/useSearch.js';
import { nav } from '../router.js';
import { DataTable, SeverityDot } from '../components/DataTable.jsx';

/**
 * Ingresses section — a table of all Ingress resources the controller knows
 * about, each row linking to the Route Detail (per-proxy compilation view).
 * Presentational: the owning Routing screen supplies the filters (see
 * GatewaysSection).
 */
export function IngressesSection({ rows = [], total, loading = false, error = null, q = '', ns = 'all' }) {
  const shown = rows.filter(
    (ing) => (ns === 'all' || ing.namespace === ns) && matchesSearch(ing.name, 'ingress', q),
  );
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
          <td><SeverityDot status={ing.status} /></td>
        </tr>
      )}
    />
  );
}
