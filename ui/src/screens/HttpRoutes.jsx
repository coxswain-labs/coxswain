import { matchesSearch } from '../hooks/useSearch.js';
import { nav } from '../router.js';
import { DataTable, SeverityDot } from '../components/DataTable.jsx';
import { worseSeverity, routeKey } from '../severity.js';

/**
 * HTTPRoutes section — a table of all HTTPRoutes in the controller's route store
 * (#293), each row linking to the Route Detail. First-class peer of Gateways and
 * Ingresses on the routing root. The `Parents` column names the Gateway(s) the
 * route attaches to (where a parent-caused degradation originates); deep-linking
 * each parent to its Gateway is deferred to a follow-up. Presentational: the
 * owning Routing screen supplies the filters (see GatewaysSection).
 */
export function HttpRoutesSection({ rows = [], total, loading = false, error = null, q = '', ns = 'all', problemKeys }) {
  const shown = rows.filter(
    (r) => (ns === 'all' || r.namespace === ns) && matchesSearch(r.name, 'httproute', q),
  );
  // Overlay /problems (conflicts/dead-routes) onto the reflector-computed status,
  // so dedicated-gateway routes (absent from the controller's table) still flag.
  const rowStatus = (r) =>
    worseSeverity(r.status, problemKeys?.has(routeKey('HTTPRoute', r.namespace, r.name)) ? 'warn' : 'ok');
  return (
    <DataTable
      columns={['Name', 'Namespace', 'Parents', 'Rules', 'Status']}
      rows={shown}
      total={total}
      loading={loading}
      error={error}
      emptyMsg="No HTTPRoutes."
      renderRow={(r) => (
        <tr
          key={`${r.namespace}/${r.name}`}
          class="clickable"
          onClick={() => nav.httproute(r.namespace, r.name)}
        >
          <td>{r.name}</td>
          <td>{r.namespace}</td>
          <td>{(r.parent_gateways ?? []).join(', ') || '—'}</td>
          <td>{r.rule_count ?? 0}</td>
          <td><SeverityDot status={rowStatus(r)} /></td>
        </tr>
      )}
    />
  );
}
