import { matchesSearch } from '../hooks/useSearch.js';
import { nav } from '../router.js';
import { poolBadge } from '../components/Badge.jsx';
import { DataTable, SeverityDot } from '../components/DataTable.jsx';

/**
 * Gateways section — a table of all Gateways the controller knows about, each
 * row linking to the Gateway detail. Presentational: the owning Routing screen
 * fetches the active tab's list (and the routing summary that drives the tab
 * badge) and supplies the namespace/search filters; `total` is the cluster-wide
 * count so the footer can show how many are hidden.
 */
export function GatewaysSection({ rows = [], total, loading = false, error = null, q = '', ns = 'all' }) {
  const shown = rows.filter(
    (gw) => (ns === 'all' || gw.namespace === ns) && matchesSearch(gw.name, 'gateway', q),
  );
  return (
    <DataTable
      columns={['Name', 'Namespace', 'Pool', 'Routes', 'Status']}
      rows={shown}
      total={total}
      loading={loading}
      error={error}
      emptyMsg="No Gateways."
      renderRow={(gw) => (
        <tr
          key={`${gw.namespace}/${gw.name}`}
          class="clickable"
          onClick={() => nav.gateway(gw.namespace, gw.name)}
        >
          <td>{gw.name}</td>
          <td>{gw.namespace}</td>
          <td>{poolBadge(gw.proxy?.pool ?? 'shared')}</td>
          <td>{gw.route_count ?? 0}</td>
          <td><SeverityDot status={gw.status} /></td>
        </tr>
      )}
    />
  );
}
