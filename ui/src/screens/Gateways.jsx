import { matchesSearch } from '../hooks/useSearch.js';
import { nav } from '../router.js';
import { poolBadge } from '../components/Badge.jsx';
import { DataTable } from '../components/DataTable.jsx';
import { sevClass, sevTitle } from '../severity.js';

/**
 * Gateways section — a table of all Gateways the controller knows about, each
 * row linking to the Gateway detail. Presentational: the owning Routing screen
 * fetches the active tab's list (and the routing summary that drives the tab
 * badge) and supplies the namespace/search filters; `total` is the cluster-wide
 * count so the footer can show how many are hidden.
 *
 * The `Routes` cell deep-links to the HTTPRoutes tab pre-filtered to this
 * Gateway (`?tab=httproutes&parent=ns/name`) — the inverse of the HTTPRoutes
 * `Parents` links — so an operator can pivot between a Gateway and the routes
 * attached to it without losing the binding context.
 */
export function GatewaysSection({ rows = [], total, page, hidePager = false, loading = false, error = null, q = '', ns = 'all', problemsOnly = false }) {
  const shown = rows.filter(
    (gw) =>
      (ns === 'all' || gw.namespace === ns) &&
      (!problemsOnly || gw.status !== 'ok') &&
      matchesSearch(gw.name, 'gateway', q),
  );
  return (
    <DataTable
      columns={['Name', 'Namespace', 'Pool', 'Address', 'Routes']}
      rows={shown}
      total={total}
      page={page}
      hidePager={hidePager}
      loading={loading}
      error={error}
      emptyMsg="No Gateways."
      renderRow={(gw) => (
        <tr
          key={`${gw.namespace}/${gw.name}`}
          class={`clickable ${sevClass(gw.status)}`}
          title={sevTitle(gw.status)}
          onClick={() => nav.gateway(gw.namespace, gw.name)}
        >
          <td>{gw.name}</td>
          <td>{gw.namespace}</td>
          <td>{poolBadge(gw.proxy?.pool ?? 'shared')}</td>
          <td>{(gw.addresses ?? []).join(', ') || '—'}</td>
          <td>
            {(gw.route_count ?? 0) > 0 ? (
              <span
                class="link-text"
                title={`Show HTTPRoutes attached to ${gw.namespace}/${gw.name}`}
                onClick={(e) => {
                  e.stopPropagation();
                  nav.routing({ tab: 'httproutes', parent: `${gw.namespace}/${gw.name}` });
                }}
              >
                {gw.route_count} →
              </span>
            ) : (
              0
            )}
          </td>
        </tr>
      )}
    />
  );
}
