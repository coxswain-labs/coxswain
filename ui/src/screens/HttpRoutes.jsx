import { matchesSearch } from '../hooks/useSearch.js';
import { nav } from '../router.js';
import { DataTable } from '../components/DataTable.jsx';
import { worseSeverity, routeKey, sevClass, sevTitle } from '../severity.js';

/**
 * HTTPRoutes section — a table of all HTTPRoutes in the controller's route store
 * (#293), each row linking to the Route Detail. First-class peer of Gateways and
 * Ingresses on the routing root. The `Parents` column names the Gateway(s) the
 * route attaches to (where a parent-caused degradation originates) and deep-links
 * each parent to its Gateway detail — the inverse of the Gateways `Routes` link.
 * When opened via a Gateway's `Routes` link the rows are pre-filtered to that
 * parent (`parent` prop). Presentational: the owning Routing screen supplies the
 * shared namespace/search filters (see GatewaysSection).
 */
export function HttpRoutesSection({ rows = [], total, loading = false, error = null, q = '', ns = 'all', parent = '', problemsOnly = false, problemKeys }) {
  // Overlay /problems (conflicts/dead-routes) onto the reflector-computed status,
  // so dedicated-gateway routes (absent from the controller's table) still flag.
  const rowStatus = (r) =>
    worseSeverity(r.status, problemKeys?.has(routeKey('HTTPRoute', r.namespace, r.name)) ? 'warn' : 'ok');
  const shown = rows.filter(
    (r) =>
      (ns === 'all' || r.namespace === ns) &&
      (!parent || (r.parent_gateways ?? []).includes(parent)) &&
      (!problemsOnly || rowStatus(r) !== 'ok') &&
      matchesSearch(r.name, 'httproute', q),
  );
  return (
    <DataTable
      columns={['Name', 'Namespace', 'Hostnames', 'Parents', 'Rules']}
      rows={shown}
      total={total}
      loading={loading}
      error={error}
      emptyMsg="No HTTPRoutes."
      renderRow={(r) => (
        <tr
          key={`${r.namespace}/${r.name}`}
          class={`clickable ${sevClass(rowStatus(r))}`}
          title={sevTitle(rowStatus(r))}
          onClick={() => nav.httproute(r.namespace, r.name)}
        >
          <td>{r.name}</td>
          <td>{r.namespace}</td>
          <td>{(r.hostnames ?? []).join(', ') || '—'}</td>
          <td>{renderParents(r.parent_gateways)}</td>
          <td>{r.rule_count ?? 0}</td>
        </tr>
      )}
    />
  );
}

/**
 * Render each `ns/name` parent Gateway as a link to its Gateway detail, stacked
 * vertically — a route attached to several Gateways lists them one per line
 * rather than as a hard-to-scan comma run.
 */
function renderParents(parents = []) {
  if (parents.length === 0) return '—';
  return (
    <div class="cell-list">
      {parents.map((p) => {
        const [pns, pname] = p.split('/');
        return (
          <span
            key={p}
            class="link-text"
            title={`Open Gateway ${p}`}
            onClick={(e) => {
              e.stopPropagation();
              if (pns && pname) nav.gateway(pns, pname);
            }}
          >
            {p}
          </span>
        );
      })}
    </div>
  );
}
