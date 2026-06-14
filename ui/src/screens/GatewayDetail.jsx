import { useState } from 'preact/hooks';
import { useApi } from '../hooks/useApi.js';
import { getGateway, getProblems } from '../api/endpoints.js';
import { nav } from '../router.js';
import { worseSeverity, problemRouteKeys, routeKey, sevClass, sevTitle } from '../severity.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { poolBadge } from '../components/Badge.jsx';
import { DetailHeader } from '../components/DetailHeader.jsx';
import { StatusBadge } from '../components/StatusBadge.jsx';
import { ConditionRow } from '../components/ConditionRow.jsx';
import { ListenerRow } from '../components/ListenerRow.jsx';
import { ManifestDialog } from '../components/ManifestDialog.jsx';
import { Icon } from '../components/Icon.jsx';
import { Spinner, ErrorState, EmptyState } from '../components/Spinner.jsx';

/**
 * Gateway detail screen.
 *
 * Displays:
 * - Listener table (name / port / protocol / TLS / attached routes).
 *   Listeners with 0 attached routes are highlighted — the Gateway is
 *   accepted but nothing routes through that listener.
 * - Status conditions.
 * - Attached routes (link to the route detail screen).
 * - Proxy pool badge + addresses.
 *
 * The endpoint was expanded (in aggregator.rs) to include `listeners[]`
 * and `attached_routes_list[]` — without that data the screen couldn't
 * be built.
 */
export function GatewayDetail({ namespace, name }) {
  const { data, loading, error } = useApi(
    () => getGateway(namespace, name),
    [namespace, name],
  );
  // Overlay the cross-proxy /problems aggregate so dead/conflict routes on this
  // Gateway light up even when the controller's table dropped them (cut-over
  // dedicated gateways) — same overlay the routing tables use.
  const problems = useApi(getProblems);
  const problemKeys = problemRouteKeys(problems.data);
  const [showManifest, setShowManifest] = useState(false);

  const breadcrumb = [
    { label: 'Routing', onClick: () => nav.routing() },
    { label: 'Gateways', onClick: () => nav.routing({ tab: 'gateways' }) },
    { label: name },
  ];

  if (loading) return <Spinner label="Loading gateway…" />;
  if (error)   return <ErrorState error={error} />;
  if (!data)   return <EmptyState message="Gateway not found." />;

  const {
    listeners = [],
    conditions = [],
    attached_routes_list = [],
    proxy,
    addresses = [],
    route_count,
    status,
  } = data;

  const pool = proxy?.pool ?? 'shared';

  return (
    <div class="screen">
      <Breadcrumb items={breadcrumb} />

      <DetailHeader
        name={name}
        namespace={namespace}
        copyLabel="Copy gateway name"
        meta={addresses.length > 0 && (
          <div class="problem-card-meta" title="Load-balancer addresses">
            Address: <code>{addresses.join(', ')}</code>
          </div>
        )}
        badges={(
          <>
            <StatusBadge status={status} />
            {poolBadge(pool)}
          </>
        )}
        actions={(
          <button class="btn btn-icon" onClick={() => setShowManifest(true)}>
            <Icon name="code" size={15} /> Manifest
          </button>
        )}
      />

      {showManifest && (
        <ManifestDialog
          kind="gateway"
          namespace={namespace}
          name={name}
          onClose={() => setShowManifest(false)}
        />
      )}

      {/* Listeners */}
      <section aria-label="Listeners">
        <h2 class="section-title">Listeners</h2>
        {listeners.length === 0 ? (
          <EmptyState message="No listeners found." />
        ) : (
          <div class="tbl-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Port</th>
                  <th>Protocol</th>
                  <th>TLS</th>
                  <th>Attached routes</th>
                </tr>
              </thead>
              <tbody>
                {listeners.map((l) => (
                  <ListenerRow key={l.name} listener={l} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Status conditions */}
      {conditions.length > 0 && (
        <section aria-label="Status conditions">
          <h2 class="section-title">Conditions</h2>
          <div class="tbl-wrap">
            <table class="cond-table">
              <thead>
                <tr>
                  <th>Condition</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {conditions.map((c) => (
                  <ConditionRow key={c.type} condition={c} />
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Attached routes */}
      {attached_routes_list.length > 0 && (
        <section aria-label="Attached routes">
          <h2 class="section-title">
            Attached routes
            <span class="section-count">{route_count ?? attached_routes_list.length}</span>
          </h2>
          <div class="tbl-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Namespace</th>
                  <th>Hostnames</th>
                  <th>Rules</th>
                </tr>
              </thead>
              <tbody>
                {attached_routes_list.map((r) => {
                  const status = worseSeverity(
                    r.status,
                    problemKeys.has(routeKey(r.kind, r.namespace, r.name)) ? 'warn' : 'ok',
                  );
                  return (
                    <tr
                      key={`${r.namespace}/${r.name}`}
                      class={`clickable ${sevClass(status)}`}
                      title={sevTitle(status)}
                      onClick={() =>
                        r.kind === 'HTTPRoute'
                          ? nav.httproute(r.namespace, r.name)
                          : nav.ingressRoute(r.namespace, r.name)
                      }
                    >
                      <td>{r.name}</td>
                      <td>{r.namespace}</td>
                      <td>{(r.hostnames ?? []).join(', ') || '—'}</td>
                      <td>{r.rule_count ?? 0}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
