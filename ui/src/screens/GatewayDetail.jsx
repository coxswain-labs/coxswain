import { useState } from 'preact/hooks';
import { useApi } from '../hooks/useApi.js';
import { getGateway } from '../api/endpoints.js';
import { nav } from '../router.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { Badge, poolBadge } from '../components/Badge.jsx';
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
 * - Attached HTTPRoutes (links to Route Inspector).
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
  const [showManifest, setShowManifest] = useState(false);

  const breadcrumb = [
    { label: 'Routing', onClick: () => nav.routing({ filter: 'gateways' }) },
    { label: `${namespace}/${name}` },
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
  } = data;

  const pool = proxy?.pool ?? 'shared';

  return (
    <div class="screen">
      <Breadcrumb items={breadcrumb} />

      <div class="screen-header">
        <div>
          <h1 class="screen-title">{name}</h1>
          <div class="screen-meta">{namespace}</div>
        </div>
        <div class="header-badges">
          {poolBadge(pool)}
          {addresses.length > 0 && (
            <span class="addr-label" title="Load-balancer addresses">
              {addresses.join(', ')}
            </span>
          )}
          <button class="btn btn-icon" onClick={() => setShowManifest(true)}>
            <Icon name="code" size={15} /> Manifest
          </button>
        </div>
      </div>

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
          <div class="cond-list">
            {conditions.map((c) => (
              <ConditionRow key={c.type} condition={c} />
            ))}
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
          <div class="attached-routes">
            {attached_routes_list.map((r) => (
              <div
                key={`${r.namespace}/${r.name}`}
                class="attached-route-row clickable"
                onClick={() =>
                  r.kind === 'HTTPRoute'
                    ? nav.httproute(r.namespace, r.name)
                    : nav.ingressRoute(r.namespace, r.name)
                }
              >
                <Badge variant="neutral">{r.kind}</Badge>
                <span>
                  <span class="ns-label">{r.namespace}/</span>
                  <strong>{r.name}</strong>
                </span>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
