import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getHttproute, getIngressRoute } from '../api/endpoints.js';
import { extractRows, extractConflicts } from '../api/routeMatch.js';
import { nav } from '../router.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { Badge } from '../components/Badge.jsx';
import { ConditionRow } from '../components/ConditionRow.jsx';
import { EndpointHealth } from '../components/EndpointHealth.jsx';
import { Spinner, ErrorState, EmptyState } from '../components/Spinner.jsx';
import { Panel } from '../components/Panel.jsx';
import { ManifestDialog } from '../components/ManifestDialog.jsx';
import { Icon } from '../components/Icon.jsx';
import { useEffect, useState } from 'preact/hooks';

/**
 * Route Detail — the centrepiece route screen (per-proxy compilation view).
 *
 * For HTTPRoutes: shows parent status conditions + per-proxy per-host route
 * table with endpoint health and conflict flags.
 *
 * For Ingress: no conditions panel (Kubernetes Ingress carries none); shows
 * only the per-proxy route table.
 *
 * Refreshes on `rebuild.completed` SSE so the operator can watch a route
 * converge in real time after applying a change.
 *
 * Deep-linkable via `#/routes/httproute/{ns}/{name}` or
 * `#/routes/ingress/{ns}/{name}`.
 */
export function RouteDetail({ kind, namespace, name }) {
  const isHttp = kind === 'httproute';
  const fetcher = isHttp
    ? () => getHttproute(namespace, name)
    : () => getIngressRoute(namespace, name);

  const { data, loading, error, refetch } = useApi(fetcher, [kind, namespace, name]);
  const sse = useSSE('/api/v1/events');
  const [showManifest, setShowManifest] = useState(false);

  useEffect(() => {
    return sse.subscribe('rebuild.completed', () => refetch());
  }, [sse.subscribe, refetch]);

  // Type-canonical breadcrumb: a route's home is always Routing, regardless of
  // how it was reached (proxy verification table, gateway attached-routes, or a
  // cold deep link). Flat for every route type — an HTTPRoute can attach to
  // multiple Gateways, so its parent(s) live in the parent-status panel, not the
  // trail. Cross-axis origin (e.g. the proxy you drilled from) is the Back
  // button's job, not the breadcrumb's.
  const breadcrumb = [
    { label: 'Routing', onClick: () => nav.routing() },
    isHttp
      ? { label: 'HTTP Routes', onClick: () => nav.routing({ tab: 'httproutes' }) }
      : { label: 'Ingresses', onClick: () => nav.routing({ tab: 'ingresses' }) },
    { label: `${namespace}/${name}` },
  ];

  if (loading) return <Spinner label={`Loading ${kind}…`} />;
  if (error)   return <ErrorState error={error} />;
  if (!data)   return <EmptyState message="Route not found." />;

  const proxies    = data.proxies ?? [];
  const parentStatuses = data.parent_statuses ?? [];  // HTTPRoute only

  return (
    <div class="screen">
      <Breadcrumb items={breadcrumb} />

      <div class="screen-header">
        <div>
          <h1 class="screen-title">{name}</h1>
          <div class="screen-meta">{namespace} · {isHttp ? 'HTTPRoute' : 'Ingress'}</div>
        </div>
        <div class="header-badges">
          <button class="btn btn-icon" onClick={() => setShowManifest(true)}>
            <Icon name="code" size={15} /> Manifest
          </button>
        </div>
      </div>

      {showManifest && (
        <ManifestDialog
          kind={kind === 'httproute' ? 'httproute' : 'ingress'}
          namespace={namespace}
          name={name}
          onClose={() => setShowManifest(false)}
        />
      )}

      {/* Parent Status Conditions — HTTPRoute only */}
      {isHttp && parentStatuses.length > 0 && (
        <section aria-label="Parent status conditions">
          <h2 class="section-title">Gateway conditions</h2>
          {parentStatuses.map((ps) => {
            const gw = ps.parent_ref
              ? `${ps.parent_ref.namespace ?? namespace}/${ps.parent_ref.name}`
              : '—';
            return (
              <div key={gw} class="parent-status">
                <div class="parent-label">
                  <Badge variant="neutral">Gateway</Badge>
                  <span
                    class="link-text"
                    onClick={() =>
                      nav.gateway(ps.parent_ref?.namespace ?? namespace, ps.parent_ref?.name ?? '')
                    }
                  >
                    {gw}
                  </span>
                </div>
                <div class="tbl-wrap">
                  <table class="cond-table">
                    <thead>
                      <tr>
                        <th>Condition</th>
                        <th>Reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(ps.conditions ?? []).map((c) => (
                        <ConditionRow key={c.type} condition={c} />
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            );
          })}
        </section>
      )}

      {/* Per-proxy breakdown */}
      <section aria-label="Per-proxy route breakdown">
        <h2 class="section-title">Proxy breakdown</h2>
        {proxies.length === 0 && <EmptyState message="No proxy data available." />}
        {proxies.map((proxy) => (
          <ProxyRoutePanel
            key={proxy.pod_name}
            proxy={proxy}
            routeKind={isHttp ? 'gateway' : 'ingress'}
            namespace={namespace}
            name={name}
          />
        ))}
      </section>
    </div>
  );
}

function ProxyRoutePanel({ proxy, routeKind, namespace, name }) {
  const reachable = proxy.reachable ?? false;
  if (!reachable) {
    return (
      <Panel title={proxy.pod_name}>
        <Badge variant="fail">unreachable</Badge>
      </Panel>
    );
  }

  const routes     = proxy.routes;           // may be null if pod didn't respond
  const spec       = routes?.[routeKind];   // { hosts, conflicts }

  const rows      = spec ? extractRows(routes, routeKind, namespace, name) : [];
  const conflicts = spec ? extractConflicts(routes, routeKind, namespace, name) : [];

  return (
    <Panel title={
      <span class="panel-title-row">
        <span
          class="link-text"
          onClick={() => nav.proxy(proxy.pod_name)}
        >
          {proxy.pod_name}
        </span>
        {!reachable && <Badge variant="fail">unreachable</Badge>}
      </span>
    }>
      {rows.length === 0 && spec !== null && (
        <div style="color:var(--muted);font-size:13px;padding:8px 0">
          Route not present in this proxy's routing table.
        </div>
      )}
      {rows.length === 0 && spec === null && (
        <div style="color:var(--muted);font-size:13px;padding:8px 0">
          No route data (proxy did not respond or routes not yet synced).
        </div>
      )}
      {rows.length > 0 && (
        <div class="tbl-wrap">
          <table>
            <thead>
              <tr>
                <th>Host</th>
                <th>Port</th>
                <th>Path</th>
                <th>Type</th>
                <th>Backend</th>
                <th>Endpoints</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <RouteRow key={i} row={r} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {conflicts.length > 0 && (
        <div class="conflict-list" aria-label="Routing conflicts">
          {conflicts.map((c, i) => (
            <div key={i} class="conflict-item">
              <Badge variant="conflict">conflict</Badge>
              {c.host}{c.path} — <code>{c.rejected_group}</code> rejected
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function RouteRow({ row }) {
  return (
    <tr>
      <td><code>{row.host}</code></td>
      <td>{row.port}</td>
      <td><code>{row.path || '/'}</code></td>
      <td><Badge variant="neutral">{row.type}</Badge></td>
      <td><code>{row.backend_group}</code></td>
      <td><EndpointHealth endpoints={row.endpoints ?? []} /></td>
    </tr>
  );
}
