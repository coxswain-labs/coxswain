import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getProxy, getProxyRoutes, getProxyHealth } from '../api/endpoints.js';
import { nav } from '../router.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { Badge, poolBadge } from '../components/Badge.jsx';
import { EndpointHealth } from '../components/EndpointHealth.jsx';
import { HealthRow } from '../components/HealthRow.jsx';
import { Tabs } from '../components/Tabs.jsx';
import { Panel } from '../components/Panel.jsx';
import { Spinner, ErrorState, EmptyState } from '../components/Spinner.jsx';
import { useEffect } from 'preact/hooks';

/**
 * Proxy detail screen.
 *
 * Shows pod metadata, subsystem health, and a tabbed route table
 * (Ingress | Gateway API). Routing conflicts are called out inline.
 * Clicking a route row navigates to the Route Inspector.
 */
export function ProxyDetail({ pod }) {
  const meta    = useApi(() => getProxy(pod), [pod]);
  const routes  = useApi(() => getProxyRoutes(pod), [pod]);
  const health  = useApi(() => getProxyHealth(pod), [pod]);
  const sse     = useSSE('/api/v1/events');

  useEffect(() => {
    const off = sse.subscribe('rebuild.completed', () => routes.refetch());
    return off;
  }, [sse.subscribe, routes.refetch]);

  const breadcrumb = [
    { label: 'Fleet', onClick: () => nav.fleet() },
    { label: pod },
  ];

  if (meta.loading) return <Spinner label="Loading proxy…" />;
  if (meta.error)   return <ErrorState error={meta.error} />;
  if (!meta.data)   return <EmptyState message="Proxy not found." />;

  const p = meta.data;
  const isReachable = p.reachable ?? false;
  const pool = p.component === 'dedicated-proxy' ? 'dedicated' : 'shared';

  return (
    <div class="screen">
      <Breadcrumb items={breadcrumb} />

      <div class="screen-header">
        <div>
          <h1 class="screen-title">{pod}</h1>
          <div class="screen-meta">
            {p.pod_ip && <span>{p.pod_ip}</span>}
            {p.gateway_ref && <span> · {p.gateway_ref}</span>}
          </div>
        </div>
        <div class="header-badges">
          {poolBadge(pool)}
          {isReachable
            ? <Badge variant="ok">reachable</Badge>
            : <Badge variant="fail">unreachable</Badge>}
          <span class={`sse-dot ${sse.connected ? 'live' : 'offline'}`} />
        </div>
      </div>

      {/* Subsystem health */}
      {health.data?.health?.subsystems && (
        <section aria-label="Subsystem health">
          <h2 class="section-title">Health</h2>
          <Panel>
            {Object.entries(health.data.health.subsystems).map(([name, snap]) => (
              <HealthRow key={name} name={name} snapshot={snap} />
            ))}
          </Panel>
        </section>
      )}

      {/* Routes */}
      <section aria-label="Routes">
        <div class="section-head">
          <h2 class="section-title">Routes</h2>
          {routes.loading && <span class="section-spinner" />}
        </div>
        {routes.error ? (
          <ErrorState error={routes.error} />
        ) : !routes.data ? null : (
          <RouteTabs routesData={routes.data} />
        )}
      </section>
    </div>
  );
}

function RouteTabs({ routesData }) {
  const ingressSpec  = routesData?.routes?.ingress;
  const gatewaySpec  = routesData?.routes?.gateway;

  const tabs = [];

  if (ingressSpec) {
    tabs.push({
      id: 'ingress',
      label: `Ingress (${countRoutes(ingressSpec)})`,
      content: <RouteSection spec={ingressSpec} kind="ingress" />,
    });
  }
  if (gatewaySpec) {
    tabs.push({
      id: 'gateway',
      label: `Gateway API (${countRoutes(gatewaySpec)})`,
      content: <RouteSection spec={gatewaySpec} kind="httproute" />,
    });
  }

  if (tabs.length === 0) return <EmptyState message="No routes synced yet." />;
  if (tabs.length === 1) return tabs[0].content;

  return <Tabs tabs={tabs} />;
}

function countRoutes(spec) {
  if (!spec?.hosts) return 0;
  return spec.hosts.reduce((sum, h) => sum + (h.routes?.length ?? 0), 0);
}

function RouteSection({ spec, kind }) {
  const hosts     = spec?.hosts ?? [];
  const conflicts = spec?.conflicts ?? [];

  return (
    <div>
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

      {hosts.length === 0 && <EmptyState message="No routes." />}

      {hosts.map((h) => (
        <div key={`${h.port}-${h.host}`} class="host-group">
          <div class="host-label">
            <code>{h.host}</code>
            <span class="host-port">:{h.port}</span>
          </div>
          <div class="tbl-wrap">
            <table>
              <thead>
                <tr>
                  <th>Path</th>
                  <th>Backend</th>
                  <th>Endpoints</th>
                  <th>Type</th>
                </tr>
              </thead>
              <tbody>
                {(h.routes ?? []).map((r, i) => (
                  <tr
                    key={i}
                    class="clickable"
                    onClick={() =>
                      kind === 'httproute'
                        ? nav.httproute(r.namespace ?? '', r.name ?? '')
                        : nav.ingressRoute(r.namespace ?? '', r.name ?? '')
                    }
                    title={`Open ${r.backend_group}`}
                  >
                    <td><code>{r.path || '/'}</code></td>
                    <td><code>{r.backend_group}</code></td>
                    <td><EndpointHealth endpoints={r.endpoints ?? []} /></td>
                    <td><Badge variant="neutral">{r.type}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </div>
  );
}
