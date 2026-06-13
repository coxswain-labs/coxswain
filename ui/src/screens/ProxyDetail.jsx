import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getProxy, getProxyRoutes, getProxyHealth } from '../api/endpoints.js';
import { nav } from '../router.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { Badge, poolBadge } from '../components/Badge.jsx';
import { CopyButton } from '../components/CopyButton.jsx';
import { Icon } from '../components/Icon.jsx';
import { EndpointHealth } from '../components/EndpointHealth.jsx';
import { HealthChips } from '../components/HealthChips.jsx';
import { Tabs } from '../components/Tabs.jsx';
import { Spinner, ErrorState, EmptyState } from '../components/Spinner.jsx';
import { useEffect } from 'preact/hooks';

/**
 * Proxy detail screen.
 *
 * Shows pod metadata, subsystem health, and a tabbed route table
 * (Ingress | Gateway API). Routing conflicts are called out inline.
 * Clicking a route row navigates to the Route Inspector.
 */
export function ProxyDetail({ pod, query }) {
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
        <div class="detail-head">
          <div class="card-ns">{p.pod_namespace || '—'}</div>
          <div class="detail-title-row">
            <h1 class="screen-title">{pod}</h1>
            <CopyButton text={pod} label="Copy pod name" />
          </div>
          {[p.pod_ip, p.gateway_ref].filter(Boolean).length > 0 && (
            <div class="screen-meta">
              {[p.pod_ip, p.gateway_ref].filter(Boolean).join(' · ')}
            </div>
          )}
        </div>
        <div class="header-badges">
          {poolBadge(pool)}
          {isReachable
            ? <Badge variant="ok">reachable</Badge>
            : <Badge variant="fail">unreachable</Badge>}
        </div>
      </div>

      {/* Subsystem health — compact chips; failing checks shown inline. */}
      {health.data?.health?.subsystems && (
        <section aria-label="Subsystem health">
          <h2 class="section-title">Health</h2>
          <HealthChips subsystems={health.data.health.subsystems} />
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
          <RouteTabs routesData={routes.data} highlight={query} pod={pod} />
        )}
      </section>
    </div>
  );
}

function RouteTabs({ routesData, highlight, pod }) {
  const specs = [
    { id: 'ingress', kind: 'ingress',   label: 'Ingress',     spec: routesData?.routes?.ingress },
    { id: 'gateway', kind: 'httproute', label: 'Gateway API', spec: routesData?.routes?.gateway },
  ].filter((s) => s.spec);

  const tabs = specs.map((s) => {
    const issues = specHasIssues(s.spec);
    return {
      id: s.id,
      label: (
        <span class={`tab-label ${issues ? 'warn' : 'ok'}`}>
          <Icon name={issues ? 'alert' : 'check'} size={13} />
          {s.label} ({countRoutes(s.spec)})
        </span>
      ),
      content: <RouteSection spec={s.spec} kind={s.kind} highlight={highlight} pod={pod} />,
    };
  });

  if (tabs.length === 0) return <EmptyState message="No routes synced yet." />;
  if (tabs.length === 1) return tabs[0].content;

  return <Tabs tabs={tabs} defaultTab={pickDefaultTab(specs, highlight)} />;
}

function countRoutes(spec) {
  if (!spec?.hosts) return 0;
  return spec.hosts.reduce((sum, h) => sum + (h.routes?.length ?? 0), 0);
}

/** A spec needs attention if it has a conflict or any route with 0 endpoints
 *  (accepted-but-dead backend). Drives the tab alert icon. */
function specHasIssues(spec) {
  if (!spec) return false;
  if ((spec.conflicts?.length ?? 0) > 0) return true;
  return (spec.hosts ?? []).some((h) =>
    (h.routes ?? []).some((r) => (r.endpoints?.length ?? 0) === 0),
  );
}

function specContainsRoute(spec, host, path) {
  const want = path || '/';
  return (spec?.hosts ?? []).some(
    (h) => h.host === host && (h.routes ?? []).some((r) => (r.path || '/') === want),
  );
}

/** Open on the tab the caller deep-linked into (the host/path that's broken),
 *  else the first tab carrying any issue, else the first tab. */
function pickDefaultTab(specs, highlight) {
  if (highlight?.host) {
    const hit = specs.find((s) => specContainsRoute(s.spec, highlight.host, highlight.path));
    if (hit) return hit.id;
  }
  const flagged = specs.find((s) => specHasIssues(s.spec));
  return (flagged ?? specs[0])?.id;
}

function RouteSection({ spec, kind, highlight, pod }) {
  const hosts     = spec?.hosts ?? [];
  const conflicts = spec?.conflicts ?? [];
  const wantPath  = highlight?.path || '/';

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
                  <th>Type</th>
                  <th>Backend</th>
                  <th>Endpoints</th>
                </tr>
              </thead>
              <tbody>
                {(h.routes ?? []).map((r, i) => {
                  const hit = highlight?.host === h.host && (r.path || '/') === wantPath;
                  // The compiled routing table doesn't carry the source route's
                  // namespace/name, so we can only deep-link to the Route
                  // Inspector when identity is present. Otherwise the row is
                  // informational — never a link that resolves to nowhere.
                  const linkable = Boolean(r.namespace && r.name);
                  const open = () =>
                    kind === 'httproute'
                      ? nav.httproute(r.namespace, r.name)
                      : nav.ingressRoute(r.namespace, r.name);
                  return (
                    <tr
                      key={i}
                      class={`${linkable ? 'clickable' : ''}${hit ? ' row-hit' : ''}`}
                      onClick={linkable ? open : undefined}
                      title={linkable ? `Open ${r.backend_group}` : r.backend_group}
                    >
                      <td><code>{r.path || '/'}</code></td>
                      <td><Badge variant="neutral">{r.type}</Badge></td>
                      <td><code>{r.backend_group}</code></td>
                      <td><EndpointHealth endpoints={r.endpoints ?? []} /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </div>
  );
}
