import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getProxy, getProxyRoutes, getProxyHealth, getControllers } from '../api/endpoints.js';
import { nav } from '../router.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { Badge, poolBadge } from '../components/Badge.jsx';
import { DetailHeader } from '../components/DetailHeader.jsx';
import { PodInfo } from '../components/PodInfo.jsx';
import { PodActions } from '../components/PodActions.jsx';
import { Icon } from '../components/Icon.jsx';
import { EndpointHealth } from '../components/EndpointHealth.jsx';
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
  const meta        = useApi(() => getProxy(pod), [pod]);
  const routes      = useApi(() => getProxyRoutes(pod), [pod]);
  const health      = useApi(() => getProxyHealth(pod), [pod]);
  const controllers = useApi(getControllers);
  const sse         = useSSE('/api/v1/events');

  useEffect(() => {
    const off = sse.subscribe('rebuild.completed', () => routes.refetch());
    return off;
  }, [sse.subscribe, routes.refetch]);

  useEffect(() => {
    const off = sse.subscribe('leader.changed', () => controllers.refetch());
    return off;
  }, [sse.subscribe]);

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

  // Navigation aid only: the fleet-wide leader is the active controller, so a
  // proxy links there as "take me to the control plane". Proxies watch
  // Kubernetes independently today (no controller→proxy config push), so this
  // is not a dependency — it'll gain meaning once the controller pushes config.
  const leaderPod = (controllers.data?.controllers ?? []).find(
    (x) => x.reachable && x.is_leader,
  )?.pod_name;

  return (
    <div class="screen">
      <Breadcrumb items={breadcrumb} />

      <DetailHeader
        name={pod}
        namespace={p.pod_namespace}
        meta={(
          <>
            {p.gateway_ref && (
              <div class="problem-card-meta">
                Gateway: <a onClick={() => nav.gateway(p.pod_namespace, p.gateway_ref)}>{p.gateway_ref}</a>
              </div>
            )}
            <div class="problem-card-meta">
              Controller:{' '}
              {leaderPod
                ? <a onClick={() => nav.controller(leaderPod)}>{leaderPod}</a>
                : <span class="meta-warn">no leader</span>}
            </div>
          </>
        )}
        badges={(
          <>
            {poolBadge(pool)}
            {isReachable
              ? <Badge variant="ok">reachable</Badge>
              : <Badge variant="fail">unreachable</Badge>}
          </>
        )}
        actions={<PodActions namespace={p.pod_namespace} name={pod} />}
      />

      <PodInfo detail={p} health={health} />

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

/** Collapse conflicts that render identically (same host+path+rejected group)
 *  but differ only by listener port — the row doesn't show the port. */
function dedupeConflicts(conflicts) {
  const seen = new Set();
  return conflicts.filter((c) => {
    const k = `${c.host}|${c.path}|${c.rejected_group}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
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
  // A routing conflict is a property of the host+path routing key (two routes
  // claim it; one is rejected) — not of a listener port. The shared proxy serves
  // the same routes on every listener, so the compiled table reports the *same*
  // conflict once per port (demo.local/ on :80 and :443); collapse those to the
  // one logical conflict. Genuinely distinct conflicts (a different rejected
  // group at the same path) have a different key and are kept.
  const conflicts = dedupeConflicts(spec?.conflicts ?? []);
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
