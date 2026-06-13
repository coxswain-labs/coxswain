import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getProxies, getControllers, getCluster } from '../api/endpoints.js';
import { nav, updateQuery } from '../router.js';
import { useSearch, matchesSearch } from '../hooks/useSearch.js';
import { Badge, poolBadge } from '../components/Badge.jsx';
import { Icon } from '../components/Icon.jsx';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { SearchBox } from '../components/SearchBox.jsx';
import { Card, CardFooter, CardGrid } from '../components/Card.jsx';
import { CopyButton } from '../components/CopyButton.jsx';
import { TruncatedName } from '../components/TruncatedName.jsx';
import { ReachableDot } from '../components/StatusDot.jsx';
import { ErrorState } from '../components/Spinner.jsx';
import { useEffect } from 'preact/hooks';

/** Segmented sections, mirroring Routing's filter. `all` shows every section;
 *  the others narrow to one. The key is encoded in `?filter=` for permalinks
 *  and is what the Dashboard tiles deep-link into. */
const FILTERS = [
  { key: 'all',         label: 'All' },
  { key: 'controllers', label: 'Controllers' },
  { key: 'shared',      label: 'Shared proxies' },
  { key: 'dedicated',   label: 'Dedicated proxies' },
];

/**
 * Fleet screen — the runtime inventory (compute axis).
 *
 * Controllers first (leader-elected status writers), then shared and dedicated
 * proxy pods. A segmented filter (`?filter=`) narrows to one section — the
 * Dashboard tiles deep-link straight into it — and a search box (`?q=`) filters
 * by pod name or type within the shown sections. Both are permalinkable. Live
 * SSE events refetch on pod connect/disconnect and rebuild.
 */
export function Fleet({ query }) {
  const proxies    = useApi(getProxies);
  const controllers = useApi(getControllers);
  const cluster    = useApi(getCluster);
  const sse        = useSSE('/api/v1/events');

  const { search, q, onSearch } = useSearch(query);
  const filter = FILTERS.some((f) => f.key === query?.filter) ? query.filter : 'all';

  // Refresh fleet cards on rebuild.
  useEffect(() => {
    const off = sse.subscribe('rebuild.completed', () => {
      proxies.refetch();
      controllers.refetch();
    });
    return off;
  }, [sse.subscribe]);

  // Also update cards when pods connect/disconnect.
  useEffect(() => {
    const unproxy = sse.subscribe('proxy.connected',      () => proxies.refetch());
    const undisco  = sse.subscribe('proxy.disconnected',  () => proxies.refetch());
    const unctrl   = sse.subscribe('controller.connected', () => controllers.refetch());
    const uncdisco = sse.subscribe('controller.disconnected', () => controllers.refetch());
    return () => { unproxy(); undisco(); unctrl(); uncdisco(); };
  }, [sse.subscribe]);

  const proxyList      = proxies.data?.proxies ?? [];
  const controllerList = controllers.data?.controllers ?? [];
  const clusterData    = cluster.data;

  // Bucket proxies by component, then apply the search. Unreachable entries
  // still carry `component` from the fleet snapshot, so dedicated proxies that
  // fail their probe land in the right section rather than a catch-all.
  const shownControllers = controllerList.filter((c) => matchesSearch(c.pod_name, 'controller', q));
  const shownShared = proxyList.filter(
    (p) => p.component !== 'dedicated-proxy' && matchesSearch(p.pod_name, 'shared proxy', q),
  );
  const shownDedicated = proxyList.filter(
    (p) => p.component === 'dedicated-proxy' && matchesSearch(p.pod_name, 'dedicated proxy', q),
  );

  const show = (key) => filter === 'all' || filter === key;
  const searching = q !== '';

  return (
    <div class="screen">
      <Breadcrumb items={[{ label: 'Fleet' }]} />
      <div class="screen-header">
        <h1 class="screen-title">Fleet</h1>
        <span class={`sse-dot ${sse.connected ? 'live' : 'offline'}`} title={sse.connected ? 'Live' : 'Disconnected'} />
        {clusterData && (
          <span class="cluster-meta">{clusterData.kubernetes_version}</span>
        )}
        <div class="header-controls">
          <div class="segmented" role="tablist" aria-label="Filter fleet">
            {FILTERS.map((f) => (
              <button
                key={f.key}
                type="button"
                role="tab"
                aria-selected={filter === f.key}
                class={`segmented-btn${filter === f.key ? ' active' : ''}`}
                onClick={() => updateQuery({ filter: f.key === 'all' ? null : f.key })}
              >
                {f.label}
              </button>
            ))}
          </div>
          <SearchBox value={search} onInput={onSearch} label="Search fleet by pod name or type" />
        </div>
      </div>

      {/* Controller inventory — leader-elected status writers come first */}
      {show('controllers') && (
        <section aria-label="Controller pods">
          <div class="section-head">
            <h2 class="section-title">Controllers</h2>
            {controllers.loading && <span class="section-spinner" aria-label="Loading" />}
          </div>
          {controllers.error ? (
            <ErrorState error={controllers.error} />
          ) : (
            <CardGrid>
              {shownControllers.map((c) => (
                <ControllerCard key={c.pod_name} controller={c} />
              ))}
              {!controllers.loading && shownControllers.length === 0 && (
                <div style="color:var(--muted);font-size:13px">
                  {searching ? 'No controllers match.' : 'No controller pods found.'}
                </div>
              )}
            </CardGrid>
          )}
        </section>
      )}

      {/* Shared-proxy inventory */}
      {show('shared') && (
        <section aria-label="Shared proxy pods">
          <div class="section-head">
            <h2 class="section-title">Shared proxies</h2>
            {proxies.loading && <span class="section-spinner" aria-label="Loading" />}
          </div>
          {proxies.error ? (
            <ErrorState error={proxies.error} />
          ) : (
            <CardGrid>
              {shownShared.map((p) => (
                <ProxyCard key={p.pod_name} proxy={p} />
              ))}
              {!proxies.loading && shownShared.length === 0 && (
                <div style="color:var(--muted);font-size:13px">
                  {searching ? 'No shared proxies match.' : 'No shared proxy pods found.'}
                </div>
              )}
            </CardGrid>
          )}
        </section>
      )}

      {/* Dedicated-proxy inventory — one set per Gateway, in user namespaces */}
      {show('dedicated') && (
        <section aria-label="Dedicated proxy pods">
          <div class="section-head">
            <h2 class="section-title">Dedicated proxies</h2>
            {proxies.loading && <span class="section-spinner" aria-label="Loading" />}
          </div>
          {proxies.error ? (
            <ErrorState error={proxies.error} />
          ) : (
            <CardGrid>
              {shownDedicated.map((p) => (
                <ProxyCard key={p.pod_name} proxy={p} />
              ))}
              {!proxies.loading && shownDedicated.length === 0 && (
                <div style="color:var(--muted);font-size:13px">
                  {searching ? 'No dedicated proxies match.' : 'No dedicated proxy pods found.'}
                </div>
              )}
            </CardGrid>
          )}
        </section>
      )}
    </div>
  );
}

/**
 * Pod card layout shared by proxy and controller cards.
 *
 * Namespace sits at the top as an eyebrow line (same font weight/size as the
 * name) with the type/status badge to its right; the long pod name gets its
 * own full-width line below so it can wrap without crowding the badge. The
 * footer carries the secondary meta (IP, gateway ref) and a reachability dot.
 */
function PodCard({ namespace, name, badge, meta, reachable, health, degradedChecks, onClick }) {
  return (
    <Card error={!reachable} onClick={reachable ? onClick : undefined}>
      <div class="card-top">
        <span class="card-ns">{namespace || '—'}</span>
        {badge}
      </div>
      <div class="card-name-row">
        <TruncatedName name={name} />
        <CopyButton text={name} label="Copy pod name" />
      </div>
      <CardFooter
        left={meta}
        right={
          <span class="card-foot-right">
            {reachable && <CardHealthChip health={health} degradedChecks={degradedChecks} />}
            <ReachableDot reachable={reachable} />
          </span>
        }
      />
    </Card>
  );
}

/** Coarse per-pod health from the list-endpoint rollup: green when every
 *  subsystem is ready, amber when any isn't (failing checks in the tooltip). */
function CardHealthChip({ health, degradedChecks }) {
  if (!health) return null;
  const degraded = health !== 'ready';
  const title = degraded
    ? `Degraded: ${(degradedChecks ?? []).join(', ') || 'subsystem not ready'}`
    : 'All subsystems ready';
  return (
    <span class={`health-chip sm ${degraded ? 'warn' : 'ok'}`} title={title}>
      <Icon name={degraded ? 'alert' : 'check'} size={12} />
      {degraded ? 'degraded' : 'healthy'}
    </span>
  );
}

function ProxyCard({ proxy }) {
  if (!proxy.reachable) {
    return (
      <PodCard
        namespace={proxy.pod_namespace}
        name={proxy.pod_name}
        badge={<Badge variant="fail">unreachable</Badge>}
        meta=""
        reachable={false}
      />
    );
  }

  const pool = proxy.component === 'dedicated-proxy' ? 'dedicated' : 'shared';
  const meta = `${proxy.pod_ip ?? ''}${proxy.gateway_ref ? ` · ${proxy.gateway_ref}` : ''}`;
  return (
    <PodCard
      namespace={proxy.pod_namespace}
      name={proxy.pod_name}
      badge={poolBadge(pool)}
      meta={meta}
      reachable
      health={proxy.health}
      degradedChecks={proxy.degraded_checks}
      onClick={() => nav.proxy(proxy.pod_name)}
    />
  );
}

function ControllerCard({ controller }) {
  if (!controller.reachable) {
    return (
      <PodCard
        namespace={controller.pod_namespace}
        name={controller.pod_name}
        badge={<Badge variant="fail">unreachable</Badge>}
        meta=""
        reachable={false}
      />
    );
  }

  return (
    <PodCard
      namespace={controller.pod_namespace}
      name={controller.pod_name}
      badge={<Badge variant={controller.is_leader ? 'leader' : 'standby'}>
        {controller.is_leader ? 'leader' : 'standby'}
      </Badge>}
      meta={controller.pod_ip ?? ''}
      reachable
      health={controller.health}
      degradedChecks={controller.degraded_checks}
      onClick={() => nav.controller(controller.pod_name)}
    />
  );
}
