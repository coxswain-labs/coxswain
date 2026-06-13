import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getProxies, getControllers } from '../api/endpoints.js';
import { nav, updateQuery } from '../router.js';
import { useSearch, matchesSearch } from '../hooks/useSearch.js';
import { Badge, poolBadge } from '../components/Badge.jsx';
import { Icon } from '../components/Icon.jsx';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { SearchBox } from '../components/SearchBox.jsx';
import { FilterSelect } from '../components/FilterSelect.jsx';
import { Card, CardFooter, CardGrid } from '../components/Card.jsx';
import { CopyButton } from '../components/CopyButton.jsx';
import { TruncatedName } from '../components/TruncatedName.jsx';
import { ErrorState } from '../components/Spinner.jsx';
import { useEffect } from 'preact/hooks';

/** Type-filter sections, mirroring Routing's filter. `all` shows every section;
 *  the others narrow to one. The key is encoded in `?filter=` for permalinks
 *  and is what the Dashboard tiles deep-link into. */
const FILTERS = [
  { value: 'all',         label: 'All types' },
  { value: 'controllers', label: 'Controllers' },
  { value: 'shared',      label: 'Shared proxies' },
  { value: 'dedicated',   label: 'Dedicated proxies' },
];

/**
 * Fleet screen — the runtime inventory (compute axis).
 *
 * Controllers first (leader-elected status writers), then shared and dedicated
 * proxy pods. A type filter (`?filter=`) narrows to one section — the
 * Dashboard tiles deep-link straight into it — and a search box (`?q=`) filters
 * by pod name or type within the shown sections. Both are permalinkable. Live
 * SSE events refetch on pod connect/disconnect and rebuild.
 */
export function Fleet({ query }) {
  const proxies    = useApi(getProxies);
  const controllers = useApi(getControllers);
  const sse        = useSSE('/api/v1/events');

  const { search, q, onSearch } = useSearch(query);
  const filter = FILTERS.some((f) => f.value === query?.filter) ? query.filter : 'all';

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

  // Namespace options span every pod, independent of the current filters, so the
  // dropdown always offers the full set. `?ns=` makes the choice permalinkable.
  const namespaces = [...new Set(
    [...controllerList, ...proxyList].map((p) => p.pod_namespace).filter(Boolean),
  )].sort();
  const nsFilter = namespaces.includes(query?.ns) ? query.ns : 'all';
  const inNs = (p) => nsFilter === 'all' || p.pod_namespace === nsFilter;

  // Bucket proxies by component, then apply the namespace + search filters.
  // Unreachable entries still carry `component`/`pod_namespace` from the fleet
  // snapshot, so they land in the right section rather than a catch-all.
  const shownControllers = controllerList.filter((c) => inNs(c) && matchesSearch(c.pod_name, 'controller', q));
  const shownShared = proxyList.filter(
    (p) => p.component !== 'dedicated-proxy' && inNs(p) && matchesSearch(p.pod_name, 'shared proxy', q),
  );
  const shownDedicated = proxyList.filter(
    (p) => p.component === 'dedicated-proxy' && inNs(p) && matchesSearch(p.pod_name, 'dedicated proxy', q),
  );

  // Dedicated proxies are always grouped under their namespace subheader: the
  // dedicated proxy → Gateway → namespace hierarchy is the natural axis, and at
  // many tenants a flat grid of near-identical cards is hard to scan. Controllers
  // and the shared proxy are cluster singletons in coxswain-system, so they stay
  // flat. Sorted by namespace for a stable, scannable order.
  const dedicatedByNs = [...shownDedicated.reduce((m, p) => {
    const ns = p.pod_namespace || '—';
    (m.get(ns) ?? m.set(ns, []).get(ns)).push(p);
    return m;
  }, new Map())].sort(([a], [b]) => a.localeCompare(b));

  const show = (key) => filter === 'all' || filter === key;
  const searching = q !== '' || nsFilter !== 'all';

  return (
    <div class="screen">
      <Breadcrumb items={[{ label: 'Fleet' }]} />
      <div class="screen-header">
        <div class="header-controls left">
          <FilterSelect
            label="Filter by namespace"
            value={nsFilter}
            options={[{ value: 'all', label: 'All namespaces' }, ...namespaces.map((ns) => ({ value: ns, label: ns }))]}
            onChange={(e) => updateQuery({ ns: e.currentTarget.value === 'all' ? null : e.currentTarget.value })}
          />
          <FilterSelect
            label="Filter by type"
            value={filter}
            options={FILTERS}
            onChange={(e) => updateQuery({ filter: e.currentTarget.value === 'all' ? null : e.currentTarget.value })}
          />
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
          ) : dedicatedByNs.length === 0 ? (
            !proxies.loading && (
              <div style="color:var(--muted);font-size:13px">
                {searching ? 'No dedicated proxies match.' : 'No dedicated proxy pods found.'}
              </div>
            )
          ) : (
            dedicatedByNs.map(([ns, pods]) => (
              <div key={ns} class="ns-group">
                <div class="ns-group-head">
                  <span class="ns-group-name">{ns}</span>
                  <span class="ns-group-count">{pods.length} {pods.length === 1 ? 'pod' : 'pods'}</span>
                </div>
                <CardGrid>
                  {pods.map((p) => (
                    <ProxyCard key={p.pod_name} proxy={p} />
                  ))}
                </CardGrid>
              </div>
            ))
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
 * footer carries the optional gateway ref and a single status chip.
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
        right={<CardStatusChip reachable={reachable} health={health} degradedChecks={degradedChecks} />}
      />
    </Card>
  );
}

/** Single per-pod status chip: one consistent pill for the whole reachable +
 *  health story (unreachable / degraded / healthy), replacing the old pairing of
 *  a "healthy" pill next to a differently-styled "reachable" dot. */
function CardStatusChip({ reachable, health, degradedChecks }) {
  if (!reachable) {
    return (
      <span class="health-chip sm err" title="Did not respond to health probe">
        <Icon name="alert" size={12} />
        unreachable
      </span>
    );
  }
  const degraded = Boolean(health) && health !== 'ready';
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
  // Pool is known from the snapshot even when unreachable, so the type badge
  // stays put; the status chip carries reachable/health. Gateway ref only (no
  // IP) as secondary meta — present for dedicated proxies, empty for shared.
  const pool = proxy.component === 'dedicated-proxy' ? 'dedicated' : 'shared';
  return (
    <PodCard
      namespace={proxy.pod_namespace}
      name={proxy.pod_name}
      badge={poolBadge(pool)}
      meta={proxy.gateway_ref ?? ''}
      reachable={proxy.reachable}
      health={proxy.health}
      degradedChecks={proxy.degraded_checks}
      onClick={proxy.reachable ? () => nav.proxy(proxy.pod_name) : undefined}
    />
  );
}

function ControllerCard({ controller }) {
  // Leadership is only known when reachable; otherwise omit the role badge
  // rather than imply "standby". The status chip carries reachable/health.
  const badge = controller.reachable ? (
    <Badge variant={controller.is_leader ? 'leader' : 'standby'}>
      {controller.is_leader ? 'leader' : 'standby'}
    </Badge>
  ) : null;
  return (
    <PodCard
      namespace={controller.pod_namespace}
      name={controller.pod_name}
      badge={badge}
      meta=""
      reachable={controller.reachable}
      health={controller.health}
      degradedChecks={controller.degraded_checks}
      onClick={controller.reachable ? () => nav.controller(controller.pod_name) : undefined}
    />
  );
}
