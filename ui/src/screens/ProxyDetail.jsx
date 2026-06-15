import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getProxy, getProxyRoutes, getProxyFacets, getProxyHealth, getControllers } from '../api/endpoints.js';
import { nav } from '../router.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { Badge, poolBadge } from '../components/Badge.jsx';
import { DetailHeader } from '../components/DetailHeader.jsx';
import { PodInfo } from '../components/PodInfo.jsx';
import { PodActions } from '../components/PodActions.jsx';
import { PodHealthChips } from '../components/HealthChips.jsx';
import { Icon } from '../components/Icon.jsx';
import { EndpointHealth } from '../components/EndpointHealth.jsx';
import { SearchBox } from '../components/SearchBox.jsx';
import { ComboFilter } from '../components/ComboFilter.jsx';
import { Table } from '../components/Table.jsx';
import { Pager, PAGE_SIZES } from '../components/DataTable.jsx';
import { Spinner, ErrorState, EmptyState } from '../components/Spinner.jsx';
import { useElementHeight } from '../hooks/useElementHeight.js';
import { useEffect, useState } from 'preact/hooks';

/**
 * Proxy detail screen.
 *
 * Shows pod metadata, header health chips, and the proxy's compiled routing
 * table as tabs (Ingress | Gateway API | Conflicts). Clicking a route row
 * navigates to the route detail screen.
 *
 * The route table is **server-side filtered + paginated** (#286): a *shared*
 * proxy holds the whole cluster's compiled table, so this screen never fetches
 * it whole. The **host** and **namespace** dropdowns (populated from the proxy's
 * `/facets`) are exact picks; the **path** box is a substring search; `status`
 * keeps only dead-backend rows; `limit`/`offset` window the page. The same
 * host/namespace/path scope narrows the Conflicts tab too.
 */
export function ProxyDetail({ pod, query }) {
  const meta        = useApi(() => getProxy(pod), [pod]);
  const health      = useApi(() => getProxyHealth(pod), [pod]);
  const facets      = useApi(() => getProxyFacets(pod), [pod]);
  const controllers = useApi(getControllers);
  const sse         = useSSE('/api/v1/events');

  // Host + namespace are exact picks from the proxy's facet dropdowns (instant);
  // path is a debounced substring search (the within-host refinement). A deep-link
  // may carry a host to pre-select so the operator lands on that route.
  const [host, setHost]               = useState(query?.host ?? '');
  const [namespace, setNamespace]     = useState('');
  const [pathSearch, setPathSearch]   = useState('');
  const dPath = useDebounced(pathSearch);
  const [problemsOnly, setProblemsOnly] = useState(false);
  const [pageSize, setPageSize] = useState(100);
  const [offset, setOffset]     = useState(0);
  // Active tab id ('ingress' | 'gateway' | 'conflicts'); null defers to the
  // data-driven default.
  const [tab, setTab] = useState(null);

  const routes = useApi(
    () =>
      getProxyRoutes(pod, {
        host: host || undefined,
        namespace: namespace || undefined,
        path: dPath || undefined,
        status: problemsOnly ? 'problem' : undefined,
        limit: pageSize,
        offset,
      }),
    [pod, host, namespace, dPath, problemsOnly, pageSize, offset],
  );

  // Reset to the first page whenever the window's shape changes — a filter edit,
  // a page-size change, or a tab switch. Each tab paginates independently and the
  // server clamps offset to the active block's total, so a stale offset from a
  // larger tab would otherwise land past a smaller tab's last page.
  useEffect(() => {
    setOffset(0);
  }, [host, namespace, dPath, problemsOnly, pageSize, tab]);

  useEffect(() => {
    const off = sse.subscribe('rebuild.completed', () => {
      routes.refetch();
      facets.refetch();
    });
    return off;
  }, [sse.subscribe, routes.refetch, facets.refetch]);

  useEffect(() => {
    const off = sse.subscribe('leader.changed', () => controllers.refetch());
    return off;
  }, [sse.subscribe]);

  if (meta.loading) return <Spinner label="Loading proxy…" />;
  if (meta.error)   return <ErrorState error={meta.error} />;
  if (!meta.data)   return <EmptyState message="Proxy not found." />;

  const p = meta.data;
  const isReachable = p.reachable ?? false;
  const pool = p.component === 'dedicated-proxy' ? 'dedicated' : 'shared';

  const breadcrumb = [
    { label: 'Fleet', onClick: () => nav.fleet() },
    pool === 'dedicated'
      ? { label: 'Dedicated proxies', onClick: () => nav.fleet({ filter: 'dedicated' }) }
      : { label: 'Shared proxies', onClick: () => nav.fleet({ filter: 'shared' }) },
    { label: pod },
  ];

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
        actions={(
          <>
            <PodHealthChips health={health} />
            <PodActions namespace={p.pod_namespace} name={pod} />
          </>
        )}
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
          <RoutesPanel
            routesData={routes.data}
            facets={facets.data}
            highlight={query}
            host={host}
            namespace={namespace}
            pathSearch={pathSearch}
            onHost={setHost}
            onNamespace={setNamespace}
            onPath={setPathSearch}
            problemsOnly={problemsOnly}
            onProblemsOnly={setProblemsOnly}
            pageSize={pageSize}
            offset={offset}
            onPage={setOffset}
            onPageSize={setPageSize}
            activeTab={tab}
            onTab={setTab}
          />
        )}
      </section>
    </div>
  );
}

/** Debounce a rapidly-changing value (search keystrokes) so each character
 *  doesn't trigger a server round-trip against a large routing table. */
function useDebounced(value, ms = 250) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return debounced;
}

/**
 * The Routes section: the host/namespace/path filters, then a tab per compiled
 * table the proxy holds (Ingress | Gateway API) plus a Conflicts tab when there
 * are any. The route tabs paginate; the Conflicts tab is bounded (no pager). All
 * filters are applied server-side and narrow both the route tabs and the
 * conflicts.
 */
function RoutesPanel({
  routesData, facets, highlight, host, namespace, pathSearch,
  onHost, onNamespace, onPath, problemsOnly, onProblemsOnly,
  pageSize, offset, onPage, onPageSize, activeTab, onTab,
}) {
  // Measured height of the pinned controls bar → the column header docks just
  // below it instead of sliding up behind it as the rows scroll the window.
  const [chromeRef, chromeH] = useElementHeight();
  const routeSpecs = [
    { id: 'ingress', kind: 'ingress',   label: 'Ingress',     spec: routesData?.routes?.ingress },
    { id: 'gateway', kind: 'httproute', label: 'Gateway API', spec: routesData?.routes?.gateway },
  ].filter((s) => s.spec);

  if (routeSpecs.length === 0) return <EmptyState message="No routes synced yet." />;

  // Conflicts from both blocks (already filtered server-side), merged + deduped,
  // shown in their own tab rather than crowding the table header.
  const conflicts = dedupeConflicts([
    ...(routesData?.routes?.ingress?.conflicts ?? []),
    ...(routesData?.routes?.gateway?.conflicts ?? []),
  ]);

  const tabs = [...routeSpecs];
  if (conflicts.length > 0) tabs.push({ id: 'conflicts', label: 'Conflicts' });

  const activeId = activeTab && tabs.some((t) => t.id === activeTab)
    ? activeTab
    : pickDefaultTab(routeSpecs, highlight);
  const active = tabs.find((t) => t.id === activeId) ?? tabs[0];
  const isConflicts = active.id === 'conflicts';

  const filtered = Boolean(host || namespace || pathSearch || problemsOnly);
  const total = isConflicts ? conflicts.length : blockTotal(active.spec);

  const hostOptions = [
    { value: '', label: 'All hosts' },
    ...(facets?.hosts ?? []).map((h) => ({ value: h, label: h })),
  ];
  const nsOptions = [
    { value: '', label: 'All namespaces' },
    ...(facets?.namespaces ?? []).map((n) => ({ value: n, label: n })),
  ];

  return (
    <div class="routes-screen" style={`--routes-chrome-h:${chromeH}px`}>
      {/* The filter + tab + pager chrome is pinned to the top of the viewport
          (see .routes-controls) so it stays reachable while the row list scrolls
          the window underneath — Routing's "controls stay put" benefit without a
          fixed-height inner-scroll container on this composite screen. */}
      <div class="routes-controls" ref={chromeRef}>
        {/* Filters narrow every tab (the backend applies them to both route
            blocks and the conflicts), so they sit ABOVE the tab bar — one shared
            scope. Namespace + host are dropdown picks (left); path is the
            free-text search (right), the conventional toolbar split. */}
        <div class="header-controls left routing-filters">
          <div class="filter-group">
            <ComboFilter
              label="Filter by namespace"
              value={namespace}
              options={nsOptions}
              onChange={onNamespace}
            />
            <ComboFilter
              label="Filter by host"
              value={host}
              options={hostOptions}
              onChange={onHost}
            />
            <button
              type="button"
              class={`toggle-pill${problemsOnly ? ' active' : ''}`}
              aria-pressed={problemsOnly}
              title="Show only routes that aren't serving traffic (no ready endpoints)"
              onClick={() => onProblemsOnly(!problemsOnly)}
            >
              <Icon name="alert" size={13} />
              Problems only
            </button>
          </div>
          <SearchBox
            value={pathSearch}
            onInput={(e) => onPath(e.currentTarget.value)}
            placeholder="Filter by path…"
            label="Filter routes by path"
          />
        </div>

        {tabs.length > 1 && (
          <div class="tabs" role="tablist">
            {tabs.map((t) => {
              const warn = t.id === 'conflicts' || specHasDeadRoute(t.spec);
              const count = t.id === 'conflicts' ? conflicts.length : blockTotal(t.spec);
              return (
                <button
                  key={t.id}
                  role="tab"
                  aria-selected={t.id === activeId}
                  class={`tab${t.id === activeId ? ' active' : ''}`}
                  onClick={() => onTab(t.id)}
                >
                  <span class={`tab-label ${warn ? 'warn' : 'ok'}`}>
                    <Icon name={warn ? 'alert' : 'check'} size={13} />
                    {t.label} ({count})
                  </span>
                </button>
              );
            })}
          </div>
        )}

        {/* Pager ABOVE the (potentially long) table so the page controls + the
            "X–Y of N" count are reachable without scrolling past every row. The
            Conflicts tab is bounded, so it gets no pager. */}
        {!isConflicts && total > 0 && (
          <div class="pager-bar">
            <Pager
              page={{
                offset: active.spec.offset ?? offset,
                returned: active.spec.returned ?? countRoutes(active.spec),
                total,
                pageSize,
                pageSizes: PAGE_SIZES,
                onPage,
                onPageSize,
              }}
            />
          </div>
        )}
      </div>

      {isConflicts ? (
        <ConflictsTable conflicts={conflicts} filtered={filtered} />
      ) : (
        <RouteSection
          spec={active.spec}
          kind={active.kind}
          highlight={highlight}
          filtered={filtered}
          scrollKey={`${activeId}-${offset}`}
        />
      )}
    </div>
  );
}

/** A block's full (pre-window) route count: the server's post-filter `total`
 *  when paginated, else the rows present (an unparameterized full dump). */
function blockTotal(spec) {
  return spec?.total ?? countRoutes(spec);
}

function countRoutes(spec) {
  if (!spec?.hosts) return 0;
  return spec.hosts.reduce((sum, h) => sum + (h.routes?.length ?? 0), 0);
}

/** Collapse conflicts that render identically (same host+path+rejected group)
 *  but differ only by listener port — the table doesn't show the port. */
function dedupeConflicts(conflicts) {
  const seen = new Set();
  return conflicts.filter((c) => {
    const k = `${c.host}|${c.path}|${c.rejected_group}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** A route tab needs attention if it carries any route with 0 endpoints (an
 *  accepted-but-dead backend). Conflicts have their own tab now, so they don't
 *  also flag the route tab. Sees only the current page — the per-row endpoint
 *  health flags dead backends wherever they land. */
function specHasDeadRoute(spec) {
  return (spec?.hosts ?? []).some((h) =>
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
 *  else the first tab carrying a dead route, else the first tab. Conflicts are
 *  opt-in, never the default. */
function pickDefaultTab(specs, highlight) {
  if (highlight?.host) {
    const hit = specs.find((s) => specContainsRoute(s.spec, highlight.host, highlight.path));
    if (hit) return hit.id;
  }
  const flagged = specs.find((s) => specHasDeadRoute(s.spec));
  return (flagged ?? specs[0])?.id;
}

function RouteSection({ spec, kind, highlight, filtered, scrollKey }) {
  const wantPath = highlight?.path || '/';

  // Flatten the host-grouped payload into one compact table.
  const rows = [];
  for (const h of spec?.hosts ?? []) {
    for (const r of h.routes ?? []) rows.push({ ...r, host: h.host, port: h.port });
  }

  const openRoute = (r) =>
    kind === 'httproute' ? nav.httproute(r.namespace, r.name) : nav.ingressRoute(r.namespace, r.name);

  return (
    <Table
      columns={['Namespace', 'Host', 'Port', 'Path', 'Type', 'Backend', 'Endpoints']}
      rows={rows}
      emptyMsg={filtered ? 'No routes match.' : 'No routes.'}
      scrollKey={scrollKey}
      renderRow={(r, i) => {
        // A compiled route serving zero ready endpoints is a dead backend —
        // amber (warn tier), the same left-edge accent the routing tables use,
        // never red (red is reserved for "down").
        const dead = (r.endpoints?.length ?? 0) === 0;
        const hit = highlight?.host === r.host && (r.path || '/') === wantPath;
        // The compiled table carries the source route's namespace/name, so we
        // deep-link when present — otherwise the row is informational.
        const linkable = Boolean(r.namespace && r.name);
        return (
          <tr
            key={`${r.port}-${r.host}-${r.path}-${i}`}
            class={`${linkable ? 'clickable' : ''}${dead ? ' sev-warn' : ''}${hit ? ' row-hit' : ''}`}
            onClick={linkable ? () => openRoute(r) : undefined}
            title={
              dead
                ? 'No ready endpoints — not serving traffic'
                : linkable
                  ? `Open ${r.backend_group}`
                  : r.backend_group
            }
          >
            <td><code>{r.namespace || '—'}</code></td>
            <td><code>{r.host}</code></td>
            <td class="col-port">{r.port}</td>
            <td><code>{r.path || '/'}</code></td>
            <td><Badge variant="neutral">{r.type}</Badge></td>
            <td><code>{r.backend_group}</code></td>
            <td><EndpointHealth endpoints={r.endpoints ?? []} /></td>
          </tr>
        );
      }}
    />
  );
}

/** The Conflicts tab: each row is a route that lost a host+path routing key to
 *  another route (its backend was rejected/shadowed). Amber throughout (a
 *  conflict is a degradation); clicking opens the rejected route. */
function ConflictsTable({ conflicts, filtered }) {
  return (
    <Table
      columns={['Namespace', 'Host', 'Path', 'Rejected backend']}
      rows={conflicts}
      emptyMsg={filtered ? 'No conflicts match.' : 'No conflicts.'}
      renderRow={(c, i) => {
        const linkable = Boolean(c.namespace && c.name);
        const open = () =>
          c.type === 'httproute' ? nav.httproute(c.namespace, c.name) : nav.ingressRoute(c.namespace, c.name);
        return (
          <tr
            key={`${c.host}-${c.path}-${c.rejected_group}-${i}`}
            class={`sev-warn${linkable ? ' clickable' : ''}`}
            onClick={linkable ? open : undefined}
            title={linkable ? `Open ${c.namespace}/${c.name}` : undefined}
          >
            <td><code>{c.namespace || '—'}</code></td>
            <td><code>{c.host}</code></td>
            <td><code>{c.path}</code></td>
            <td><code>{c.rejected_group}</code></td>
          </tr>
        );
      }}
    />
  );
}
