import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getProxy, getProxyRoutes, getProxyHealth, getControllers } from '../api/endpoints.js';
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
import { Table } from '../components/Table.jsx';
import { Pager, PAGE_SIZES } from '../components/DataTable.jsx';
import { Spinner, ErrorState, EmptyState } from '../components/Spinner.jsx';
import { useEffect, useState } from 'preact/hooks';

/**
 * Proxy detail screen.
 *
 * Shows pod metadata, subsystem health, and a tabbed route table
 * (Ingress | Gateway API). Routing conflicts are called out inline.
 * Clicking a route row navigates to the route detail screen.
 *
 * The route table is **server-side filtered + paginated** (#286): a *shared*
 * proxy holds the whole cluster's compiled routing table (every Ingress + every
 * HTTPRoute, unioned), so this screen must never fetch or render it whole. The
 * Host and Path inputs map 1:1 to the backend's two substring params (which
 * AND); `limit`/`offset` window the post-filter rows and the footer pager shows
 * "X–Y of N". Each tab paginates independently against the same params.
 */
export function ProxyDetail({ pod, query }) {
  const meta        = useApi(() => getProxy(pod), [pod]);
  const health      = useApi(() => getProxyHealth(pod), [pod]);
  const controllers = useApi(getControllers);
  const sse         = useSSE('/api/v1/events');

  // One search box filters the route table by host OR path (the backend's `q`
  // param). A deep-link (e.g. from a conflict) may carry the host of a specific
  // route; pre-filling the box narrows the (otherwise cluster-wide) table to it
  // so the operator lands on that route instead of page 1 of thousands — the row
  // is then flashed via `row-hit`.
  const [search, setSearch] = useState(query?.host ?? '');
  const dSearch = useDebounced(search);
  // Problems-only: filtered server-side via `status=problem` — for the compiled
  // table a "problem" route is one serving zero ready endpoints (a dead backend),
  // which the proxy can see directly (unlike Routing's cross-proxy aggregate), so
  // the count stays honest rather than narrowing a page client-side.
  const [problemsOnly, setProblemsOnly] = useState(false);
  const [pageSize, setPageSize] = useState(100);
  const [offset, setOffset]     = useState(0);
  // Active tab id ('ingress' | 'gateway'); null defers to the data-driven default.
  const [tab, setTab] = useState(null);

  const routes = useApi(
    () =>
      getProxyRoutes(pod, {
        q: dSearch,
        status: problemsOnly ? 'problem' : undefined,
        limit: pageSize,
        offset,
      }),
    [pod, dSearch, problemsOnly, pageSize, offset],
  );

  // Reset to the first page whenever the window's shape changes — a search edit,
  // the problems-only toggle, a page-size change, or a tab switch. Each tab
  // paginates independently and the server clamps offset to the active block's
  // total, so a stale offset from a larger tab would otherwise land past a
  // smaller tab's last page.
  useEffect(() => {
    setOffset(0);
  }, [dSearch, problemsOnly, pageSize, tab]);

  useEffect(() => {
    const off = sse.subscribe('rebuild.completed', () => routes.refetch());
    return off;
  }, [sse.subscribe, routes.refetch]);

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
            highlight={query}
            search={search}
            onSearch={setSearch}
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

/** Debounce a rapidly-changing value (filter keystrokes) so each character
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
 * The Routes section: a tab per compiled table the proxy holds (Ingress |
 * Gateway API), the shared Host/Path filters, the active tab's host-grouped
 * table, and the footer pager. Tabs are structural (present whenever the proxy
 * holds that table) — a filter that matches nothing leaves the tab in place with
 * an empty body, never makes it vanish.
 */
function RoutesPanel({
  routesData, highlight, search, onSearch, problemsOnly, onProblemsOnly,
  pageSize, offset, onPage, onPageSize, activeTab, onTab,
}) {
  const specs = [
    { id: 'ingress', kind: 'ingress',   label: 'Ingress',     spec: routesData?.routes?.ingress },
    { id: 'gateway', kind: 'httproute', label: 'Gateway API', spec: routesData?.routes?.gateway },
  ].filter((s) => s.spec);

  if (specs.length === 0) return <EmptyState message="No routes synced yet." />;

  const activeId = activeTab && specs.some((s) => s.id === activeTab)
    ? activeTab
    : pickDefaultTab(specs, highlight);
  const active = specs.find((s) => s.id === activeId) ?? specs[0];

  const filtered = Boolean(search) || problemsOnly;
  // Show the filter controls whenever there's something to filter (any tab has
  // rows) or a filter is active (so it stays dismissable after narrowing to 0).
  const showFilters = filtered || specs.some((s) => blockTotal(s.spec) > 0);
  const total = blockTotal(active.spec);

  return (
    <div>
      {/* One search box narrows both tabs by host OR path (the backend filters
          both blocks by the same `q`), so it sits ABOVE the tab bar — one shared
          scope, not a per-tab control. */}
      {showFilters && (
        <div class="header-controls left routing-filters" style="margin-bottom:14px">
          <div class="filter-group">
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
            value={search}
            onInput={(e) => onSearch(e.currentTarget.value)}
            placeholder="Filter by host or path…"
            label="Filter routes by host or path"
          />
        </div>
      )}

      {specs.length > 1 && (
        <div class="tabs" role="tablist">
          {specs.map((s) => {
            const issues = specHasIssues(s.spec);
            return (
              <button
                key={s.id}
                role="tab"
                aria-selected={s.id === activeId}
                class={`tab${s.id === activeId ? ' active' : ''}`}
                onClick={() => onTab(s.id)}
              >
                <span class={`tab-label ${issues ? 'warn' : 'ok'}`}>
                  <Icon name={issues ? 'alert' : 'check'} size={13} />
                  {s.label} ({blockTotal(s.spec)})
                </span>
              </button>
            );
          })}
        </div>
      )}

      {/* Pager ABOVE the (tall, host-grouped) table so the page controls + the
          "X–Y of N" count are reachable without scrolling past every row. */}
      {total > 0 && (
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

      <RouteSection
        spec={active.spec}
        kind={active.kind}
        highlight={highlight}
        filtered={filtered}
        scrollKey={`${activeId}-${offset}`}
      />
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
 *  (accepted-but-dead backend). Drives the tab alert icon. Conflicts are always
 *  returned whole (bounded), so that signal is complete; the dead-backend check
 *  sees only the current page, which is acceptable — the per-row endpoint health
 *  still flags dead backends wherever they land. */
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

function RouteSection({ spec, kind, highlight, filtered, scrollKey }) {
  // A routing conflict is a property of the host+path routing key (two routes
  // claim it; one is rejected) — not of a listener port. The shared proxy serves
  // the same routes on every listener, so the compiled table reports the *same*
  // conflict once per port (demo.local/ on :80 and :443); collapse those to the
  // one logical conflict. Genuinely distinct conflicts (a different rejected
  // group at the same path) have a different key and are kept.
  const conflicts = dedupeConflicts(spec?.conflicts ?? []);
  const wantPath  = highlight?.path || '/';

  // Flatten the host-grouped payload into one compact table. The backend orders
  // rows grouped by (port, host), so consecutive rows share a host — we blank the
  // repeated Host cell to keep the grouped reading without a sub-table per host
  // (that chrome was what made this screen so tall).
  const rows = [];
  for (const h of spec?.hosts ?? []) {
    for (const r of h.routes ?? []) rows.push({ ...r, host: h.host, port: h.port });
  }

  const openRoute = (r) =>
    kind === 'httproute' ? nav.httproute(r.namespace, r.name) : nav.ingressRoute(r.namespace, r.name);

  return (
    <>
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

      <Table
        columns={['Host', 'Port', 'Path', 'Type', 'Backend', 'Endpoints']}
        rows={rows}
        emptyMsg={filtered ? 'No routes match.' : 'No routes.'}
        scrollKey={scrollKey}
        renderRow={(r, i) => {
          // A compiled route serving zero ready endpoints is a dead backend —
          // amber (warn tier), the same left-edge accent the routing tables use,
          // never red (red is reserved for "down").
          const dead = (r.endpoints?.length ?? 0) === 0;
          const hit = highlight?.host === r.host && (r.path || '/') === wantPath;
          // The compiled table doesn't carry the source route's namespace/name,
          // so we only deep-link when identity is present — otherwise the row is
          // informational, never a link that resolves to nowhere.
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
    </>
  );
}
