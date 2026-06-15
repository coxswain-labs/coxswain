import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { updateQuery } from '../router.js';
import { useSearch } from '../hooks/useSearch.js';
import { getRoutingSummary, getGateways, getHttproutes, getIngresses, getProblems } from '../api/endpoints.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { SearchBox } from '../components/SearchBox.jsx';
import { ComboFilter } from '../components/ComboFilter.jsx';
import { Icon } from '../components/Icon.jsx';
import { PAGE_SIZES, Pager } from '../components/DataTable.jsx';
import { useElementHeight } from '../hooks/useElementHeight.js';
import { useEffect, useState } from 'preact/hooks';
import { problemRouteKeys, categoryHasProblem } from '../severity.js';
import { GatewaysSection } from './Gateways.jsx';
import { HttpRoutesSection } from './HTTPRoutes.jsx';
import { IngressesSection } from './Ingresses.jsx';

/**
 * Routing — the config axis, as tabs of scalable tables (#292/#293).
 *
 * Three typed tabs (Gateways · HTTPRoutes · Ingresses), each a `DataTable`. The
 * tab bar's per-tab count + warning icon come from the compact
 * `routing/summary` aggregate (cluster-wide, pagination-independent), so a
 * warned tab is honest even though only the active tab's full list is fetched.
 * The active tab is permalinked via `?tab=`; with none set, the view opens on
 * the first tab that has a problem, else Gateways. A shared namespace filter +
 * search narrow the active table.
 */
// `problemKind` is the route kind a tab's `/problems` overlay matches (Gateways
// warn on binding/condition status only — upstream-only — so they have none).
const TABS = [
  { key: 'gateways',   label: 'Gateways',   fetch: getGateways,   dataKey: 'gateways',   Section: GatewaysSection,    problemKind: null },
  { key: 'httproutes', label: 'HTTP Routes', fetch: getHttproutes, dataKey: 'httproutes', Section: HttpRoutesSection,  problemKind: 'HTTPRoute' },
  { key: 'ingresses',  label: 'Ingresses',  fetch: getIngresses,  dataKey: 'ingresses',  Section: IngressesSection,   problemKind: 'Ingress' },
];

export function Routing({ query }) {
  const summary = useApi(getRoutingSummary);
  const problems = useApi(getProblems);
  const sse = useSSE('/api/v1/events');
  const cats = summary.data ?? {};
  // Overlay the cross-proxy /problems aggregate onto the reflector status so
  // dedicated-gateway conflicts/dead-routes (absent from the controller's table)
  // surface in the per-row status and the tab warning icons.
  const problemKeys = problemRouteKeys(problems.data);

  // Active tab: explicit ?tab=, else the first tab with a problem, else Gateways.
  const explicit = TABS.find((t) => t.key === query?.tab);
  const firstProblem = TABS.find((t) => cats[t.key]?.worst && cats[t.key].worst !== 'ok');
  const activeKey = explicit?.key ?? firstProblem?.key ?? 'gateways';
  const active = TABS.find((t) => t.key === activeKey) ?? TABS[0];

  const { search, q, onSearch } = useSearch(query);

  // Namespace options come from the summary (cluster-wide): the list is now
  // paginated, so the current page can't enumerate every namespace. `?ns=` makes
  // the choice permalinkable.
  const namespaces = summary.data?.namespaces ?? [];
  const nsFilter = query?.ns ?? 'all';

  // Parent-Gateway filter, set by a Gateway row's "Routes →" deep-link. Only the
  // HTTPRoutes tab honours it; switching away clears it.
  const parent = activeKey === 'httproutes' ? (query?.parent ?? '') : '';

  // "Problems only" is client-side on the *effective* (overlaid) status — the
  // server's `?status=problem` can't see the cross-proxy /problems aggregate, so
  // filtering server-side would re-open the green-tick blind spot. It narrows the
  // current page.
  const problemsOnly = query?.problems === '1';

  // Server-side pagination: name search + namespace narrow the set server-side;
  // the window is limit/offset. Offset resets whenever the tab or a server-side
  // filter changes. `PAGE_SIZES` is shared with the per-proxy route table.
  const [pageSize, setPageSize] = useState(100);
  const [offset, setOffset] = useState(0);
  useEffect(() => {
    setOffset(0);
  }, [activeKey, q, nsFilter, pageSize]);

  const list = useApi(
    () =>
      active.fetch({
        name: q || undefined,
        namespace: nsFilter === 'all' ? undefined : nsFilter,
        limit: pageSize,
        offset,
      }),
    [activeKey, q, nsFilter, pageSize, offset],
  );
  const rows = list.data?.[active.dataKey] ?? [];

  useEffect(() => {
    const off = sse.subscribe('rebuild.completed', () => {
      summary.refetch();
      problems.refetch();
      list.refetch();
    });
    return off;
  }, [sse.subscribe, activeKey]);

  const page = {
    offset,
    returned: list.data?.returned ?? rows.length,
    total: list.data?.total ?? rows.length,
    pageSize,
    pageSizes: PAGE_SIZES,
    onPage: setOffset,
    onPageSize: setPageSize,
  };

  const Section = active.Section;

  // Measured height of the pinned controls bar → the table header docks just
  // below it instead of sliding up behind it as the rows scroll the window
  // (shared with ProxyDetail; see .routes-controls / .routes-screen).
  const [chromeRef, chromeH] = useElementHeight();

  return (
    <div class="screen routes-screen" style={`--routes-chrome-h:${chromeH}px`}>
      <Breadcrumb items={[{ label: 'Routing' }, { label: 'Overview' }]} />

      {/* Filters + tabs + pager are pinned to the top of the viewport so they
          stay reachable while the row list scrolls the window underneath — the
          same model as ProxyDetail (window scroll, no fixed-height inner box). */}
      <div class="routes-controls" ref={chromeRef}>
        {/* Filters are shared across all tabs (one namespace/search scope applied
            to whichever tab is active), so they sit above the tab bar — the tabs
            only switch which resource type the scope is viewed through. Scoping
            filters (namespace · problems-only) group left; free-text name search
            anchors right — the conventional toolbar split. */}
        <div class="header-controls left routing-filters">
          <div class="filter-group">
            <ComboFilter
              label="Filter by namespace"
              value={nsFilter}
              options={[{ value: 'all', label: 'All namespaces' }, ...namespaces.map((ns) => ({ value: ns, label: ns }))]}
              onChange={(v) => updateQuery({ ns: v === 'all' ? null : v })}
            />
            <button
              type="button"
              class={`toggle-pill${problemsOnly ? ' active' : ''}`}
              aria-pressed={problemsOnly}
              title="Show only resources that aren't fully serving traffic"
              onClick={() => updateQuery({ problems: problemsOnly ? null : '1' })}
            >
              <Icon name="alert" size={13} />
              Problems only
            </button>
          </div>
          <SearchBox value={search} onInput={onSearch} placeholder="Search by name…" label="Search routing by name" />
        </div>

        {/* Deep-link-driven parent filter sits on its own row below the toolbar —
            it's a transient, dismissable scope, not a standing filter control. */}
        {parent && (
          <div class="filter-row-below">
            <span class="active-filter" title="Filtered to routes attached to this Gateway">
              Parent: {parent}
              <button
                class="active-filter-x"
                aria-label="Clear parent filter"
                onClick={() => updateQuery({ parent: null })}
              >
                ×
              </button>
            </span>
          </div>
        )}

        <div class="tabs" role="tablist">
          {TABS.map((t) => {
            const cat = cats[t.key] ?? {};
            const warn =
              (cat.worst && cat.worst !== 'ok') ||
              (t.problemKind && categoryHasProblem(problems.data, t.problemKind));
            return (
              <button
                key={t.key}
                role="tab"
                aria-selected={t.key === activeKey}
                class={`tab${t.key === activeKey ? ' active' : ''}`}
                onClick={() => updateQuery({ tab: t.key })}
              >
                <span class={`tab-label ${warn ? 'warn' : 'ok'}`}>
                  <Icon name={warn ? 'alert' : 'check'} size={13} />
                  {t.label} ({cat.total ?? 0})
                </span>
              </button>
            );
          })}
        </div>

        {/* Pager ABOVE the (potentially long) table so the page controls + the
            "X–Y of N" count are reachable without scrolling past every row. The
            Section omits its own footer pager (hidePager) to avoid a double. */}
        {page.total > 0 && (
          <div class="pager-bar">
            <Pager page={page} />
          </div>
        )}
      </div>

      <Section
        rows={rows}
        total={list.data?.total}
        page={page}
        hidePager
        loading={list.loading}
        error={list.error}
        q={q}
        ns={nsFilter}
        parent={parent}
        problemsOnly={problemsOnly}
        problemKeys={problemKeys}
      />
    </div>
  );
}
