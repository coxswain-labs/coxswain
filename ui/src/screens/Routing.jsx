import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { updateQuery } from '../router.js';
import { useSearch } from '../hooks/useSearch.js';
import { getRoutingSummary, getGateways, getHttproutes, getIngresses, getProblems } from '../api/endpoints.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { SearchBox } from '../components/SearchBox.jsx';
import { ComboFilter } from '../components/ComboFilter.jsx';
import { Icon } from '../components/Icon.jsx';
import { useEffect } from 'preact/hooks';
import { problemRouteKeys, categoryHasProblem } from '../severity.js';
import { GatewaysSection } from './Gateways.jsx';
import { HttpRoutesSection } from './HttpRoutes.jsx';
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
  { key: 'httproutes', label: 'HTTPRoutes', fetch: getHttproutes, dataKey: 'httproutes', Section: HttpRoutesSection,  problemKind: 'HTTPRoute' },
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
  // Lazy-load only the active tab's list; refetch on tab switch + rebuild.
  const list = useApi(() => active.fetch(), [activeKey]);
  const rows = list.data?.[active.dataKey] ?? [];

  useEffect(() => {
    const off = sse.subscribe('rebuild.completed', () => {
      summary.refetch();
      problems.refetch();
      list.refetch();
    });
    return off;
  }, [sse.subscribe, activeKey]);

  // Namespace options from the loaded rows; `?ns=` makes the choice permalinkable.
  const namespaces = [...new Set(rows.map((r) => r.namespace).filter(Boolean))].sort();
  const nsFilter = namespaces.includes(query?.ns) ? query.ns : 'all';

  // Parent-Gateway filter, set by a Gateway row's "Routes →" deep-link. Only the
  // HTTPRoutes tab honours it; switching away clears it.
  const parent = activeKey === 'httproutes' ? (query?.parent ?? '') : '';

  const Section = active.Section;

  return (
    <div class="screen">
      <Breadcrumb items={[{ label: 'Routing' }, { label: 'Overview' }]} />

      {/* Filters are shared across all tabs (one namespace/search scope applied to
          whichever tab is active), so they sit above the tab bar — the tabs only
          switch which resource type the scope is viewed through. */}
      <div class="screen-header">
        <div class="header-controls left">
          <ComboFilter
            label="Filter by namespace"
            value={nsFilter}
            options={[{ value: 'all', label: 'All namespaces' }, ...namespaces.map((ns) => ({ value: ns, label: ns }))]}
            onChange={(v) => updateQuery({ ns: v === 'all' ? null : v })}
          />
          <SearchBox value={search} onInput={onSearch} label="Search routing by name" />
          {parent && (
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
          )}
        </div>
      </div>

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

      <Section
        rows={rows}
        total={cats[active.key]?.total}
        loading={list.loading}
        error={list.error}
        q={q}
        ns={nsFilter}
        parent={parent}
        problemKeys={problemKeys}
      />
    </div>
  );
}
