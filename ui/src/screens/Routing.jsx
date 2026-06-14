import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { updateQuery } from '../router.js';
import { useSearch } from '../hooks/useSearch.js';
import { getRoutingSummary, getGateways, getHttproutes, getIngresses } from '../api/endpoints.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { SearchBox } from '../components/SearchBox.jsx';
import { FilterSelect } from '../components/FilterSelect.jsx';
import { Icon } from '../components/Icon.jsx';
import { useEffect } from 'preact/hooks';
import { GatewaysSection } from './Gateways.jsx';
import { HttproutesSection } from './Httproutes.jsx';
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
const TABS = [
  { key: 'gateways',   label: 'Gateways',   fetch: getGateways,   dataKey: 'gateways',   Section: GatewaysSection },
  { key: 'httproutes', label: 'HTTPRoutes', fetch: getHttproutes, dataKey: 'httproutes', Section: HttproutesSection },
  { key: 'ingresses',  label: 'Ingresses',  fetch: getIngresses,  dataKey: 'ingresses',  Section: IngressesSection },
];

export function Routing({ query }) {
  const summary = useApi(getRoutingSummary);
  const sse = useSSE('/api/v1/events');
  const cats = summary.data ?? {};

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
      list.refetch();
    });
    return off;
  }, [sse.subscribe, activeKey]);

  // Namespace options from the loaded rows; `?ns=` makes the choice permalinkable.
  const namespaces = [...new Set(rows.map((r) => r.namespace).filter(Boolean))].sort();
  const nsFilter = namespaces.includes(query?.ns) ? query.ns : 'all';

  const Section = active.Section;

  return (
    <div class="screen">
      <Breadcrumb items={[{ label: 'Routing' }, { label: 'Overview' }]} />

      <div class="tabs" role="tablist">
        {TABS.map((t) => {
          const cat = cats[t.key] ?? {};
          const warn = cat.worst && cat.worst !== 'ok';
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

      <div class="screen-header">
        <div class="header-controls left">
          <FilterSelect
            label="Filter by namespace"
            value={nsFilter}
            options={[{ value: 'all', label: 'All namespaces' }, ...namespaces.map((ns) => ({ value: ns, label: ns }))]}
            onChange={(e) => updateQuery({ ns: e.currentTarget.value === 'all' ? null : e.currentTarget.value })}
          />
          <SearchBox value={search} onInput={onSearch} label="Search routing by name" />
        </div>
      </div>

      <Section
        rows={rows}
        total={cats[active.key]?.total}
        loading={list.loading}
        error={list.error}
        q={q}
        ns={nsFilter}
      />
    </div>
  );
}
