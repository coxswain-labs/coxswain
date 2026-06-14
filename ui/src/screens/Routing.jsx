import { useApi } from '../hooks/useApi.js';
import { updateQuery } from '../router.js';
import { useSearch } from '../hooks/useSearch.js';
import { getGateways, getIngresses } from '../api/endpoints.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { SearchBox } from '../components/SearchBox.jsx';
import { FilterSelect } from '../components/FilterSelect.jsx';
import { GatewaysSection } from './Gateways.jsx';
import { IngressesSection } from './Ingresses.jsx';

/**
 * Routing — the unified live-configuration surface (config axis).
 *
 * One page for all routing resources: Gateways and Ingresses. A type filter
 * (All · Gateways · Ingresses) and a namespace filter narrow the view; the
 * choices are encoded in the hash query (`?filter=gateways`, `?ns=tenant-a`) so
 * the view is permalinkable. Routing owns the data fetch and computes the
 * namespace options, passing filtered lists down to the presentational
 * sections, which link into the existing detail screens (Gateway Detail, Route
 * Inspector). Chunk 4 replaces the flat sections with traffic trees.
 */
const FILTERS = [
  { value: 'all',       label: 'All types' },
  { value: 'gateways',  label: 'Gateways' },
  { value: 'ingresses', label: 'Ingresses' },
];

export function Routing({ query }) {
  const filter = FILTERS.some((f) => f.value === query?.filter) ? query.filter : 'all';
  const { search, q, onSearch } = useSearch(query);

  const gateways  = useApi(getGateways);
  const ingresses = useApi(getIngresses);
  const gwList  = gateways.data?.gateways ?? [];
  const ingList = ingresses.data?.ingresses ?? [];

  // Namespace options span every routing resource, independent of the type and
  // search filters, so the dropdown always offers the full set. `?ns=` makes the
  // choice permalinkable.
  const namespaces = [...new Set(
    [...gwList, ...ingList].map((r) => r.namespace).filter(Boolean),
  )].sort();
  const nsFilter = namespaces.includes(query?.ns) ? query.ns : 'all';

  return (
    <div class="screen">
      <Breadcrumb items={[{ label: 'Routing' }]} />
      <div class="screen-header">
        <div class="header-controls left">
          <FilterSelect
            label="Filter by namespace"
            value={nsFilter}
            options={[{ value: 'all', label: 'All namespaces' }, ...namespaces.map((ns) => ({ value: ns, label: ns }))]}
            onChange={(e) => updateQuery({ ns: e.currentTarget.value === 'all' ? null : e.currentTarget.value })}
          />
          <FilterSelect
            label="Filter routing resources by type"
            value={filter}
            options={FILTERS}
            onChange={(e) => updateQuery({ filter: e.currentTarget.value === 'all' ? null : e.currentTarget.value })}
          />
          <SearchBox value={search} onInput={onSearch} label="Search routing by name or type" />
        </div>
      </div>

      {filter !== 'ingresses' && (
        <GatewaysSection gateways={gwList} loading={gateways.loading} error={gateways.error} q={q} ns={nsFilter} />
      )}
      {filter !== 'gateways' && (
        <IngressesSection ingresses={ingList} loading={ingresses.loading} error={ingresses.error} q={q} ns={nsFilter} />
      )}
    </div>
  );
}
