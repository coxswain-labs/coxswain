import { updateQuery } from '../router.js';
import { useSearch } from '../hooks/useSearch.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { SearchBox } from '../components/SearchBox.jsx';
import { GatewaysSection } from './Gateways.jsx';
import { IngressesSection } from './Ingresses.jsx';

/**
 * Routing — the unified live-configuration surface (config axis).
 *
 * One page for all routing resources: Gateways and Ingresses. A segmented
 * filter (All · Gateways · Ingresses) narrows the view; the choice is encoded
 * in the hash query (`?filter=gateways`) so the view is permalinkable. Card
 * nodes link into the existing detail screens (Gateway Detail, Route
 * Inspector). Chunk 4 replaces the flat sections with traffic trees.
 */
const FILTERS = [
  { key: 'all',       label: 'All' },
  { key: 'gateways',  label: 'Gateways' },
  { key: 'ingresses', label: 'Ingresses' },
];

export function Routing({ query }) {
  const filter = FILTERS.some((f) => f.key === query?.filter) ? query.filter : 'all';
  const { search, q, onSearch } = useSearch(query);

  return (
    <div class="screen">
      <Breadcrumb items={[{ label: 'Routing' }]} />
      <div class="screen-header">
        <h1 class="screen-title">Routing</h1>
        <div class="header-controls">
          <div class="segmented" role="tablist" aria-label="Filter routing resources">
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
          <SearchBox value={search} onInput={onSearch} label="Search routing by name or type" />
        </div>
      </div>

      {filter !== 'ingresses' && <GatewaysSection q={q} />}
      {filter !== 'gateways' && <IngressesSection q={q} />}
    </div>
  );
}
