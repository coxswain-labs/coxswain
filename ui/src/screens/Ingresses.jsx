import { matchesSearch } from '../hooks/useSearch.js';
import { nav } from '../router.js';
import { Badge } from '../components/Badge.jsx';
import { Card, CardHeader, CardFooter, CardGrid } from '../components/Card.jsx';
import { ErrorState, EmptyState } from '../components/Spinner.jsx';

/**
 * Ingresses section — a list of all Ingress resources the controller knows
 * about, each card linking to the Route Inspector. Presentational: the owning
 * Routing screen fetches the data and supplies the type/namespace/search
 * filters (see GatewaysSection).
 */
export function IngressesSection({ ingresses = [], loading = false, error = null, q = '', ns = 'all' }) {
  const shown = ingresses.filter(
    (ing) => (ns === 'all' || ing.namespace === ns) && matchesSearch(ing.name, 'ingress', q),
  );
  const filtering = q !== '' || ns !== 'all';

  return (
    <section aria-label="Ingresses">
      <div class="section-head">
        <h2 class="section-title">Ingresses</h2>
        <span class="section-count">{shown.length}</span>
        {loading && <span class="section-spinner" aria-label="Loading" />}
      </div>
      {error ? (
        <ErrorState error={error} />
      ) : shown.length === 0 && !loading ? (
        <EmptyState message={filtering ? 'No Ingresses match.' : 'No Ingresses found.'} />
      ) : (
        <CardGrid>
          {shown.map((ing) => (
            <IngressCard key={`${ing.namespace}/${ing.name}`} ing={ing} />
          ))}
        </CardGrid>
      )}
    </section>
  );
}

function IngressCard({ ing }) {
  return (
    <Card onClick={() => nav.ingressRoute(ing.namespace, ing.name)}>
      <CardHeader
        name={ing.name}
        badge={<Badge variant="neutral">ingress</Badge>}
      />
      <CardFooter
        left={`${ing.namespace} · ${ing.route_count ?? 0} rule${ing.route_count !== 1 ? 's' : ''}`}
      />
    </Card>
  );
}
