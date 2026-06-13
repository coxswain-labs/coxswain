import { useApi } from '../hooks/useApi.js';
import { matchesSearch } from '../hooks/useSearch.js';
import { getIngresses } from '../api/endpoints.js';
import { nav } from '../router.js';
import { Badge } from '../components/Badge.jsx';
import { Card, CardHeader, CardFooter, CardGrid } from '../components/Card.jsx';
import { ErrorState, EmptyState } from '../components/Spinner.jsx';

/**
 * Ingresses section — a list of all Ingress resources the controller knows
 * about, each card linking to the Route Inspector. Rendered as a section within
 * the unified Routing screen (config axis) rather than as a standalone page.
 */
export function IngressesSection({ q = '' }) {
  const { data, loading, error } = useApi(getIngresses);
  const ingresses = (data?.ingresses ?? []).filter((ing) => matchesSearch(ing.name, 'ingress', q));

  return (
    <section aria-label="Ingresses">
      <div class="section-head">
        <h2 class="section-title">Ingresses</h2>
        <span class="section-count">{ingresses.length}</span>
        {loading && <span class="section-spinner" aria-label="Loading" />}
      </div>
      {error ? (
        <ErrorState error={error} />
      ) : ingresses.length === 0 && !loading ? (
        <EmptyState message={q ? 'No Ingresses match.' : 'No Ingresses found.'} />
      ) : (
        <CardGrid>
          {ingresses.map((ing) => (
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
