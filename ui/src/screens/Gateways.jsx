import { matchesSearch } from '../hooks/useSearch.js';
import { nav } from '../router.js';
import { Badge } from '../components/Badge.jsx';
import { Card, CardHeader, CardFooter, CardGrid } from '../components/Card.jsx';
import { StatusDot } from '../components/StatusDot.jsx';
import { ErrorState, EmptyState } from '../components/Spinner.jsx';

/**
 * Gateways section — a list of all Gateways the controller knows about, each
 * card linking to the Gateway detail. Presentational: the owning Routing screen
 * fetches the data and supplies the type/namespace/search filters, so a single
 * fetch backs both this and the Ingresses section and feeds the namespace
 * dropdown.
 */
export function GatewaysSection({ gateways = [], loading = false, error = null, q = '', ns = 'all' }) {
  const shown = gateways.filter(
    (gw) => (ns === 'all' || gw.namespace === ns) && matchesSearch(gw.name, 'gateway', q),
  );
  const filtering = q !== '' || ns !== 'all';

  return (
    <section aria-label="Gateways">
      <div class="section-head">
        <h2 class="section-title">Gateways</h2>
        <span class="section-count">{shown.length}</span>
        {loading && <span class="section-spinner" aria-label="Loading" />}
      </div>
      {error ? (
        <ErrorState error={error} />
      ) : shown.length === 0 && !loading ? (
        <EmptyState message={filtering ? 'No Gateways match.' : 'No Gateways found.'} />
      ) : (
        <CardGrid>
          {shown.map((gw) => (
            <GatewayCard key={`${gw.namespace}/${gw.name}`} gw={gw} />
          ))}
        </CardGrid>
      )}
    </section>
  );
}

function GatewayCard({ gw }) {
  const programmed = gw.conditions?.some((c) => c.type === 'Programmed' && c.status === 'True');
  const pool = gw.proxy?.pool ?? 'shared';
  return (
    <Card onClick={() => nav.gateway(gw.namespace, gw.name)}>
      <CardHeader
        name={gw.name}
        badge={<Badge variant={programmed ? 'ok' : 'fail'}>{programmed ? 'programmed' : 'not programmed'}</Badge>}
      />
      <CardFooter
        left={`${gw.namespace} · ${gw.route_count ?? 0} route${gw.route_count !== 1 ? 's' : ''} · ${pool}`}
        right={<StatusDot state={programmed ? 'ok' : 'err'} />}
      />
    </Card>
  );
}
