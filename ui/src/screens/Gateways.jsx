import { useApi } from '../hooks/useApi.js';
import { matchesSearch } from '../hooks/useSearch.js';
import { getGateways } from '../api/endpoints.js';
import { nav } from '../router.js';
import { Badge } from '../components/Badge.jsx';
import { Card, CardHeader, CardFooter, CardGrid } from '../components/Card.jsx';
import { StatusDot } from '../components/StatusDot.jsx';
import { ErrorState, EmptyState } from '../components/Spinner.jsx';

/**
 * Gateways section — a list of all Gateways the controller knows about, each
 * card linking to the Gateway detail. Rendered as a section within the unified
 * Routing screen (config axis) rather than as a standalone page.
 */
export function GatewaysSection({ q = '' }) {
  const { data, loading, error } = useApi(getGateways);
  const gateways = (data?.gateways ?? []).filter((gw) => matchesSearch(gw.name, 'gateway', q));

  return (
    <section aria-label="Gateways">
      <div class="section-head">
        <h2 class="section-title">Gateways</h2>
        <span class="section-count">{gateways.length}</span>
        {loading && <span class="section-spinner" aria-label="Loading" />}
      </div>
      {error ? (
        <ErrorState error={error} />
      ) : gateways.length === 0 && !loading ? (
        <EmptyState message={q ? 'No Gateways match.' : 'No Gateways found.'} />
      ) : (
        <CardGrid>
          {gateways.map((gw) => (
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
