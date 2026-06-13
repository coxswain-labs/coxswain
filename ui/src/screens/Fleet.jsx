import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getProxies, getControllers, getProblems, getCluster } from '../api/endpoints.js';
import { nav } from '../router.js';
import { NeedsAttention } from '../components/NeedsAttention.jsx';
import { Badge, poolBadge } from '../components/Badge.jsx';
import { Card, CardHeader, CardFooter, CardGrid } from '../components/Card.jsx';
import { ReachableDot } from '../components/StatusDot.jsx';
import { Spinner, ErrorState } from '../components/Spinner.jsx';
import { useEffect } from 'preact/hooks';

/**
 * Fleet landing screen.
 *
 * Loads in parallel: problems summary, proxies, controllers, cluster info.
 * Problems panel leads; inventory cards follow. Live SSE events trigger a
 * re-fetch on `rebuild.completed` so the card grid reflects the current state.
 */
export function Fleet() {
  const proxies    = useApi(getProxies);
  const controllers = useApi(getControllers);
  const problems   = useApi(getProblems);
  const cluster    = useApi(getCluster);
  const sse        = useSSE('/api/v1/events');

  // Refresh fleet cards on rebuild.
  useEffect(() => {
    const off = sse.subscribe('rebuild.completed', () => {
      proxies.refetch();
      controllers.refetch();
      problems.refetch();
    });
    return off;
  }, [sse.subscribe]);

  // Also update cards when pods connect/disconnect.
  useEffect(() => {
    const unproxy = sse.subscribe('proxy.connected',      () => proxies.refetch());
    const undisco  = sse.subscribe('proxy.disconnected',  () => proxies.refetch());
    const unctrl   = sse.subscribe('controller.connected', () => controllers.refetch());
    const uncdisco = sse.subscribe('controller.disconnected', () => controllers.refetch());
    return () => { unproxy(); undisco(); unctrl(); uncdisco(); };
  }, [sse.subscribe]);

  const proxyList      = proxies.data?.proxies ?? [];
  const controllerList = controllers.data?.controllers ?? [];
  const clusterData    = cluster.data;

  // Derive signals for NeedsAttention from already-fetched data.
  const unreachable = [
    ...proxyList.filter((p) => !p.reachable),
    ...controllerList.filter((c) => !c.reachable),
  ];
  const leaderGap =
    controllerList.length > 0 &&
    !controllerList.some((c) => c.reachable && c.is_leader);

  const anyLoading = proxies.loading || controllers.loading || problems.loading;
  const anyError   = proxies.error || controllers.error;

  return (
    <div class="screen">
      <div class="screen-header">
        <h1 class="screen-title">Fleet</h1>
        <span class={`sse-dot ${sse.connected ? 'live' : 'offline'}`} title={sse.connected ? 'Live' : 'Disconnected'} />
        {clusterData && (
          <span class="cluster-meta">{clusterData.kubernetes_version}</span>
        )}
      </div>

      {/* Problems-first panel — always rendered, even if empty */}
      <NeedsAttention
        problems={problems.data}
        unreachable={unreachable}
        leaderGap={leaderGap}
      />

      {/* Proxy inventory */}
      <section aria-label="Proxy pods">
        <div class="section-head">
          <h2 class="section-title">Proxies</h2>
          {proxies.loading && <span class="section-spinner" aria-label="Loading" />}
        </div>
        {proxies.error ? (
          <ErrorState error={proxies.error} />
        ) : (
          <CardGrid>
            {proxyList.map((p) => (
              <ProxyCard key={p.pod_name} proxy={p} />
            ))}
            {!proxies.loading && proxyList.length === 0 && (
              <div style="color:var(--muted);font-size:13px">No proxy pods found.</div>
            )}
          </CardGrid>
        )}
      </section>

      {/* Controller inventory */}
      <section aria-label="Controller pods">
        <div class="section-head">
          <h2 class="section-title">Controllers</h2>
          {controllers.loading && <span class="section-spinner" aria-label="Loading" />}
        </div>
        {controllers.error ? (
          <ErrorState error={controllers.error} />
        ) : (
          <CardGrid>
            {controllerList.map((c) => (
              <ControllerCard key={c.pod_name} controller={c} />
            ))}
            {!controllers.loading && controllerList.length === 0 && (
              <div style="color:var(--muted);font-size:13px">No controller pods found.</div>
            )}
          </CardGrid>
        )}
      </section>
    </div>
  );
}

function ProxyCard({ proxy }) {
  if (!proxy.reachable) {
    return (
      <Card error>
        <CardHeader
          name={proxy.pod_name}
          badge={<Badge variant="fail">unreachable</Badge>}
        />
        <CardFooter left="did not respond" right={<ReachableDot reachable={false} />} />
      </Card>
    );
  }

  const pool = proxy.component === 'dedicated-proxy' ? 'dedicated' : 'shared';
  return (
    <Card onClick={() => nav.proxy(proxy.pod_name)}>
      <CardHeader
        name={proxy.pod_name}
        badge={poolBadge(pool)}
      />
      <CardFooter
        left={`${proxy.pod_ip ?? ''}${proxy.gateway_ref ? ` · ${proxy.gateway_ref}` : ''}`}
        right={<ReachableDot reachable />}
      />
    </Card>
  );
}

function ControllerCard({ controller }) {
  if (!controller.reachable) {
    return (
      <Card error>
        <CardHeader
          name={controller.pod_name}
          badge={<Badge variant="fail">unreachable</Badge>}
        />
        <CardFooter left="did not respond" right={<ReachableDot reachable={false} />} />
      </Card>
    );
  }

  return (
    <Card onClick={() => nav.controller(controller.pod_name)}>
      <CardHeader
        name={controller.pod_name}
        badge={<Badge variant={controller.is_leader ? 'leader' : 'standby'}>
          {controller.is_leader ? 'leader' : 'standby'}
        </Badge>}
      />
      <CardFooter
        left={controller.pod_ip ?? ''}
        right={<ReachableDot reachable />}
      />
    </Card>
  );
}
