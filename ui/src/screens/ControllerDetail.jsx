import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getController, getControllerHealth, getControllers, getProxies } from '../api/endpoints.js';
import { nav } from '../router.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { Badge } from '../components/Badge.jsx';
import { DetailHeader } from '../components/DetailHeader.jsx';
import { PodInfo } from '../components/PodInfo.jsx';
import { PodActions } from '../components/PodActions.jsx';
import { PodHealthChips } from '../components/HealthChips.jsx';
import { Spinner, ErrorState, EmptyState } from '../components/Spinner.jsx';
import { useEffect } from 'preact/hooks';

/**
 * Controller detail screen — the runtime view of one controller pod.
 *
 * The counterpart to ProxyDetail. A controller has no routing table of its own
 * (routes live on the proxies, which watch Kubernetes independently), so the
 * page is about the controller's actual job: leadership, the per-resource
 * reconciler health checks, and the proxy fleet (the dedicated proxies it
 * provisions, plus the shared pool for context). Leader status refetches live
 * on `leader.changed`; the pool summary refetches on proxy connect/disconnect.
 */
export function ControllerDetail({ pod }) {
  const meta        = useApi(() => getController(pod), [pod]);
  const health      = useApi(() => getControllerHealth(pod), [pod]);
  const controllers = useApi(getControllers);
  const proxies     = useApi(getProxies);
  const sse         = useSSE('/api/v1/events');

  useEffect(() => {
    const off = sse.subscribe('leader.changed', () => {
      meta.refetch();
      controllers.refetch();
    });
    return off;
  }, [sse.subscribe]);

  useEffect(() => {
    const offs = [
      sse.subscribe('proxy.connected', () => proxies.refetch()),
      sse.subscribe('proxy.disconnected', () => proxies.refetch()),
    ];
    return () => offs.forEach((off) => off());
  }, [sse.subscribe]);

  const breadcrumb = [
    { label: 'Fleet', onClick: () => nav.fleet() },
    { label: 'Controllers', onClick: () => nav.fleet({ filter: 'controllers' }) },
    { label: pod },
  ];

  if (meta.loading) return <Spinner label="Loading controller…" />;
  if (meta.error)   return <ErrorState error={meta.error} />;
  if (!meta.data)   return <EmptyState message="Controller not found." />;

  const c = meta.data;
  const isReachable = c.reachable ?? false;

  // When this pod is a standby, surface who currently holds leadership so the
  // operator can jump straight to the controller that's actually writing status.
  const leaderPod = (controllers.data?.controllers ?? []).find(
    (x) => x.reachable && x.is_leader,
  )?.pod_name;
  const otherLeader = !c.is_leader && leaderPod && leaderPod !== pod ? leaderPod : null;

  // The proxy fleet: the shared pool plus the dedicated proxies, grouped by the
  // Gateway each one serves.
  const proxyList = proxies.data?.proxies ?? [];
  const sharedPool = proxyList.filter((p) => p.component === 'shared-proxy');
  const dedicatedPools = [...proxyList
    .filter((p) => p.component === 'dedicated-proxy')
    .reduce((m, p) => {
      const key = `${p.pod_namespace}/${p.gateway_ref ?? '—'}`;
      (m.get(key) ?? m.set(key, []).get(key)).push(p);
      return m;
    }, new Map())].sort(([a], [b]) => a.localeCompare(b));

  return (
    <div class="screen">
      <Breadcrumb items={breadcrumb} />

      <DetailHeader
        name={pod}
        namespace={c.pod_namespace}
        meta={otherLeader && (
          <div class="problem-card-meta">
            Leader: <a onClick={() => nav.controller(otherLeader)}>{otherLeader}</a>
          </div>
        )}
        badges={(
          <>
            <Badge variant={c.is_leader ? 'leader' : 'standby'}>
              {c.is_leader ? 'leader' : 'standby'}
            </Badge>
            {isReachable
              ? <Badge variant="ok">reachable</Badge>
              : <Badge variant="fail">unreachable</Badge>}
          </>
        )}
        actions={(
          <>
            <PodHealthChips health={health} />
            <PodActions namespace={c.pod_namespace} name={pod} />
          </>
        )}
      />

      <PodInfo detail={c} health={health} />

      {/* Proxy fleet — same card vocabulary as the Dashboard problem cards. */}
      <section aria-label="Proxy pools">
        <h2 class="section-title">Proxy pools</h2>
        <p class="section-desc">
          The cluster's proxy fleet — the shared pool and the dedicated pools the
          controller provisions.
        </p>
        {proxies.error ? (
          <ErrorState error={proxies.error} />
        ) : sharedPool.length === 0 && dedicatedPools.length === 0 ? (
          !proxies.loading && <EmptyState message="No proxy pods in the fleet." />
        ) : (
          <div class="problems-list">
            {sharedPool.length > 0 && (
              <PoolCard
                name="Shared pool"
                ns={sharedPool[0]?.pod_namespace}
                kind="Proxy (shared)"
                pods={sharedPool}
                onClick={() => nav.fleet({ filter: 'shared' })}
              />
            )}
            {dedicatedPools.map(([key, pods]) => {
              const [ns, gw] = key.split('/');
              return (
                <PoolCard
                  key={key}
                  name={gw}
                  ns={ns}
                  kind="Proxy (dedicated)"
                  pods={pods}
                  onClick={() => nav.gateway(ns, gw)}
                />
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}

/** One proxy pool, rendered on the same card vocabulary as the Dashboard
 *  problem cards: severity left-border + status badge, Namespace and Kind lines,
 *  and a pod-count rollup. Clicking drills into Fleet (shared) or Gateway
 *  (dedicated). Severity follows the Dashboard rules: red = unreachable pods,
 *  amber = degraded, neutral = healthy. */
function PoolCard({ name, ns, kind, pods, onClick }) {
  const unreachable = pods.filter((p) => !p.reachable).length;
  const degraded = pods.filter((p) => p.reachable && p.health === 'degraded').length;
  const summary = [`${pods.length} pod${pods.length !== 1 ? 's' : ''}`];
  if (unreachable) summary.push(`${unreachable} unreachable`);
  if (degraded) summary.push(`${degraded} degraded`);

  const variant = unreachable > 0 ? 'err' : degraded > 0 ? 'warn' : '';
  const status = unreachable > 0
    ? <Badge variant="fail">unreachable</Badge>
    : degraded > 0
      ? <Badge variant="warn">degraded</Badge>
      : <Badge variant="ok">healthy</Badge>;

  return (
    <div
      class={`problem-card ${variant} clickable`}
      role="button"
      tabIndex={0}
      onClick={onClick}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick(); } }}
    >
      <div class="problem-card-main">
        <div class="problem-card-head">
          <strong>{name}</strong>
          {status}
        </div>
        {ns && <div class="problem-card-meta">Namespace: <code>{ns}</code></div>}
        <div class="problem-card-meta">Kind: <code>{kind}</code></div>
        <div class="problem-card-detail">{summary.join(' · ')}</div>
      </div>
      <span class="problem-card-chevron" aria-hidden="true">→</span>
    </div>
  );
}
