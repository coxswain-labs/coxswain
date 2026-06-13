import { useEffect } from 'preact/hooks';
import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import {
  getProxies,
  getControllers,
  getProblems,
  getCluster,
  getGateways,
  getIngresses,
} from '../api/endpoints.js';
import { nav } from '../router.js';
import { ProblemsPanel } from '../components/ProblemsPanel.jsx';
import { Icon } from '../components/Icon.jsx';

/**
 * Dashboard — the landing screen.
 *
 * Overview tiles lead (at-a-glance fleet + routing scale), followed by the
 * severity-ordered `ProblemsPanel` (the merged Problems view). Live SSE events
 * refresh both. Deep exploration lives on the Fleet (runtime) and Routing
 * (config) screens; this screen answers "is anything wrong, and how big is it"
 * in one view.
 */
export function Dashboard() {
  const proxies     = useApi(getProxies);
  const controllers = useApi(getControllers);
  const problems    = useApi(getProblems);
  const cluster     = useApi(getCluster);
  const gateways    = useApi(getGateways);
  const ingresses   = useApi(getIngresses);
  const sse         = useSSE('/api/v1/events');

  // Refresh on rebuild — routing config may have changed.
  useEffect(() => {
    const off = sse.subscribe('rebuild.completed', () => {
      problems.refetch();
      gateways.refetch();
      ingresses.refetch();
    });
    return off;
  }, [sse.subscribe]);

  // Refresh fleet counts on pod connect/disconnect.
  useEffect(() => {
    const offs = [
      sse.subscribe('proxy.connected',         () => proxies.refetch()),
      sse.subscribe('proxy.disconnected',      () => proxies.refetch()),
      sse.subscribe('controller.connected',    () => controllers.refetch()),
      sse.subscribe('controller.disconnected', () => controllers.refetch()),
      sse.subscribe('leader.changed',          () => controllers.refetch()),
    ];
    return () => offs.forEach((off) => off());
  }, [sse.subscribe]);

  const proxyList      = proxies.data?.proxies ?? [];
  const controllerList = controllers.data?.controllers ?? [];
  const clusterData    = cluster.data;
  const { conflicts = [], dead_routes = [] } = problems.data ?? {};

  const sharedProxies    = proxyList.filter((p) => p.component !== 'dedicated-proxy');
  const dedicatedProxies = proxyList.filter((p) => p.component === 'dedicated-proxy');

  const unreachable = [
    ...proxyList.filter((p) => !p.reachable),
    ...controllerList.filter((c) => !c.reachable),
  ];
  // Reachable pods self-reporting a non-ready subsystem (health rollup from the
  // list endpoints). Distinct from unreachable: these respond, but something
  // inside is impaired — the failing check rides along in `degraded_checks`.
  const degraded = [
    ...proxyList.filter((p) => p.reachable && p.health === 'degraded'),
    ...controllerList.filter((c) => c.reachable && c.health === 'degraded'),
  ];
  const leaderGap =
    controllerList.length > 0 &&
    !controllerList.some((c) => c.reachable && c.is_leader);

  // Per-tile health for the top-right status icon. Pod tiles warn on
  // unreachable/degraded (controllers also on a leader gap). Gateways warn on a
  // non-True Gateway condition OR a routing problem on a gateway route; ingresses
  // warn on a routing problem on an ingress route. `/problems` now tags each
  // conflict/dead route with `kind`, so route issues attribute to the right tile.
  const gatewayList  = gateways.data?.gateways ?? [];
  const ingressList  = ingresses.data?.ingresses ?? [];
  const podWarn = (pods) => pods.some((p) => !p.reachable || p.health === 'degraded');
  const routeWarn = (kind) =>
    conflicts.some((c) => c.kind === kind) || dead_routes.some((d) => d.kind === kind);
  const gatewayCondWarn =
    gatewayList.some((g) => (g.conditions ?? []).some((c) => c.status !== 'True'));

  const stats = [
    { key: 'controllers', label: 'Controllers',      icon: 'server',     accent: 'var(--blue)',   value: controllerList.length,  status: (leaderGap || podWarn(controllerList)) ? 'warn' : 'ok', onClick: () => nav.fleet({ filter: 'controllers' }) },
    { key: 'shared',      label: 'Shared proxies',    icon: 'layers',     accent: 'var(--green)',  value: sharedProxies.length,    status: podWarn(sharedProxies) ? 'warn' : 'ok',    onClick: () => nav.fleet({ filter: 'shared' }) },
    { key: 'dedicated',   label: 'Dedicated proxies', icon: 'box',        accent: 'var(--purple)', value: dedicatedProxies.length, status: podWarn(dedicatedProxies) ? 'warn' : 'ok', onClick: () => nav.fleet({ filter: 'dedicated' }) },
    { key: 'gateways',    label: 'Gateways',          icon: 'git-branch', accent: 'var(--amber)',  value: gatewayList.length,      status: (gatewayCondWarn || routeWarn('gateway')) ? 'warn' : 'ok', onClick: () => nav.routing({ filter: 'gateways' }) },
    { key: 'ingresses',   label: 'Ingresses',         icon: 'log-in',     accent: 'var(--teal)',   value: ingressList.length,      status: routeWarn('ingress') ? 'warn' : 'ok',      onClick: () => nav.routing({ filter: 'ingresses' }) },
  ];

  return (
    <div class="screen">
      <div class="screen-header">
        <h1 class="screen-title">Dashboard</h1>
        {clusterData && <span class="cluster-meta">{clusterData.kubernetes_version}</span>}
      </div>

      {/* Overview tiles first — compact at-a-glance scale; problems below. */}
      <div class="summary-grid" aria-label="Fleet and routing summary">
        {stats.map((s) => (
          <button key={s.key} type="button" class="stat" style={`--accent:${s.accent}`} onClick={s.onClick}>
            <span class={`stat-status ${s.status}`} title={s.status === 'warn' ? 'Needs attention' : 'Healthy'}>
              <Icon name={s.status === 'warn' ? 'alert' : 'check'} size={15} />
            </span>
            <span class="stat-icon"><Icon name={s.icon} /></span>
            <span class="stat-body">
              <span class="stat-value">{s.value}</span>
              <span class="stat-label">{s.label}</span>
            </span>
          </button>
        ))}
      </div>

      <ProblemsPanel
        conflicts={conflicts}
        dead_routes={dead_routes}
        unreachable={unreachable}
        degraded={degraded}
        leaderGap={leaderGap}
      />
    </div>
  );
}
