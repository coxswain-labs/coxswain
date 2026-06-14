import { useEffect } from 'preact/hooks';
import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getFleetSummary, getRoutingSummary, getProblems } from '../api/endpoints.js';
import { nav } from '../router.js';
import { ProblemsPanel } from '../components/ProblemsPanel.jsx';
import { Icon } from '../components/Icon.jsx';

/**
 * Dashboard — the landing screen.
 *
 * Overview tiles lead (at-a-glance fleet + routing scale), followed by the
 * severity-ordered `ProblemsPanel` (the merged Problems view). All three data
 * sources are compact, cluster-wide aggregates — the controller does the
 * counting and severity rollup server-side (#301), so the Dashboard never
 * downloads the full pod/resource lists. Live SSE events refresh them.
 */
export function Dashboard() {
  const fleet   = useApi(getFleetSummary);
  const routing = useApi(getRoutingSummary);
  const problems = useApi(getProblems);
  const sse     = useSSE('/api/v1/events');

  const refreshAll = () => {
    fleet.refetch();
    routing.refetch();
    problems.refetch();
  };

  // Routing config may change on rebuild; fleet membership on pod connect/leader.
  useEffect(() => {
    const offs = [
      sse.subscribe('rebuild.completed', refreshAll),
      sse.subscribe('proxy.connected', () => fleet.refetch()),
      sse.subscribe('proxy.disconnected', () => fleet.refetch()),
      sse.subscribe('controller.connected', () => fleet.refetch()),
      sse.subscribe('controller.disconnected', () => fleet.refetch()),
      sse.subscribe('leader.changed', () => { fleet.refetch(); problems.refetch(); }),
    ];
    return () => offs.forEach((off) => off());
  }, [sse.subscribe]);

  const f = fleet.data ?? {};
  const r = routing.data ?? {};
  const { fleet: fleetProblems = {}, routing: routeProblems = {} } = problems.data ?? {};
  const { leaderless = false, unreachable = [], degraded = [] } = fleetProblems;
  const { conflicts = [], dead_routes = [] } = routeProblems;

  // A category tile warns when its worst severity is anything but `ok` (the
  // server already folded routing conflicts/dead-routes into each resource's
  // status, so the tile needs no client-side route-problem derivation).
  const warnOf = (cat) => (cat && cat.worst && cat.worst !== 'ok' ? 'warn' : 'ok');
  const total = (cat) => cat?.total ?? 0;

  const stats = [
    { key: 'controllers', label: 'Controllers',      icon: 'server',     accent: 'var(--blue)',   value: total(f.controllers),       status: (leaderless || warnOf(f.controllers) === 'warn') ? 'warn' : 'ok', onClick: () => nav.fleet({ filter: 'controllers' }) },
    { key: 'shared',      label: 'Shared proxies',    icon: 'layers',     accent: 'var(--green)',  value: total(f.shared_proxies),    status: warnOf(f.shared_proxies),    onClick: () => nav.fleet({ filter: 'shared' }) },
    { key: 'dedicated',   label: 'Dedicated proxies', icon: 'box',        accent: 'var(--purple)', value: total(f.dedicated_proxies), status: warnOf(f.dedicated_proxies), onClick: () => nav.fleet({ filter: 'dedicated' }) },
    { key: 'gateways',    label: 'Gateways',          icon: 'git-branch', accent: 'var(--amber)',  value: total(r.gateways),          status: warnOf(r.gateways),          onClick: () => nav.routing({ tab: 'gateways' }) },
    { key: 'httproutes',  label: 'HTTPRoutes',        icon: 'route',      accent: 'var(--pink)',   value: total(r.httproutes),        status: warnOf(r.httproutes),        onClick: () => nav.routing({ tab: 'httproutes' }) },
    { key: 'ingresses',   label: 'Ingresses',         icon: 'log-in',     accent: 'var(--teal)',   value: total(r.ingresses),         status: warnOf(r.ingresses),         onClick: () => nav.routing({ tab: 'ingresses' }) },
  ];

  return (
    <div class="screen">
      <div class="screen-header">
        <h1 class="screen-title">Dashboard</h1>
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
        leaderGap={leaderless}
      />
    </div>
  );
}
