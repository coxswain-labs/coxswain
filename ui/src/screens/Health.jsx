import { useApi } from '../hooks/useApi.js';
import { getHealth, getProxies, getControllers, getProxyHealth, getControllerHealth } from '../api/endpoints.js';
import { HealthRow } from '../components/HealthRow.jsx';
import { Badge } from '../components/Badge.jsx';
import { Panel } from '../components/Panel.jsx';
import { Spinner, ErrorState, EmptyState } from '../components/Spinner.jsx';

/**
 * Health screen — the "why is /readyz failing?" view.
 *
 * Three sections:
 * 1. Cluster-wide `/api/v1/health` — subsystem grid for the local process.
 * 2. Per-proxy health (fanned out per-pod from `/proxies/{pod}/health`).
 * 3. Per-controller health.
 *
 * All fetches happen in parallel at mount. No auto-refresh (operators use
 * this to diagnose a stuck pod — a one-shot snapshot is clearest).
 */
export function Health() {
  const health      = useApi(getHealth);
  const proxies     = useApi(getProxies);
  const controllers = useApi(getControllers);

  if (health.loading) return <Spinner label="Loading health…" />;
  if (health.error)   return <ErrorState error={health.error} />;

  const subsystems = health.data?.subsystems ?? {};
  const version    = health.data?.version ?? '';

  return (
    <div class="screen">
      <div class="screen-header">
        <h1 class="screen-title">Health</h1>
        {version && <span class="cluster-meta">coxswain {version}</span>}
      </div>

      {/* Controller process subsystems */}
      <section aria-label="Controller subsystems">
        <h2 class="section-title">Controller subsystems</h2>
        <Panel>
          {Object.keys(subsystems).length === 0 ? (
            <EmptyState message="No subsystem data." />
          ) : (
            Object.entries(subsystems).map(([name, snap]) => (
              <HealthRow key={name} name={name} snapshot={snap} />
            ))
          )}
        </Panel>
      </section>

      {/* Per-proxy subsystems */}
      <section aria-label="Proxy subsystems">
        <div class="section-head">
          <h2 class="section-title">Proxy pods</h2>
          {proxies.loading && <span class="section-spinner" />}
        </div>
        {proxies.error && <ErrorState error={proxies.error} />}
        {(proxies.data?.proxies ?? []).map((p) => (
          <PodHealthPanel key={p.pod_name} pod={p} fetcher={getProxyHealth} />
        ))}
      </section>

      {/* Per-controller subsystems */}
      <section aria-label="Controller pods">
        <div class="section-head">
          <h2 class="section-title">Controller pods</h2>
          {controllers.loading && <span class="section-spinner" />}
        </div>
        {controllers.error && <ErrorState error={controllers.error} />}
        {(controllers.data?.controllers ?? []).map((c) => (
          <PodHealthPanel key={c.pod_name} pod={c} fetcher={getControllerHealth} />
        ))}
      </section>
    </div>
  );
}

function PodHealthPanel({ pod, fetcher }) {
  const health = useApi(() => fetcher(pod.pod_name), [pod.pod_name]);

  if (!pod.reachable) {
    return (
      <Panel title={pod.pod_name}>
        <Badge variant="fail">unreachable</Badge>
      </Panel>
    );
  }

  const subsystems = health.data?.health?.subsystems ?? {};

  return (
    <Panel title={pod.pod_name}>
      {health.loading && <span class="section-spinner" />}
      {health.error && <ErrorState error={health.error} />}
      {!health.loading && !health.error && Object.keys(subsystems).length === 0 && (
        <EmptyState message="No subsystem data." />
      )}
      {Object.entries(subsystems).map(([name, snap]) => (
        <HealthRow key={name} name={name} snapshot={snap} />
      ))}
    </Panel>
  );
}
