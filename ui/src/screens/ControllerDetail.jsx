import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getController, getControllerHealth } from '../api/endpoints.js';
import { nav } from '../router.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { Badge } from '../components/Badge.jsx';
import { CopyButton } from '../components/CopyButton.jsx';
import { HealthChips } from '../components/HealthChips.jsx';
import { Spinner, ErrorState, EmptyState } from '../components/Spinner.jsx';
import { useEffect } from 'preact/hooks';

/**
 * Controller detail screen — the runtime view of one controller pod.
 *
 * The counterpart to ProxyDetail. A controller has no routing table, so the
 * page is identity + leadership + subsystem health: the per-resource reconciler
 * checks (one per watched kind) plus the proxy-link check. That health is the
 * "is this controller actually reconciling" signal `kubectl` can't show. Leader
 * status refetches live on `leader.changed`.
 */
export function ControllerDetail({ pod }) {
  const meta   = useApi(() => getController(pod), [pod]);
  const health = useApi(() => getControllerHealth(pod), [pod]);
  const sse    = useSSE('/api/v1/events');

  useEffect(() => {
    const off = sse.subscribe('leader.changed', () => meta.refetch());
    return off;
  }, [sse.subscribe, meta.refetch]);

  const breadcrumb = [
    { label: 'Fleet', onClick: () => nav.fleet() },
    { label: pod },
  ];

  if (meta.loading) return <Spinner label="Loading controller…" />;
  if (meta.error)   return <ErrorState error={meta.error} />;
  if (!meta.data)   return <EmptyState message="Controller not found." />;

  const c = meta.data;
  const isReachable = c.reachable ?? false;

  return (
    <div class="screen">
      <Breadcrumb items={breadcrumb} />

      <div class="screen-header">
        <div class="detail-head">
          <div class="card-ns">{c.pod_namespace || '—'}</div>
          <div class="detail-title-row">
            <h1 class="screen-title">{pod}</h1>
            <CopyButton text={pod} label="Copy pod name" />
          </div>
          {c.pod_ip && <div class="screen-meta">{c.pod_ip}</div>}
        </div>
        <div class="header-badges">
          <Badge variant={c.is_leader ? 'leader' : 'standby'}>
            {c.is_leader ? 'leader' : 'standby'}
          </Badge>
          {isReachable
            ? <Badge variant="ok">reachable</Badge>
            : <Badge variant="fail">unreachable</Badge>}
          <span class={`sse-dot ${sse.connected ? 'live' : 'offline'}`} />
        </div>
      </div>

      {/* Subsystem health — per-resource reconciler checks + proxy link. */}
      <section aria-label="Subsystem health">
        <h2 class="section-title">Health</h2>
        {!isReachable ? (
          <EmptyState message="Controller is unreachable — no health to show." />
        ) : health.loading ? (
          <Spinner label="Loading health…" />
        ) : health.error ? (
          <ErrorState error={health.error} />
        ) : (
          <HealthChips subsystems={health.data?.health?.subsystems} />
        )}
      </section>
    </div>
  );
}
