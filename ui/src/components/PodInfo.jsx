import { HealthChips } from './HealthChips.jsx';
import { Spinner, ErrorState, EmptyState } from './Spinner.jsx';

/**
 * Shared "Pod" section for the pod-detail pages (controller + proxy): the pod's
 * runtime facts (node, age, restarts, phase, admin endpoint, version) plus its
 * subsystem health. Both detail screens are pods, so this keeps them identical.
 *
 * @param detail the `get_controller`/`get_proxy` object (carries node, restarts,
 *               phase, created_at, pod_ip, admin_port, reachable)
 * @param health the `useApi` result for that pod's `/health` ({data,loading,error})
 */
export function PodInfo({ detail, health }) {
  const reachable = detail.reachable ?? false;
  const version = health?.data?.health?.version;
  const subsystems = health?.data?.health?.subsystems;
  const hasSubsystems = subsystems && Object.keys(subsystems).length > 0;

  const facts = [
    { label: 'Node', value: detail.node },
    { label: 'Age', value: formatAge(detail.created_at) },
    { label: 'Restarts', value: detail.restarts != null ? String(detail.restarts) : null, warn: detail.restarts > 0 },
    { label: 'Phase', value: detail.phase },
    { label: 'IP', value: detail.pod_ip },
    { label: 'Version', value: version ? `v${version}` : null },
  ].filter((f) => f.value != null && f.value !== '');

  return (
    <section aria-label="Pod">
      <h2 class="section-title">Pod</h2>
      <dl class="pod-facts">
        {facts.map((f) => (
          <div class="pod-fact" key={f.label}>
            <dt>{f.label}</dt>
            <dd><code class={f.warn ? 'warn' : ''}>{f.value}</code></dd>
          </div>
        ))}
      </dl>

      <h3 class="section-title pod-health-head">Health</h3>
      {!reachable ? (
        <EmptyState message="Pod is unreachable — no health to show." />
      ) : health?.loading ? (
        <Spinner label="Loading health…" />
      ) : health?.error ? (
        <ErrorState error={health.error} />
      ) : hasSubsystems ? (
        <>
          <p class="section-desc">
            Each subsystem this pod runs and its readiness checks — every check
            must pass for the subsystem to be ready. Green is all ready; amber
            lists the checks that aren't.
          </p>
          <HealthChips subsystems={subsystems} />
        </>
      ) : (
        <EmptyState message="No subsystem health reported." />
      )}
    </section>
  );
}

/** Compact relative age from an RFC 3339 timestamp, e.g. "3d", "5h", "12m". */
function formatAge(iso) {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}
