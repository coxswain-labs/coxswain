import { nav } from '../router.js';
import { Badge } from './Badge.jsx';

/**
 * Problems-first landing panel.
 *
 * Shows the first N problems of each category; a "View all" link navigates to
 * the dedicated Problems screen.
 *
 * @param {{ conflicts, dead_routes }} problems - from /api/v1/problems
 * @param {Array} unreachable - unreachable proxy/controller entries
 * @param {boolean} leaderGap - true when no controller reports is_leader=true
 */
export function NeedsAttention({ problems, unreachable = [], leaderGap = false }) {
  const { conflicts = [], dead_routes = [] } = problems ?? {};
  const rows = [];

  // Leader gap is the highest-severity signal.
  if (leaderGap) {
    rows.push({
      key: 'leader-gap',
      variant: 'fail',
      icon: '🔴',
      title: 'No elected leader',
      detail: 'All controller pods show is_leader: false — election may be stalled.',
    });
  }

  // Unreachable pods.
  for (const pod of unreachable.slice(0, 3)) {
    rows.push({
      key: `unreachable-${pod.pod_name}`,
      variant: 'fail',
      icon: '🔴',
      title: `${pod.pod_name} unreachable`,
      detail: `${pod.component ?? 'pod'} did not respond to health probe`,
    });
  }

  // Routing conflicts.
  for (const c of conflicts.slice(0, 3)) {
    rows.push({
      key: `conflict-${c.host}-${c.path}`,
      variant: 'conflict',
      icon: '⚠',
      title: `Routing conflict: ${c.host}${c.path}`,
      detail: `${c.rejected_group} rejected (${c.pods?.length ?? '?'} proxy${(c.pods?.length ?? 0) !== 1 ? 'ies' : ''})`,
      onClick: () => nav.problems(),
    });
  }

  // Dead backends.
  for (const d of dead_routes.slice(0, 3)) {
    rows.push({
      key: `dead-${d.host}-${d.path}`,
      variant: 'dead',
      icon: '⚠',
      title: `Dead backend: ${d.host}${d.path}`,
      detail: `${d.backend_group} has 0 ready endpoints`,
      onClick: () => nav.problems(),
    });
  }

  const total =
    (leaderGap ? 1 : 0) + unreachable.length + conflicts.length + dead_routes.length;

  return (
    <div class="needs-attention" aria-label="Needs attention">
      <div class="needs-attention-header">
        <span class="needs-attention-title">
          {total === 0 ? '✓ All systems healthy' : `⚠ ${total} issue${total !== 1 ? 's' : ''} need attention`}
        </span>
        {total > 0 && (
          <a
            onClick={() => nav.problems()}
            aria-label="View all problems"
            style="font-size:12px"
          >
            View all →
          </a>
        )}
      </div>

      {rows.length === 0 ? (
        <div class="all-good" role="status" aria-live="polite">
          <span style="color:var(--green)">✔</span>
          No conflicts, no dead backends, all pods reachable, leader elected.
        </div>
      ) : (
        rows.map((r) => (
          <ProblemRow key={r.key} {...r} />
        ))
      )}
    </div>
  );
}

function ProblemRow({ variant, icon, title, detail, onClick }) {
  return (
    <div
      class="problem-row"
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onClick={onClick}
      onKeyDown={onClick ? (e) => { if (e.key === 'Enter') onClick(); } : undefined}
      style={onClick ? 'cursor:pointer' : undefined}
    >
      <span class="problem-icon" aria-hidden="true">{icon}</span>
      <div class="problem-body">
        <div class="problem-title">{title}</div>
        <div class="problem-detail">{detail}</div>
      </div>
    </div>
  );
}
