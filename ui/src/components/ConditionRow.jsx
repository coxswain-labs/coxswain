import { Badge } from './Badge.jsx';

/**
 * One Kubernetes status condition row.
 *
 * @param {{ type: string, status: string, reason?: string, message?: string }} condition
 */
export function ConditionRow({ condition }) {
  const isTrue = condition.status === 'True';
  const isUnknown = condition.status === 'Unknown';
  const variant = isTrue ? 'ok' : isUnknown ? 'neutral' : 'fail';
  const icon = isTrue ? '✔' : isUnknown ? '—' : '✖';

  return (
    <div class="cond-row">
      <Badge variant={variant} label={condition.status}>{icon}</Badge>
      <div class="cond-body">
        <div class="cond-name">{condition.type}</div>
        {condition.reason && (
          <div class="cond-detail">reason: {condition.reason}</div>
        )}
        {condition.message && condition.message !== condition.reason && (
          <div class="cond-detail">{condition.message}</div>
        )}
        {!condition.reason && !condition.message && (
          <div class="cond-detail" style="color:var(--muted)">no detail</div>
        )}
      </div>
    </div>
  );
}
