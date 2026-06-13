import { Badge } from './Badge.jsx';

/**
 * One subsystem row in the health grid.
 *
 * @param {string} name
 * @param {{ ready: boolean, message?: string }} snapshot
 */
export function HealthRow({ name, snapshot }) {
  const ready = snapshot?.ready ?? false;
  const state = ready ? 'ok' : 'fail';
  const variant = ready ? 'ok' : 'fail';
  const label = ready ? 'ready' : 'failing';
  const detail = snapshot?.message ?? '';

  return (
    <div class={`health-row ${state}`} role="row">
      <span class="health-name">{name}</span>
      <Badge variant={variant} label={label}>{label}</Badge>
      <span class="health-detail">{detail}</span>
    </div>
  );
}
