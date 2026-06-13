import { Icon } from './Icon.jsx';

/**
 * Compact per-subsystem health, replacing the old tall row-per-check panel.
 *
 * One chip per subsystem: green check when ready, amber alert when not. A
 * degraded chip lists its failing check names inline, so the actionable detail
 * (which check broke) stays visible without a click — but a healthy fleet stays
 * a quiet single line instead of a stack of green rows. Same green/amber
 * vocabulary as the route tabs and the Dashboard.
 *
 * `subsystems` is the raw `/health` map: `{ name: { state: {state}, checks: { name: {state} } } }`.
 */
export function HealthChips({ subsystems }) {
  const entries = Object.entries(subsystems ?? {});
  if (entries.length === 0) {
    return <span class="health-chips-empty">No subsystem data.</span>;
  }
  return (
    <div class="health-chips">
      {entries.map(([name, snap]) => {
        const failing  = failingChecks(snap);
        const degraded = stateOf(snap?.state) !== 'ready' || failing.length > 0;
        return (
          <div key={name} class={`health-chip ${degraded ? 'warn' : 'ok'}`}>
            <Icon name={degraded ? 'alert' : 'check'} size={13} />
            <span class="health-chip-name">{name}</span>
            {degraded && failing.length > 0 && (
              <span class="health-chip-detail">{failing.join(', ')}</span>
            )}
          </div>
        );
      })}
    </div>
  );
}

/** A subsystem's state is `{state, reason?}`; a check's state is the bare string.
 *  Normalise both to the state string. */
function stateOf(st) {
  return typeof st === 'object' && st !== null ? st.state : st;
}

/** Names of this subsystem's checks that aren't `ready`. */
function failingChecks(snap) {
  return Object.entries(snap?.checks ?? {})
    .filter(([, c]) => stateOf(c?.state) !== 'ready')
    .map(([cname]) => cname);
}
