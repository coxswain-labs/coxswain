import { useState } from 'preact/hooks';
import { Icon } from './Icon.jsx';

/**
 * Per-subsystem health for a pod, shown as a collapsible row per subsystem.
 *
 * Each row summarises the subsystem — green check / amber alert plus an
 * `N/M ready` count — and expands to the full list of its checks (one per
 * watched Kubernetes kind for the controller subsystem; the routing-table load
 * for the proxy subsystem), each green/amber. Healthy subsystems collapse to a
 * quiet line; degraded ones auto-expand so the failing check is visible without
 * a click. Replaces the retired standalone Health page's flat per-check dump
 * (now per-pod and grouped).
 *
 * `subsystems` is the raw `/health` map: `{ name: { state: {state}, checks: { name: {state} } } }`.
 */
export function HealthChips({ subsystems }) {
  const entries = Object.entries(subsystems ?? {});
  if (entries.length === 0) {
    return <span class="health-chips-empty">No subsystem data.</span>;
  }
  return (
    <div class="health-subsystems">
      {entries.map(([name, snap]) => (
        <SubsystemRow key={name} name={name} snap={snap} />
      ))}
    </div>
  );
}

function SubsystemRow({ name, snap }) {
  const checks = Object.entries(snap?.checks ?? {})
    .map(([cname, c]) => ({ name: cname, ready: stateOf(c?.state) === 'ready' }))
    // Failing checks first so they lead the expanded list.
    .sort((a, b) => Number(a.ready) - Number(b.ready) || a.name.localeCompare(b.name));
  const total = checks.length;
  const ready = checks.filter((c) => c.ready).length;
  const degraded = stateOf(snap?.state) !== 'ready' || ready < total;
  const [open, setOpen] = useState(degraded);

  return (
    <div class={`health-sub ${degraded ? 'warn' : 'ok'}`}>
      <button
        type="button"
        class="health-sub-head"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <Icon name={degraded ? 'alert' : 'check'} size={14} />
        <span class="health-sub-name">{name}</span>
        <span class="health-sub-count">{ready}/{total} ready</span>
        {total > 0 && (
          <span class={`health-sub-caret${open ? ' open' : ''}`} aria-hidden="true">▸</span>
        )}
      </button>
      {open && total > 0 && (
        <ul class="health-checks">
          {checks.map((c) => (
            <li key={c.name} class={`health-check ${c.ready ? 'ok' : 'warn'}`}>
              <Icon name={c.ready ? 'check' : 'alert'} size={12} />
              <span>{c.name}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** A subsystem's state is `{state, reason?}`; a check's state is the bare string.
 *  Normalise both to the state string. */
function stateOf(st) {
  return typeof st === 'object' && st !== null ? st.state : st;
}
