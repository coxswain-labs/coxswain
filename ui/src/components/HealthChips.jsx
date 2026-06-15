import { useState, useRef, useEffect } from 'preact/hooks';
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
/**
 * Display labels for the registered subsystem names. The wire names are
 * `controller` (the Kubernetes-watch/reflector subsystem) and `proxy` (the data
 * plane) — both misleading next to the controller *role* and the proxy *pool*,
 * so we relabel for display only; the registered names (and the
 * `is_subsystem_ready("controller")` gates) are unchanged.
 */
const LABELS = { controller: 'Cluster', proxy: 'Data plane' };

export function HealthChips({ subsystems }) {
  const entries = Object.entries(subsystems ?? {});
  if (entries.length === 0) {
    return <span class="health-chips-empty">No subsystem data.</span>;
  }
  return (
    <div class="health-subsystems">
      {entries.map(([name, snap]) => (
        <SubsystemRow key={name} label={LABELS[name] ?? name} snap={snap} />
      ))}
    </div>
  );
}

/**
 * Header-placed health chips for the pod-detail pages: renders nothing until the
 * pod's `/health` has subsystems (so an unreachable or still-loading pod shows no
 * chips — its reachability badge already covers that), then the same chips.
 */
export function PodHealthChips({ health }) {
  const subsystems = health?.data?.health?.subsystems;
  if (!subsystems || Object.keys(subsystems).length === 0) return null;
  return <HealthChips subsystems={subsystems} />;
}

function SubsystemRow({ label, snap }) {
  const checks = Object.entries(snap?.checks ?? {})
    .map(([cname, c]) => ({ name: cname, ready: stateOf(c?.state) === 'ready' }))
    // Failing checks first so they lead the dropdown.
    .sort((a, b) => Number(a.ready) - Number(b.ready) || a.name.localeCompare(b.name));
  const total = checks.length;
  const ready = checks.filter((c) => c.ready).length;
  const degraded = stateOf(snap?.state) !== 'ready' || ready < total;
  const [open, setOpen] = useState(false);
  const rootRef = useRef(null);

  // The checks open in a dropdown anchored under the chip; close on Escape or an
  // outside click (mirrors ComboFilter). The chip's amber icon/count already
  // flags a degraded subsystem at a glance, so the dropdown is opt-in detail
  // rather than auto-floating on load.
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => {
      if (e.key === 'Escape') setOpen(false);
    };
    const onOutside = (e) => {
      if (!rootRef.current?.contains(e.target)) setOpen(false);
    };
    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onOutside);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onOutside);
    };
  }, [open]);

  return (
    <div class={`health-sub ${degraded ? 'warn' : 'ok'}`} ref={rootRef}>
      <button
        type="button"
        class="health-sub-head"
        aria-expanded={open}
        aria-haspopup="true"
        disabled={total === 0}
        onClick={() => setOpen((o) => !o)}
      >
        <Icon name={degraded ? 'alert' : 'check'} size={14} />
        <span class="health-sub-name">{label}</span>
        <span class="health-sub-count">{ready}/{total}</span>
        {total > 0 && (
          <span class={`health-sub-caret${open ? ' open' : ''}`} aria-hidden="true">
            <Icon name="chevron-down" size={14} />
          </span>
        )}
      </button>
      {open && total > 0 && (
        <ul class="health-checks" role="menu">
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
