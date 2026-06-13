import { useState, useEffect, useRef } from 'preact/hooks';
import { Icon } from './Icon.jsx';

/**
 * Version "about" popover for the nav bar.
 *
 * An info button that opens a small dismissible popover listing the
 * deployment's versions. Read-only reference info, so it's a lightweight
 * popover (outside-click + Escape) rather than a focus-trapped modal. Versions
 * are passed in by the nav (single fetch); `rows` is easy to extend with proxy
 * versions / build SHA as that data becomes available.
 */
export function VersionInfo({ rows = [], class: className = '' }) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false); };
    const onOutside = (e) => { if (!wrapRef.current?.contains(e.target)) setOpen(false); };
    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onOutside);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onOutside);
    };
  }, [open]);

  return (
    <div class={`version-info ${className}`} ref={wrapRef}>
      <button
        type="button"
        class="version-info-btn"
        aria-label="Version information"
        aria-expanded={open}
        aria-haspopup="dialog"
        title="Version information"
        onClick={() => setOpen((o) => !o)}
      >
        <Icon name="info" size={18} />
      </button>
      {open && (
        <div class="version-popover" role="dialog" aria-label="Versions">
          <div class="version-popover-title">Versions</div>
          <dl class="version-list">
            {rows.map((r) => (
              <div class="version-row" key={r.label}>
                <dt>{r.label}</dt>
                <dd>{r.value ? `v${r.value}` : '—'}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}
