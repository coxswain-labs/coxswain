import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { logStreamUrl } from '../api/endpoints.js';
import { useLogStream } from '../hooks/useLogStream.js';
import { ErrorState } from './Spinner.jsx';

/**
 * Modal that tails a pod's logs, streamed through the controller
 * (`/api/v1/pods/{name}/logs`). Chrome and a11y (focus trap, Escape, backdrop
 * click, `role="dialog"`) mirror {@link ManifestDialog}; the body is a live log
 * pane instead of a static manifest.
 *
 * coxswain logs JSON, so each line is parsed and rendered structured (time,
 * level chip, message) and is level-filterable; non-JSON lines fall back to raw
 * text under an "other" bucket. Controls: tail size (re-opens the stream),
 * level filter, auto-scroll pause/resume, and clear. The stream is bound to
 * this dialog — it starts on open and is aborted on close.
 *
 * @param {string}   name     the pod name
 * @param {function} onClose  called when the dialog should be dismissed
 */
export function LogsDialog({ name, onClose }) {
  const [tail, setTail]       = useState(1000);
  const [follow, setFollow]   = useState(true); // auto-scroll to newest
  const [active, setActive]   = useState(new Set(LEVELS)); // visible levels
  const dialogRef = useRef(null);
  const closeRef  = useRef(null);
  const feedRef   = useRef(null);
  const titleId   = 'logs-dialog-title';

  const url = useMemo(() => logStreamUrl(name, { tail, follow: true }), [name, tail]);
  const { lines, status, error, clear } = useLogStream(url, { active: true });

  // Focus the close button on open.
  useEffect(() => { closeRef.current?.focus(); }, []);

  // Trap focus inside the dialog; Escape closes. (Mirrors ManifestDialog.)
  useEffect(() => {
    const el = dialogRef.current;
    if (!el) return undefined;
    const focusable = () =>
      Array.from(
        el.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'),
      ).filter((n) => !n.disabled);
    const onKey = (e) => {
      if (e.key === 'Escape') { onClose(); return; }
      if (e.key !== 'Tab') return;
      const nodes = focusable();
      if (nodes.length === 0) { e.preventDefault(); return; }
      const first = nodes[0];
      const last  = nodes[nodes.length - 1];
      if (e.shiftKey) {
        if (document.activeElement === first) { e.preventDefault(); last.focus(); }
      } else if (document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    el.addEventListener('keydown', onKey);
    return () => el.removeEventListener('keydown', onKey);
  }, [onClose]);

  const rows = useMemo(() => lines.map(toRow), [lines]);
  const visible = rows.filter((r) => active.has(r.level));

  // Auto-scroll to newest while following.
  useEffect(() => {
    if (follow && feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [visible.length, follow]);

  function toggleLevel(level) {
    setActive((s) => {
      const next = new Set(s);
      if (next.has(level)) next.delete(level); else next.add(level);
      return next;
    });
  }

  return (
    <>
      <div class="dialog-backdrop" aria-hidden="true" onClick={onClose} />
      <div ref={dialogRef} class="dialog logs-dialog" role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <div class="dialog-header">
          <div class="dialog-title-group">
            <span class="dialog-kind-badge">Logs</span>
            <h2 id={titleId} class="dialog-title">{name}</h2>
            <span class={`log-status log-status-${status}`}>{STATUS_LABEL[status] ?? status}</span>
          </div>
          <div class="dialog-actions">
            <label class="log-tail-label">
              tail
              <select
                class="log-tail-select"
                value={String(tail)}
                onChange={(e) => setTail(Number(e.currentTarget.value))}
                aria-label="Number of trailing lines"
              >
                {TAIL_OPTIONS.map((n) => <option key={n} value={String(n)}>{n}</option>)}
              </select>
            </label>
            <button
              class={follow ? 'btn btn-secondary' : 'btn'}
              onClick={() => setFollow((f) => !f)}
              aria-pressed={!follow}
            >
              {follow ? 'Pause' : 'Follow'}
            </button>
            <button class="btn btn-secondary" onClick={clear}>Clear</button>
            <button ref={closeRef} class="btn dialog-close" onClick={onClose} aria-label="Close logs dialog">✕</button>
          </div>
        </div>

        {/* Level filter */}
        <div class="log-filter" aria-label="Log level filter">
          {LEVELS.map((lvl) => (
            <label key={lvl} class="ev-filter-chip">
              <input
                type="checkbox"
                checked={active.has(lvl)}
                onChange={() => toggleLevel(lvl)}
                aria-label={`Show ${lvl} lines`}
              />
              {LEVEL_LABEL[lvl]}
            </label>
          ))}
        </div>

        <div class="dialog-body">
          {error && <ErrorState error={error} />}
          {!error && (
            <div ref={feedRef} class="log-feed" role="log" aria-live={follow ? 'polite' : 'off'} aria-label={`Logs for ${name}`}>
              {visible.length === 0 && (
                <div class="log-empty">
                  {lines.length === 0 ? 'Waiting for log lines…' : 'No lines match the active level filter.'}
                </div>
              )}
              {visible.map((r) => (
                <div key={r.id} class={`log-row log-${r.level}`} title={r.text}>
                  {r.time && <span class="log-time">{r.time}</span>}
                  <span class={`log-level log-level-${r.level}`}>{LEVEL_LABEL[r.level]}</span>
                  <span class="log-msg">{r.message}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// ── Line model ──────────────────────────────────────────────────────────────

const LEVELS = ['error', 'warn', 'info', 'debug', 'trace', 'other'];
const LEVEL_LABEL = {
  error: 'ERROR', warn: 'WARN', info: 'INFO', debug: 'DEBUG', trace: 'TRACE', other: 'other',
};
const TAIL_OPTIONS = [100, 1000, 5000];
const STATUS_LABEL = {
  idle: '', connecting: 'connecting…', streaming: 'live', closed: 'ended', error: 'error',
};

/**
 * Normalise one streamed line into a render row. Tolerant of unknown JSON
 * shapes: pulls level/timestamp/message from the common tracing-subscriber
 * field names, and falls back to raw text under the "other" bucket.
 */
function toRow(line) {
  const j = line.json;
  if (!j) return { id: line.id, level: 'other', time: '', message: line.text, text: line.text };
  const level   = normalizeLevel(j.level ?? j.severity);
  const time    = shortTime(j.timestamp ?? j.ts ?? j.time);
  const message = j.fields?.message ?? j.message ?? j.msg ?? line.text;
  return { id: line.id, level, time, message: String(message), text: line.text };
}

function normalizeLevel(raw) {
  const s = String(raw ?? '').toLowerCase();
  if (s === 'error' || s === 'err' || s === 'fatal' || s === 'critical') return 'error';
  if (s === 'warn' || s === 'warning') return 'warn';
  if (s === 'info') return 'info';
  if (s === 'debug') return 'debug';
  if (s === 'trace') return 'trace';
  return 'other';
}

/** Trim an ISO timestamp to its `HH:MM:SS` clock part, else pass through. */
function shortTime(ts) {
  if (!ts) return '';
  const s = String(ts);
  const m = s.match(/(\d{2}:\d{2}:\d{2})/);
  return m ? m[1] : s;
}
