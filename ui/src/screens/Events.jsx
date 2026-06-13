import { useState, useRef, useEffect, useCallback } from 'preact/hooks';
import { useSSE } from '../hooks/useSSE.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { formatEventDetail } from '../components/EventRow.jsx';

/**
 * Live event feed screen.
 *
 * Subscribes to all known SSE event types from `/api/v1/events`.
 * Features:
 * - Scrolling log — newest at top.
 * - Pause / resume (keeps accumulating while paused, shows "N buffered" badge).
 * - Clear.
 * - Type filter (multi-select checkboxes).
 * - Max 500 events in memory.
 *
 * Correct SSE payloads per events.rs wire contract are forwarded to
 * `formatEventDetail` for human-readable detail strings.
 */

const EVENT_TYPES = [
  'rebuild.completed',
  'proxy.connected',
  'proxy.disconnected',
  'controller.connected',
  'controller.disconnected',
  'leader.changed',
  'ownership.changed',
];

const MAX_EVENTS = 500;

export function Events() {
  const sse    = useSSE('/api/v1/events');
  const [events, setEvents]     = useState([]);
  const [paused, setPaused]     = useState(false);
  const [buffered, setBuffered]  = useState([]);
  const [filter, setFilter]     = useState(new Set(EVENT_TYPES));
  const counterRef = useRef(0);

  // A stable callback so subscribe is called once.
  const handleEvent = useCallback((type) => (data) => {
    const entry = {
      id: ++counterRef.current,
      ts: new Date().toLocaleTimeString(),
      type,
      detail: formatEventDetail(type, data),
      raw: data,
    };
    if (paused) {
      setBuffered((b) => [...b, entry].slice(-MAX_EVENTS));
    } else {
      setEvents((ev) => [entry, ...ev].slice(0, MAX_EVENTS));
    }
  }, [paused]);

  useEffect(() => {
    const offs = EVENT_TYPES.map((t) => sse.subscribe(t, handleEvent(t)));
    return () => offs.forEach((off) => off());
  }, [sse.subscribe, handleEvent]);

  function resume() {
    setEvents((ev) => [...buffered, ...ev].slice(0, MAX_EVENTS));
    setBuffered([]);
    setPaused(false);
  }

  function toggleType(type) {
    setFilter((f) => {
      const next = new Set(f);
      if (next.has(type)) next.delete(type); else next.add(type);
      return next;
    });
  }

  const visible = events.filter((e) => filter.has(e.type));

  return (
    <div class="screen">
      <Breadcrumb items={[{ label: 'Events' }]} />
      <div class="screen-header">
        <h1 class="screen-title">Events</h1>
        <div class="event-controls">
          {paused ? (
            <button class="btn" onClick={resume}>
              Resume {buffered.length > 0 && <span class="badge b-conflict">{buffered.length}</span>}
            </button>
          ) : (
            <button class="btn btn-secondary" onClick={() => setPaused(true)}>Pause</button>
          )}
          <button class="btn btn-secondary" onClick={() => { setEvents([]); setBuffered([]); }}>
            Clear
          </button>
        </div>
      </div>

      {/* Type filter */}
      <div class="ev-filter" aria-label="Event type filter">
        {EVENT_TYPES.map((t) => (
          <label key={t} class="ev-filter-chip">
            <input
              type="checkbox"
              checked={filter.has(t)}
              onChange={() => toggleType(t)}
              aria-label={`Show ${t} events`}
            />
            {t}
          </label>
        ))}
      </div>

      {/* Feed */}
      <div class="ev-feed" role="log" aria-live={paused ? 'off' : 'polite'} aria-label="Event log">
        {visible.length === 0 && (
          <div style="color:var(--muted);font-size:13px;padding:12px">
            {events.length === 0 ? 'Waiting for events…' : 'No events match the active filter.'}
          </div>
        )}
        {visible.map((e) => (
          <div key={e.id} class="ev-row">
            <span class="ev-time">{e.ts}</span>
            <span class="ev-type">{e.type}</span>
            <span class="ev-detail">{e.detail}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
