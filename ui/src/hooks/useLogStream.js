import { useState, useEffect, useRef, useCallback } from 'preact/hooks';

/**
 * Tail a pod's logs over a chunked NDJSON stream.
 *
 * Unlike `useSSE` (a shared, reference-counted, auto-reconnecting EventSource
 * for the singleton `/api/v1/events` feed), a log tail is *ephemeral* and bound
 * to one pod: it must start when the Logs dialog opens and fully stop when it
 * closes. So this hook owns a private `fetch()` + `AbortController` per mount —
 * aborting on unmount or URL change — and deliberately never auto-reconnects (a
 * reconnect would re-tail the last N lines and duplicate them).
 *
 * The controller relays kubelet's body byte-for-byte; coxswain logs JSON, so we
 * split on newlines and `JSON.parse` each line, keeping the raw text as a
 * fallback for non-JSON lines (and skipping the empty keepalive lines the
 * relay injects when idle).
 *
 * @param {string|null} url            the log-stream URL, or null/'' to stay idle
 * @param {{active?: boolean}} [opts]  `active=false` keeps the stream closed
 * @returns {{ lines: Array<{id:number,text:string,json:object|null}>,
 *             status: 'idle'|'connecting'|'streaming'|'closed'|'error',
 *             error: Error|null, clear: () => void }}
 */
export function useLogStream(url, { active = true } = {}) {
  const [lines, setLines]   = useState([]);
  const [status, setStatus] = useState('idle');
  const [error, setError]   = useState(null);
  const idRef = useRef(0);

  const clear = useCallback(() => setLines([]), []);

  useEffect(() => {
    if (!active || !url) {
      setStatus('idle');
      return undefined;
    }

    const ctrl = new AbortController();
    let cancelled = false;
    // A fresh URL (e.g. a new tail size) is a fresh view — drop the old buffer.
    setLines([]);
    setError(null);
    setStatus('connecting');

    (async () => {
      try {
        const res = await fetch(url, { signal: ctrl.signal });
        if (cancelled) return;
        if (!res.ok) {
          const err = new Error(`log stream failed: HTTP ${res.status}`);
          err.status = res.status;
          setError(err);
          setStatus('error');
          return;
        }
        if (!res.body) {
          setStatus('closed');
          return;
        }
        setStatus('streaming');

        const reader  = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';
        for (;;) {
          const { done, value } = await reader.read();
          if (done || cancelled) break;
          buf += decoder.decode(value, { stream: true });
          const parts = buf.split('\n');
          buf = parts.pop() ?? ''; // trailing partial line stays buffered
          const fresh = parts
            .filter((l) => l.length > 0) // skip injected keepalive blank lines
            .map((text) => ({ id: ++idRef.current, text, json: tryParse(text) }));
          if (fresh.length > 0) {
            setLines((ls) => [...ls, ...fresh].slice(-MAX_LINES));
          }
        }
        if (!cancelled) setStatus('closed');
      } catch (e) {
        // AbortError is the expected teardown path, not a failure.
        if (!cancelled && e.name !== 'AbortError') {
          setError(e);
          setStatus('error');
        }
      }
    })();

    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [url, active]);

  return { lines, status, error, clear };
}

/** Cap on retained lines — bounds memory on a chatty pod. */
const MAX_LINES = 2000;

function tryParse(text) {
  try {
    const v = JSON.parse(text);
    return v && typeof v === 'object' ? v : null;
  } catch {
    return null;
  }
}
