import { useState, useEffect, useRef, useCallback } from 'preact/hooks';

/**
 * Subscribe to the `/api/v1/events` SSE stream.
 *
 * Returns `{ connected, subscribe }`.
 * - `connected` — `true` when the EventSource is open.
 * - `subscribe(eventName, handler)` — register a handler for a named event;
 *   returns an unsubscribe function.  Can be called multiple times for
 *   different event names.
 *
 * The EventSource uses *named* events (sent as `event: <name>` on the wire);
 * `EventSource.onmessage` only fires for unnamed events, so this hook wires
 * `addEventListener(name, …)` per subscription.
 *
 * The connection is opened once and shared across all subscribers.  On
 * unmount the source is closed.
 */
export function useSSE(url = '/api/v1/events') {
  const [connected, setConnected] = useState(false);
  const sourceRef = useRef(null);
  // Map of eventName → Set<handler>; kept as a ref so subscribe/unsubscribe
  // don't re-open the connection.
  const listenersRef = useRef(new Map());

  useEffect(() => {
    const es = new EventSource(url);
    sourceRef.current = es;

    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    // Attach each already-registered listener to the new EventSource.
    for (const [name, handlers] of listenersRef.current) {
      for (const handler of handlers) {
        es.addEventListener(name, handler);
      }
    }

    return () => {
      es.close();
      setConnected(false);
      sourceRef.current = null;
    };
  }, [url]);

  /**
   * Subscribe to a named SSE event.
   *
   * @param {string} eventName - e.g. "rebuild.completed"
   * @param {function} handler - called with the parsed JSON data object.
   *   Parsing errors are swallowed; `handler` receives `null` on bad JSON.
   * @returns {function} unsubscribe
   */
  const subscribe = useCallback((eventName, handler) => {
    const wrapped = (evt) => {
      let data = null;
      try { data = JSON.parse(evt.data); } catch (_) { /* ignore */ }
      handler(data);
    };

    if (!listenersRef.current.has(eventName)) {
      listenersRef.current.set(eventName, new Set());
    }
    listenersRef.current.get(eventName).add(wrapped);

    if (sourceRef.current) {
      sourceRef.current.addEventListener(eventName, wrapped);
    }

    return () => {
      listenersRef.current.get(eventName)?.delete(wrapped);
      sourceRef.current?.removeEventListener(eventName, wrapped);
    };
  }, []);

  return { connected, subscribe };
}
