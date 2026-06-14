import { useState, useEffect, useCallback } from 'preact/hooks';

/**
 * One shared EventSource per URL, reference-counted across every `useSSE`
 * consumer. The always-mounted Nav opens the stream for its connection
 * indicator; screens that mount later piggyback on the same socket instead of
 * each opening their own. The source closes only when the last consumer
 * unmounts.
 */
const hubs = new Map(); // url -> hub

function getHub(url) {
  let hub = hubs.get(url);
  if (!hub) {
    hub = {
      url,
      es: null,
      refCount: 0,
      connected: false,
      stateSubs: new Set(),  // () => void — notified on connected change
      listeners: new Map(),  // eventName -> Set<wrapped handler>
    };
    hubs.set(url, hub);
  }
  return hub;
}

function notify(hub) {
  hub.stateSubs.forEach((fn) => fn());
}

function acquire(hub) {
  hub.refCount += 1;
  if (hub.es) return;
  const es = new EventSource(hub.url);
  hub.es = es;
  es.onopen  = () => { hub.connected = true;  notify(hub); };
  es.onerror = () => { hub.connected = false; notify(hub); };
  // Re-attach handlers registered before (re)connection.
  for (const [name, set] of hub.listeners) {
    for (const wrapped of set) es.addEventListener(name, wrapped);
  }
}

function release(hub) {
  hub.refCount -= 1;
  if (hub.refCount <= 0 && hub.es) {
    hub.es.close();
    hub.es = null;
    hub.connected = false;
  }
}

/**
 * Subscribe to the shared `/api/v1/events` SSE stream.
 *
 * Returns `{ connected, subscribe }`.
 * - `connected` — `true` while the shared EventSource is open.
 * - `subscribe(eventName, handler)` — register a handler for a *named* event
 *   (sent as `event: <name>` on the wire, so `onmessage` never fires); returns
 *   an unsubscribe function. `handler` receives the parsed JSON (or `null` on
 *   bad JSON).
 */
export function useSSE(url = '/api/v1/events') {
  const [connected, setConnected] = useState(() => getHub(url).connected);

  useEffect(() => {
    const hub = getHub(url);
    const onState = () => setConnected(hub.connected);
    hub.stateSubs.add(onState);
    acquire(hub);
    setConnected(hub.connected);
    return () => {
      hub.stateSubs.delete(onState);
      release(hub);
    };
  }, [url]);

  const subscribe = useCallback((eventName, handler) => {
    const hub = getHub(url);
    const wrapped = (evt) => {
      let data = null;
      try { data = JSON.parse(evt.data); } catch (_) { /* ignore */ }
      handler(data);
    };
    if (!hub.listeners.has(eventName)) hub.listeners.set(eventName, new Set());
    hub.listeners.get(eventName).add(wrapped);
    if (hub.es) hub.es.addEventListener(eventName, wrapped);
    return () => {
      hub.listeners.get(eventName)?.delete(wrapped);
      hub.es?.removeEventListener(eventName, wrapped);
    };
  }, [url]);

  return { connected, subscribe };
}
