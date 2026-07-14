import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getTopology, getFleetSummary, getControllers } from '../api/endpoints.js';
import { nav } from '../router.js';
import { Spinner } from '../components/Spinner.jsx';

/**
 * Topology — discovery convergence canvas.
 *
 * Layout: controller at top-center; scope groups (cluster shared pool +
 * per-namespace Gateway groups) in a horizontal flex row below. SVG bezier
 * edges show the gRPC push path from the controller to each proxy node.
 *
 * Data flow is unidirectional: controller → proxy (push). Proxies ACK each
 * snapshot; no proxy-to-proxy or proxy-to-controller traffic exists.
 */
export function Topology() {
  const topo    = useApi(getTopology);
  const summary = useApi(getFleetSummary);
  const ctrls   = useApi(getControllers);
  const sse     = useSSE('/api/v1/events');

  const refetchAll = () => { topo.refetch(); summary.refetch(); ctrls.refetch(); };
  useEffect(() => {
    const offs = [
      sse.subscribe('rebuild.completed',  refetchAll),
      sse.subscribe('proxy.connected',    refetchAll),
      sse.subscribe('proxy.disconnected', refetchAll),
    ];
    return () => offs.forEach((off) => off());
  }, [sse.subscribe]);

  if (topo.loading && !topo.data) {
    return (
      <div class="screen">
        <Spinner label="Loading topology…" />
      </div>
    );
  }

  if (topo.error) {
    return (
      <div class="screen">
        <p class="error-msg">Failed to load topology data.</p>
      </div>
    );
  }

  const { discovery_active, controller_version, nodes = [] } = topo.data ?? {};
  const allInSync = summary.data?.all_in_sync ?? true;

  // Control plane: leader (the snapshot source) + any standbys. Falls back to a
  // single synthetic controller when fleet/controllers isn't available (dev).
  const controllers = (ctrls.data?.controllers ?? []).map((c) => ({
    name:      c.pod_name,
    leader:    c.is_leader === true,
    reachable: c.reachable !== false,
    degraded:  (c.degraded_checks?.length ?? 0) > 0 || c.health === 'degraded',
  }));

  const notice = discovery_active && !allInSync
    ? "A proxy hasn't Ack'd the latest snapshot — re-converging…"
    : null;

  return (
    <div class="screen topo-screen">
      <div class="topo-canvas">
        {discovery_active === false && (
          <p class="topo-empty">Discovery not active in dev mode.</p>
        )}
        {discovery_active && nodes.length === 0 && (
          <p class="topo-empty">No proxies connected yet.</p>
        )}
        {discovery_active && nodes.length > 0 && (
          <ZoomCanvas notice={notice}>
            <TopoGraph
              controllerVersion={controller_version}
              controllers={controllers}
              nodes={nodes}
            />
          </ZoomCanvas>
        )}
      </div>
    </div>
  );
}

/**
 * Partition the flat node list into the N-tier shape the graph renders (#585).
 *
 * A node with `parent == null` sits one hop below the controller — a directly
 * connected proxy OR a relay (`is_relay`). A node with a `parent` is a leaf
 * folded from that relay's RosterReport and hangs under the relay's card. No
 * scope kind is dropped: unrecognised kinds land in an "Other" column so a new
 * scope always stays visible.
 */
function tierModel(nodes) {
  const childrenByParent = new Map();
  for (const n of nodes) {
    if (n.parent) {
      if (!childrenByParent.has(n.parent)) childrenByParent.set(n.parent, []);
      childrenByParent.get(n.parent).push(n);
    }
  }
  const topLevel = nodes.filter((n) => !n.parent);

  // Direct (non-relay) proxies keep the pre-#585 grouping.
  const sharedDirect = topLevel.filter((n) => !n.is_relay && n.scope?.kind === 'SharedPool');
  const nsMap = new Map(); // namespace → gatewayName → nodes[]
  for (const n of topLevel.filter((n) => !n.is_relay && n.scope?.kind === 'Gateway')) {
    const { namespace, name } = n.scope;
    if (!nsMap.has(namespace)) nsMap.set(namespace, new Map());
    const gwMap = nsMap.get(namespace);
    if (!gwMap.has(name)) gwMap.set(name, []);
    gwMap.get(name).push(n);
  }
  // Relays each become their own column, children nested below.
  const relays = topLevel.filter((n) => n.is_relay);
  // Anything else (a future scope kind) — surfaced, never silently dropped.
  const other = topLevel.filter(
    (n) => !n.is_relay && n.scope?.kind !== 'SharedPool' && n.scope?.kind !== 'Gateway',
  );

  return { childrenByParent, sharedDirect, nsMap, relays, other };
}

/** Human label for a relay column, from its subscription scope. */
function relayLabel(node) {
  if (node.scope?.kind === 'Namespace') return `Relay · ${node.scope.namespace}`;
  if (node.scope?.kind === 'SharedPool') return 'Relay · Shared pool';
  return 'Relay';
}

const PAN_STEP = 80;

/** Pannable + zoomable canvas. Wheel zooms toward cursor; drag background to pan. */
function ZoomCanvas({ children, notice }) {
  const vp   = useRef(null);
  const sv   = useRef({ scale: 1, panX: 0, panY: 0 });
  const drag = useRef(null);
  const [disp, setDisp] = useState({ scale: 1, panX: 0, panY: 0 });

  const commit = (next) => { sv.current = next; setDisp(next); };

  // Wheel must be non-passive to call preventDefault (stops page scroll).
  useEffect(() => {
    const el = vp.current;
    if (!el) return;
    const onWheel = (e) => {
      e.preventDefault();
      const { scale, panX, panY } = sv.current;
      const rect = el.getBoundingClientRect();
      const cx   = e.clientX - rect.left;
      const cy   = e.clientY - rect.top;
      // Normalise across wheel modes (pixel/line/page) then clamp to avoid
      // huge jumps on momentum scrolling. Each 100px ≈ 10% scale change.
      const px      = e.deltaMode === 1 ? e.deltaY * 30 : e.deltaMode === 2 ? e.deltaY * 600 : e.deltaY;
      const clamped = Math.max(-150, Math.min(150, px));
      const f       = Math.exp(-clamped * 0.001);
      const next    = Math.max(0.15, Math.min(6, scale * f));
      commit({ scale: next, panX: cx - (cx - panX) * (next / scale), panY: cy - (cy - panY) * (next / scale) });
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, []);

  const onMouseDown = (e) => {
    if (e.button !== 0) return;
    // Only drag on the background — don't eat clicks on cards or controls.
    if (e.target.closest('.topo-topbar, .topo-proxy-card, .topo-ctrl-card')) return;
    const { panX, panY } = sv.current;
    drag.current = { ox: e.clientX - panX, oy: e.clientY - panY };
  };
  const onMouseMove = (e) => {
    if (!drag.current) return;
    commit({ ...sv.current, panX: e.clientX - drag.current.ox, panY: e.clientY - drag.current.oy });
  };
  const stopDrag = () => { drag.current = null; };

  // Center content in the viewport (used on mount and reset).
  const centerContent = () => {
    const el = vp.current;
    if (!el) return;
    const t = el.querySelector('.topo-transform');
    if (!t) return;
    const vw = el.offsetWidth, vh = el.offsetHeight;
    const cw = t.offsetWidth,  ch = t.offsetHeight;
    commit({ scale: 1, panX: Math.max(24, (vw - cw) / 2), panY: Math.max(24, (vh - ch) / 2) });
  };

  // Centre once after the first render (children lay out before this fires).
  useLayoutEffect(centerContent, []); // eslint-disable-line react-hooks/exhaustive-deps

  const zoomCenter = (f) => {
    if (!vp.current) return;
    const { scale, panX, panY } = sv.current;
    const vw = vp.current.offsetWidth / 2, vh = vp.current.offsetHeight / 2;
    const next = Math.max(0.15, Math.min(6, scale * f));
    commit({ scale: next, panX: vw - (vw - panX) * (next / scale), panY: vh - (vh - panY) * (next / scale) });
  };

  const panBy = (dx, dy) => {
    commit({ ...sv.current, panX: sv.current.panX + dx, panY: sv.current.panY + dy });
  };

  const { scale, panX, panY } = disp;

  return (
    <div
      class="topo-viewport"
      ref={vp}
      onMouseDown={onMouseDown}
      onMouseMove={onMouseMove}
      onMouseUp={stopDrag}
      onMouseLeave={stopDrag}
    >
      {/* Top bar: floating controls + (optional) lag notice to their right. */}
      <div class="topo-topbar">
        <div class="topo-zoom-controls">
          <button class="topo-zoom-btn" onClick={() => panBy(PAN_STEP, 0)} title="Pan left">←</button>
          <button class="topo-zoom-btn" onClick={() => panBy(-PAN_STEP, 0)} title="Pan right">→</button>
          <button class="topo-zoom-btn" onClick={() => panBy(0, PAN_STEP)} title="Pan up">↑</button>
          <button class="topo-zoom-btn" onClick={() => panBy(0, -PAN_STEP)} title="Pan down">↓</button>
          <span class="topo-ctrl-sep" />
          <button class="topo-zoom-btn" onClick={() => zoomCenter(1.25)} title="Zoom in">+</button>
          <span class="topo-zoom-level">{Math.round(scale * 100)}%</span>
          <button class="topo-zoom-btn" onClick={() => zoomCenter(1 / 1.25)} title="Zoom out">−</button>
          <span class="topo-ctrl-sep" />
          <button class="topo-zoom-btn" onClick={centerContent} title="Reset view">↺</button>
        </div>
        {notice && (
          <div class="topo-banner" role="alert" aria-live="polite">{notice}</div>
        )}
      </div>

      {/* Transformed content — drag only starts on background, not on cards */}
      <div
        class="topo-transform"
        style={`transform: translate(${panX}px, ${panY}px) scale(${scale}); transform-origin: 0 0;`}
      >
        {children}
      </div>
    </div>
  );
}

/**
 * Graph canvas: controller at top-center, scope groups in a horizontal row.
 *
 * Edge coordinates use offsetLeft/offsetTop (CSS pixels, transform-agnostic)
 * so they stay accurate at any zoom level without knowing the current scale.
 */
function TopoGraph({ controllerVersion, controllers, nodes }) {
  const graphRef  = useRef(null);
  const ctrlRef   = useRef(null);
  const proxyRefs = useRef({});
  const lastStr   = useRef('');
  const [edges, setEdges] = useState([]);

  const { childrenByParent, sharedDirect, nsMap, relays, other } = tierModel(nodes);

  // The leader is the sole snapshot source — edges originate there. Fall back to
  // a single synthetic "Controller" when the fleet list is empty (dev mode).
  const ctrlList = controllers.length > 0
    ? controllers
    : [{ name: null, leader: true, reachable: true, degraded: false }];
  // Standbys fill a horizontal top row; the leader sits centered in the row
  // below. Edges originate from the leader (the bottom-most card) and drop
  // straight down to the proxies without crossing the standbys.
  const leader   = ctrlList.find((c) => c.leader);
  const standbys = ctrlList
    .filter((c) => !c.leader)
    .sort((a, b) => (a.name ?? '').localeCompare(b.name ?? ''));

  // Edges: controller → every top-level node (direct proxy or relay), and each
  // relay → each of its folded leaves (#585). A leaf therefore hangs off its
  // relay, not the controller — the visual proof of the tier.
  const recompute = () => {
    const graph = graphRef.current;
    const ctrl  = ctrlRef.current;
    if (!graph || !ctrl) return;
    const ctrlX = elOffsetLeft(ctrl, graph) + ctrl.offsetWidth  / 2;
    const ctrlY = elOffsetTop(ctrl, graph)  + ctrl.offsetHeight;
    const next = [];
    for (const n of nodes) {
      const el = proxyRefs.current[n.node_id];
      if (!el) continue;
      const x2 = elOffsetLeft(el, graph) + el.offsetWidth / 2;
      const y2 = elOffsetTop(el, graph);
      if (!n.parent) {
        next.push({ id: n.node_id, x1: ctrlX, y1: ctrlY, x2, y2 });
      } else {
        const pel = proxyRefs.current[n.parent];
        if (!pel) continue;
        next.push({
          id: n.node_id,
          x1: elOffsetLeft(pel, graph) + pel.offsetWidth / 2,
          y1: elOffsetTop(pel, graph) + pel.offsetHeight,
          x2,
          y2,
        });
      }
    }
    const s = JSON.stringify(next);
    if (s !== lastStr.current) { lastStr.current = s; setEdges(next); }
  };

  useLayoutEffect(recompute);
  useEffect(() => {
    window.addEventListener('resize', recompute);
    return () => window.removeEventListener('resize', recompute);
  }, []);

  const setRef = (id) => (el) => { proxyRefs.current[id] = el; };

  return (
    <div class="topo-graph" ref={graphRef}>
      {/* SVG edge layer — absolute, covers the full graph */}
      <svg class="topo-edges" aria-hidden="true">
        <defs>
          <marker id="topo-arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
            <path d="M0,0 L0,6 L6,3 z" fill="rgba(180, 188, 208, 0.4)" />
          </marker>
        </defs>
        {edges.map((e) => {
          const my = (e.y1 + e.y2) / 2;
          return (
            <path
              key={e.id}
              d={`M ${e.x1} ${e.y1} C ${e.x1} ${my}, ${e.x2} ${my}, ${e.x2} ${e.y2}`}
              class="topo-edge-path"
              marker-end="url(#topo-arrow)"
            />
          );
        })}
      </svg>

      {/* Control plane — leader (snapshot source) + standbys, grouped and
          centered above the scope groups. Only the leader anchors the edges. */}
      <div class="topo-ctrl-band">
        <div class="topo-ns-group topo-ns-group--ctrl">
          <div class="topo-ns-label">Cluster · Control plane</div>
          {standbys.length > 0 && (
            <div class="topo-ctrl-standbys">
              {standbys.map((c) => (
                <ControllerCard key={c.name ?? 'standby'} ctrl={c} version={controllerVersion} />
              ))}
            </div>
          )}
          {leader && (
            <div class="topo-ctrl-leader-row">
              <ControllerCard
                key={leader.name ?? 'leader'}
                ctrl={leader}
                version={controllerVersion}
                cardRef={ctrlRef}
              />
            </div>
          )}
        </div>
      </div>

      {/* Scope groups — horizontal row */}
      <div class="topo-groups-row">
        {/* Shared pool — direct proxies */}
        {sharedDirect.length > 0 && (
          <div class="topo-ns-group topo-ns-group--cluster">
            <div class="topo-ns-label">Cluster · Shared pool</div>
            <div class="topo-nodes-row">
              {sharedDirect.map((n) => (
                <div key={n.node_id} ref={setRef(n.node_id)}>
                  <ProxyCard node={n} />
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Per-namespace groups — direct dedicated proxies */}
        {[...nsMap.entries()].map(([ns, gwMap]) => (
          <div key={ns} class="topo-ns-group">
            <div class="topo-ns-label">{ns}</div>
            {[...gwMap.entries()].map(([gwName, gwNodes]) => (
              <div key={gwName} class="topo-scope-section">
                <div class="topo-scope-label">Gateway: {gwName}</div>
                <div class="topo-nodes-row">
                  {gwNodes.map((n) => (
                    <div key={n.node_id} ref={setRef(n.node_id)}>
                      <ProxyCard node={n} />
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ))}

        {/* Relay columns — the relay card, then its folded leaves nested below */}
        {relays.map((relay) => {
          const leaves = childrenByParent.get(relay.node_id) ?? [];
          return (
            <div key={relay.node_id} class="topo-ns-group topo-ns-group--relay">
              <div class="topo-ns-label">{relayLabel(relay)}</div>
              <div class="topo-relay-row">
                <div ref={setRef(relay.node_id)}>
                  <ProxyCard node={relay} />
                </div>
              </div>
              <div class="topo-scope-section topo-relay-leaves">
                <div class="topo-scope-label">
                  {leaves.length > 0 ? 'Leaves' : 'No leaves connected'}
                </div>
                <div class="topo-nodes-row">
                  {leaves.map((n) => (
                    <div key={n.node_id} ref={setRef(n.node_id)}>
                      <ProxyCard node={n} />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          );
        })}

        {/* Any unrecognised scope kind — surfaced so it is never silently dropped */}
        {other.length > 0 && (
          <div class="topo-ns-group">
            <div class="topo-ns-label">Other</div>
            <div class="topo-nodes-row">
              {other.map((n) => (
                <div key={n.node_id} ref={setRef(n.node_id)}>
                  <ProxyCard node={n} />
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * A control-plane card. The leader is the gRPC snapshot source (carries the
 * pushed `version` and anchors the edges); standbys are passive (no edges).
 */
function ControllerCard({ ctrl, version, cardRef }) {
  const { name, leader, reachable, degraded } = ctrl;
  const state = !reachable ? 'gone' : degraded ? 'degraded' : leader ? 'leader' : 'standby';
  const label = leader ? 'Leader' : 'Standby';
  const sub   = !reachable ? 'Unreachable'
    : degraded ? 'Degraded'
    : leader   ? 'gRPC snapshot source'
    : 'Passive — promoted on failover';
  // Deep-link to the controller's Fleet detail (synthetic dev card has no name).
  const link = name ? linkProps(() => nav.controller(name), `Open ${name} in Fleet`) : {};
  return (
    <div class={`topo-ctrl-card topo-ctrl-card--${state}${name ? ' topo-card--link' : ''}`} ref={cardRef} {...link}>
      <div class="topo-card-kind topo-card-kind--ctrl">
        <span class={`topo-sync-dot ${reachable && !degraded ? 'ok' : degraded ? 'warn' : 'err'}`} aria-hidden="true" />
        Controller · {label}
      </div>
      {name && <div class="topo-proxy-id">{name}</div>}
      <div class="topo-card-meta">{sub}</div>
      {leader && (
        <div class="topo-proxy-meta">
          <span class="topo-meta-label">Snapshot</span>
          <code class="topo-meta-val">{version ? shortHash(version) : 'Pending…'}</code>
        </div>
      )}
    </div>
  );
}

/** A single proxy or relay node card. Deep-links to its Fleet detail on click. */
function ProxyCard({ node }) {
  const ok = node.in_sync;
  const kind = node.is_relay ? 'Relay' : 'Proxy';
  const link = linkProps(() => nav.proxy(node.node_id), `Open ${node.node_id} in Fleet`);
  return (
    <div class={`topo-proxy-card topo-card--link ${node.is_relay ? 'topo-proxy-card--relay ' : ''}${ok ? 'topo-proxy-card--ok' : 'topo-proxy-card--warn'}`} {...link}>
      <div class="topo-card-kind">
        <span class={`topo-sync-dot ${ok ? 'ok' : 'warn'}`} aria-hidden="true" />
        {kind}
      </div>
      <div class="topo-proxy-id">{node.node_id}</div>
      <div class="topo-proxy-status">{ok ? 'In sync' : 'Lagging'}</div>
      <div class="topo-proxy-meta">
        <span class="topo-meta-label">Acked</span>
        <code class="topo-meta-val">{shortHash(node.last_acked_version)}</code>
      </div>
      <div class="topo-proxy-meta">
        <span class="topo-meta-label">Since</span>
        <span class="topo-meta-val">{shortTime(node.connected_since)}</span>
      </div>
    </div>
  );
}

/** Props that turn a card into a keyboard-accessible link to a Fleet detail. */
function linkProps(go, label) {
  return {
    role: 'button',
    tabIndex: 0,
    title: label,
    'aria-label': label,
    onClick: go,
    onKeyDown: (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); }
    },
  };
}

function elOffsetLeft(el, container) {
  let x = 0, cur = el;
  while (cur && cur !== container) { x += cur.offsetLeft; cur = cur.offsetParent; }
  return x;
}

function elOffsetTop(el, container) {
  let y = 0, cur = el;
  while (cur && cur !== container) { y += cur.offsetTop; cur = cur.offsetParent; }
  return y;
}

function shortHash(v) {
  if (!v) return '—';
  const h = v.startsWith('sha256:') ? v.slice(7) : v;
  return h.length > 12 ? `${h.slice(0, 12)}…` : h;
}

function shortTime(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  } catch {
    return iso;
  }
}
