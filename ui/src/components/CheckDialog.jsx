import { useEffect, useRef, useState } from 'preact/hooks';
import { getRouteCheck } from '../api/endpoints.js';
import { nav } from '../router.js';
import { Badge } from './Badge.jsx';
import { EndpointHealth } from './EndpointHealth.jsx';
import { Icon } from './Icon.jsx';
import { Spinner, ErrorState } from './Spinner.jsx';
import { sevClass } from '../severity.js';

/**
 * Modal dialog for the on-demand data-plane check of a single route.
 *
 * Opens on an explanation/confirm step rather than running immediately — the
 * check is an N-pod fan-out, the one verification independent of the
 * controller's view, so the operator fires it deliberately. On confirm it asks
 * each proxy that should serve the route what it has compiled and reports drift.
 *
 * Follows the ManifestDialog a11y pattern: role=dialog, focus trap, Escape /
 * backdrop close, focus restored to the trigger on close.
 *
 * @param {string}   kind       URL kind ("httproute" | "ingress")
 * @param {string}   kindLabel  display label ("HTTPRoute" | "Ingress")
 * @param {string}   namespace
 * @param {string}   name
 * @param {function} onClose
 */
export function CheckDialog({ kind, kindLabel, namespace, name, onClose }) {
  // phase: 'confirm' | 'loading' | 'done' | 'error'
  const [phase, setPhase] = useState('confirm');
  const [data, setData]   = useState(null);
  const [error, setError] = useState(null);
  const dialogRef = useRef(null);
  const runRef    = useRef(null);
  const titleId   = 'check-dialog-title';

  const run = async () => {
    setPhase('loading');
    setError(null);
    try {
      setData(await getRouteCheck(kind, namespace, name));
      setPhase('done');
    } catch (e) {
      setError(e);
      setPhase('error');
    }
  };

  // Focus the primary action when the dialog opens.
  useEffect(() => { runRef.current?.focus(); }, []);

  // Trap focus inside the dialog; Escape closes.
  useEffect(() => {
    const el = dialogRef.current;
    if (!el) return;
    const focusable = () =>
      Array.from(
        el.querySelectorAll('button, [href], [tabindex]:not([tabindex="-1"])'),
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

  return (
    <>
      <div class="dialog-backdrop" aria-hidden="true" onClick={onClose} />
      <div
        ref={dialogRef}
        class="dialog dialog-narrow"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <div class="dialog-header">
          <div class="dialog-title-group">
            <span class="dialog-kind-badge">Check</span>
            <h2 id={titleId} class="dialog-title">
              <span class="dialog-ns">{namespace}/</span>{name}
            </h2>
          </div>
          <div class="dialog-actions">
            {phase === 'done' && (
              <button class="btn btn-icon" onClick={run} aria-label="Run check again">
                <Icon name="refresh" size={13} /> Run again
              </button>
            )}
            <button class="btn dialog-close" onClick={onClose} aria-label="Close check dialog">
              ✕
            </button>
          </div>
        </div>

        <div class="dialog-body dialog-body-padded">
          {phase === 'confirm' && (
            <div class="check-confirm">
              <p>
                Asks every proxy that should serve this {kindLabel} what it has actually
                compiled and flags any drift from the controller's view. Fans out to all serving
                proxies, so it runs on demand.
              </p>
              <button ref={runRef} class="btn btn-icon btn-primary" onClick={run}>
                <Icon name="refresh" size={14} /> Run check
              </button>
            </div>
          )}
          {phase === 'loading' && <Spinner label="Querying proxies…" />}
          {phase === 'error'   && <ErrorState error={error} />}
          {phase === 'done'    && <CheckResult data={data} />}
        </div>
      </div>
    </>
  );
}

function CheckResult({ data }) {
  const proxies = data.proxies ?? [];
  return (
    <>
      <div class="check-verdict">
        {data.consistent ? (
          <Badge variant="ok">consistent</Badge>
        ) : (
          <Badge variant="fail">drift detected</Badge>
        )}
        <span class="check-summary">
          {proxies.length} serving {proxies.length === 1 ? 'proxy' : 'proxies'} checked
        </span>
      </div>
      {proxies.length === 0 && (
        <div class="check-idle">No proxies are expected to serve this route.</div>
      )}
      {proxies.map((p) => (
        <CheckProxy key={p.pod_name} proxy={p} />
      ))}
    </>
  );
}

function CheckProxy({ proxy }) {
  const head = (
    <div class="check-proxy-head">
      <span class="link-text" onClick={() => nav.proxy(proxy.pod_name)}>
        {proxy.pod_name}
      </span>
      {!proxy.reachable && <Badge variant="fail">unreachable</Badge>}
    </div>
  );

  if (!proxy.reachable) {
    return <div class="check-proxy">{head}</div>;
  }
  const rows = proxy.rows ?? [];
  const missing = proxy.missing ?? [];
  return (
    <div class="check-proxy">
      {head}
      {rows.length === 0 && missing.length === 0 && (
        <div class="check-idle">No rows for this route on this proxy.</div>
      )}
      {rows.length > 0 && (
        <div class="tbl-wrap">
          <table>
            <thead>
              <tr>
                <th>Host</th>
                <th>Path</th>
                <th>Backend</th>
                <th>Endpoints</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr
                  key={i}
                  class={sevClass(r.dead ? 'error' : 'ok')}
                  title={r.dead ? 'No ready endpoints — Service has no ready Pods' : undefined}
                >
                  <td><code>{r.host}</code></td>
                  <td><code>{r.path || '/'}</code></td>
                  <td><code>{r.backend_group}</code></td>
                  <td><EndpointHealth endpoints={r.endpoints ?? []} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {missing.length > 0 && (
        <div class="check-missing" aria-label="Missing rows">
          {missing.map((m, i) => (
            <div key={i} class="conflict-item">
              <Badge variant="fail">missing</Badge>
              <code>{m.host}{m.path}</code> → <code>{m.backend_group}</code> not compiled here
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
