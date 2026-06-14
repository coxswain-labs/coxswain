import { useState } from 'preact/hooks';
import { getRouteReconcile } from '../api/endpoints.js';
import { nav } from '../router.js';
import { Badge } from './Badge.jsx';
import { EndpointHealth } from './EndpointHealth.jsx';
import { Panel } from './Panel.jsx';
import { Icon } from './Icon.jsx';
import { sevClass } from '../severity.js';

/**
 * On-demand data-plane reconcile for a single route — shared by HTTPRouteDetail
 * and IngressDetail.
 *
 * Everything else on the route page reflects the *controller's* view (status,
 * conditions, `/problems`). This is the one independent check: a button that
 * fans out to the proxies that should serve the route and reports whether they
 * agree — a proxy missing a row its peers have, or an unreachable proxy, is
 * drift. Off by default (an N-pod fan-out), fired only when the operator
 * suspects the data plane has diverged from the controller.
 *
 * `kind` is the URL kind (`httproute` | `ingress`).
 */
export function RouteReconcile({ kind, namespace, name }) {
  const [state, setState] = useState({ status: 'idle' });

  const run = async () => {
    setState({ status: 'loading' });
    try {
      const data = await getRouteReconcile(kind, namespace, name);
      setState({ status: 'done', data });
    } catch (e) {
      setState({ status: 'error', error: e });
    }
  };

  return (
    <section aria-label="Data-plane reconcile">
      <h2 class="section-title">
        Data-plane reconcile
        <button
          class="btn btn-icon section-action"
          onClick={run}
          disabled={state.status === 'loading'}
        >
          <Icon name="refresh" size={14} />
          {state.status === 'loading' ? 'Checking…' : 'Reconcile'}
        </button>
      </h2>
      <p class="section-hint">
        Asks each proxy that should serve this route what it has actually compiled — the one
        check independent of the controller's view. Run it when you suspect the dashboard is
        green but traffic isn't flowing.
      </p>
      {state.status === 'idle' && <div class="reconcile-idle">Not run yet.</div>}
      {state.status === 'error' && (
        <div class="reconcile-idle">
          Reconcile failed: {String(state.error?.message ?? state.error)}
        </div>
      )}
      {state.status === 'done' && <ReconcileResult data={state.data} />}
    </section>
  );
}

function ReconcileResult({ data }) {
  const proxies = data.proxies ?? [];
  return (
    <>
      <div class="reconcile-verdict">
        {data.consistent ? (
          <Badge variant="ok">consistent</Badge>
        ) : (
          <Badge variant="fail">drift detected</Badge>
        )}
        <span class="reconcile-summary">
          {proxies.length} serving {proxies.length === 1 ? 'proxy' : 'proxies'} checked
        </span>
      </div>
      {proxies.length === 0 && (
        <div class="reconcile-idle">No proxies are expected to serve this route.</div>
      )}
      {proxies.map((p) => (
        <ReconcileProxy key={p.pod_name} proxy={p} />
      ))}
    </>
  );
}

function ReconcileProxy({ proxy }) {
  if (!proxy.reachable) {
    return (
      <Panel title={proxy.pod_name}>
        <Badge variant="fail">unreachable</Badge>
      </Panel>
    );
  }
  const rows = proxy.rows ?? [];
  const missing = proxy.missing ?? [];
  return (
    <Panel
      title={
        <span class="link-text" onClick={() => nav.proxy(proxy.pod_name)}>
          {proxy.pod_name}
        </span>
      }
    >
      {rows.length === 0 && missing.length === 0 && (
        <div class="reconcile-idle">No rows for this route on this proxy.</div>
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
        <div class="reconcile-missing" aria-label="Missing rows">
          {missing.map((m, i) => (
            <div key={i} class="conflict-item">
              <Badge variant="fail">missing</Badge>
              <code>{m.host}{m.path}</code> → <code>{m.backend_group}</code> not compiled here
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
