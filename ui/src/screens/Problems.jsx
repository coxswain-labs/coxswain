import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getProblems, getProxies, getControllers } from '../api/endpoints.js';
import { nav } from '../router.js';
import { Badge } from '../components/Badge.jsx';
import { Spinner, ErrorState, EmptyState } from '../components/Spinner.jsx';
import { useEffect } from 'preact/hooks';

/**
 * Problems screen — the full problem list linked from the NeedsAttention panel.
 *
 * Shows:
 * 1. Routing conflicts (routes competing for the same host/path).
 * 2. Dead backends (routes with 0 ready endpoints — accepted but serving 503s).
 * 3. Unreachable pods.
 *
 * Refreshes on rebuild.completed so the panel goes green as issues are resolved.
 */
export function Problems() {
  const problems    = useApi(getProblems);
  const proxies     = useApi(getProxies);
  const controllers = useApi(getControllers);
  const sse         = useSSE('/api/v1/events');

  useEffect(() => {
    const off = sse.subscribe('rebuild.completed', () => {
      problems.refetch();
      proxies.refetch();
      controllers.refetch();
    });
    return off;
  }, [sse.subscribe]);

  if (problems.loading && proxies.loading) return <Spinner label="Loading problems…" />;
  if (problems.error) return <ErrorState error={problems.error} />;

  const { conflicts = [], dead_routes = [] } = problems.data ?? {};
  const unreachable = [
    ...(proxies.data?.proxies ?? []).filter((p) => !p.reachable),
    ...(controllers.data?.controllers ?? []).filter((c) => !c.reachable),
  ];

  const total = conflicts.length + dead_routes.length + unreachable.length;

  return (
    <div class="screen">
      <div class="screen-header">
        <h1 class="screen-title">Problems</h1>
        <span class={`sse-dot ${sse.connected ? 'live' : 'offline'}`} />
        {total === 0 && <Badge variant="ok">All clear</Badge>}
        {total > 0 && <Badge variant="fail">{total} issue{total !== 1 ? 's' : ''}</Badge>}
      </div>

      {total === 0 && (
        <EmptyState message="No conflicts, no dead backends, all pods reachable." />
      )}

      {/* Unreachable pods */}
      {unreachable.length > 0 && (
        <section aria-label="Unreachable pods">
          <h2 class="section-title section-err">
            Unreachable pods
            <span class="section-count">{unreachable.length}</span>
          </h2>
          <div class="problems-list">
            {unreachable.map((p) => (
              <div key={p.pod_name} class="problem-card err">
                <div class="problem-card-head">
                  <Badge variant="fail">unreachable</Badge>
                  <strong>{p.pod_name}</strong>
                </div>
                <div class="problem-card-detail">
                  Pod did not respond to health probe. Check pod logs and RBAC.
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Routing conflicts */}
      {conflicts.length > 0 && (
        <section aria-label="Routing conflicts">
          <h2 class="section-title section-warn">
            Routing conflicts
            <span class="section-count">{conflicts.length}</span>
          </h2>
          <p class="section-desc">
            Two or more route rules compete for the same host/path. The losing rule
            is silently rejected — traffic is served only by the winner.
          </p>
          <div class="problems-list">
            {conflicts.map((c, i) => (
              <div key={i} class="problem-card conflict">
                <div class="problem-card-head">
                  <Badge variant="conflict">conflict</Badge>
                  <code>{c.host}{c.path}</code>
                </div>
                <div class="problem-card-detail">
                  <span>Rejected: <code>{c.rejected_group}</code></span>
                  {c.pods?.length > 0 && (
                    <span class="pods-label"> · {c.pods.length} proxy{c.pods.length !== 1 ? 'ies' : ''}</span>
                  )}
                </div>
                <div class="problem-card-actions">
                  <a
                    class="link-text"
                    onClick={() => openConflictRoute(c)}
                    title="Open in Route Inspector"
                  >
                    Inspect →
                  </a>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Dead backends */}
      {dead_routes.length > 0 && (
        <section aria-label="Dead backends">
          <h2 class="section-title section-warn">
            Dead backends
            <span class="section-count">{dead_routes.length}</span>
          </h2>
          <p class="section-desc">
            These routes are accepted but their backend Service has 0 ready pods.
            Requests will receive a 503 until at least one pod becomes ready.
          </p>
          <div class="problems-list">
            {dead_routes.map((d, i) => (
              <div key={i} class="problem-card dead">
                <div class="problem-card-head">
                  <Badge variant="dead">0 endpoints</Badge>
                  <code>{d.host}{d.path}</code>
                </div>
                <div class="problem-card-detail">
                  Backend: <code>{d.backend_group}</code>
                  {d.pods?.length > 0 && (
                    <span class="pods-label"> · {d.pods.length} proxy{d.pods.length !== 1 ? 'ies' : ''}</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

/**
 * Best-effort navigation: extract kind/namespace/name from the backend_group
 * or rejected_group string (format: `namespace/name` or `kind/namespace/name`).
 * Falls back to fleet if the format is unexpected.
 */
function openConflictRoute(conflict) {
  const group = conflict.rejected_group ?? '';
  const parts = group.split('/');
  if (parts.length >= 2) {
    const [ns, name] = parts.slice(-2);
    nav.httproute(ns, name);
  } else {
    nav.fleet();
  }
}
