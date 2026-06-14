import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getIngressRoute, getProblems } from '../api/endpoints.js';
import { nav } from '../router.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { DetailHeader } from '../components/DetailHeader.jsx';
import { StatusBadge } from '../components/StatusBadge.jsx';
import { Badge } from '../components/Badge.jsx';
import { CheckDialog } from '../components/CheckDialog.jsx';
import { Spinner, ErrorState, EmptyState } from '../components/Spinner.jsx';
import { ManifestDialog } from '../components/ManifestDialog.jsx';
import { Icon } from '../components/Icon.jsx';
import {
  worseSeverity,
  problemRouteKeys,
  routeKey,
  routeProblemSets,
  sevClass,
} from '../severity.js';
import { useEffect, useState } from 'preact/hooks';

/**
 * Ingress detail (networking/v1).
 *
 * Ingress is a flat resource — no parent Gateways, no per-parent conditions —
 * so the page is deliberately leaner than HTTPRoute: header (address + class),
 * inline TLS blocks, the effective config (host/path → backend, overlaid with
 * runtime problems), and the on-demand data-plane check.
 *
 * Deep-linkable via `#/routes/ingress/{ns}/{name}`. Refreshes on
 * `rebuild.completed` SSE.
 */
export function IngressDetail({ namespace, name }) {
  const { data, loading, error, refetch } = useApi(
    () => getIngressRoute(namespace, name),
    [namespace, name],
  );
  const problems = useApi(getProblems);
  const sse = useSSE('/api/v1/events');
  const [showManifest, setShowManifest] = useState(false);
  const [showCheck, setShowCheck] = useState(false);

  useEffect(() => {
    return sse.subscribe('rebuild.completed', () => {
      refetch();
      problems.refetch();
    });
  }, [sse.subscribe, refetch]);

  const breadcrumb = [
    { label: 'Routing', onClick: () => nav.routing() },
    { label: 'Ingresses', onClick: () => nav.routing({ tab: 'ingresses' }) },
    { label: name },
  ];

  if (loading) return <Spinner label="Loading Ingress…" />;
  if (error)   return <ErrorState error={error} />;
  if (!data)   return <EmptyState message="Ingress not found." />;

  const tls = data.tls ?? [];
  const rules = data.rules ?? [];
  const defaultBackend = data.default_backend;

  const problemKeys = problemRouteKeys(problems.data);
  const status = worseSeverity(
    data.status,
    problemKeys.has(routeKey('Ingress', namespace, name)) ? 'warn' : 'ok',
  );
  const { dead, shadowed } = routeProblemSets(problems.data, 'Ingress', namespace, name);

  // Flatten host → paths into one row per (host, path).
  const flatRows = rules.flatMap((r) =>
    (r.paths ?? []).map((p) => ({ host: r.host, ...p })),
  );

  return (
    <div class="screen">
      <Breadcrumb items={breadcrumb} />

      <DetailHeader
        name={name}
        namespace={namespace}
        copyLabel="Copy ingress name"
        meta={(
          <>
            {data.load_balancer && (
              <div class="problem-card-meta" title="Load-balancer address">
                Address: <code>{data.load_balancer}</code>
              </div>
            )}
            <div class="problem-card-meta" title="Ingress class">
              Class: <code>{data.class || '(default)'}</code>
            </div>
          </>
        )}
        badges={<StatusBadge status={status} />}
        actions={(
          <>
            <button class="btn btn-icon" onClick={() => setShowCheck(true)}>
              <Icon name="refresh" size={15} /> Check
            </button>
            <button class="btn btn-icon" onClick={() => setShowManifest(true)}>
              <Icon name="code" size={15} /> Manifest
            </button>
          </>
        )}
      />

      {showManifest && (
        <ManifestDialog
          kind="ingress"
          namespace={namespace}
          name={name}
          onClose={() => setShowManifest(false)}
        />
      )}

      {showCheck && (
        <CheckDialog
          kind="ingress"
          kindLabel="Ingress"
          namespace={namespace}
          name={name}
          onClose={() => setShowCheck(false)}
        />
      )}

      {/* Inline TLS blocks. Declared intent from spec.tls — Ingress carries no
          per-block status, so the cert/Secret is shown as a reference, never as
          verified health (no teal "good" lock — that would be the Gateway's
          listener-condition signal, which Ingress doesn't have). */}
      {tls.length > 0 && (
        <section aria-label="TLS">
          <h2 class="section-title">TLS</h2>
          <p class="section-hint">
            Declared TLS termination. Certificate validity isn't verified here.
          </p>
          <div class="tbl-wrap">
            <table>
              <thead>
                <tr>
                  <th>Hosts</th>
                  <th>Secret</th>
                </tr>
              </thead>
              <tbody>
                {tls.map((t, i) => (
                  <tr key={i}>
                    <td><code>{(t.hosts ?? []).join(', ') || '*'}</code></td>
                    <td>
                      <span class="backend-cell">
                        <Icon name="lock" size={12} />
                        <code>{t.secret || '—'}</code>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Effective config — host/path → backend, overlaid with runtime problems. */}
      <section aria-label="Effective config">
        <h2 class="section-title">
          Effective config
          <span class="section-count">{flatRows.length}</span>
        </h2>
        {flatRows.length === 0 ? (
          <EmptyState message="No rules declared." />
        ) : (
          <div class="tbl-wrap">
            <table>
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Path</th>
                  <th>Backend</th>
                </tr>
              </thead>
              <tbody>
                {flatRows.map((r, i) => {
                  const group = backendGroup(r.backend, namespace);
                  const isDead = group && dead.has(group);
                  const sev = isDead ? 'error' : shadowed.has(r.path) ? 'warn' : 'ok';
                  return (
                    <tr key={i} class={sevClass(sev)}>
                      <td><code>{r.host || '*'}</code></td>
                      <td><code>{r.path_type} {r.path || '/'}</code></td>
                      <td>
                        <span class="backend-cell">
                          <code>{backendLabel(r.backend, namespace)}</code>
                          {isDead && <Badge variant="fail">no endpoints</Badge>}
                          {shadowed.has(r.path) && <Badge variant="conflict">shadowed</Badge>}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {defaultBackend && (
          <p class="section-hint">
            Default backend: <code>{backendLabel(defaultBackend, namespace)}</code>
          </p>
        )}
      </section>
    </div>
  );
}

/** `{namespace}/{service}` group key for a service backend (matches `/problems`
 *  `backend_group`); `null` for a resource backend. */
function backendGroup(backend, ns) {
  if (!backend || !backend.service) return null;
  return `${ns}/${backend.service}`;
}

/** Human label for an Ingress backend: `service:port` or `resource:…`. */
function backendLabel(backend, ns) {
  if (!backend) return '—';
  if (backend.service) {
    return `${ns}/${backend.service}${backend.port ? `:${backend.port}` : ''}`;
  }
  if (backend.resource) return `resource:${backend.resource}`;
  return '—';
}
