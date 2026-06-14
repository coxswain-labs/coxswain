import { useApi } from '../hooks/useApi.js';
import { useSSE } from '../hooks/useSSE.js';
import { getHttproute, getProblems } from '../api/endpoints.js';
import { nav } from '../router.js';
import { Breadcrumb } from '../components/Breadcrumb.jsx';
import { DetailHeader } from '../components/DetailHeader.jsx';
import { StatusBadge } from '../components/StatusBadge.jsx';
import { ConditionRow } from '../components/ConditionRow.jsx';
import { Badge } from '../components/Badge.jsx';
import { RouteReconcile } from '../components/RouteReconcile.jsx';
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
 * HTTPRoute detail (Gateway API).
 *
 * Three on-language sections: the per-parentRef conditions (the route's
 * acceptance/resolution verdict — the richest Gateway-API troubleshooting
 * surface), the effective config (declared rules: match predicates, weighted
 * backends, filters — overlaid with runtime problems from `/problems`), and the
 * on-demand data-plane reconcile. No eager proxy fan-out.
 *
 * Deep-linkable via `#/routes/httproute/{ns}/{name}`. Refreshes on
 * `rebuild.completed` SSE so a route can be watched converging after an apply.
 */
export function HTTPRouteDetail({ namespace, name }) {
  const { data, loading, error, refetch } = useApi(
    () => getHttproute(namespace, name),
    [namespace, name],
  );
  const problems = useApi(getProblems);
  const sse = useSSE('/api/v1/events');
  const [showManifest, setShowManifest] = useState(false);

  useEffect(() => {
    return sse.subscribe('rebuild.completed', () => {
      refetch();
      problems.refetch();
    });
  }, [sse.subscribe, refetch]);

  const breadcrumb = [
    { label: 'Routing', onClick: () => nav.routing() },
    { label: 'HTTP Routes', onClick: () => nav.routing({ tab: 'httproutes' }) },
    { label: `${namespace}/${name}` },
  ];

  if (loading) return <Spinner label="Loading HTTPRoute…" />;
  if (error)   return <ErrorState error={error} />;
  if (!data)   return <EmptyState message="HTTPRoute not found." />;

  const parentStatuses = data.parent_statuses ?? [];
  // Parent Gateways → header links.
  const parents = parentStatuses
    .map((ps) => ps.parent_ref)
    .filter(Boolean)
    .map((r) => ({ ns: r.namespace ?? namespace, name: r.name }))
    .filter((p) => p.name);

  const hostnames = data.hostnames ?? [];
  const rules = data.rules ?? [];

  const problemKeys = problemRouteKeys(problems.data);
  const status = worseSeverity(
    data.status,
    problemKeys.has(routeKey('HTTPRoute', namespace, name)) ? 'warn' : 'ok',
  );
  const { dead, shadowed } = routeProblemSets(problems.data, 'HTTPRoute', namespace, name);

  return (
    <div class="screen">
      <Breadcrumb items={breadcrumb} />

      <DetailHeader
        name={name}
        namespace={namespace}
        copyLabel="Copy route name"
        meta={(
          <>
            {parents.map((p) => (
              <div class="problem-card-meta" key={`${p.ns}/${p.name}`}>
                Gateway: <a onClick={() => nav.gateway(p.ns, p.name)}>{p.ns}/{p.name}</a>
              </div>
            ))}
            {hostnames.length > 0 && (
              <div class="problem-card-meta" title="Route hostnames">
                Hostnames: <code>{hostnames.join(', ')}</code>
              </div>
            )}
          </>
        )}
        badges={<StatusBadge status={status} />}
        actions={(
          <button class="btn btn-icon" onClick={() => setShowManifest(true)}>
            <Icon name="code" size={15} /> Manifest
          </button>
        )}
      />

      {showManifest && (
        <ManifestDialog
          kind="httproute"
          namespace={namespace}
          name={name}
          onClose={() => setShowManifest(false)}
        />
      )}

      {/* Per-parentRef conditions — one table per attached Gateway. */}
      {parentStatuses.length > 0 && (
        <section aria-label="Parent conditions">
          <h2 class="section-title">Parent conditions</h2>
          {parentStatuses.map((ps) => {
            const ref = ps.parent_ref ?? {};
            const pns = ref.namespace ?? namespace;
            return (
              <div class="parent-conditions" key={`${pns}/${ref.name}`}>
                <div class="parent-conditions-head">
                  Gateway{' '}
                  <a onClick={() => nav.gateway(pns, ref.name)}>{pns}/{ref.name}</a>
                </div>
                <div class="tbl-wrap">
                  <table class="cond-table">
                    <thead>
                      <tr>
                        <th>Condition</th>
                        <th>Reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(ps.conditions ?? []).map((c) => (
                        <ConditionRow key={c.type} condition={c} />
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            );
          })}
        </section>
      )}

      {/* Effective config — declared rules, overlaid with runtime problems. */}
      <section aria-label="Effective config">
        <h2 class="section-title">
          Effective config
          <span class="section-count">{rules.length}</span>
        </h2>
        {rules.length === 0 ? (
          <EmptyState message="No rules declared." />
        ) : (
          <div class="tbl-wrap">
            <table>
              <thead>
                <tr>
                  <th>Match</th>
                  <th>Backends</th>
                  <th>Filters</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule, i) => (
                  <HttpRouteRuleRow
                    key={i}
                    rule={rule}
                    routeNs={namespace}
                    dead={dead}
                    shadowed={shadowed}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <RouteReconcile kind="httproute" namespace={namespace} name={name} />
    </div>
  );
}

/** One HTTPRoute rule as a table row: stacked matches, weighted backends, and
 *  filter kinds. Severity edge from the `/problems` overlay — error when a
 *  backend is dead, warn when a match path was shadowed by a conflict. */
function HttpRouteRuleRow({ rule, routeNs, dead, shadowed }) {
  const matches = rule.matches ?? [];
  const backends = rule.backends ?? [];
  const filters = rule.filters ?? [];

  const anyShadowed = matches.some((m) => shadowed.has(m.path?.value));
  const anyDead = backends.some((b) => dead.has(`${b.namespace ?? routeNs}/${b.name}`));
  const sev = anyDead ? 'error' : anyShadowed ? 'warn' : 'ok';

  return (
    <tr class={sevClass(sev)}>
      <td>
        <div class="cell-list">
          {matches.length === 0 && <code>PathPrefix /</code>}
          {matches.map((m, i) => (
            <MatchSummary key={i} match={m} shadowed={shadowed.has(m.path?.value)} />
          ))}
        </div>
      </td>
      <td>
        <div class="cell-list">
          {backends.map((b, i) => {
            const group = `${b.namespace ?? routeNs}/${b.name}`;
            return (
              <span key={i} class="backend-cell">
                <code>{group}{b.port != null ? `:${b.port}` : ''}</code>
                {b.weight != null && <Badge variant="neutral">w{b.weight}</Badge>}
                {dead.has(group) && <Badge variant="fail">no endpoints</Badge>}
              </span>
            );
          })}
        </div>
      </td>
      <td>
        <div class="cell-list">
          {filters.length === 0 && <span class="muted">—</span>}
          {filters.map((f, i) => (
            <Badge key={i} variant="neutral">{f}</Badge>
          ))}
        </div>
      </td>
    </tr>
  );
}

/** A single match predicate: path, then optional method / header / query tags. */
function MatchSummary({ match, shadowed }) {
  const path = match.path ?? {};
  const headers = match.headers ?? [];
  const query = match.query_params ?? [];
  return (
    <span class="match-summary">
      <code>{path.type ?? 'PathPrefix'} {path.value ?? '/'}</code>
      {match.method && <Badge variant="neutral">{match.method}</Badge>}
      {headers.map((h, i) => (
        <Badge key={`h${i}`} variant="neutral">{h.name}={h.value}</Badge>
      ))}
      {query.map((q, i) => (
        <Badge key={`q${i}`} variant="neutral">?{q.name}={q.value}</Badge>
      ))}
      {shadowed && <Badge variant="conflict">shadowed</Badge>}
    </span>
  );
}
