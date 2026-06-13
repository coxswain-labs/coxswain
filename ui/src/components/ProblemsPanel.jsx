import { nav } from '../router.js';
import { Badge } from './Badge.jsx';
import { Icon } from './Icon.jsx';

/**
 * Problems panel — the severity-ordered triage view, embedded directly on the
 * Dashboard (no separate Problems screen). Presentational: the caller fetches
 * and passes the data.
 *
 * Ordering is by severity, highest first:
 *   1. No elected leader   — control plane can't write status
 *   2. Unreachable pods    — a pod is down / not responding
 *   3. Routing conflicts   — a route rule is silently shadowed
 *   4. Dead backends       — accepted route, 0 ready endpoints (503s)
 *
 * Every card deep-links to the most specific reachable view. Conflicts and dead
 * backends carry host/path + the proxy pods that see them, so they link to that
 * proxy's detail anchored to the route (`?host=&path=`). They can't link to the
 * Route Inspector yet — `/problems` carries the backend group, not the source
 * route's identity (the proxy table is compiled). That's a follow-up that needs
 * the controller to resolve host/path → route.
 */
export function ProblemsPanel({ conflicts = [], dead_routes = [], unreachable = [], degraded = [], leaderGap = false }) {
  const total =
    (leaderGap ? 1 : 0) + unreachable.length + degraded.length + conflicts.length + dead_routes.length;

  if (total === 0) {
    return <AllClear />;
  }

  return (
    <div class="problems">
      {leaderGap && (
        <ProblemSection
          title="Control plane"
          count={1}
          severity="err"
          desc="No controller reports leadership — status writes are stalled until an election completes."
        >
          <ProblemCard
            variant="err"
            badge={<Badge variant="fail">no leader</Badge>}
            title="No elected leader"
            detail="All controller pods report is_leader: false."
            onClick={() => nav.fleet()}
          />
        </ProblemSection>
      )}

      {unreachable.length > 0 && (
        <ProblemSection
          title="Unreachable pods"
          count={unreachable.length}
          severity="err"
          desc="These pods did not respond to a health probe. Check pod logs and RBAC."
        >
          {unreachable.map((p) => (
            <ProblemCard
              key={p.pod_name}
              variant="err"
              namespace={p.pod_namespace}
              badge={<Badge variant="fail">unreachable</Badge>}
              title={p.pod_name}
              detail={`${p.component === 'controller' ? 'Controller' : 'Proxy'} did not respond to health probe.`}
              onClick={p.component === 'controller' ? () => nav.controller(p.pod_name) : () => nav.proxy(p.pod_name)}
            />
          ))}
        </ProblemSection>
      )}

      {degraded.length > 0 && (
        <ProblemSection
          title="Degraded pods"
          count={degraded.length}
          severity="warn"
          desc="These pods are reachable but report a subsystem that isn't ready. Traffic may still flow, but the impaired subsystem needs attention — open the pod to see and follow logs for the failing check."
        >
          {degraded.map((p) => (
            <ProblemCard
              key={p.pod_name}
              variant="warn"
              namespace={p.pod_namespace}
              badge={<Badge variant="warn">degraded</Badge>}
              title={p.pod_name}
              detail={degradedDetail(p)}
              onClick={p.component === 'controller' ? () => nav.controller(p.pod_name) : () => nav.proxy(p.pod_name)}
            />
          ))}
        </ProblemSection>
      )}

      {conflicts.length > 0 && (
        <ProblemSection
          title="Routing conflicts"
          count={conflicts.length}
          severity="warn"
          desc="Two or more route rules compete for the same host/path. The losing rule is silently rejected — traffic is served only by the winner."
        >
          {conflicts.map((c, i) => (
            <ProblemCard
              key={i}
              variant="conflict"
              badge={<Badge variant="conflict">conflict</Badge>}
              title={`${c.host}${c.path}`}
              namespace={c.route?.namespace}
              kind={c.route?.kind}
              detail={<>Rejected: <code>{c.rejected_group}</code>{podsLabel(c.pods)}</>}
              onClick={routeTarget(c)}
            />
          ))}
        </ProblemSection>
      )}

      {dead_routes.length > 0 && (
        <ProblemSection
          title="Dead backends"
          count={dead_routes.length}
          severity="warn"
          desc="These routes are accepted but their backend Service has 0 ready pods. Requests receive a 503 until at least one pod becomes ready."
        >
          {dead_routes.map((d, i) => (
            <ProblemCard
              key={i}
              variant="dead"
              badge={<Badge variant="dead">0 endpoints</Badge>}
              title={`${d.host}${d.path}`}
              namespace={d.route?.namespace}
              kind={d.route?.kind}
              detail={<>Backend: <code>{d.backend_group}</code>{podsLabel(d.pods)}</>}
              onClick={routeTarget(d)}
            />
          ))}
        </ProblemSection>
      )}
    </div>
  );
}

/** The reward state: a green status board affirming each check that passed,
 *  shown when there are zero problems. */
function AllClear() {
  const checks = [
    'No routing conflicts',
    'All backends have ready endpoints',
    'All pods reachable',
    'All subsystems ready',
    'Leader elected',
  ];
  return (
    <div class="all-clear" role="status" aria-live="polite">
      <div class="all-clear-badge"><Icon name="check" size={26} /></div>
      <div class="all-clear-body">
        <div class="all-clear-title">All systems healthy</div>
        <ul class="all-clear-checks">
          {checks.map((c) => (
            <li key={c} class="all-clear-check">
              <Icon name="check" size={14} />
              {c}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

/** Deep-link a routing problem (conflict / dead backend) to its source route in
 *  the Route Inspector — a routing problem belongs on the Routing axis, not a
 *  proxy. `row.route` ({kind, namespace, name}) is the route's identity from
 *  `/problems`; the existing `kind` ("ingress"/"gateway") picks the route type.
 *  Falls back to the proxy-anchored link when identity is absent (older
 *  controller / unresolved), so the row is never a dead link. */
function routeTarget(row) {
  const r = row.route;
  if (r?.namespace && r?.name) {
    return row.kind === 'ingress'
      ? () => nav.ingressRoute(r.namespace, r.name)
      : () => nav.httproute(r.namespace, r.name);
  }
  return proxyTarget(row);
}

/** Fallback deep-link to the first proxy that sees the row, anchored to the
 *  offending host/path. Undefined (non-clickable) if no pod is recorded. */
function proxyTarget(row) {
  const pod = row.pods?.[0];
  return pod ? () => nav.proxy(pod, { host: row.host, path: row.path }) : undefined;
}

/** The failing-check detail line for a degraded pod, from the rollup's
 *  `degraded_checks` (`"subsystem/check"` names). */
function degradedDetail(p) {
  const checks = p.degraded_checks ?? [];
  const role = p.component === 'controller' ? 'Controller' : 'Proxy';
  if (checks.length === 0) return `${role} reports a subsystem not ready.`;
  return <>Failing: <code>{checks.join(', ')}</code></>;
}

function podsLabel(pods) {
  if (!pods?.length) return null;
  return <span class="pods-label"> · {pods.length} {pods.length === 1 ? 'proxy' : 'proxies'}</span>;
}

function ProblemSection({ title, count, severity, desc, children }) {
  return (
    <section aria-label={title}>
      <h2 class={`section-title section-${severity}`}>
        {title}
        <span class="section-count">{count}</span>
      </h2>
      {desc && <p class="section-desc">{desc}</p>}
      <div class="problems-list">{children}</div>
    </section>
  );
}

function ProblemCard({ variant, badge, title, detail, namespace, kind, onClick }) {
  const clickable = !!onClick;
  return (
    <div
      class={`problem-card ${variant}${clickable ? ' clickable' : ''}`}
      role={clickable ? 'button' : undefined}
      tabIndex={clickable ? 0 : undefined}
      onClick={onClick}
      onKeyDown={clickable ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick(); } } : undefined}
    >
      <div class="problem-card-main">
        <div class="problem-card-head">
          <strong>{title}</strong>
          {badge}
        </div>
        {namespace && <div class="problem-card-meta">Namespace: <code>{namespace}</code></div>}
        {kind && <div class="problem-card-meta">Kind: <code>{kind}</code></div>}
        <div class="problem-card-detail">{detail}</div>
      </div>
      {clickable && <span class="problem-card-chevron" aria-hidden="true">→</span>}
    </div>
  );
}
