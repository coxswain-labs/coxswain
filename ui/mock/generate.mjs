/**
 * Generate a comprehensive mock cluster into mock/data/ — one coherent world
 * that exercises every distinct UI state, so `npm run dev` can reach edge cases
 * a live cluster rarely holds all at once. Run: `node mock/generate.mjs`.
 *
 * The state matrix this enumerates (search a state to find where it's built):
 *   Controllers  : leader · standby · standby+degraded · unreachable
 *   Proxies      : shared healthy · shared degraded · dedicated (per-ns groups,
 *                  mixed health within a group) · dedicated unreachable
 *   Gateways     : shared programmed · dedicated programmed+ready ·
 *                  dedicated NOT programmed (proxy not ready) · NOT accepted ·
 *                  TLS listener · listener with 0 attached routes
 *   Ingresses    : healthy rules · all-dead rules · tenant-namespaced
 *   Routes       : healthy backend · dead backend (0 endpoints) · conflicts
 *                  (ingress + gateway) · multi-endpoint
 *   Route detail : HTTPRoute accepted+healthy · accepted+dead · NOT accepted
 *                  (unresolved refs) · ingress healthy · ingress dead
 *   Problems     : ingress conflict · gateway conflict · ingress/gateway dead
 *   Health       : all ready · degraded subsystem
 *
 * Fixtures are recaptured from a real controller instead with mock/capture.sh.
 */
import { writeFileSync, rmSync, mkdirSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = join(dirname(fileURLToPath(import.meta.url)), 'data');

// ── helpers ─────────────────────────────────────────────────────────────────
const write = (apiPath, obj) =>
  writeFileSync(join(DIR, `${apiPath.replace(/\//g, '_')}.json`), `${JSON.stringify(obj, null, 2)}\n`);

const cond = (type, status, reason, message) =>
  message ? { type, status, reason, message } : { type, status, reason };
const ACCEPTED = cond('Accepted', 'True', 'Accepted');
const NOT_ACCEPTED = cond('Accepted', 'False', 'NoMatchingListener', 'No listener matches this parent ref');
const PROGRAMMED = cond('Programmed', 'True', 'Programmed');
const NOT_PROGRAMMED = cond('Programmed', 'False', 'Pending', 'Waiting for dedicated proxy to become Ready');
const DED_READY = cond('gateway.coxswain-labs.dev/DedicatedProxyReady', 'True', 'Ready', 'Dedicated proxy has at least one Ready pod');
const DED_NOT_READY = cond('gateway.coxswain-labs.dev/DedicatedProxyReady', 'False', 'NoReadyPods', 'Dedicated proxy has no Ready pods yet');
const RESOLVED = cond('ResolvedRefs', 'True', 'ResolvedRefs');
const UNRESOLVED = cond('ResolvedRefs', 'False', 'BackendNotFound', 'Service "payments" not found');

const EP2 = ['10.42.0.48:80', '10.42.0.49:80'];
const EP1 = ['10.42.0.97:80'];
const row = (name, ns, path, group, endpoints = [], type = 'prefix') =>
  ({ backend_group: group, endpoints, name, namespace: ns, path, type });
const host = (h, port, routes) => ({ host: h, port, routes });

const CONTROLLER_CHECKS = [
  'backend_tls_policy', 'config_map', 'endpoint_slice', 'gateway', 'gateway_class',
  'httproute', 'ingress', 'ingress_class', 'reference_grant', 'routing_table_built',
  'secret', 'service',
];
const checks = (names, degraded = []) =>
  Object.fromEntries(names.map((n) => [n, { state: degraded.includes(n) ? 'degraded' : 'ready' }]));
const controllerSubsystem = (degraded = []) => ({
  state: { state: degraded.length ? 'degraded' : 'ready' },
  checks: checks(CONTROLLER_CHECKS, degraded),
});
const proxySubsystem = (degraded = []) => ({
  state: { state: degraded.length ? 'degraded' : 'ready' },
  checks: checks(['routing_table_loaded'], degraded),
});

const SYS = 'coxswain-system';

// ── controllers ───────────────────────────────────────────────────────────────
// leader · standby · standby+degraded · unreachable
const CONTROLLERS = [
  { name: 'coxswain-controller-7f9c8-leadr', leader: true,  health: 'ready',    degraded: [] },
  { name: 'coxswain-controller-7f9c8-stdby', leader: false, health: 'ready',    degraded: [] },
  { name: 'coxswain-controller-7f9c8-degrd', leader: false, health: 'degraded', degraded: ['gateway'] },
  { name: 'coxswain-controller-7f9c8-gone',  reachable: false },
];
// Pod runtime for the mock. The generator can't call Date.now(), so creation
// timestamps are fixed (a few days back); the UI renders age relative to today.
const NODES = ['node-cp-1', 'node-w-1', 'node-w-2'];
const CTRL_RESTARTS = [0, 0, 2, 7];
const PROXY_RESTARTS = [0, 0, 0, 1, 0, 4];
function runtime(i, restarts) {
  return {
    node: NODES[i % NODES.length],
    restarts,
    phase: 'Running',
    created_at: `2026-06-${String(8 + (i % 5)).padStart(2, '0')}T0${i % 9}:30:00Z`,
  };
}

// A representative Pod manifest for the "View manifest" dialog (kind=pod). The
// real backend returns the verbatim K8s object; this mirrors its shape closely
// enough to exercise the YAML rendering. `role` ∈ controller | shared-proxy |
// dedicated-proxy.
function podManifest(name, ns, role, i, restarts) {
  const isCtrl = role === 'controller';
  const ip = isCtrl ? `10.42.0.${10 + i}` : `10.42.0.${100 + i}`;
  const created = runtime(i, restarts).created_at;
  const args =
    role === 'controller' ? ['serve', 'controller']
    : role === 'shared-proxy' ? ['serve', 'proxy', '--shared']
    : ['serve', 'proxy'];
  return {
    apiVersion: 'v1',
    kind: 'Pod',
    metadata: {
      name,
      namespace: ns,
      uid: `a1b2c3d4-0000-4000-8000-${String(i).padStart(12, '0')}`,
      resourceVersion: `${1000 + i * 7}`,
      creationTimestamp: created,
      labels: {
        'app.kubernetes.io/name': 'coxswain',
        'app.kubernetes.io/component': role,
        'pod-template-hash': name.split('-').slice(-2, -1)[0] ?? 'abcde',
      },
      annotations: { 'coxswain-labs.dev/admin-port': '8082' },
      ownerReferences: [
        { apiVersion: 'apps/v1', kind: 'ReplicaSet', name: name.replace(/-[^-]+$/, ''), uid: `rs-${role}-${i}`, controller: true, blockOwnerDeletion: true },
      ],
    },
    spec: {
      serviceAccountName: isCtrl ? 'coxswain-controller' : 'coxswain-proxy',
      nodeName: NODES[i % NODES.length],
      containers: [
        {
          name: 'coxswain',
          image: 'ghcr.io/coxswain-labs/coxswain:v0.1.0',
          args,
          ports: [
            { name: 'http', containerPort: 8080, protocol: 'TCP' },
            { name: 'https', containerPort: 8443, protocol: 'TCP' },
            { name: 'admin', containerPort: 8082, protocol: 'TCP' },
          ],
          env: [
            { name: 'COXSWAIN_LOG_FORMAT', value: 'json' },
            { name: 'POD_NAMESPACE', valueFrom: { fieldRef: { fieldPath: 'metadata.namespace' } } },
          ],
          resources: { requests: { cpu: '50m', memory: '64Mi' }, limits: { memory: '128Mi' } },
          readinessProbe: { httpGet: { path: '/readyz', port: 'admin' }, periodSeconds: 10, timeoutSeconds: 1 },
        },
      ],
    },
    status: {
      phase: 'Running',
      podIP: ip,
      hostIP: '192.168.65.4',
      startTime: created,
      conditions: [
        { type: 'Initialized', status: 'True' },
        { type: 'Ready', status: 'True' },
        { type: 'ContainersReady', status: 'True' },
        { type: 'PodScheduled', status: 'True' },
      ],
      containerStatuses: [
        {
          name: 'coxswain',
          image: 'ghcr.io/coxswain-labs/coxswain:v0.1.0',
          ready: true,
          started: true,
          restartCount: restarts,
          state: { running: { startedAt: created } },
        },
      ],
    },
  };
}

function emitControllers() {
  const list = CONTROLLERS.map((c, i) => (c.reachable === false
    ? { component: 'controller', pod_name: c.name, pod_namespace: SYS, pod_ip: `10.42.0.${10 + i}`, admin_port: 8082, reachable: false, ...runtime(i, CTRL_RESTARTS[i] ?? 0) }
    : {
        admin_port: 8082, component: 'controller', degraded_checks: c.degraded,
        health: c.health, is_leader: c.leader, pod_ip: `10.42.0.${10 + i}`,
        pod_name: c.name, pod_namespace: SYS, reachable: true, ...runtime(i, CTRL_RESTARTS[i] ?? 0),
      }));
  write('/api/v1/fleet/controllers', { controllers: list });
  CONTROLLERS.forEach((c, i) => {
    write(`/api/v1/manifests/pod/${SYS}/${c.name}`, podManifest(c.name, SYS, 'controller', i, CTRL_RESTARTS[i] ?? 0));
    if (c.reachable === false) {
      write(`/api/v1/fleet/controllers/${c.name}`, { pod_name: c.name, component: 'controller', pod_namespace: SYS, pod_ip: `10.42.0.${10 + i}`, admin_port: 8082, reachable: false, ...runtime(i, CTRL_RESTARTS[i] ?? 0) });
      write(`/api/v1/fleet/controllers/${c.name}/health`, { pod_name: c.name, reachable: false });
      return;
    }
    write(`/api/v1/fleet/controllers/${c.name}`, {
      admin_port: 8082, component: 'controller', is_leader: c.leader,
      pod_ip: `10.42.0.${10 + i}`, pod_name: c.name, pod_namespace: SYS, reachable: true,
      ...runtime(i, CTRL_RESTARTS[i] ?? 0),
    });
    write(`/api/v1/fleet/controllers/${c.name}/health`, {
      pod_name: c.name, reachable: true,
      health: { version: '0.1.0', subsystems: { controller: controllerSubsystem(c.degraded) } },
    });
  });
}

// ── proxies ─────────────────────────────────────────────────────────────────
// shared healthy · shared degraded · dedicated groups (mixed health) · unreachable
const PROXIES = [
  { name: 'coxswain-shared-proxy-66d-ah7x2', kind: 'shared-proxy',    ns: SYS,        health: 'ready',    degraded: [] },
  { name: 'coxswain-shared-proxy-66d-bk9p4', kind: 'shared-proxy',    ns: SYS,        health: 'degraded', degraded: ['routing_table_loaded'] },
  { name: 'tenant-a-gw-coxswain-7db74-j8cjt', kind: 'dedicated-proxy', ns: 'tenant-a', health: 'ready',    degraded: [], gw: 'tenant-a-gw' },
  { name: 'tenant-a-gw-coxswain-7db74-r5tfb', kind: 'dedicated-proxy', ns: 'tenant-a', health: 'degraded', degraded: ['routing_table_loaded'], gw: 'tenant-a-gw' },
  { name: 'tenant-b-gw-coxswain-5cc91-m2qd8', kind: 'dedicated-proxy', ns: 'tenant-b', health: 'ready',    degraded: [], gw: 'tenant-b-gw' },
  { name: 'tenant-b-gw-coxswain-5cc91-zzz00', kind: 'dedicated-proxy', ns: 'tenant-b', reachable: false, gw: 'tenant-b-gw' },
];
function proxyListEntry(p, i) {
  if (p.reachable === false) {
    return { component: p.kind, gateway_ref: p.gw, pod_name: p.name, pod_namespace: p.ns, pod_ip: `10.42.0.${100 + i}`, admin_port: 8082, reachable: false, ...runtime(i, PROXY_RESTARTS[i] ?? 0) };
  }
  const e = {
    admin_port: 8082, component: p.kind, degraded_checks: p.degraded, health: p.health,
    pod_ip: `10.42.0.${100 + i}`, pod_name: p.name, pod_namespace: p.ns, reachable: true,
    ...runtime(i, PROXY_RESTARTS[i] ?? 0),
  };
  if (p.gw) e.gateway_ref = p.gw;
  return e;
}
function emitProxies() {
  write('/api/v1/fleet/proxies', { proxies: PROXIES.map(proxyListEntry) });
  PROXIES.forEach((p, i) => {
    write(`/api/v1/manifests/pod/${p.ns}/${p.name}`, podManifest(p.name, p.ns, p.kind, i, PROXY_RESTARTS[i] ?? 0));
    if (p.reachable === false) {
      write(`/api/v1/fleet/proxies/${p.name}`, { component: p.kind, gateway_ref: p.gw, pod_name: p.name, pod_namespace: p.ns, pod_ip: `10.42.0.${100 + i}`, admin_port: 8082, reachable: false, ...runtime(i, PROXY_RESTARTS[i] ?? 0) });
      write(`/api/v1/fleet/proxies/${p.name}/health`, { pod_name: p.name, reachable: false });
      write(`/api/v1/fleet/proxies/${p.name}/routes`, { pod_name: p.name, reachable: false });
      return;
    }
    const detail = { admin_port: 8082, component: p.kind, pod_ip: `10.42.0.${100 + i}`, pod_name: p.name, pod_namespace: p.ns, reachable: true, ...runtime(i, PROXY_RESTARTS[i] ?? 0) };
    if (p.gw) detail.gateway_ref = p.gw;
    write(`/api/v1/fleet/proxies/${p.name}`, detail);
    write(`/api/v1/fleet/proxies/${p.name}/health`, {
      pod_name: p.name, reachable: true,
      health: {
        version: '0.1.0',
        subsystems: { controller: controllerSubsystem(), proxy: proxySubsystem(p.degraded) },
      },
    });
    write(`/api/v1/fleet/proxies/${p.name}/routes`, { pod_name: p.name, reachable: true, routes: routesFor(p) });
  });
}

// ── routing tables ────────────────────────────────────────────────────────────
// Shared proxies hold the whole cluster's ingress + gateway table (with dead
// backends + conflicts); dedicated proxies hold only their gateway's routes.
const SHARED_GATEWAY = {
  conflicts: [
    { port: 8080, host: 'app.demo.local', type: 'prefix', path: '/', rejected_group: 'demo/legacy-api', namespace: 'demo', name: 'web-route' },
  ],
  hosts: [
    host('api.demo.local', 8080, [row('api-route', 'demo', '/', 'demo/api', [])]),                // dead
    host('docs.demo.local', 8080, [row('docs-route', 'demo', '/', 'demo/web', EP2)]),
    host('app.demo.local', 8080, [
      row('web-route', 'demo', '/', 'demo/web', EP2),
      row('health-probe-route', 'demo', '/health', 'demo/api', []),                                // dead
    ]),
  ],
};
const SHARED_INGRESS = {
  conflicts: [
    { port: 443, host: 'demo.local', type: 'prefix', path: '/', rejected_group: 'demo/old-frontend', namespace: 'demo', name: 'frontend-ingress' },
  ],
  hosts: [443, 80].flatMap((port) => ([
    host('demo.local', port, [
      row('frontend-ingress', 'demo', '/', 'demo/frontend', EP1),
      row('demo-ingress', 'demo', '/', 'demo/web', EP2),
      row('demo-ingress', 'demo', '/api', 'demo/api', []),                                          // dead
    ]),
    host('staging.local', port, [
      row('staging-ingress', 'staging', '/', 'staging/app', []),                                    // dead
      row('staging-ingress', 'staging', '/api', 'staging/app', []),                                 // dead
    ]),
  ])),
};
const EMPTY_SIDE = { conflicts: [], hosts: [] };
function routesFor(p) {
  if (p.kind === 'shared-proxy') return { gateway: SHARED_GATEWAY, ingress: SHARED_INGRESS };
  if (p.gw === 'tenant-a-gw') {
    return {
      gateway: { conflicts: [], hosts: [host('app.tenant-a.local', 8100, [row('a-web', 'tenant-a', '/', 'tenant-a/web', EP2)])] },
      ingress: EMPTY_SIDE,
    };
  }
  if (p.gw === 'tenant-b-gw') {
    return {
      gateway: { conflicts: [], hosts: [host('app.tenant-b.local', 8100, [row('b-api', 'tenant-b', '/', 'tenant-b/api', [])])] }, // dead
      ingress: EMPTY_SIDE,
    };
  }
  return { gateway: EMPTY_SIDE, ingress: EMPTY_SIDE };
}

// ── gateways ──────────────────────────────────────────────────────────────────
// shared programmed (TLS + 0-attached listener) · dedicated programmed+ready ·
// dedicated NOT programmed/not ready · NOT accepted
const GATEWAYS = [
  {
    ns: 'demo', name: 'demo-gw', pool: 'shared', addresses: [], route_count: 4,
    conditions: [ACCEPTED, PROGRAMMED],
    listeners: [
      { name: 'http', port: 8080, protocol: 'HTTP', tls_enabled: false, attached_routes: 4 },
      { name: 'https', port: 8443, protocol: 'HTTPS', tls_enabled: true, attached_routes: 0 }, // TLS + 0 attached (warn)
    ],
    routes: [['demo', 'api-route'], ['demo', 'docs-route'], ['demo', 'health-probe-route'], ['demo', 'web-route']],
  },
  {
    ns: 'tenant-a', name: 'tenant-a-gw', pool: 'dedicated', addresses: ['192.168.194.187'], route_count: 1,
    conditions: [ACCEPTED, PROGRAMMED, DED_READY],
    listeners: [{ name: 'http', port: 8100, protocol: 'HTTP', tls_enabled: false, attached_routes: 1 }],
    routes: [['tenant-a', 'a-web-route']],
  },
  {
    ns: 'tenant-b', name: 'tenant-b-gw', pool: 'dedicated', addresses: [], route_count: 1,
    conditions: [ACCEPTED, NOT_PROGRAMMED, DED_NOT_READY], // dedicated not ready
    listeners: [{ name: 'http', port: 8100, protocol: 'HTTP', tls_enabled: false, attached_routes: 1 }],
    routes: [['tenant-b', 'b-api-route']],
  },
  {
    ns: 'staging', name: 'staging-gw', pool: 'shared', addresses: [], route_count: 0,
    conditions: [NOT_ACCEPTED], // not accepted
    listeners: [{ name: 'http', port: 80, protocol: 'HTTP', tls_enabled: false, attached_routes: 0 }],
    routes: [],
  },
];
// Gateway binding health: error when any condition is False (Accepted /
// Programmed / DedicatedProxyReady), else ok — mirrors the controller's
// upstream-only gateway severity (#301).
const gatewayStatus = (g) => (g.conditions.some((c) => c.status === 'False') ? 'error' : 'ok');
function emitGateways() {
  const gateways = GATEWAYS.map((g) => ({
    addresses: g.addresses, conditions: g.conditions, name: g.name, namespace: g.ns,
    proxy: { pool: g.pool }, route_count: g.route_count, status: gatewayStatus(g),
  }));
  write('/api/v1/routing/gateways', { gateways, total: gateways.length, returned: gateways.length, offset: 0 });
  GATEWAYS.forEach((g) => write(`/api/v1/routing/gateways/${g.ns}/${g.name}`, {
    addresses: g.addresses,
    attached_routes_list: g.routes.map(([ns, name]) => ({ kind: 'HTTPRoute', name, namespace: ns })),
    conditions: g.conditions, listeners: g.listeners, name: g.name, namespace: g.ns,
    proxy: { pool: g.pool }, route_count: g.route_count, status: gatewayStatus(g),
  }));
}

// ── HTTPRoutes listing (#293) ───────────────────────────────────────────────────
// First-class routing resource: name · namespace · parent gateways · rules ·
// traffic-served status (ok/warn/error), exercising every state.
const HTTPROUTES = [
  { ns: 'demo', name: 'web-route', hostnames: ['app.demo.local'], parents: ['demo/demo-gw'], rule_count: 1, status: 'warn' },   // shadowed (conflict)
  { ns: 'demo', name: 'api-route', hostnames: ['api.demo.local'], parents: ['demo/demo-gw'], rule_count: 1, status: 'error' },  // dead backend
  { ns: 'demo', name: 'docs-route', hostnames: ['docs.demo.local'], parents: ['demo/demo-gw'], rule_count: 1, status: 'ok' },
  { ns: 'demo', name: 'health-probe-route', hostnames: ['app.demo.local'], parents: ['demo/demo-gw'], rule_count: 1, status: 'error' }, // dead
  { ns: 'demo', name: 'payments-route', hostnames: ['pay.demo.local'], parents: ['demo/demo-gw'], rule_count: 1, status: 'error' },     // unresolved refs
  { ns: 'tenant-a', name: 'a-web-route', hostnames: ['app.tenant-a.local'], parents: ['tenant-a/tenant-a-gw'], rule_count: 1, status: 'ok' },
  { ns: 'tenant-b', name: 'b-api-route', hostnames: ['app.tenant-b.local'], parents: ['tenant-b/tenant-b-gw'], rule_count: 1, status: 'error' }, // dead + proxy not ready
];
function emitHttproutesList() {
  const httproutes = HTTPROUTES.map((r) => ({
    name: r.name, namespace: r.ns, hostnames: r.hostnames,
    parent_gateways: r.parents, rule_count: r.rule_count, status: r.status,
  }));
  write('/api/v1/routing/httproutes', { httproutes, total: httproutes.length, returned: httproutes.length, offset: 0 });
}

// ── summaries (#301) ────────────────────────────────────────────────────────────
// Compact per-category counts + worst severity, backing the routing tab badges
// and the Dashboard tiles.
const worst = (sevs) => (sevs.includes('error') ? 'error' : sevs.includes('warn') ? 'warn' : 'ok');
const cat = (items) => ({ total: items.length, worst: worst(items.map((x) => x.status ?? 'ok')) });
function emitSummaries() {
  write('/api/v1/routing/summary', {
    gateways: { total: GATEWAYS.length, worst: worst(GATEWAYS.map(gatewayStatus)) },
    httproutes: cat(HTTPROUTES),
    ingresses: cat(INGRESSES),
  });
  // A pod's severity: error when unreachable, warn when degraded, else ok.
  const podSev = (p) => (p.reachable === false ? 'error' : (p.degraded?.length ? 'warn' : 'ok'));
  const ctrlSev = (c) => (c.reachable === false ? 'error' : (c.degraded?.length ? 'warn' : 'ok'));
  const shared = PROXIES.filter((p) => p.kind === 'shared-proxy');
  const dedicated = PROXIES.filter((p) => p.kind === 'dedicated-proxy');
  write('/api/v1/fleet/summary', {
    controllers: { total: CONTROLLERS.length, worst: worst(CONTROLLERS.map(ctrlSev)) },
    shared_proxies: { total: shared.length, worst: worst(shared.map(podSev)) },
    dedicated_proxies: { total: dedicated.length, worst: worst(dedicated.map(podSev)) },
  });
}

// ── HTTPRoute details ─────────────────────────────────────────────────────────
// accepted+healthy · accepted+dead · NOT accepted (unresolved refs)
function httproute(ns, name, parentGw, conditions, podRoutes) {
  return {
    name, namespace: ns,
    parent_statuses: [{ conditions, parent_ref: { name: parentGw, namespace: null } }],
    proxies: podRoutes,
  };
}
function emitHttproutes() {
  const sharedPod = PROXIES[0].name;
  const onShared = (gatewaySide) => ([
    { pod_name: sharedPod, reachable: true, routes: { gateway: gatewaySide, ingress: EMPTY_SIDE } },
  ]);
  // demo/web-route — accepted + healthy
  write('/api/v1/routing/routes/httproute/demo/web-route', httproute('demo', 'web-route', 'demo-gw',
    [ACCEPTED, PROGRAMMED, RESOLVED],
    onShared({ conflicts: [], hosts: [host('app.demo.local', 8080, [row('web-route', 'demo', '/', 'demo/web', EP2)])] })));
  // demo/api-route — accepted but dead backend (0 endpoints)
  write('/api/v1/routing/routes/httproute/demo/api-route', httproute('demo', 'api-route', 'demo-gw',
    [ACCEPTED, PROGRAMMED, RESOLVED],
    onShared({ conflicts: [], hosts: [host('api.demo.local', 8080, [row('api-route', 'demo', '/', 'demo/api', [])])] })));
  // demo/docs-route — accepted + healthy
  write('/api/v1/routing/routes/httproute/demo/docs-route', httproute('demo', 'docs-route', 'demo-gw',
    [ACCEPTED, PROGRAMMED, RESOLVED],
    onShared({ conflicts: [], hosts: [host('docs.demo.local', 8080, [row('docs-route', 'demo', '/', 'demo/web', EP2)])] })));
  // demo/health-probe-route — accepted + dead
  write('/api/v1/routing/routes/httproute/demo/health-probe-route', httproute('demo', 'health-probe-route', 'demo-gw',
    [ACCEPTED, PROGRAMMED, RESOLVED],
    onShared({ conflicts: [], hosts: [host('app.demo.local', 8080, [row('health-probe-route', 'demo', '/health', 'demo/api', [])])] })));
  // demo/payments-route — NOT accepted (unresolved backend ref), not on any proxy
  write('/api/v1/routing/routes/httproute/demo/payments-route', httproute('demo', 'payments-route', 'demo-gw',
    [ACCEPTED, cond('Programmed', 'False', 'Invalid', 'Route has an unresolved backendRef'), UNRESOLVED], []));
  // tenant-a/a-web-route — dedicated proxy, healthy
  write('/api/v1/routing/routes/httproute/tenant-a/a-web-route', httproute('tenant-a', 'a-web-route', 'tenant-a-gw',
    [ACCEPTED, PROGRAMMED, RESOLVED],
    [{ pod_name: PROXIES[2].name, reachable: true, routes: { gateway: { conflicts: [], hosts: [host('app.tenant-a.local', 8100, [row('a-web-route', 'tenant-a', '/', 'tenant-a/web', EP2)])] }, ingress: EMPTY_SIDE } }]));
  // tenant-b/b-api-route — dedicated, accepted but dead + proxy not ready
  write('/api/v1/routing/routes/httproute/tenant-b/b-api-route', httproute('tenant-b', 'b-api-route', 'tenant-b-gw',
    [ACCEPTED, NOT_PROGRAMMED, RESOLVED],
    [{ pod_name: PROXIES[4].name, reachable: true, routes: { gateway: { conflicts: [], hosts: [host('app.tenant-b.local', 8100, [row('b-api-route', 'tenant-b', '/', 'tenant-b/api', [])])] }, ingress: EMPTY_SIDE } }]));
}

// ── Ingresses ─────────────────────────────────────────────────────────────────
// healthy rules · all-dead rules · tenant-namespaced
const INGRESSES = [
  { ns: 'demo', name: 'demo-ingress', route_count: 2, ingress_class: 'coxswain', load_balancer: '192.168.194.180', status: 'warn' },     // one dead rule
  { ns: 'demo', name: 'frontend-ingress', route_count: 1, ingress_class: 'coxswain', load_balancer: '192.168.194.180', status: 'warn' }, // shadowed (conflict)
  { ns: 'staging', name: 'staging-ingress', route_count: 2, ingress_class: 'coxswain', load_balancer: '', status: 'error' }, // all dead, no address yet
  { ns: 'tenant-b', name: 'tenant-b-ingress', route_count: 1, ingress_class: '', load_balancer: '192.168.194.181', status: 'ok' }, // default-class fallback
];
function emitIngresses() {
  const ingresses = INGRESSES.map((i) => ({
    name: i.name, namespace: i.ns, route_count: i.route_count,
    ...(i.ingress_class ? { ingress_class: i.ingress_class } : {}),
    ...(i.load_balancer ? { load_balancer: i.load_balancer } : {}),
    status: i.status,
  }));
  write('/api/v1/routing/ingresses', { ingresses, total: ingresses.length, returned: ingresses.length, offset: 0 });
  const sharedPod = PROXIES[0].name;
  const ingRoute = (ns, name, ingressSide) => write(`/api/v1/routing/routes/ingress/${ns}/${name}`, {
    name, namespace: ns,
    proxies: [{ pod_name: sharedPod, reachable: true, routes: { gateway: EMPTY_SIDE, ingress: ingressSide } }],
  });
  ingRoute('demo', 'demo-ingress', { conflicts: [], hosts: [host('demo.local', 80, [
    row('demo-ingress', 'demo', '/', 'demo/web', EP2),
    row('demo-ingress', 'demo', '/api', 'demo/api', []), // dead
  ])] });
  ingRoute('demo', 'frontend-ingress', { conflicts: [], hosts: [host('demo.local', 80, [row('frontend-ingress', 'demo', '/', 'demo/frontend', EP1)])] });
  ingRoute('staging', 'staging-ingress', { conflicts: [], hosts: [host('staging.local', 80, [
    row('staging-ingress', 'staging', '/', 'staging/app', []),   // dead
    row('staging-ingress', 'staging', '/api', 'staging/app', []), // dead
  ])] });
  ingRoute('tenant-b', 'tenant-b-ingress', { conflicts: [], hosts: [host('app.tenant-b.local', 80, [row('tenant-b-ingress', 'tenant-b', '/', 'tenant-b/web', EP2)])] });
}

// ── problems · health · cluster ─────────────────────────────────────────────────
function emitProblems() {
  const sharedPods = [PROXIES[0].name, PROXIES[1].name];
  // `route` is the source route's identity (the rejected route for a conflict);
  // it points at routes that have detail fixtures so the deep-links resolve.
  const r = (kind, namespace, name) => ({ kind, namespace, name });
  // Fleet problem classes, derived from the mock world (issue #301): unreachable
  // pods, degraded pods, and whether a leader exists.
  const unreachable = [
    ...CONTROLLERS.filter((c) => c.reachable === false).map((c) => ({ pod_name: c.name, pod_namespace: SYS, component: 'controller', reachable: false })),
    ...PROXIES.filter((p) => p.reachable === false).map((p) => ({ pod_name: p.name, pod_namespace: p.ns, component: p.kind, reachable: false })),
  ];
  const degraded = [
    ...CONTROLLERS.filter((c) => c.reachable !== false && c.degraded?.length).map((c) => ({ pod_name: c.name, pod_namespace: SYS, component: 'controller', reachable: true, degraded_checks: c.degraded })),
    ...PROXIES.filter((p) => p.reachable !== false && p.degraded?.length).map((p) => ({ pod_name: p.name, pod_namespace: p.ns, component: p.kind, reachable: true, degraded_checks: p.degraded })),
  ];
  const leaderless = !CONTROLLERS.some((c) => c.reachable !== false && c.leader);
  write('/api/v1/problems', {
    fleet: { leaderless, unreachable, degraded },
    routing: {
      conflicts: [
        { host: 'demo.local', path: '/', rejected_group: 'demo/old-frontend', kind: 'ingress', pods: sharedPods, route: r('Ingress', 'demo', 'frontend-ingress') },
        { host: 'app.demo.local', path: '/', rejected_group: 'demo/legacy-api', kind: 'gateway', pods: sharedPods, route: r('HTTPRoute', 'demo', 'web-route') },
      ],
      dead_routes: [
        { host: 'api.demo.local', path: '/', backend_group: 'demo/api', kind: 'gateway', pods: sharedPods, route: r('HTTPRoute', 'demo', 'api-route') },
        { host: 'app.demo.local', path: '/health', backend_group: 'demo/api', kind: 'gateway', pods: sharedPods, route: r('HTTPRoute', 'demo', 'health-probe-route') },
        { host: 'demo.local', path: '/api', backend_group: 'demo/api', kind: 'ingress', pods: sharedPods, route: r('Ingress', 'demo', 'demo-ingress') },
        { host: 'staging.local', path: '/', backend_group: 'staging/app', kind: 'ingress', pods: sharedPods, route: r('Ingress', 'staging', 'staging-ingress') },
        { host: 'staging.local', path: '/api', backend_group: 'staging/app', kind: 'ingress', pods: sharedPods, route: r('Ingress', 'staging', 'staging-ingress') },
        { host: 'app.tenant-b.local', path: '/', backend_group: 'tenant-b/api', kind: 'gateway', pods: [PROXIES[4].name], route: r('HTTPRoute', 'tenant-b', 'b-api-route') },
      ],
    },
  });
}
function emitHealth() {
  // Aggregate health: controller ready, but a proxy subsystem degraded. Now also
  // carries the apiserver version + leader flag (the version popover + the
  // per-controller leadership probe both read /health).
  write('/api/v1/health', {
    version: '0.1.0',
    kubernetes_version: 'v1.31.2',
    leader: true,
    subsystems: { controller: controllerSubsystem(), proxy: proxySubsystem(['routing_table_loaded']) },
  });
}

// ── run ───────────────────────────────────────────────────────────────────────
rmSync(DIR, { recursive: true, force: true });
mkdirSync(DIR, { recursive: true });
emitControllers();
emitProxies();
emitGateways();
emitHttproutesList();
emitHttproutes();
emitIngresses();
emitSummaries();
emitProblems();
emitHealth();
console.log(`generated ${readdirSync(DIR).length} fixtures → ${DIR}`);
