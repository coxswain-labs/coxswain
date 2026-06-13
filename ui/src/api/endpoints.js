import { fetchJson } from './client.js';

// ── Fleet overview ────────────────────────────────────────────────────────────

export const getCluster = () => fetchJson('/api/v1/cluster');
export const getProxies = () => fetchJson('/api/v1/proxies');
export const getControllers = () => fetchJson('/api/v1/controllers');
export const getProblems = () => fetchJson('/api/v1/problems');

// ── Proxy detail ──────────────────────────────────────────────────────────────

export const getProxy = (pod) => fetchJson(`/api/v1/proxies/${encodeURIComponent(pod)}`);
export const getProxyRoutes = (pod) =>
  fetchJson(`/api/v1/proxies/${encodeURIComponent(pod)}/routes`);
export const getProxyHealth = (pod) =>
  fetchJson(`/api/v1/proxies/${encodeURIComponent(pod)}/health`);

// ── Controller detail ─────────────────────────────────────────────────────────

export const getController = (pod) =>
  fetchJson(`/api/v1/controllers/${encodeURIComponent(pod)}`);
export const getControllerHealth = (pod) =>
  fetchJson(`/api/v1/controllers/${encodeURIComponent(pod)}/health`);

// ── Gateways ──────────────────────────────────────────────────────────────────

export const getGateways = () => fetchJson('/api/v1/gateways');
export const getGateway = (ns, name) =>
  fetchJson(`/api/v1/gateways/${encodeURIComponent(ns)}/${encodeURIComponent(name)}`);

// ── Ingresses ─────────────────────────────────────────────────────────────────

export const getIngresses = () => fetchJson('/api/v1/ingresses');
export const getIngress = (ns, name) =>
  fetchJson(`/api/v1/ingresses/${encodeURIComponent(ns)}/${encodeURIComponent(name)}`);

// ── Routes (Route Inspector) ──────────────────────────────────────────────────

export const getHttproute = (ns, name) =>
  fetchJson(`/api/v1/routes/httproute/${encodeURIComponent(ns)}/${encodeURIComponent(name)}`);
export const getIngressRoute = (ns, name) =>
  fetchJson(`/api/v1/routes/ingress/${encodeURIComponent(ns)}/${encodeURIComponent(name)}`);

// ── Health ────────────────────────────────────────────────────────────────────

export const getHealth = () => fetchJson('/api/v1/health');
