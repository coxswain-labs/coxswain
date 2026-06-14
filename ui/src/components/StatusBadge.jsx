import { Badge } from './Badge.jsx';

/**
 * Traffic-served severity → a header status badge, shared by the resource-detail
 * screens (Gateway, Route). Mirrors the fleet's reachable/unreachable badge:
 * `ok` = serving, `warn` = degraded, `error` = not serving. Renders nothing for
 * an unknown/absent status.
 */
export function StatusBadge({ status }) {
  if (status === 'error') return <Badge variant="fail">not serving</Badge>;
  if (status === 'warn')  return <Badge variant="warn">degraded</Badge>;
  if (status === 'ok')    return <Badge variant="ok">serving</Badge>;
  return null;
}
