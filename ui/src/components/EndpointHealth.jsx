/**
 * Endpoint-health indicator for a route table row.
 *
 * Renders "N endpoints" when healthy, or a bold amber warning when 0
 * endpoints — the most common cause of "route accepted but returns 503".
 */
export function EndpointHealth({ endpoints = [] }) {
  const count = endpoints.length;
  if (count === 0) {
    return (
      <span
        class="endpoint-health dead"
        title="No ready endpoints — Service has no ready Pods"
        aria-label="0 endpoints: no ready pods"
      >
        ⚠ 0 endpoints
      </span>
    );
  }
  return (
    <span class="endpoint-health" aria-label={`${count} endpoint${count !== 1 ? 's' : ''}`}>
      {count} endpoint{count !== 1 ? 's' : ''}
    </span>
  );
}
