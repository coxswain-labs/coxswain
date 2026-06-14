/** One row in the live event feed. */
export function EventRow({ event }) {
  const { ts, type, detail } = event;
  return (
    <div class="ev-row" role="row">
      <span class="ev-time" aria-label={`at ${ts}`}>{ts}</span>
      <span class="ev-type">{type}</span>
      <span class="ev-detail">{detail}</span>
    </div>
  );
}

/** Format a JSON SSE data payload as a readable detail string. */
export function formatEventDetail(type, data) {
  if (!data) return '';
  switch (type) {
    case 'rebuild.completed':
      return `cycle: ${data.cycle}`;
    case 'proxy.connected':
      return `pod: ${data.pod}  mode: ${data.mode}  addr: ${data.admin_addr}`;
    case 'proxy.disconnected':
      return `pod: ${data.pod}  reason: ${data.reason ?? '—'}`;
    case 'controller.connected':
    case 'controller.disconnected':
      return `pod: ${data.pod}`;
    case 'leader.changed':
      return `pod: ${data.pod}  is_leader: ${data.is_leader}`;
    case 'ownership.changed':
      return `gateway: ${data.gateway}  ${data.from} → ${data.to}`;
    default:
      return JSON.stringify(data);
  }
}
