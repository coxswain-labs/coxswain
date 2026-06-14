import { Badge } from './Badge.jsx';
import { Icon } from './Icon.jsx';
import { sevClass } from '../severity.js';

/**
 * One listener row in the Gateway detail listener table.
 *
 * The severity left-border reflects the listener's own **health** — its TLS
 * status (`error` = certificateRefs unresolved → no TLS traffic; `warn` = not
 * programmed yet). A healthy listener stays calm even with 0 attached routes:
 * "nothing routes through it yet" is informational, not a health fault, so it's
 * shown as a muted amber count in the routes cell rather than flagging the row
 * (which would contradict a green TLS tag).
 */
export function ListenerRow({ listener }) {
  const { name, port, protocol, tls_enabled, tls_status, tls_reason, attached_routes } = listener;
  const tlsSev = tls_enabled ? (tls_status ?? 'ok') : 'ok';
  const noRoutes = attached_routes === 0;

  return (
    <tr class={sevClass(tlsSev)} title={tlsSev !== 'ok' ? tls_reason || `TLS ${tlsSev}` : undefined}>
      <td><code>{name}</code></td>
      <td>{port}</td>
      <td>{protocol}</td>
      <td>{tls_enabled ? tlsBadge(tls_status, tls_reason) : '—'}</td>
      <td>
        {noRoutes ? (
          <span class="routes-none" title="No routes attached — nothing routes through this listener">0</span>
        ) : (
          attached_routes
        )}
      </td>
    </tr>
  );
}

/** TLS cell tag: a teal padlock only when the cert genuinely resolved + programmed;
 *  otherwise an alert tag in the matching severity colour, tooltip naming the reason. */
function tlsBadge(status, reason) {
  if (status == null || status === 'ok') {
    return <Badge variant="tls"><Icon name="lock" size={11} /> TLS</Badge>;
  }
  const variant = status === 'error' ? 'fail' : 'warn';
  const label = `TLS ${status === 'error' ? 'unresolved' : 'pending'}${reason ? `: ${reason}` : ''}`;
  return <Badge variant={variant} label={label}><Icon name="alert" size={11} /> TLS</Badge>;
}
