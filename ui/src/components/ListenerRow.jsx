/**
 * One listener row in the Gateway detail listener table.
 *
 * Rows with 0 attached routes are highlighted in amber — the listener exists
 * but nothing is routing through it.
 */
export function ListenerRow({ listener }) {
  const { name, port, protocol, tls_enabled, attached_routes } = listener;
  const warn = attached_routes === 0;

  return (
    <tr class={warn ? 'listener-warn' : ''}>
      <td><code>{name}</code></td>
      <td>{port}</td>
      <td>{protocol}</td>
      <td>
        {tls_enabled
          ? <span style="color:var(--green)">✔ TLS</span>
          : <span style="color:var(--muted)">—</span>}
      </td>
      <td>
        {warn
          ? <span aria-label="0 attached routes — no routes using this listener">⚠ 0</span>
          : attached_routes}
      </td>
    </tr>
  );
}
