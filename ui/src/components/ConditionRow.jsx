import { sevClass } from '../severity.js';

/** Condition status → row severity (the table warning left-edge). Positive
 *  polarity (Gateway API standard conditions): True = ok, False = error,
 *  Unknown = warn. */
const SEV = { True: 'ok', False: 'error', Unknown: 'warn' };

/**
 * One Kubernetes status condition as a table row, using the same warning visual
 * language as the other tables: a severity-coloured left edge for the status
 * (calm when True, red/amber otherwise), the condition type, and its reason +
 * message. The raw status is in the row tooltip.
 *
 * @param {{ type: string, status: string, reason?: string, message?: string }} condition
 */
export function ConditionRow({ condition }) {
  const { type, status, reason, message } = condition;
  const sev = SEV[status] ?? 'warn';
  const primary = reason || message || '—';
  const secondary = message && message !== reason ? message : null;

  return (
    <tr class={sevClass(sev)} title={`status: ${status}`}>
      <td><strong>{type}</strong></td>
      <td>
        {primary}
        {secondary && <div class="cond-detail">{secondary}</div>}
      </td>
    </tr>
  );
}
