import { Table } from './Table.jsx';
import { StatusDot } from './StatusDot.jsx';
import { ErrorState } from './Spinner.jsx';

/**
 * Shared list table for the routing screens (#292/#296).
 *
 * Wraps the dumb [`Table`] primitive with the routing-table chrome: an
 * error/empty state and a "showing X of Y" footer that surfaces server-side
 * truncation (the no-silent-truncation rule). The owning screen still owns the
 * search/namespace/type filters and supplies already-filtered `rows`; `total`
 * is the pre-filter (or server-reported) count so the footer can show how many
 * were hidden.
 *
 * Sortable headers and client-side virtualization are deliberately deferred to a
 * follow-up iteration (tracked under #292) — this lands the consistent table
 * shape first so the routing tabs are usable.
 *
 * @param {{label: string}[]|string[]} columns
 * @param {Array} rows                  already-filtered rows
 * @param {(row, i) => any} renderRow
 * @param {number} [total]              full count before filtering (for the footer)
 * @param {string} [emptyMsg]
 * @param {boolean} [loading]
 * @param {any} [error]
 */
export function DataTable({
  columns,
  rows,
  renderRow,
  total,
  emptyMsg = 'No data.',
  loading = false,
  error = null,
}) {
  if (error) return <ErrorState error={error} />;
  const labels = columns.map((c) => (typeof c === 'string' ? c : c.label));
  const shownOfTotal =
    total != null && total !== rows.length
      ? `Showing ${rows.length} of ${total}`
      : `${rows.length} ${rows.length === 1 ? 'item' : 'items'}`;
  return (
    <>
      <Table columns={labels} rows={rows} renderRow={renderRow} emptyMsg={emptyMsg} />
      <div class="table-foot" aria-live="polite">
        {loading ? 'Loading…' : shownOfTotal}
      </div>
    </>
  );
}

/**
 * Tri-state health badge for a routing resource's `status`
 * (`ok`/`warn`/`error`), reusing the shared dot styling. `error` maps to the
 * `err` dot state.
 */
export function SeverityDot({ status }) {
  const state = status === 'error' ? 'err' : status === 'warn' ? 'warn' : 'ok';
  const label = status === 'error' ? 'error' : status === 'warn' ? 'degraded' : 'healthy';
  return <StatusDot state={state} label={label}>{label}</StatusDot>;
}
