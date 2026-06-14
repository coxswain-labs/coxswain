import { Table } from './Table.jsx';
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
 * Server-side pagination: pass `page = { offset, returned, total, pageSize,
 * onPage }` and the footer renders a `Showing A–B of N` window with Prev/Next
 * that call `onPage(newOffset)`. Without `page`, the simple `total` footer is
 * used. (When the owning screen applies an extra *client-side* filter — e.g.
 * problems-only — `rows` may be shorter than the server window; the window still
 * reflects the server's filtered total, which is the honest pagination count.)
 *
 * @param {{label: string}[]|string[]} columns
 * @param {Array} rows                  already-filtered rows
 * @param {(row, i) => any} renderRow
 * @param {number} [total]              full count before filtering (simple footer)
 * @param {{offset:number,returned:number,total:number,pageSize:number,onPage:(n:number)=>void}} [page]
 * @param {string} [emptyMsg]
 * @param {boolean} [loading]
 * @param {any} [error]
 */
export function DataTable({
  columns,
  rows,
  renderRow,
  total,
  page,
  emptyMsg = 'No data.',
  loading = false,
  error = null,
}) {
  if (error) return <ErrorState error={error} />;
  const labels = columns.map((c) => (typeof c === 'string' ? c : c.label));
  const paged = page && page.total > 0;
  const shownOfTotal =
    total != null && total !== rows.length
      ? `Showing ${rows.length} of ${total}`
      : `${rows.length} ${rows.length === 1 ? 'item' : 'items'}`;

  return (
    <>
      <Table columns={labels} rows={rows} renderRow={renderRow} emptyMsg={emptyMsg} />
      <div class="table-foot" aria-live="polite">
        {loading ? (
          'Loading…'
        ) : paged ? (
          <Pager page={page} />
        ) : (
          shownOfTotal
        )}
      </div>
    </>
  );
}

/** Prev/Next pager + `Showing A–B of N` window for server-side pagination. */
function Pager({ page }) {
  const { offset, returned, total, pageSize, onPage } = page;
  const from = total === 0 ? 0 : offset + 1;
  const to = offset + returned;
  const hasPrev = offset > 0;
  const hasNext = to < total;
  return (
    <span class="pager">
      <span class="pager-info">Showing {from}–{to} of {total}</span>
      <button
        class="pager-btn"
        disabled={!hasPrev}
        aria-label="Previous page"
        onClick={() => onPage(Math.max(0, offset - pageSize))}
      >
        ‹ Prev
      </button>
      <button
        class="pager-btn"
        disabled={!hasNext}
        aria-label="Next page"
        onClick={() => onPage(offset + pageSize)}
      >
        Next ›
      </button>
    </span>
  );
}
