import { Table } from './Table.jsx';
import { ErrorState } from './Spinner.jsx';
import { Icon } from './Icon.jsx';

/** Shared page-size options for every paginated table (routing lists + the
 *  per-proxy route table), so the choices don't drift between screens. */
export const PAGE_SIZES = [25, 50, 100, 200];

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
 * @param {boolean} [hidePager] when the owning screen renders the pager itself
 *        (e.g. in a sticky top toolbar), omit the in-`<tfoot>` pager/count here
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
  hidePager = false,
}) {
  if (error) return <ErrorState error={error} />;
  const labels = columns.map((c) => (typeof c === 'string' ? c : c.label));
  const paged = page && page.total > 0;
  const simple =
    total != null && total !== rows.length
      ? `Showing ${rows.length} of ${total}`
      : `${rows.length} ${rows.length === 1 ? 'item' : 'items'}`;

  // The footer lives in the table's <tfoot> so it spans the columns and stays
  // attached. While loading, omit it (the body shows the loading text); when the
  // screen pins its own pager in a top toolbar, omit it too (no double pager).
  const footer = loading || hidePager
    ? null
    : paged
      ? <Pager page={page} />
      : <span class="pager-info">{simple}</span>;

  return (
    <Table
      columns={labels}
      rows={rows}
      renderRow={renderRow}
      emptyMsg={loading ? 'Loading…' : emptyMsg}
      footer={footer}
      scrollKey={page ? page.offset : undefined}
    />
  );
}

/**
 * Datatable footer: the row range on the left, the page-size selector +
 * First/Prev/Next/Last nav grouped on the right.
 *
 * Exported so screens with a non-`DataTable` layout (the per-proxy route table,
 * which is tabbed + host-grouped) can render the same pager directly.
 */
export function Pager({ page }) {
  const { offset, returned, total, pageSize, pageSizes = [], onPage, onPageSize } = page;
  const from = total === 0 ? 0 : offset + 1;
  const to = offset + returned;
  const atStart = offset <= 0;
  const atEnd = to >= total;
  const lastOffset = total === 0 ? 0 : Math.floor((total - 1) / pageSize) * pageSize;
  return (
    <div class="pager">
      <span class="pager-info">
        Showing <strong>{from}–{to}</strong> of <strong>{total}</strong>
      </span>
      <div class="pager-controls">
        {onPageSize && pageSizes.length > 0 && (
          <label class="pager-size">
            Rows per page
            <select value={pageSize} onChange={(e) => onPageSize(Number(e.target.value))}>
              {pageSizes.map((n) => (
                <option key={n} value={n}>{n}</option>
              ))}
            </select>
          </label>
        )}
        <div class="pager-nav" role="group" aria-label="Pagination">
          <button class="pager-btn" disabled={atStart} aria-label="First page" onClick={() => onPage(0)}>
            <Icon name="chevrons-left" size={16} />
          </button>
          <button class="pager-btn" disabled={atStart} aria-label="Previous page" onClick={() => onPage(Math.max(0, offset - pageSize))}>
            <Icon name="chevron-left" size={16} />
          </button>
          <button class="pager-btn" disabled={atEnd} aria-label="Next page" onClick={() => onPage(offset + pageSize)}>
            <Icon name="chevron-right" size={16} />
          </button>
          <button class="pager-btn" disabled={atEnd} aria-label="Last page" onClick={() => onPage(lastOffset)}>
            <Icon name="chevrons-right" size={16} />
          </button>
        </div>
      </div>
    </div>
  );
}
