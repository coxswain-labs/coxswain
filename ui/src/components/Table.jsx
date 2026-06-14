import { useEffect, useRef } from 'preact/hooks';

/**
 * Generic data table.
 *
 * The table shell always renders (empty state becomes a full-width row) so the
 * header and the optional `footer` stay attached and column-aligned. The body
 * scrolls inside a bounded wrapper with a sticky header and footer; changing
 * `scrollKey` (e.g. the page offset) snaps the scroll back to the top so a new
 * page reads from its first row.
 *
 * @param {string[]}   columns   - Column header labels.
 * @param {Array}      rows      - Array of row data; each item passed to `renderRow`.
 * @param {function}   renderRow - (row, index) → <tr> element.
 * @param {string}     [emptyMsg] - Message shown when `rows` is empty.
 * @param {any}        [footer]   - Rendered in a `<tfoot>` cell spanning all columns.
 * @param {any}        [scrollKey] - When it changes, the body scrolls back to top.
 */
export function Table({ columns, rows, renderRow, emptyMsg = 'No data.', footer = null, scrollKey }) {
  const wrap = useRef(null);
  useEffect(() => {
    if (wrap.current) wrap.current.scrollTop = 0;
  }, [scrollKey]);
  return (
    <div class="tbl-wrap" ref={wrap}>
      <table>
        <thead>
          <tr>
            {columns.map((col) => <th key={col}>{col}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td class="tbl-empty" colspan={columns.length}>{emptyMsg}</td>
            </tr>
          ) : (
            rows.map((row, i) => renderRow(row, i))
          )}
        </tbody>
        {footer && (
          <tfoot>
            <tr>
              <td class="table-foot" colspan={columns.length}>{footer}</td>
            </tr>
          </tfoot>
        )}
      </table>
    </div>
  );
}
