/**
 * Generic data table.
 *
 * @param {string[]}   columns  - Column header labels.
 * @param {Array}      rows     - Array of row data; each item passed to `renderRow`.
 * @param {function}   renderRow - (row, index) → <tr> element.
 * @param {string}     [emptyMsg] - Message shown when `rows` is empty.
 */
export function Table({ columns, rows, renderRow, emptyMsg = 'No data.' }) {
  return (
    <div class="tbl-wrap">
      {rows.length === 0 ? (
        <div style="padding:16px;color:var(--muted);font-size:13px">{emptyMsg}</div>
      ) : (
        <table>
          <thead>
            <tr>
              {columns.map((col) => <th key={col}>{col}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => renderRow(row, i))}
          </tbody>
        </table>
      )}
    </div>
  );
}
