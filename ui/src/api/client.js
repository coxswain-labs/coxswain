/**
 * Fetch a JSON endpoint on the controller admin port.
 *
 * Paths are relative to the page origin (works both when served embedded in
 * the binary and when Vite's dev server proxies to a port-forwarded controller).
 *
 * Returns the parsed JSON on success.  Throws an Error on network failure or
 * non-2xx response; the Error carries a human-readable `.message` and the raw
 * HTTP `.status` when applicable.
 */
export async function fetchJson(path) {
  let resp;
  try {
    resp = await fetch(path);
  } catch (e) {
    throw new Error(`Network error fetching ${path}: ${e.message}`);
  }
  if (!resp.ok) {
    const err = new Error(`${resp.status} ${resp.statusText} (${path})`);
    err.status = resp.status;
    throw err;
  }
  return resp.json();
}
