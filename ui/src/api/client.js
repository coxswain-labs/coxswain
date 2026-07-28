/**
 * Forward the page's `?mock=<variant>` to the API request, in dev only.
 *
 * The mock backend selects an alternate fixture per request; without this the
 * variant is reachable by `curl` but not by any screen, so error branches like
 * the standby `503` on `/api/v1/topology` could never actually be seen. A no-op
 * in production: nothing sets the parameter, and the real controller ignores it.
 */
function withMockVariant(path) {
  const variant = new URLSearchParams(window.location.search).get('mock');
  if (!variant) return path;
  return `${path}${path.includes('?') ? '&' : '?'}mock=${encodeURIComponent(variant)}`;
}

/**
 * Fetch a JSON endpoint on the controller operator port.
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
    resp = await fetch(withMockVariant(path));
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
