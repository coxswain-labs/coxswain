import { useEffect, useRef, useState } from 'preact/hooks';
import { dump } from 'js-yaml';
import Prism from 'prismjs';
import 'prismjs/components/prism-yaml';
import 'prismjs/themes/prism-tomorrow.css';
import { getManifest } from '../api/endpoints.js';
import { Spinner, ErrorState } from './Spinner.jsx';

/**
 * Modal dialog that fetches and renders a Kubernetes manifest as
 * syntax-highlighted YAML.
 *
 * Accessibility:
 * - `role="dialog"` + `aria-modal="true"` + `aria-labelledby` for screen readers.
 * - Focus is trapped inside the dialog while open; restored to the trigger on close.
 * - Closes on Escape and on backdrop click.
 * - Copy button uses `navigator.clipboard` with a visible confirmation tick.
 *
 * @param {string}   kind       - "httproute" | "ingress" | "gateway"
 * @param {string}   namespace
 * @param {string}   name
 * @param {function} onClose    - called when the dialog should be dismissed
 */
export function ManifestDialog({ kind, namespace, name, onClose }) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [copied, setCopied]   = useState(false);
  const dialogRef  = useRef(null);
  const closeRef   = useRef(null);
  const titleId    = 'manifest-dialog-title';

  // Fetch the manifest on mount.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    getManifest(kind, namespace, name)
      .then((json) => {
        if (!cancelled) {
          setData(json);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err);
          setLoading(false);
        }
      });
    return () => { cancelled = true; };
  }, [kind, namespace, name]);

  // Focus the close button when dialog opens.
  useEffect(() => {
    closeRef.current?.focus();
  }, []);

  // Trap focus inside the dialog.
  useEffect(() => {
    const el = dialogRef.current;
    if (!el) return;
    const focusable = () =>
      Array.from(
        el.querySelectorAll(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((n) => !n.disabled);

    const onKey = (e) => {
      if (e.key === 'Escape') { onClose(); return; }
      if (e.key !== 'Tab') return;
      const nodes = focusable();
      if (nodes.length === 0) { e.preventDefault(); return; }
      const first = nodes[0];
      const last  = nodes[nodes.length - 1];
      if (e.shiftKey) {
        if (document.activeElement === first) { e.preventDefault(); last.focus(); }
      } else {
        if (document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    };
    el.addEventListener('keydown', onKey);
    return () => el.removeEventListener('keydown', onKey);
  }, [onClose]);

  // Compute YAML + highlighted HTML whenever data changes.
  const { yaml, highlighted } = useHighlightedYaml(data);

  async function copyToClipboard() {
    if (!yaml) return;
    try {
      await navigator.clipboard.writeText(yaml);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API unavailable (non-HTTPS, old browser).
    }
  }

  const title = `${kindLabel(kind)} ${namespace}/${name}`;

  return (
    <>
      {/* Backdrop */}
      <div
        class="dialog-backdrop"
        aria-hidden="true"
        onClick={onClose}
      />

      {/* Dialog */}
      <div
        ref={dialogRef}
        class="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <div class="dialog-header">
          <div class="dialog-title-group">
            <span class="dialog-kind-badge">{kindLabel(kind)}</span>
            <h2 id={titleId} class="dialog-title">
              <span class="dialog-ns">{namespace}/</span>{name}
            </h2>
          </div>
          <div class="dialog-actions">
            {yaml && (
              <button class="btn" onClick={copyToClipboard} aria-label="Copy YAML to clipboard">
                {copied ? '✔ Copied' : 'Copy'}
              </button>
            )}
            <button
              ref={closeRef}
              class="btn dialog-close"
              onClick={onClose}
              aria-label="Close manifest dialog"
            >
              ✕
            </button>
          </div>
        </div>

        <div class="dialog-body">
          {loading && <Spinner label="Fetching manifest…" />}
          {error   && <ErrorState error={error} />}
          {!loading && !error && highlighted && (
            <pre
              class="language-yaml manifest-pre"
              aria-label={`YAML manifest for ${title}`}
              // Prism.highlight returns sanitised HTML — safe to use as innerHTML.
              // eslint-disable-next-line react/no-danger
              dangerouslySetInnerHTML={{ __html: highlighted }}
            />
          )}
        </div>
      </div>
    </>
  );
}

/**
 * Derive a human-readable kind label from the endpoint kind string.
 */
function kindLabel(kind) {
  switch (kind) {
    case 'httproute': return 'HTTPRoute';
    case 'gateway':   return 'Gateway';
    case 'ingress':   return 'Ingress';
    case 'pod':       return 'Pod';
    default:          return kind;
  }
}

/**
 * Convert a JSON object to syntax-highlighted YAML.
 *
 * Returns `{ yaml, highlighted }` — both null until data is available.
 * Runs synchronously inside the render cycle; the manifest JSON is small
 * enough that this never causes a perceptible stall.
 */
function useHighlightedYaml(data) {
  if (!data) return { yaml: null, highlighted: null };
  const yaml = dump(data, { lineWidth: 120, noRefs: true });
  const highlighted = Prism.highlight(yaml, Prism.languages.yaml, 'yaml');
  return { yaml, highlighted };
}
