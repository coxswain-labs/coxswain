import { useState } from 'preact/hooks';

/**
 * Small inline button that copies `text` to the clipboard.
 *
 * Lives inside clickable cards/rows, so every pointer/keyboard event is
 * stopped from propagating — otherwise copying would also trigger the card's
 * navigation. Shows a brief checkmark on success.
 */
export function CopyButton({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false);

  const copy = (e) => {
    e.stopPropagation();
    e.preventDefault();
    navigator.clipboard?.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    });
  };
  const stop = (e) => e.stopPropagation();

  return (
    <button
      type="button"
      class={`copy-btn${copied ? ' copied' : ''}`}
      aria-label={copied ? 'Copied' : `${label}: ${text}`}
      title={copied ? 'Copied' : 'Copy'}
      onClick={copy}
      onKeyDown={stop}
      onMouseDown={stop}
    >
      {copied ? (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
          <path d="M20 6 9 17l-5-5" />
        </svg>
      ) : (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
          <rect x="9" y="9" width="13" height="13" rx="2" />
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
        </svg>
      )}
    </button>
  );
}
