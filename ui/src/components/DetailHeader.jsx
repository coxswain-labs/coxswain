import { CopyButton } from './CopyButton.jsx';

/**
 * Shared header for the pod-detail pages (controller + proxy). Renders the
 * common skeleton — resource name (+ copy), a `Namespace:` line (white value,
 * matching the Dashboard cards), and a top-aligned badge cluster — and leaves
 * the page-specific bits to slots:
 *
 * @param name     resource (pod) name
 * @param namespace pod namespace
 * @param meta     optional extra meta lines below `Namespace:` (e.g. the
 *                 controller's `Leader:` link, a dedicated proxy's `Gateway:`)
 * @param badges   the badge cluster (page picks: leader/standby or pool, + reachable)
 * @param actions  optional action buttons (e.g. View manifest / Logs), shown
 *                 below the badges, right-aligned
 */
export function DetailHeader({ name, namespace, meta, badges, actions }) {
  return (
    <div class="screen-header">
      <div class="detail-head">
        <div class="detail-title-row">
          <h1 class="screen-title">{name}</h1>
          <CopyButton text={name} label="Copy pod name" />
        </div>
        <div class="problem-card-meta">Namespace: <code>{namespace || '—'}</code></div>
        {meta}
      </div>
      <div class="header-aside">
        <div class="header-badges">{badges}</div>
        {actions && <div class="header-actions">{actions}</div>}
      </div>
    </div>
  );
}
