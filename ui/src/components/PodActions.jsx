import { useState } from 'preact/hooks';
import { Icon } from './Icon.jsx';
import { ManifestDialog } from './ManifestDialog.jsx';

/**
 * The action buttons shared by the pod-detail pages (controller + proxy):
 * "View manifest" (opens the live Pod YAML, reusing ManifestDialog) and a
 * "Logs" placeholder. Logs is intentionally inert for now — streaming pod logs
 * through the controller is tracked in #285.
 *
 * @param namespace the pod's namespace
 * @param name      the pod name
 */
export function PodActions({ namespace, name }) {
  const [showManifest, setShowManifest] = useState(false);

  return (
    <>
      <button class="btn btn-icon" onClick={() => setShowManifest(true)}>
        <Icon name="code" size={15} /> Manifest
      </button>
      <button class="btn btn-icon" disabled title="Pod logs — coming soon (#285)">
        <Icon name="terminal" size={15} /> Logs
      </button>

      {showManifest && (
        <ManifestDialog
          kind="pod"
          namespace={namespace}
          name={name}
          onClose={() => setShowManifest(false)}
        />
      )}
    </>
  );
}
