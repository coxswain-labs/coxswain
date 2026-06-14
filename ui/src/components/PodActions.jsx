import { useState } from 'preact/hooks';
import { Icon } from './Icon.jsx';
import { ManifestDialog } from './ManifestDialog.jsx';
import { LogsDialog } from './LogsDialog.jsx';

/**
 * The action buttons shared by the pod-detail pages (controller + proxy):
 * "Manifest" (opens the live Pod YAML, reusing ManifestDialog) and "Logs"
 * (tails the pod's logs streamed through the controller, see LogsDialog). The
 * logs endpoint is generic over component, so the same button works for both
 * controllers and proxies with just the pod name.
 *
 * @param namespace the pod's namespace
 * @param name      the pod name
 */
export function PodActions({ namespace, name }) {
  const [showManifest, setShowManifest] = useState(false);
  const [showLogs, setShowLogs] = useState(false);

  return (
    <>
      <button class="btn btn-icon" onClick={() => setShowManifest(true)}>
        <Icon name="code" size={15} /> Manifest
      </button>
      <button class="btn btn-icon" onClick={() => setShowLogs(true)}>
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
      {showLogs && (
        <LogsDialog name={name} onClose={() => setShowLogs(false)} />
      )}
    </>
  );
}
