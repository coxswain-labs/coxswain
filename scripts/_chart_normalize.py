"""Normalize a multi-document YAML stream for diffing chart output vs raw manifests.

Strips Helm-only labels (helm.sh/chart, app.kubernetes.io/version,
app.kubernetes.io/managed-by, app.kubernetes.io/instance), sorts documents
by (kind, metadata.name), and writes them back out with consistent key ordering.

Usage: python3 _chart_normalize.py <input.yaml> > normalized.yaml
"""

import sys
import yaml

# Labels added by Helm that do not exist in the raw manifests.
HELM_ONLY_LABELS = {
    "helm.sh/chart",
    "app.kubernetes.io/version",
    "app.kubernetes.io/managed-by",
    "app.kubernetes.io/instance",
}

# Metadata-level annotations / fields that only Helm sets.
HELM_ONLY_ANNOTATIONS: set[str] = set()


def _strip_helm_labels(obj: dict) -> None:
    """Remove Helm-only labels and annotations from every resource's metadata in-place."""
    meta = obj.get("metadata", {})
    labels = meta.get("labels", {})
    for key in HELM_ONLY_LABELS:
        labels.pop(key, None)
    if not labels:
        meta.pop("labels", None)
    elif labels != meta.get("labels"):
        meta["labels"] = labels

    # Recurse into template.metadata for Deployment/DaemonSet/etc.
    spec = obj.get("spec", {})
    tmpl = spec.get("template", {})
    if tmpl:
        _strip_helm_labels(tmpl)


def _sort_key(doc: dict) -> tuple[str, str]:
    kind = doc.get("kind", "")
    name = (doc.get("metadata") or {}).get("name", "")
    return (kind, name)


def _ordered(obj):
    """Return a recursively sorted representation for stable YAML output."""
    if isinstance(obj, dict):
        return {k: _ordered(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_ordered(i) for i in obj]
    return obj


def main() -> None:
    path = sys.argv[1]
    with open(path) as fh:
        docs = [d for d in yaml.safe_load_all(fh) if d is not None]

    for doc in docs:
        _strip_helm_labels(doc)

    docs.sort(key=_sort_key)

    yaml.dump_all(
        [_ordered(d) for d in docs],
        sys.stdout,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,  # _ordered already sorted keys
    )


if __name__ == "__main__":
    main()
