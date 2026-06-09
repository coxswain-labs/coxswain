"""Substitute ``X.Y.Z`` placeholders with the build's package version.

The version is read from ``PACKAGE_VERSION``. Substitution only happens when
that value parses as a SemVer (e.g. ``0.1.2``); the literal ``v`` prefix in
``vX.Y.Z`` is preserved so URLs like ``releases/download/vX.Y.Z/...`` substitute
to ``releases/download/v0.1.2/...``.

When ``PACKAGE_VERSION`` is unset or non-SemVer (e.g. the ``main`` default used
for unreleased docs built from the main branch), placeholders are left
untouched. This keeps install commands honest:

- ``helm install --version X.Y.Z`` (Helm OCI charts only ship SemVer tags),
- ``releases/download/vX.Y.Z/install.yaml`` (no ``main`` GitHub release exists),
- ``ghcr.io/coxswain-labs/charts/coxswain:X.Y.Z`` (chart only published on tags)

would all break if blindly rewritten to ``main``. On dev docs the literal
placeholder signals "substitute the release you want" by the established
convention; on versioned docs the hook fills it in.
"""

import os
import re

_SEMVER = re.compile(r"^\d+\.\d+\.\d+")


def _is_semver():
    return bool(_SEMVER.match(os.environ.get("PACKAGE_VERSION", "main")))


def on_config(config):
    # Surface a flag the announce-block override reads to decide whether to
    # render the "dev docs" banner on every page.
    config["extra"]["dev_banner"] = not _is_semver()
    return config


def on_page_markdown(markdown, *, page, config, files):
    version = os.environ.get("PACKAGE_VERSION", "main")
    if not _SEMVER.match(version):
        return markdown
    return markdown.replace("X.Y.Z", version)
