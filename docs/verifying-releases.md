# Verifying releases

Every Coxswain release artifact — the OCI image and the Helm chart — is signed with
[cosign](https://github.com/sigstore/cosign) using keyless [Sigstore](https://sigstore.dev)
signing. Signing happens inside the GitHub Actions release workflow using the job's OIDC
identity token; no long-lived private key is stored anywhere.

## Install cosign

```bash
# macOS
brew install cosign

# Linux — see https://github.com/sigstore/cosign#installation for package manager options
```

## Verify the OCI image

Replace `v0.1.0` with the tag you pulled:

```bash
cosign verify \
  --certificate-identity-regexp \
    "https://github.com/coxswain-labs/coxswain/.github/workflows/release.yml" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/coxswain-labs/coxswain:v0.1.0
```

A successful verification prints the certificate claims and exits 0. A non-zero exit means the
image is unsigned or the signature does not match the expected workflow identity.

## Verify the Helm chart

The Helm chart is published as an OCI artifact and signed at the same digest level:

```bash
cosign verify \
  --certificate-identity-regexp \
    "https://github.com/coxswain-labs/coxswain/.github/workflows/release.yml" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/coxswain-labs/charts/coxswain:0.1.0
```

Note: the chart version does not carry the `v` prefix (e.g. `0.1.0`, not `v0.1.0`).

## What the signature covers

The signature is attached to the content digest of the artifact, not just the tag. Tags are
mutable (they can be re-pointed), but the digest is a content hash and is immutable. If a tag is
ever re-published, the old digest retains its original signature; the new digest will have a
different (or absent) signature.

## Policy enforcement

If your cluster uses an admission webhook that evaluates cosign signatures (e.g. Kyverno,
Ratify, Sigstore Policy Controller), configure it to match:

| Field | Value |
|-------|-------|
| Certificate identity regexp | `https://github.com/coxswain-labs/coxswain/.github/workflows/release.yml` |
| OIDC issuer | `https://token.actions.githubusercontent.com` |
| Image reference | `ghcr.io/coxswain-labs/coxswain` |
