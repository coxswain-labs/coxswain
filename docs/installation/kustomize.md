# Kustomize install

Coxswain's deployment manifests are structured as a Kustomize base under `deploy/manifests/`. Use this method when you need to apply overlays — custom resource limits, additional labels, namespace changes, or image overrides.

## Install from main

For a quick install without version pinning:

```bash
# Install Gateway API CRDs first (once per cluster)
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml

# Install Coxswain
kubectl apply -k "github.com/coxswain-labs/coxswain//deploy/manifests?ref=main"
```

## Install a specific version

The remote base always uses `image: ...:latest`. To pin both the manifests and the image to a specific release, create a local overlay (replace `vX.Y.Z` with the release tag you want):

```bash
mkdir coxswain-install && cd coxswain-install
```

```yaml
# kustomization.yaml
resources:
  - github.com/coxswain-labs/coxswain//deploy/manifests?ref=vX.Y.Z

images:
  - name: ghcr.io/coxswain-labs/coxswain
    newTag: vX.Y.Z
```

```bash
kubectl apply -k .
```

## Upgrade

Update the `?ref=` and `newTag:` values in your overlay to the new version, then re-apply:

```bash
kubectl apply -k .
```

## Uninstall

```bash
kubectl delete -k .
```

!!! warning
    This removes the `coxswain-system` namespace and everything in it. Gateway API CRDs and any user-created `Gateway`/`HTTPRoute`/`Ingress` objects in other namespaces are not affected.
