# Kustomize install

Coxswain's deployment manifests are structured as a Kustomize base under `deploy/manifests/`. Use this method when you need to apply overlays — custom resource limits, additional labels, namespace changes, or image overrides. The base's core resource, `coxswain.yaml`, is **rendered from the Helm chart**, so a Kustomize install produces the same result as `helm install`; it plus all of Coxswain's CRDs and a `ValidatingAdmissionPolicy` for Ingress annotation validation (silently skipped on Kubernetes < 1.30) make up the base.

## Install from main

For a quick install without version pinning:

```bash
# Install Gateway API CRDs first (once per cluster)
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml

# Install Coxswain
kubectl apply -k "github.com/coxswain-labs/coxswain//deploy/manifests?ref=main"
```

## Install a specific version

The remote base always uses `image: ...:latest`. To pin both the manifests and the image to a specific release, create a local overlay:

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

## Control-plane CA

The base runs the controller in `auto` CA mode: it self-generates the discovery
CA and works out of the box. To consume an external CA instead, apply
`deploy/manifests/cert-manager-example.yaml` (a standalone recipe, not part of
the base), set `COXSWAIN_DISCOVERY_CA_MODE=external` on the controller, and delete
the `coxswain-controller-discovery-ca` Role/RoleBinding. See
[Control-plane security](../operations/control-plane-security.md).

## Uninstall

```bash
kubectl delete -k .
```

!!! warning
    This removes the `coxswain-system` namespace and everything in it. Gateway API CRDs and any user-created `Gateway`/`HTTPRoute`/`Ingress` objects in other namespaces are not affected.
