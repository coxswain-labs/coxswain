# Raw manifests install

Every Coxswain release publishes a pre-rendered `install.yaml` as a GitHub Release asset. It includes the `Namespace`, `RBAC`, `GatewayClass`, `IngressClass`, `CoxswainGatewayParameters` and `RateLimit` CRDs, a `ValidatingAdmissionPolicy` for Ingress annotation validation, and `Deployments` (controller and shared proxy), with the image pinned to the exact release tag.

!!! note
    The `ValidatingAdmissionPolicy` is silently skipped on clusters that do not advertise `admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy` (Kubernetes < 1.30). Service and PodDisruptionBudget resources are Helm-only; use the [Helm install](helm.md) for production deployments.

## Install the latest release

```bash
# Install Gateway API CRDs first (once per cluster)
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml

# Install Coxswain
kubectl apply -f https://github.com/coxswain-labs/coxswain/releases/latest/download/install.yaml
```

!!! note
    The `releases/latest/download/install.yaml` URL resolves only after the first tagged release. It returns 404 if no `v*` tag has been published yet.

## Pin a specific version

```bash
kubectl apply -f https://github.com/coxswain-labs/coxswain/releases/download/vX.Y.Z/install.yaml
```

## Upgrade

```bash
kubectl apply -f https://github.com/coxswain-labs/coxswain/releases/download/vX.Y.Z/install.yaml
```

The rolling update strategy on each Deployment ensures zero-downtime upgrades when running ≥ 2 replicas.

## Uninstall

```bash
kubectl delete -f https://github.com/coxswain-labs/coxswain/releases/download/vX.Y.Z/install.yaml
```

!!! warning
    This removes the `coxswain-system` namespace and everything in it. Gateway API CRDs and any user-created `Gateway`/`HTTPRoute`/`Ingress` objects in other namespaces are not affected.
