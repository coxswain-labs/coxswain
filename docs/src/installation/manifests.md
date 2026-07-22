# Raw manifests install

Every Coxswain release publishes a pre-rendered `install.yaml` as a GitHub Release asset — `kustomize build` of the chart-rendered base, with the image pinned to the exact release tag. It includes the `Namespace`, `RBAC`, `GatewayClass`, `IngressClass`, all of Coxswain's CRDs, a `ValidatingAdmissionPolicy` for Ingress annotation validation, the controller `Deployment` and its Services, and the shared-proxy data-plane `Service`. (The shared proxy pool's Deployment and the rest of its resources are provisioned by the controller at runtime, in every install method.)

!!! note
    `install.yaml` is rendered from the Helm chart, so it installs the **same resources** as `helm install` — Services and the `PodDisruptionBudget` included. The `ValidatingAdmissionPolicy` is silently skipped on clusters that do not advertise `admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy` (Kubernetes < 1.30). Helm is still recommended for production, for values-driven configuration and upgrades.

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

## Control-plane CA

`install.yaml` runs the controller in `auto` CA mode — it self-generates the
discovery CA, so the controller↔proxy mTLS works with no extra steps. To consume
an external CA, switch the controller to `COXSWAIN_DISCOVERY_CA_MODE=external` and
supply the `coxswain-discovery-ca` Secret. See
[Control-plane security](../operations/control-plane-security.md).

## Uninstall

```bash
kubectl delete -f https://github.com/coxswain-labs/coxswain/releases/download/vX.Y.Z/install.yaml
```

!!! warning
    This removes the `coxswain-system` namespace and everything in it. Gateway API CRDs and any user-created `Gateway`/`HTTPRoute`/`Ingress` objects in other namespaces are not affected.
