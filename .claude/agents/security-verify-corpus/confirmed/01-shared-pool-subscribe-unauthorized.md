# Candidate finding

**Adversary:** a pod scheduled in the cluster holding zero Kubernetes RBAC.

**Precondition:** the pod can reach the controller's discovery Service on the
bootstrap and stream ports. It declares a projected ServiceAccount token in its
own pod spec with audience `coxswain-discovery` — no RBAC grant is involved,
the kubelet issues it.

**Concrete input:**

1. `Bootstrap(sa_token, csr_pem, wire_version = 2)` to
   `coxswain-controller-discovery.<install-ns>.svc:50052`, where `sa_token` is
   the pod's own projected token and the CSR is locally generated.
2. `Subscribe(node_id = "x", wire_version = 2)` over mTLS to `:50051` with the
   returned SVID and **no `scope` field set**.

**Asserted path:** the bootstrap handler authenticates the token and signs the
CSR without consulting which `(namespace, serviceaccount)` it belongs to. The
subscribe handler treats an absent `scope` as `Scope::SharedPool` and applies no
identity check to that scope — the Gateway-scope binding and the `Namespace`
authorizer are the only two open-time gates. The stream is accepted and the
server sends the full shared-pool snapshot.

**Asset exposed:** every TLS server certificate **and private key** the shared
pool serves, cluster-wide, plus every basic-auth credential hash and resolved
JWKS on the same wire.
