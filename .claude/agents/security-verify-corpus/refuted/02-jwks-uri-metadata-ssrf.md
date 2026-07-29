# Candidate finding

**Adversary:** a tenant with create-rights on `JwtAuth` in exactly one namespace.

**Precondition:** the cluster runs on a cloud provider exposing an instance
metadata service at `169.254.169.254`, and the controller pod's network path to
it is unfiltered.

**Concrete input:** the tenant creates a `JwtAuth` whose
`spec.jwks.remote.uri` is `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
The controller's JWKS refresher fetches it on the next poll (every 30 s to 5 min)
and records the outcome, which the tenant reads back through the route's
`Unavailable` → resolved status transition.

**Asserted path:** `remote.uri` is a namespaced-CRD field the tenant fully
controls, and the fetch is performed by the controller — a cluster-privileged pod
sitting inside the cluster network. Nothing about the URL constrains it to a
public destination, so the tenant steers a privileged fetcher at link-local
metadata, ClusterIPs, or node-local ports and reads the result back as a status
oracle.

**Asset exposed:** cloud instance credentials, and blind reachability probing of
the cluster network from the controller's vantage point.
