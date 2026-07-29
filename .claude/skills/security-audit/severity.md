# Severity rubric

Severity is a **lookup**, not a judgment call. Two audits that agree on the
reachability tier and the asset tier must produce the same severity, or the
ranking drifts between runs and the milestone order becomes arbitrary.

Score every finding by answering two questions in order, then read the cell.

## Reachability — what the attacker must already have

| Tier | Precondition |
|---|---|
| **R1** | Nothing. An anonymous client reaching a data-plane listener, or any pod scheduled in the cluster holding **zero** Kubernetes RBAC. |
| **R2** | Create-rights in exactly one namespace — an ordinary tenant. |
| **R3** | An operator misconfiguration, or a non-default feature the operator had to enable. |
| **R4** | An already-compromised coxswain component (proxy, relay, controller) or node-level access. |

A projected ServiceAccount token is **not** RBAC: any pod spec may request any
audience and the kubelet issues it. A finding reachable that way is R1, not R2.

## Asset — what the attacker reaches

| Tier | Asset |
|---|---|
| **A1** | Private keys — TLS server keys, the discovery CA, cluster Secrets. |
| **A2** | Cross-tenant traffic integrity or an authentication bypass: serving, intercepting, or authorizing traffic for a tenant that is not the attacker. |
| **A3** | Availability of a shared plane — a data-plane listener, or the control plane's convergence, for tenants other than the attacker. |
| **A4** | Disclosure and reconnaissance: topology, backend addresses, route inventory. |

## The matrix

|  | A1 | A2 | A3 | A4 |
|---|---|---|---|---|
| **R1** | Critical | High | High | Medium |
| **R2** | Critical | High | High | Low |
| **R3** | High | Medium | Medium | Low |
| **R4** | Medium | Medium | Low | Low |

**Tie-break, applied only within a cell:** a finding an attacker can trigger
*accidentally* — a malformed value a well-meaning tenant might submit — outranks
one requiring deliberate construction. #693 (any tenant's bad regex freezes
cluster-wide convergence) sits above a same-cell finding needing a crafted
certificate.

**R4 is not "ignore".** An R4/A2 finding is what decides whether a compromise
stays contained; it is simply not what an attacker starts from.

## Placement on the milestone board

`Order` follows severity, with one override: within a severity band, a finding
whose blast radius crosses tenants precedes one bounded to a single tenant.
Insert relative to the existing wave rather than renumbering it — the sequence
tolerates gaps (`62`, `65`, `95`), and renumbering destroys the board's history.

## Worked examples

Kept because a rubric with no worked cases gets read as advisory.

| Finding | Reachability | Asset | Severity |
|---|---|---|---|
| #726 — any pod bootstraps an SVID, subscribes SharedPool, reads every shared TLS private key | R1 — a pod spec and a projected token, no RBAC | A1 | **Critical** |
| #727 — an Ingress in any namespace claims another tenant's hostname, forcing fail-closed mTLS on it | R2 | A2 (cert displacement) + A3 (denial) | **High** |
| #728 — a tenant attaches a more-specific path under another tenant's host | R2 | A2 | **High** |
| #729 — spoofed UDP sources exhaust the session table | R1 | A3 | **High** |
| #730 — `AllowInsecureFallback` forwards an unverified client cert | R3 — needs the non-default fallback mode plus cert forwarding | A2 | **Medium** |
| #731 — XFF private-range skip lets a privately-sourced client forge its IP | R3 — needs `ForwardedForConfig` and a private-addressed client population | A2 | **Medium** |
| Controller holds cluster-wide `secrets` read | R4 | A1 | **Medium** — accepted, mitigated by the `watchNamespace` lockdown |
