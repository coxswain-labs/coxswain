# Candidate finding

**Adversary:** a tenant with create-rights on `Ingress` in exactly one namespace.

**Precondition:** the cluster runs the shared proxy pool serving Ingress traffic,
and another tenant serves `victim.example.com` over HTTPS through it.

**Concrete input:** the attacker creates, in their own namespace, an Ingress
claiming the coxswain class with:

```yaml
metadata:
  annotations:
    ingress.coxswain-labs.dev/auth-tls-secret: does-not-exist
spec:
  tls:
    - hosts: [victim.example.com]
      secretName: attacker-own-cert
```

**Asserted path:** Ingress client-cert configuration is registered keyed by
`(shared HTTPS port, hostname)` with no check that the claiming namespace owns
the hostname, and a duplicate key is last-writer-wins. The named CA Secret does
not resolve, so the entry becomes the `Unavailable` state, which the proxy's SNI
callback treats as fail-closed: it requires a peer certificate with no CA store
installed, so every handshake for that SNI aborts.

**Asset exposed:** availability of another tenant's HTTPS listener — every client
of `victim.example.com` fails its TLS handshake for as long as the attacker's
Ingress exists, with no signal on the victim's own object.
