# Candidate finding

**Adversary:** an anonymous client of a route protected by a `JwtAuth` policy.

**Precondition:** the route resolves a JWKS containing an RSA or EC public key,
and the attacker can read that public key — JWKS endpoints are public by
definition.

**Concrete input:** the attacker forges a token whose header declares
`{"alg": "HS256"}` and signs it with the **public key bytes** of the JWKS entry
as the HMAC secret, then presents it as `Authorization: Bearer <token>`.

**Asserted path:** the verifier reads the algorithm from the token header and
selects an HMAC verification routine, then passes the JWKS key material as the
HMAC secret. Because the attacker holds that material, the signature validates.
This is the classic RS→HS algorithm-confusion attack, and the token header is
entirely attacker-controlled input.

**Asset exposed:** authentication bypass on every route protected by that
`JwtAuth` — the attacker mints tokens with arbitrary `sub`, and any claim copied
to an upstream header via `claimToHeaders` is attacker-chosen.
