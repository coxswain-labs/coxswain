# Candidate finding

**Adversary:** an anonymous client of an HTTPS listener where one hostname
requires client certificates and another on the same port does not.

**Precondition:** the shared HTTPS port serves both `open.example.com` (no
frontend validation) and `secure.example.com` (mTLS required, `AllowValidOnly`).
Both are served by the same process and therefore the same acceptor.

**Concrete input:**

1. The attacker completes a normal handshake to `open.example.com`, which
   requires no client certificate, and retains the session ticket the server
   issues.
2. The attacker opens a new connection presenting that ticket with SNI
   `secure.example.com`.

**Asserted path:** session resumption short-circuits the full handshake, so the
per-SNI certificate callback — which is where client-certificate enforcement is
configured — does not run for the resumed connection. The session's cached
parameters carry no client certificate, and the request proceeds to the mTLS-
protected host without one.

**Asset exposed:** the client-certificate requirement on `secure.example.com` is
bypassed, and any backend trusting the proxy's mTLS enforcement is reachable
without a certificate.
