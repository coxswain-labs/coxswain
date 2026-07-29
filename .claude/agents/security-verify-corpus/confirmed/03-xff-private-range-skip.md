# Candidate finding

**Adversary:** an anonymous client of a route protected by an `IpAccessControl`
allow-list.

**Precondition:** the route sets a forwarded-for configuration naming a trusted
load balancer, the load balancer is inside `trusted_cidrs`, and the attacker
reaches it from a private address — a corporate VPN on `10.0.0.0/8`, a NAT'd
private client, or another in-cluster caller.

**Concrete input:** the attacker sends `X-Forwarded-For: 203.0.113.7` (an address
inside the allow-list they do not hold). The load balancer appends the real
source, producing `X-Forwarded-For: 203.0.113.7, 10.1.2.3`.

**Asserted path:** effective-client-IP resolution walks the header right-to-left
and skips a token when it is inside a trusted CIDR **or** inside a fixed table of
private and reserved ranges. The rightmost token `10.1.2.3` is discarded as
private, so the scan returns `203.0.113.7` — the value the client chose — and
that is what the allow-list check evaluates.

**Asset exposed:** the source-IP allow-list is bypassed; the attacker presents
whatever client IP admits them.
