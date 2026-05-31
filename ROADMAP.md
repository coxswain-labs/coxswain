# Coxswain — Product Roadmap

## Feature Classification

### MUST HAVE *(v1.0 blockers)*

**Spec Correctness & Multi-tenancy**
- IngressClass filtering (currently picks up all Ingress resources regardless of class)
- `parentRef` matching for HTTPRoute (currently reads all HTTPRoutes regardless of Gateway)
- `ReferenceGrant` support for cross-namespace backend refs
- Namespace-scoped watch (`--controller-watch-namespace` is parsed but never wired)
- Gateway resource reconciliation + status patching (watched but ignored today)
- Ingress `.status.loadBalancer` patching (required by cert-manager and external-dns)
- Default backend for Ingress (`spec.defaultBackend` not implemented)
- Cross-namespace backend refs in HTTPRoute

**TLS**
- TLS termination via `kubernetes.io/tls` Secret for both Ingress and Gateway API
- SNI-based routing
- Secret watch + hot reload without restart
- cert-manager integration for both APIs (`cert-manager.io/issuer` on Ingress, `gateway.cert-manager.io/issuer` on Gateway)

**Traffic Management**
- Full HTTPRoute filter support: `URLRewrite`, `RequestRedirect`, `RequestHeaderModifier`, `ResponseHeaderModifier`
- HTTPRoute header, method, and query parameter matching
- HTTPRoute `timeouts` field (GA in Gateway API v1.1)
- `BackendLBPolicy` (session persistence + timeouts per backend)
- `BackendTLSPolicy`
- Weighted backend refs (`backendRefs[].weight`)
- `coxswain-labs.dev/*` annotation namespace for Ingress (timeouts, retries, path rewriting)
- Nginx-compatible annotation aliases for migration

**Protocol**
- WebSocket passthrough (upgrade handshake)
- PROXY protocol v1/v2 support (client IP preservation behind cloud load balancers)

**Observability**
- Custom Prometheus metrics: requests/sec, latency (p50/p95/p99), error rate — all with per-route labels
- Structured per-request access logs (host, path, upstream, status, latency)

**Health & Reliability**
- Passive backend health checking: track in-flight errors, temporarily remove failing endpoints
- Endpoint drain: respect `conditions.serving` on EndpointSlice endpoints during rolling deploys

**Security & Policy**
- `SecurityPolicy` (Gateway API) for external auth (`ext_authz`)
- `ext_authz` annotation for Ingress
- Per-route, per-client rate limiting (by IP, header, namespace) for both APIs

**Distribution & Community**
- Dockerfile + published OCI image on a public registry
- OCI image signing with cosign (Sigstore, keyless via GitHub Actions OIDC)
- Helm chart with full configuration surface
- PodDisruptionBudget and resource requests/limits in deployment manifests
- GitHub Actions CI/CD pipeline (build, test, lint, release)
- `ValidatingAdmissionPolicy` for annotation validation (K8s 1.30+)
- Full Gateway API conformance test suite passing
- Docs site (getting started, config reference, architecture)
- Contributing guide, GitHub issue templates, conformance badge

---

### SHOULD HAVE *(post-v1.0, high priority)*

- HTTP/2 downstream with HTTP/1.1 upstream bridging (h2c)
- `GRPCRoute` + gRPC protocol support
- Active backend health probing (configurable HTTP check per upstream)
- OpenTelemetry trace context propagation across the proxy hop
- `GatewayClass` `ParametersRef` support

---

### NICE TO HAVE *(future, community-driven)*

- Session affinity for Ingress (via `coxswain-labs.dev/session-affinity` annotation; Gateway API session affinity ships in v0.4 via `BackendLBPolicy`)
- Response caching (HTTP cache semantics)
- Canary deployments (progressive `backendRefs[].weight` shifting with metrics-gated automation)
- Traffic mirroring / shadow traffic (fire-and-forget parallel backend for safe rollout validation)
- Blue/green orchestration (health-gated atomic cutover with automatic rollback)
- CORS built-in filter
- IPv6 / dual-stack explicit handling
- Performance profiling endpoints on admin port (CPU flamegraph via `pprof-rs`, Tokio task metrics)
- Dry-run mode for controller

---

## Milestones

**Milestone order is strict** — do not start a milestone before the previous one is complete. Within each milestone, items are listed in recommended implementation sequence.

### v0.1 — Current State *(done)*
Core routing engine, HTTP/1.1 proxy, round-robin LB, HTTPRoute + Ingress path/host routing, leader election, health/readiness/metrics/routes/status endpoints, debounced reconciler.

---

### v0.2 — Multi-tenancy & Spec Correctness
*Target: Week 1–2*

The most critical correctness gaps. Without these, Coxswain is unsafe in any shared cluster and fails Gateway API conformance on basic tests.

- [x] ~~Basic GitHub Actions CI (fmt, clippy, test) — [#45](https://github.com/coxswain-labs/coxswain/issues/45) `MUST`~~
- [x] ~~IngressClass filtering — [#1](https://github.com/coxswain-labs/coxswain/issues/1) `MUST`~~
- [ ] `parentRef` matching for HTTPRoute — [#2](https://github.com/coxswain-labs/coxswain/issues/2) `MUST`
- [ ] `ReferenceGrant` for cross-namespace backends — [#3](https://github.com/coxswain-labs/coxswain/issues/3) `MUST`
- [ ] Namespace-scoped watch (wire up `--controller-watch-namespace`) — [#4](https://github.com/coxswain-labs/coxswain/issues/4) `MUST`
- [ ] Gateway resource status patching — [#5](https://github.com/coxswain-labs/coxswain/issues/5) `MUST`
- [ ] Ingress `.status.loadBalancer` patching — [#48](https://github.com/coxswain-labs/coxswain/issues/48) `MUST`
- [ ] Default backend for Ingress — [#6](https://github.com/coxswain-labs/coxswain/issues/6) `MUST`
- [ ] HTTPRoute header, method, query matching — [#7](https://github.com/coxswain-labs/coxswain/issues/7) `MUST`

---

### v0.3 — TLS & WebSocket
*Target: Week 3–4*

TLS is a launch blocker. WebSocket is the minimum protocol expansion needed to support real-time workloads.

- [ ] TLS termination for Ingress (`spec.tls`) — [#8](https://github.com/coxswain-labs/coxswain/issues/8) `MUST`
- [ ] TLS termination for Gateway API (listeners) — [#9](https://github.com/coxswain-labs/coxswain/issues/9) `MUST`
- [ ] Secret watch + hot TLS reload — [#10](https://github.com/coxswain-labs/coxswain/issues/10) `MUST`
- [ ] cert-manager integration (both APIs) — [#11](https://github.com/coxswain-labs/coxswain/issues/11) `MUST`
- [ ] WebSocket upgrade passthrough — [#12](https://github.com/coxswain-labs/coxswain/issues/12) `MUST`
- [ ] PROXY protocol v1/v2 support — [#49](https://github.com/coxswain-labs/coxswain/issues/49) `MUST`

---

### v0.4 — Traffic Management
*Target: Week 5–6*

Full HTTPRoute filter compliance + the annotation layer for Ingress. This is the largest milestone by surface area.

- [ ] `URLRewrite`, `RequestRedirect`, `RequestHeaderModifier`, `ResponseHeaderModifier` filters — [#13](https://github.com/coxswain-labs/coxswain/issues/13) `MUST`
- [ ] HTTPRoute `timeouts` field — [#14](https://github.com/coxswain-labs/coxswain/issues/14) `MUST`
- [ ] `BackendLBPolicy` (session persistence + timeouts per backend) — [#15](https://github.com/coxswain-labs/coxswain/issues/15) `MUST`
- [ ] `BackendTLSPolicy` — [#16](https://github.com/coxswain-labs/coxswain/issues/16) `MUST`
- [ ] Weighted backend refs — [#17](https://github.com/coxswain-labs/coxswain/issues/17) `MUST`
- [ ] `coxswain-labs.dev/*` annotation namespace — [#18](https://github.com/coxswain-labs/coxswain/issues/18) `MUST`
- [ ] Nginx-compatible annotation aliases — [#19](https://github.com/coxswain-labs/coxswain/issues/19) `MUST`

---

### v0.5 — Observability & Health
*Target: Week 7*

Operators need signals before they trust any controller in production. This milestone gives them the three they care about most.

- [ ] Custom per-route Prometheus metrics (latency, rps, errors) — [#20](https://github.com/coxswain-labs/coxswain/issues/20) `MUST`
- [ ] Structured per-request access logs — [#21](https://github.com/coxswain-labs/coxswain/issues/21) `MUST`
- [ ] Passive backend health checking — [#22](https://github.com/coxswain-labs/coxswain/issues/22) `MUST`
- [ ] Endpoint drain (`conditions.serving`) — [#50](https://github.com/coxswain-labs/coxswain/issues/50) `MUST`

---

### v0.6 — Security & Policy
*Target: Week 8*

Auth and rate limiting close the gap with production-grade controllers.

- [ ] `SecurityPolicy` (Gateway API ext_authz) — [#23](https://github.com/coxswain-labs/coxswain/issues/23) `MUST`
- [ ] `ext_authz` annotation for Ingress — [#24](https://github.com/coxswain-labs/coxswain/issues/24) `MUST`
- [ ] Per-route, per-client rate limiting (both APIs) — [#25](https://github.com/coxswain-labs/coxswain/issues/25) `MUST`

---

### v0.7 — Distribution & Community Readiness
*Target: Week 9–10*

The core is locked in. This milestone makes Coxswain installable and opens the door for community contributions.

- [ ] Dockerfile + OCI image on public registry — [#26](https://github.com/coxswain-labs/coxswain/issues/26) `MUST`
- [ ] Helm chart — [#27](https://github.com/coxswain-labs/coxswain/issues/27) `MUST`
- [ ] PodDisruptionBudget + resource requests/limits — [#51](https://github.com/coxswain-labs/coxswain/issues/51) `MUST`
- [ ] GitHub Actions release pipeline (OCI image, Helm chart, conformance) — [#28](https://github.com/coxswain-labs/coxswain/issues/28) `MUST`
- [ ] Sign OCI images with cosign (Sigstore) — [#46](https://github.com/coxswain-labs/coxswain/issues/46) `MUST`
- [ ] `ValidatingAdmissionPolicy` (K8s 1.30+) — [#29](https://github.com/coxswain-labs/coxswain/issues/29) `MUST`
- [ ] Docs site (getting started, config reference, architecture) — [#30](https://github.com/coxswain-labs/coxswain/issues/30) `MUST`
- [ ] Contributing guide + issue templates — [#31](https://github.com/coxswain-labs/coxswain/issues/31) `MUST`

**Community opens for contributions at this milestone.**

---

### v0.8 — HTTP/2 & gRPC
*Target: Week 11 — first community-contributed milestone*

- [ ] HTTP/2 downstream (h2c), HTTP/1.1 upstream bridging — [#32](https://github.com/coxswain-labs/coxswain/issues/32) `SHOULD`
- [ ] `GRPCRoute` + gRPC protocol support — [#33](https://github.com/coxswain-labs/coxswain/issues/33) `SHOULD`

---

### v1.0 — Conformance & GA
*Target: Week 12–14*

The finish line: full Gateway API conformance suite passing, conformance badge, stable public API.

- [ ] Full Gateway API conformance test suite — all applicable tests passing — [#34](https://github.com/coxswain-labs/coxswain/issues/34) `MUST`
- [ ] Conformance badge + stable `coxswain-labs.dev/*` annotation API — [#35](https://github.com/coxswain-labs/coxswain/issues/35) `MUST`
- [ ] Any remaining conformance gaps from v0.2–v0.8 `MUST`

---

### Post-v1.0 — Community Roadmap

- [ ] OpenTelemetry trace context propagation — [#36](https://github.com/coxswain-labs/coxswain/issues/36) `SHOULD`
- [ ] Active backend health probing — [#37](https://github.com/coxswain-labs/coxswain/issues/37) `SHOULD`
- [ ] `GatewayClass` `ParametersRef` support — [#38](https://github.com/coxswain-labs/coxswain/issues/38) `SHOULD`
- [ ] Session affinity / sticky sessions — [#39](https://github.com/coxswain-labs/coxswain/issues/39) `NICE`
- [ ] Response caching — [#40](https://github.com/coxswain-labs/coxswain/issues/40) `NICE`
- [ ] CORS built-in filter — [#41](https://github.com/coxswain-labs/coxswain/issues/41) `NICE`
- [ ] IPv6 / dual-stack explicit handling — [#42](https://github.com/coxswain-labs/coxswain/issues/42) `NICE`
- [ ] Performance profiling on admin port — [#43](https://github.com/coxswain-labs/coxswain/issues/43) `NICE`
- [ ] Dry-run mode for controller — [#44](https://github.com/coxswain-labs/coxswain/issues/44) `NICE`
- [ ] Canary deployments (progressive weight shifting) — [#53](https://github.com/coxswain-labs/coxswain/issues/53) `SHOULD`
- [ ] Traffic mirroring / shadow traffic — [#54](https://github.com/coxswain-labs/coxswain/issues/54) `SHOULD`
- [ ] Blue/green orchestration — [#55](https://github.com/coxswain-labs/coxswain/issues/55) `NICE`
