# Coxswain — Product Roadmap

## Milestones

Items within each milestone are listed in recommended implementation sequence.

### v0.1 — First Usable Release

The first fully usable version: all MUST-have features implemented, OCI image published, and Gateway API conformance test suite passing. Themes below reflect recommended implementation order.

#### Multi-tenancy & Spec Correctness

The most critical correctness gaps. Without these, Coxswain is unsafe in any shared cluster and fails Gateway API conformance on basic tests.

- [x] ~~Basic GitHub Actions CI (fmt, clippy, test) — [#45](https://github.com/coxswain-labs/coxswain/issues/45) `MUST`~~
- [x] ~~Cluster-backed integration test harness (`crates/coxswain-e2e`) — [#61](https://github.com/coxswain-labs/coxswain/issues/61) `SHOULD`~~
- [x] ~~IngressClass filtering — [#1](https://github.com/coxswain-labs/coxswain/issues/1) `MUST`~~
- [x] ~~`parentRef` matching for HTTPRoute — [#2](https://github.com/coxswain-labs/coxswain/issues/2) `MUST`~~
- [x] ~~`ReferenceGrant` for cross-namespace backends — [#3](https://github.com/coxswain-labs/coxswain/issues/3) `MUST`~~
- [x] ~~Namespace-scoped watch (wire up `--controller-watch-namespace`) — [#4](https://github.com/coxswain-labs/coxswain/issues/4) `MUST`~~
- [ ] Multi-namespace watch (comma-separated list + label selector) — [#59](https://github.com/coxswain-labs/coxswain/issues/59) `SHOULD`
- [x] ~~Gateway resource status patching — [#5](https://github.com/coxswain-labs/coxswain/issues/5) `MUST`~~
- [x] ~~Ingress `.status.loadBalancer` patching — [#48](https://github.com/coxswain-labs/coxswain/issues/48) `MUST`~~
- [x] ~~Default backend for Ingress — [#6](https://github.com/coxswain-labs/coxswain/issues/6) `MUST`~~
- [x] ~~HTTPRoute header, method, query matching — [#7](https://github.com/coxswain-labs/coxswain/issues/7) `MUST`~~

#### TLS & WebSocket

TLS is a launch blocker. WebSocket is the minimum protocol expansion needed to support real-time workloads.

- [x] ~~TLS termination for Ingress (`spec.tls`) — [#8](https://github.com/coxswain-labs/coxswain/issues/8) `MUST`~~
- [x] ~~TLS termination for Gateway API (listeners) — [#9](https://github.com/coxswain-labs/coxswain/issues/9) `MUST`~~
- [x] ~~Secret watch + hot TLS reload — [#10](https://github.com/coxswain-labs/coxswain/issues/10) `MUST`~~
- [ ] cert-manager integration (both APIs) — [#11](https://github.com/coxswain-labs/coxswain/issues/11) `MUST`
- [ ] WebSocket upgrade passthrough — [#12](https://github.com/coxswain-labs/coxswain/issues/12) `MUST`
- [ ] PROXY protocol v1/v2 support — [#49](https://github.com/coxswain-labs/coxswain/issues/49) `MUST`

#### Traffic Management

Full HTTPRoute filter compliance + the annotation layer for Ingress.

- [ ] `URLRewrite`, `RequestRedirect`, `RequestHeaderModifier`, `ResponseHeaderModifier` filters — [#13](https://github.com/coxswain-labs/coxswain/issues/13) `MUST`
- [ ] HTTPRoute `timeouts` field — [#14](https://github.com/coxswain-labs/coxswain/issues/14) `MUST`
- [ ] `BackendLBPolicy` (session persistence + timeouts per backend) — [#15](https://github.com/coxswain-labs/coxswain/issues/15) `MUST`
- [ ] `BackendTLSPolicy` — [#16](https://github.com/coxswain-labs/coxswain/issues/16) `MUST`
- [ ] Weighted backend refs — [#17](https://github.com/coxswain-labs/coxswain/issues/17) `MUST`
- [ ] `coxswain-labs.dev/*` annotation namespace — [#18](https://github.com/coxswain-labs/coxswain/issues/18) `MUST`
- [ ] Nginx-compatible annotation aliases — [#19](https://github.com/coxswain-labs/coxswain/issues/19) `MUST`

#### Observability & Health

Operators need signals before they trust any controller in production.

- [ ] Custom per-route Prometheus metrics (latency, rps, errors) — [#20](https://github.com/coxswain-labs/coxswain/issues/20) `MUST`
- [ ] Structured per-request access logs — [#21](https://github.com/coxswain-labs/coxswain/issues/21) `MUST`
- [ ] Passive backend health checking — [#22](https://github.com/coxswain-labs/coxswain/issues/22) `MUST`
- [ ] Endpoint drain (`conditions.serving`) — [#50](https://github.com/coxswain-labs/coxswain/issues/50) `MUST`

#### Security & Policy

Auth and rate limiting close the gap with production-grade controllers.

- [ ] `SecurityPolicy` (Gateway API ext_authz) — [#23](https://github.com/coxswain-labs/coxswain/issues/23) `MUST`
- [ ] `ext_authz` annotation for Ingress — [#24](https://github.com/coxswain-labs/coxswain/issues/24) `MUST`
- [ ] Per-route, per-client rate limiting (both APIs) — [#25](https://github.com/coxswain-labs/coxswain/issues/25) `MUST`

#### Distribution & Community

Makes Coxswain installable and opens the door for community contributions.

- [ ] Dockerfile + OCI image on public registry — [#26](https://github.com/coxswain-labs/coxswain/issues/26) `MUST`
- [ ] Helm chart — [#27](https://github.com/coxswain-labs/coxswain/issues/27) `MUST`
- [ ] PodDisruptionBudget + resource requests/limits — [#51](https://github.com/coxswain-labs/coxswain/issues/51) `MUST`
- [ ] GitHub Actions release pipeline (OCI image, Helm chart, conformance) — [#28](https://github.com/coxswain-labs/coxswain/issues/28) `MUST`
- [ ] Sign OCI images with cosign (Sigstore) — [#46](https://github.com/coxswain-labs/coxswain/issues/46) `MUST`
- [ ] `ValidatingAdmissionPolicy` (K8s 1.30+) — [#29](https://github.com/coxswain-labs/coxswain/issues/29) `MUST`
- [ ] Docs site (getting started, config reference, architecture) — [#30](https://github.com/coxswain-labs/coxswain/issues/30) `MUST`
- [ ] Contributing guide + issue templates — [#31](https://github.com/coxswain-labs/coxswain/issues/31) `MUST`
- [ ] Multi-namespace watch — [#56](https://github.com/coxswain-labs/coxswain/issues/56) `SHOULD`

**Community opens for contributions at this milestone.**

#### Conformance

The final gate: all applicable Gateway API conformance tests passing, badge published, and annotation API declared stable.

- [ ] Full Gateway API conformance test suite — all applicable tests passing — [#34](https://github.com/coxswain-labs/coxswain/issues/34) `MUST`
- [ ] Conformance badge + stable `coxswain-labs.dev/*` annotation API — [#35](https://github.com/coxswain-labs/coxswain/issues/35) `MUST`

---

### Post-v0.1 — Improvements

#### MUST

*None yet — issues will be added here as gaps emerge after v0.1 ships.*

#### SHOULD

- [ ] HTTP/2 downstream (h2c), HTTP/1.1 upstream bridging — [#32](https://github.com/coxswain-labs/coxswain/issues/32)
- [ ] `GRPCRoute` + gRPC protocol support — [#33](https://github.com/coxswain-labs/coxswain/issues/33)
- [ ] OpenTelemetry trace context propagation — [#36](https://github.com/coxswain-labs/coxswain/issues/36)
- [ ] Active backend health probing — [#37](https://github.com/coxswain-labs/coxswain/issues/37)
- [ ] `GatewayClass` `ParametersRef` support — [#38](https://github.com/coxswain-labs/coxswain/issues/38)
- [ ] Canary deployments (progressive weight shifting) — [#53](https://github.com/coxswain-labs/coxswain/issues/53)
- [ ] Traffic mirroring / shadow traffic — [#54](https://github.com/coxswain-labs/coxswain/issues/54)

#### NICE

- [ ] Session affinity / sticky sessions — [#39](https://github.com/coxswain-labs/coxswain/issues/39)
- [ ] Response caching — [#40](https://github.com/coxswain-labs/coxswain/issues/40)
- [ ] CORS built-in filter — [#41](https://github.com/coxswain-labs/coxswain/issues/41)
- [ ] IPv6 / dual-stack explicit handling — [#42](https://github.com/coxswain-labs/coxswain/issues/42)
- [ ] Performance profiling on admin port — [#43](https://github.com/coxswain-labs/coxswain/issues/43)
- [ ] Dry-run mode for controller — [#44](https://github.com/coxswain-labs/coxswain/issues/44)
- [ ] Blue/green orchestration — [#55](https://github.com/coxswain-labs/coxswain/issues/55)
